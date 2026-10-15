// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

use super::model::{
    BoundedList, CapabilityBinding, CapabilityOperation, MAX_BINDING_NAME_BYTES,
    MAX_CAPABILITIES_PER_SERVICE, MAX_DEPENDENCIES_PER_SERVICE, MAX_IMAGE_PATH_BYTES,
    MAX_MANIFEST_BYTES, MAX_PURPOSE_NAME_BYTES, MAX_RIGHT_NAME_BYTES, MAX_RIGHTS_PER_CAPABILITY,
    MAX_SERVICE_NAME_BYTES, MAX_SERVICES, Manifest, RestartPolicy, Service, ServicePhase,
    VmConfiguration,
};

const FORMAT: &str = "hyper.service-manifest";
const MAX_JSON_DEPTH: usize = 8;

/// Precise class of syntax or schema failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParseErrorKind {
    TooLarge,
    UnexpectedEnd,
    UnexpectedToken,
    TrailingInput,
    DepthExceeded,
    EscapeNotAllowed,
    StringTooLong,
    UnknownField,
    DuplicateField,
    MissingField,
    InvalidFormat,
    InvalidEnum,
    TooManyServices,
    TooManyDependencies,
    TooManyCapabilities,
    TooManyRights,
}

/// A parse failure at one byte offset in the original manifest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParseError {
    kind: ParseErrorKind,
    offset: usize,
}

impl ParseError {
    pub const fn kind(self) -> ParseErrorKind {
        self.kind
    }

    pub const fn offset(self) -> usize {
        self.offset
    }
}

/// Parses the complete manifest into bounded heap-backed collections.
///
/// Manifest strings are canonical UTF-8 text and may not contain JSON escape
/// sequences. This deliberate schema restriction gives names and paths one
/// byte representation and lets the parsed model borrow immutable file data.
pub fn parse(input: &str) -> Result<Manifest<'_>, ParseError> {
    let mut manifest = Manifest::empty();
    parse_into(input, &mut manifest)?;
    Ok(manifest)
}

/// Parses into an empty destination, preserving the schema's resource limits.
/// A failed parse may leave partial data, which the caller must discard.
pub(crate) fn parse_into<'manifest>(
    input: &'manifest str,
    manifest: &mut Manifest<'manifest>,
) -> Result<(), ParseError> {
    if input.len() > MAX_MANIFEST_BYTES {
        return Err(ParseError {
            kind: ParseErrorKind::TooLarge,
            offset: MAX_MANIFEST_BYTES,
        });
    }
    if !manifest.services.is_empty() {
        return Err(ParseError {
            kind: ParseErrorKind::DuplicateField,
            offset: 0,
        });
    }
    let mut parser = Parser::new(input);
    parser.parse_manifest_into(manifest)?;
    parser.skip_whitespace();
    if parser.position != parser.bytes.len() {
        return Err(parser.error(ParseErrorKind::TrailingInput));
    }
    Ok(())
}

struct Parser<'manifest> {
    input: &'manifest str,
    bytes: &'manifest [u8],
    position: usize,
    depth: usize,
}

impl<'manifest> Parser<'manifest> {
    const fn new(input: &'manifest str) -> Self {
        Self {
            input,
            bytes: input.as_bytes(),
            position: 0,
            depth: 0,
        }
    }

    fn parse_manifest_into(
        &mut self,
        manifest: &mut Manifest<'manifest>,
    ) -> Result<(), ParseError> {
        self.open(b'{')?;
        let mut format = None;
        let mut copyright_present = false;
        let mut license_present = false;
        let mut vm_configuration = None;
        let mut services_present = false;
        if self.consume_close(b'}') {
            return Err(self.error(ParseErrorKind::MissingField));
        }
        loop {
            let field_offset = self.position;
            let field = self.parse_string(MAX_BINDING_NAME_BYTES)?;
            self.colon()?;
            match field {
                "SPDX-FileCopyrightText" => {
                    parse_unique_metadata(self, &mut copyright_present, field_offset)?;
                }
                "SPDX-License-Identifier" => {
                    parse_unique_metadata(self, &mut license_present, field_offset)?;
                }
                "format" => assign_once(
                    &mut format,
                    self.parse_string(MAX_BINDING_NAME_BYTES)?,
                    field_offset,
                )?,
                "virtual-machines" => assign_once(
                    &mut vm_configuration,
                    self.parse_vm_configuration()?,
                    field_offset,
                )?,
                "services" => {
                    if services_present {
                        return Err(self.at(ParseErrorKind::DuplicateField, field_offset));
                    }
                    self.parse_services(&mut manifest.services)?;
                    services_present = true;
                }
                _ => return Err(self.at(ParseErrorKind::UnknownField, field_offset)),
            }
            if self.next_field_or_close(b'}')? {
                break;
            }
        }
        let Some(format) = format else {
            return Err(self.error(ParseErrorKind::MissingField));
        };
        if format != FORMAT {
            return Err(self.error(ParseErrorKind::InvalidFormat));
        }
        if !services_present {
            return Err(self.error(ParseErrorKind::MissingField));
        }
        manifest.vm_configuration = vm_configuration;
        Ok(())
    }

    fn parse_vm_configuration(&mut self) -> Result<VmConfiguration<'manifest>, ParseError> {
        self.open(b'{')?;
        let mut config = None;
        if self.consume_close(b'}') {
            return Err(self.error(ParseErrorKind::MissingField));
        }
        loop {
            let field_offset = self.position;
            let field = self.parse_string(MAX_BINDING_NAME_BYTES)?;
            self.colon()?;
            match field {
                "config" => assign_once(
                    &mut config,
                    self.parse_string(MAX_IMAGE_PATH_BYTES)?,
                    field_offset,
                )?,
                _ => return Err(self.at(ParseErrorKind::UnknownField, field_offset)),
            }
            if self.next_field_or_close(b'}')? {
                break;
            }
        }
        Ok(VmConfiguration {
            config: config.ok_or_else(|| self.error(ParseErrorKind::MissingField))?,
        })
    }

    fn parse_services(
        &mut self,
        services: &mut BoundedList<Service<'manifest>, MAX_SERVICES>,
    ) -> Result<(), ParseError> {
        self.open(b'[')?;
        if self.consume_close(b']') {
            return Ok(());
        }
        loop {
            let service = self.parse_service()?;
            services.push(service).map_err(|_| ParseError {
                kind: ParseErrorKind::TooManyServices,
                offset: self.position,
            })?;
            if self.next_field_or_close(b']')? {
                return Ok(());
            }
        }
    }

    fn parse_service(&mut self) -> Result<Service<'manifest>, ParseError> {
        self.open(b'{')?;
        let mut name = None;
        let mut image = None;
        let mut critical = None;
        let mut restart = None;
        let mut phase = None;
        let mut loader = None;
        let mut dependencies = None;
        let mut capabilities = None;
        if self.consume_close(b'}') {
            return Err(self.error(ParseErrorKind::MissingField));
        }
        loop {
            let field_offset = self.position;
            let field = self.parse_string(MAX_BINDING_NAME_BYTES)?;
            self.colon()?;
            match field {
                "name" => assign_once(
                    &mut name,
                    self.parse_string(MAX_SERVICE_NAME_BYTES)?,
                    field_offset,
                )?,
                "image" => assign_once(
                    &mut image,
                    self.parse_string(MAX_IMAGE_PATH_BYTES)?,
                    field_offset,
                )?,
                "critical" => {
                    let value = self.parse_bool()?;
                    assign_once(&mut critical, value, field_offset)?;
                }
                "restart" => {
                    let value = match self.parse_string(MAX_BINDING_NAME_BYTES)? {
                        "never" => RestartPolicy::Never,
                        "on-failure" => RestartPolicy::OnFailure,
                        "always" => RestartPolicy::Always,
                        _ => return Err(self.error(ParseErrorKind::InvalidEnum)),
                    };
                    assign_once(&mut restart, value, field_offset)?;
                }
                "loader" => {
                    let value = match self.parse_string(MAX_BINDING_NAME_BYTES)? {
                        "bootstrap" => hyper_service::process::LoaderKind::Bootstrap,
                        "dynamic" => hyper_service::process::LoaderKind::Dynamic,
                        _ => return Err(self.error(ParseErrorKind::InvalidEnum)),
                    };
                    assign_once(&mut loader, value, field_offset)?;
                }
                "phase" => {
                    let value = match self.parse_string(MAX_BINDING_NAME_BYTES)? {
                        "boot" => ServicePhase::Boot,
                        "system" => ServicePhase::System,
                        _ => return Err(self.error(ParseErrorKind::InvalidEnum)),
                    };
                    assign_once(&mut phase, value, field_offset)?;
                }
                "after" => {
                    let value = self.parse_string_array::<MAX_DEPENDENCIES_PER_SERVICE>(
                        MAX_SERVICE_NAME_BYTES,
                        ParseErrorKind::TooManyDependencies,
                    )?;
                    assign_once(&mut dependencies, value, field_offset)?;
                }
                "capabilities" => {
                    let value = self.parse_capabilities()?;
                    assign_once(&mut capabilities, value, field_offset)?;
                }
                _ => return Err(self.at(ParseErrorKind::UnknownField, field_offset)),
            }
            if self.next_field_or_close(b'}')? {
                break;
            }
        }
        Ok(Service {
            name: name.ok_or_else(|| self.error(ParseErrorKind::MissingField))?,
            image: image.ok_or_else(|| self.error(ParseErrorKind::MissingField))?,
            critical: critical.ok_or_else(|| self.error(ParseErrorKind::MissingField))?,
            restart: restart.ok_or_else(|| self.error(ParseErrorKind::MissingField))?,
            phase: phase.unwrap_or(ServicePhase::Boot),
            loader: loader.unwrap_or(hyper_service::process::LoaderKind::Dynamic),
            dependencies: dependencies.ok_or_else(|| self.error(ParseErrorKind::MissingField))?,
            capabilities: capabilities.ok_or_else(|| self.error(ParseErrorKind::MissingField))?,
        })
    }

    fn parse_capabilities(
        &mut self,
    ) -> Result<BoundedList<CapabilityBinding<'manifest>, MAX_CAPABILITIES_PER_SERVICE>, ParseError>
    {
        self.open(b'[')?;
        let mut capabilities = BoundedList::new();
        if self.consume_close(b']') {
            return Ok(capabilities);
        }
        loop {
            let capability = self.parse_capability()?;
            capabilities.push(capability).map_err(|_| ParseError {
                kind: ParseErrorKind::TooManyCapabilities,
                offset: self.position,
            })?;
            if self.next_field_or_close(b']')? {
                return Ok(capabilities);
            }
        }
    }

    fn parse_capability(&mut self) -> Result<CapabilityBinding<'manifest>, ParseError> {
        self.open(b'{')?;
        let mut source = None;
        let mut purpose = None;
        let mut operation = None;
        let mut rights = None;
        if self.consume_close(b'}') {
            return Err(self.error(ParseErrorKind::MissingField));
        }
        loop {
            let field_offset = self.position;
            let field = self.parse_string(MAX_BINDING_NAME_BYTES)?;
            self.colon()?;
            match field {
                "source" => assign_once(
                    &mut source,
                    self.parse_string(MAX_BINDING_NAME_BYTES)?,
                    field_offset,
                )?,
                "purpose" => assign_once(
                    &mut purpose,
                    self.parse_string(MAX_PURPOSE_NAME_BYTES)?,
                    field_offset,
                )?,
                "operation" => {
                    let value = match self.parse_string(MAX_BINDING_NAME_BYTES)? {
                        "move" => CapabilityOperation::Move,
                        "duplicate" => CapabilityOperation::Duplicate,
                        "create" => CapabilityOperation::Create,
                        _ => return Err(self.error(ParseErrorKind::InvalidEnum)),
                    };
                    assign_once(&mut operation, value, field_offset)?;
                }
                "rights" => {
                    let value = self.parse_string_array::<MAX_RIGHTS_PER_CAPABILITY>(
                        MAX_RIGHT_NAME_BYTES,
                        ParseErrorKind::TooManyRights,
                    )?;
                    assign_once(&mut rights, value, field_offset)?;
                }
                _ => return Err(self.at(ParseErrorKind::UnknownField, field_offset)),
            }
            if self.next_field_or_close(b'}')? {
                break;
            }
        }
        Ok(CapabilityBinding {
            source: source.ok_or_else(|| self.error(ParseErrorKind::MissingField))?,
            purpose: purpose.ok_or_else(|| self.error(ParseErrorKind::MissingField))?,
            operation: operation.ok_or_else(|| self.error(ParseErrorKind::MissingField))?,
            rights: rights.ok_or_else(|| self.error(ParseErrorKind::MissingField))?,
        })
    }

    fn parse_string_array<const N: usize>(
        &mut self,
        maximum_length: usize,
        overflow: ParseErrorKind,
    ) -> Result<BoundedList<&'manifest str, N>, ParseError> {
        self.open(b'[')?;
        let mut values = BoundedList::new();
        if self.consume_close(b']') {
            return Ok(values);
        }
        loop {
            let value = self.parse_string(maximum_length)?;
            values.push(value).map_err(|_| ParseError {
                kind: overflow,
                offset: self.position,
            })?;
            if self.next_field_or_close(b']')? {
                return Ok(values);
            }
        }
    }

    fn parse_string(&mut self, maximum_length: usize) -> Result<&'manifest str, ParseError> {
        self.skip_whitespace();
        self.expect(b'"')?;
        let start = self.position;
        while let Some(byte) = self.bytes.get(self.position).copied() {
            match byte {
                b'"' => {
                    let end = self.position;
                    self.position += 1;
                    if end.saturating_sub(start) > maximum_length {
                        return Err(self.at(ParseErrorKind::StringTooLong, start));
                    }
                    return self
                        .input
                        .get(start..end)
                        .ok_or_else(|| self.at(ParseErrorKind::UnexpectedToken, start));
                }
                b'\\' => return Err(self.error(ParseErrorKind::EscapeNotAllowed)),
                0x00..=0x1f => return Err(self.error(ParseErrorKind::UnexpectedToken)),
                _ => self.position += 1,
            }
        }
        Err(self.error(ParseErrorKind::UnexpectedEnd))
    }

    fn parse_bool(&mut self) -> Result<bool, ParseError> {
        self.skip_whitespace();
        if self.consume_literal(b"true") {
            return Ok(true);
        }
        if self.consume_literal(b"false") {
            return Ok(false);
        }
        Err(self.error(ParseErrorKind::UnexpectedToken))
    }

    fn colon(&mut self) -> Result<(), ParseError> {
        self.skip_whitespace();
        self.expect(b':')
    }

    fn open(&mut self, token: u8) -> Result<(), ParseError> {
        self.skip_whitespace();
        if self.depth == MAX_JSON_DEPTH {
            return Err(self.error(ParseErrorKind::DepthExceeded));
        }
        self.expect(token)?;
        self.depth += 1;
        Ok(())
    }

    fn consume_close(&mut self, token: u8) -> bool {
        self.skip_whitespace();
        if self.bytes.get(self.position) != Some(&token) {
            return false;
        }
        self.position += 1;
        self.depth = self.depth.saturating_sub(1);
        true
    }

    fn next_field_or_close(&mut self, close: u8) -> Result<bool, ParseError> {
        self.skip_whitespace();
        if self.consume_close(close) {
            return Ok(true);
        }
        self.expect(b',')?;
        self.skip_whitespace();
        if self.bytes.get(self.position) == Some(&close) {
            return Err(self.error(ParseErrorKind::UnexpectedToken));
        }
        Ok(false)
    }

    fn consume_literal(&mut self, literal: &[u8]) -> bool {
        let Some(end) = self.position.checked_add(literal.len()) else {
            return false;
        };
        if self.bytes.get(self.position..end) != Some(literal) {
            return false;
        }
        self.position = end;
        true
    }

    fn expect(&mut self, token: u8) -> Result<(), ParseError> {
        let Some(actual) = self.bytes.get(self.position) else {
            return Err(self.error(ParseErrorKind::UnexpectedEnd));
        };
        if *actual != token {
            return Err(self.error(ParseErrorKind::UnexpectedToken));
        }
        self.position += 1;
        Ok(())
    }

    fn skip_whitespace(&mut self) {
        while matches!(
            self.bytes.get(self.position),
            Some(b' ' | b'\n' | b'\r' | b'\t')
        ) {
            self.position += 1;
        }
    }

    const fn error(&self, kind: ParseErrorKind) -> ParseError {
        self.at(kind, self.position)
    }

    const fn at(&self, kind: ParseErrorKind, offset: usize) -> ParseError {
        ParseError { kind, offset }
    }
}

fn parse_unique_metadata(
    parser: &mut Parser<'_>,
    present: &mut bool,
    field_offset: usize,
) -> Result<(), ParseError> {
    if *present {
        return Err(parser.at(ParseErrorKind::DuplicateField, field_offset));
    }
    let _ = parser.parse_string(MAX_BINDING_NAME_BYTES)?;
    *present = true;
    Ok(())
}

fn assign_once<T>(slot: &mut Option<T>, value: T, offset: usize) -> Result<(), ParseError> {
    if slot.is_some() {
        return Err(ParseError {
            kind: ParseErrorKind::DuplicateField,
            offset,
        });
    }
    *slot = Some(value);
    Ok(())
}
