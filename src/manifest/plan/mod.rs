// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

mod capabilities;
mod graph;

use super::model::{
    CapabilityOperation, MAX_CAPABILITIES_PER_SERVICE, MAX_SERVICES, Manifest, Service,
};

/// Declarative ceiling for one authority resolved during process preparation.
///
/// This is policy metadata, not an object reference. The runtime adapter must
/// resolve and revalidate the real handle immediately before `ProcessBuilder`
/// commit; a validated plan can never manufacture authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorityKey(u16);

impl AuthorityKey {
    /// Creates one policy-local authority identity.
    ///
    /// Keys are opaque to the manifest and need only be unique within one
    /// `AuthorityPolicy` implementation. The runtime consumes the resolved key
    /// instead of interpreting the manifest's source string a second time.
    pub const fn new(value: u16) -> Self {
        Self(value)
    }

    pub const fn as_raw(self) -> u16 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorityDeclaration<'policy> {
    pub key: AuthorityKey,
    pub provider: Option<&'policy str>,
    pub object_kind: u32,
    pub rights: u64,
    /// The named source may be consumed and transferred exactly once.
    pub movable: bool,
    /// The named source may be retained while a duplicate is transferred.
    pub duplicable: bool,
    /// The named source is a typed factory which can create fresh authority.
    pub creatable: bool,
}

/// One service-contract name resolved to a typed startup-stack purpose.
///
/// The required and allowed masks define the complete authority contract for
/// this purpose. The manifest may attenuate within that interval, but cannot
/// silently grant an implementation more authority merely because the source
/// object happens to support it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StartupPurposeDeclaration {
    pub value: u32,
    pub object_kind: u32,
    pub required_rights: u64,
    pub allowed_rights: u64,
}

/// One capability grant fully resolved by manifest validation.
///
/// Keeping these facts together prevents launch code from accidentally
/// combining the authority, operation, kind, purpose, or rights of different
/// capability rows.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapabilityGrant {
    authority: AuthorityKey,
    operation: CapabilityOperation,
    object_kind: u32,
    purpose: u32,
    rights: u64,
}

impl CapabilityGrant {
    pub const fn authority(self) -> AuthorityKey {
        self.authority
    }

    pub const fn operation(self) -> CapabilityOperation {
        self.operation
    }

    pub const fn object_kind(self) -> u32 {
        self.object_kind
    }

    pub const fn purpose(self) -> u32 {
        self.purpose
    }

    pub const fn rights(self) -> u64 {
        self.rights
    }
}

/// Adapter from manifest vocabulary to the actual bootstrap authority policy.
pub trait AuthorityPolicy {
    fn authority<'policy>(&'policy self, source: &str) -> Option<AuthorityDeclaration<'policy>>;

    /// Resolves a symbolic purpose in the contract selected by `image`.
    fn startup_purpose(&self, image: &str, name: &str) -> Option<StartupPurposeDeclaration>;

    /// Resolves the deployed service contract. Bootstrap and formal images may
    /// share a path while intentionally receiving different authorities.
    fn service_purpose(
        &self,
        service: &Service<'_>,
        name: &str,
    ) -> Option<StartupPurposeDeclaration> {
        self.startup_purpose(service.image(), name)
    }

    /// Resolves one named right to exactly one bit.
    fn right(&self, name: &str) -> Option<u64>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValidationErrorKind {
    EmptyManifest,
    InvalidServiceName,
    InvalidImagePath,
    DuplicateServiceName,
    InvalidDependencyName,
    DuplicateDependency,
    SelfDependency,
    UnknownDependency,
    BootDependsOnSystem,
    TooManyDependencyEdges,
    DependencyCycle,
    ConflictingAuthorityKey,
    InvalidVmConfigPath,
    InvalidBindingName,
    DuplicateCapabilityPurpose,
    InvalidPurposeName,
    InvalidPurposeDeclaration,
    UnknownCapabilityPurpose,
    UnknownAuthority,
    UnknownAuthorityProvider,
    MissingProviderDependency,
    ObjectKindMismatch,
    InvalidRightName,
    UnknownRight,
    InvalidRightDeclaration,
    DuplicateRight,
    RightsEscalation,
    MissingRequiredRights,
    ExcessPurposeRights,
    TransferForbidden,
    DuplicateForbidden,
    CreateForbidden,
    RestartConsumesAuthority,
    MoveSourceReused,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidationError {
    kind: ValidationErrorKind,
    service: Option<usize>,
    capability: Option<usize>,
}

impl ValidationError {
    pub const fn kind(self) -> ValidationErrorKind {
        self.kind
    }

    pub const fn service(self) -> Option<usize> {
        self.service
    }

    pub const fn capability(self) -> Option<usize> {
        self.capability
    }
}

/// Deterministic topological order plus resolved, attenuated capability facts.
#[derive(Debug, Eq, PartialEq)]
pub struct LaunchPlan<'manifest> {
    service_count: usize,
    vm_config_path: Option<&'manifest str>,
    order: [usize; MAX_SERVICES],
    grants: Vec<Vec<Option<CapabilityGrant>>>,
}

impl LaunchPlan<'_> {
    pub const fn service_count(&self) -> usize {
        self.service_count
    }

    pub const fn vm_config_path(&self) -> Option<&str> {
        self.vm_config_path
    }

    pub fn service_index(&self, launch_position: usize) -> Option<usize> {
        self.order
            .get(launch_position)
            .copied()
            .filter(|_| launch_position < self.service_count)
    }

    /// Returns one complete resolved row or no row at all.
    pub fn capability_grant(&self, service: usize, capability: usize) -> Option<CapabilityGrant> {
        if service >= self.service_count || capability >= MAX_CAPABILITIES_PER_SERVICE {
            return None;
        }
        self.grants[service][capability]
    }

    /// Finds the only service which receives `purpose`.
    ///
    /// Singleton service roles are bound to a validated capability contract,
    /// not to a mutable executable path. Zero or ambiguous matches are both
    /// rejected so callers cannot accidentally provision the wrong process.
    pub fn unique_service_for_purpose(&self, purpose: u32) -> Option<usize> {
        if purpose == 0 {
            return None;
        }
        let mut selected = None;
        for service in 0..self.service_count {
            if self.grants[service]
                .iter()
                .flatten()
                .any(|grant| grant.purpose() == purpose)
            {
                if selected.is_some() {
                    return None;
                }
                selected = Some(service);
            }
        }
        selected
    }
}

/// Validates the complete graph before any `ProcessBuilder` may start a service.
pub fn validate<'manifest>(
    manifest: &Manifest<'manifest>,
    policy: &impl AuthorityPolicy,
) -> Result<LaunchPlan<'manifest>, ValidationError> {
    if manifest.services.is_empty() {
        return Err(error(ValidationErrorKind::EmptyManifest, None, None));
    }
    graph::validate_service_identities(manifest)?;
    graph::validate_vm_configuration(manifest)?;
    graph::validate_dependencies(manifest)?;

    let mut plan = LaunchPlan {
        service_count: manifest.services.len(),
        vm_config_path: manifest.vm_config_path(),
        order: [0; MAX_SERVICES],
        grants: vec![vec![None; MAX_CAPABILITIES_PER_SERVICE]; manifest.services.len()],
    };
    capabilities::validate(manifest, policy, &mut plan)?;
    graph::build_topological_order(manifest, &mut plan)?;
    Ok(plan)
}

fn valid_identifier(value: &str, maximum_length: usize) -> bool {
    if value.is_empty() || value.len() > maximum_length {
        return false;
    }
    value.bytes().enumerate().all(|(index, byte)| match byte {
        b'a'..=b'z' => true,
        b'0'..=b'9' | b'_' | b'-' if index != 0 => true,
        b'.' if index != 0 && index + 1 != value.len() => true,
        _ => false,
    })
}

const fn error(
    kind: ValidationErrorKind,
    service: Option<usize>,
    capability: Option<usize>,
) -> ValidationError {
    ValidationError {
        kind,
        service,
        capability,
    }
}
