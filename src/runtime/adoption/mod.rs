// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Resource-transfer adapters confirm each replacement before retirement.
//! The dedicated retirement service owns final predecessor teardown.

mod process;
mod retirement;

use super::Runtime;
use core::mem::MaybeUninit;
use hyper_os::capability_channel::{CapabilityChannel, CapabilityReceiveSlot};
use hyper_os::handle::*;

const READY: u32 = 0x8008_0020;
const ADOPTED: &[u8] = b"HYPER-SERVICE-ADOPTED/1";
const PROCESS_RIGHTS: Rights = Rights::TRANSFER
    .union(Rights::WAIT)
    .union(Rights::INSPECT)
    .union(Rights::REQUEST_STOP);

impl Runtime {
    pub(super) fn adopt_provider(
        &mut self,
        role: usize,
        name: &str,
        program: &hyper_component_config::Program,
    ) -> hyper_os::Result<()> {
        let Some(index) = self.providers[role] else {
            return Err(hyper_os::Error::MissingHandle);
        };
        if role != 0 && !self.bootstrap_storage_ready {
            return Err(hyper_os::Error::Status(hyper_os::Status::BAD_STATE));
        }
        // One adoption budget covers description, owner transfer and confirmation;
        // a peer sending partial progress cannot restart the timeout each step.
        let until =
            hyper_os::time::deadline_after(std::time::Duration::from_millis(program.timeout_ms))?
                .as_raw();
        let result = match role {
            0 => self.adopt_console(index, name, program, until),
            1 => self.adopt_io(index, name, program, until),
            _ => self.adopt_filesystems(index, name, program, until),
        };
        if result.is_err() {
            self.retain_unconfirmed_provider(role == 0);
            self.retirement_ready = false;
            // An unstarted successor must not leave the predecessor waiting
            // forever for a migration handshake; close unopened rendezvous.
            self.launcher.authorities.io_handoff.take();
            self.launcher.authorities.filesystem_handoff.take();
            eprintln!(
                "HypeR system-startup: provider adoption failed: bootstrap retirement disabled; {name}: {result:?}"
            );
        }
        result
    }

    fn adopt_console(
        &mut self,
        index: usize,
        name: &str,
        program: &hyper_component_config::Program,
        until: u64,
    ) -> hyper_os::Result<()> {
        let (control, controller) = CapabilityChannel::create()?;
        let (logs, connector) = CapabilityChannel::create()?;
        let (ready, reader) = hyper_os::channel::create_pair()?;
        let builder = self.provider_builder(name, program, None)?;
        let a = &self.launcher.authorities;
        duplicate(
            &builder,
            a.console.as_handle_ref(),
            hyper_service::console::SYSTEM_CONSOLE.as_raw(),
            Rights::READ.union(Rights::WRITE).union(Rights::WAIT),
        )?;
        move_handle(
            &builder,
            control.into_handle(),
            hyper_service::console::CONTROL.as_raw(),
            Rights::READ.union(Rights::WAIT),
        )?;
        move_handle(
            &builder,
            logs.into_handle(),
            hyper_service::console::LOG_CONNECTOR.as_raw(),
            Rights::READ.union(Rights::WAIT),
        )?;
        move_handle(&builder, ready, READY, Rights::WRITE.union(Rights::WAIT))?;
        self.start_provider(index, builder)?;
        ready_message(&reader, ADOPTED, until)?;
        self.confirm_provider(index)?;
        self.launcher.authorities.raw_controller = Some(controller.into_handle());
        self.launcher.authorities.log_connector = connector.into_handle();
        Ok(())
    }

    fn adopt_io(
        &mut self,
        index: usize,
        name: &str,
        program: &hyper_component_config::Program,
        until: u64,
    ) -> hyper_os::Result<()> {
        let endpoint = self
            .launcher
            .authorities
            .io_handoff
            .take()
            .ok_or(hyper_os::Error::MissingHandle)?;
        let channel = CapabilityChannel::from_handle(endpoint);
        let description = receive_description(&channel, b"HYPER-IO-DESCRIBE/2", until)?;
        let (ready, reader) = hyper_os::channel::create_pair()?;
        let builder = self.provider_builder(name, program, Some(name))?;
        move_handle(
            &builder,
            channel.into_handle(),
            0x8008_0010,
            Rights::READ.union(Rights::WAIT),
        )?;
        move_handle(
            &builder,
            description,
            0x8008_0012,
            Rights::READ.union(Rights::INSPECT),
        )?;
        move_handle(&builder, ready, READY, Rights::WRITE.union(Rights::WAIT))?;
        self.start_provider(index, builder)?;
        ready_message(&reader, b"HYPER-IO-READY/2", until)?;
        self.confirm_provider(index)
    }

    fn adopt_filesystems(
        &mut self,
        index: usize,
        name: &str,
        program: &hyper_component_config::Program,
        until: u64,
    ) -> hyper_os::Result<()> {
        let endpoint = self
            .launcher
            .authorities
            .filesystem_handoff
            .take()
            .ok_or(hyper_os::Error::MissingHandle)?;
        let channel = CapabilityChannel::from_handle(endpoint);
        let description = receive_description(&channel, b"HYPER-FS-DESCRIBE/1", until)?;
        let (ready, reader) = hyper_os::channel::create_pair()?;
        let (owners, sender) = CapabilityChannel::create()?;
        let builder = self.provider_builder(name, program, Some(name))?;
        self.delegate_filesystem_launch(&builder)?;
        move_handle(
            &builder,
            channel.into_handle(),
            0x8008_0011,
            Rights::READ.union(Rights::WRITE).union(Rights::WAIT),
        )?;
        move_handle(
            &builder,
            description,
            0x8008_0013,
            Rights::READ.union(Rights::INSPECT),
        )?;
        move_handle(&builder, ready, READY, Rights::WRITE.union(Rights::WAIT))?;
        move_handle(
            &builder,
            sender.into_handle(),
            0x8008_0021,
            Rights::WRITE.union(Rights::WAIT),
        )?;
        self.start_provider(index, builder)?;
        loop {
            let mut bytes = [MaybeUninit::uninit(); 64];
            let mut slots = [CapabilityReceiveSlot::new::<ProcessObject>(PROCESS_RIGHTS)];
            let message = owners.receive(until, &mut bytes, &mut slots)?;
            if message.bytes() == b"HYPER-BOOT-OWNERS-END/1" && message.capability_count() == 0 {
                break;
            }
            if message.bytes() != b"HYPER-BOOT-OWNER/1" || message.capability_count() != 1 {
                return Err(hyper_os::Error::InvalidResponse);
            }
            if self.retired_processes.len() >= hyper_bootstrap_handoff::retirement::MAX_PREDECESSORS
            {
                return Err(hyper_os::Error::Status(hyper_os::Status::RESOURCE_LIMIT));
            }
            self.retired_processes.push(
                slots[0]
                    .take::<ProcessObject>()?
                    .ok_or(hyper_os::Error::MissingHandle)?,
            );
        }
        ready_message(&reader, ADOPTED, until)?;
        self.confirm_provider(index)
    }
}

fn receive_description(
    channel: &CapabilityChannel,
    expected: &[u8],
    until: u64,
) -> hyper_os::Result<OwnedHandle<VmoObject>> {
    let mut bytes = [MaybeUninit::uninit(); 64];
    let mut slots = [CapabilityReceiveSlot::new::<VmoObject>(
        Rights::READ.union(Rights::TRANSFER).union(Rights::INSPECT),
    )];
    let message = channel.receive(until, &mut bytes, &mut slots)?;
    if message.bytes() != expected || message.capability_count() != 1 {
        return Err(hyper_os::Error::InvalidResponse);
    }
    slots[0]
        .take::<VmoObject>()?
        .ok_or(hyper_os::Error::MissingHandle)
}

fn ready_message(
    channel: &OwnedHandle<ByteChannelObject>,
    expected: &[u8],
    until: u64,
) -> hyper_os::Result<()> {
    use hyper_os::wait::{ObjectSignals, WaitItem, wait_many};
    wait_many(
        &[WaitItem::new(
            channel.as_handle_ref(),
            ObjectSignals::<ByteChannelObject>::READABLE
                .union(ObjectSignals::<ByteChannelObject>::PEER_CLOSED),
        )],
        until,
    )?;
    let mut bytes = [0; 64];
    let length = channel.as_byte_channel().try_receive(&mut bytes)?;
    if &bytes[..length] != expected {
        return Err(hyper_os::Error::InvalidResponse);
    }
    Ok(())
}

fn duplicate<T: TypedObject>(
    builder: &hyper_os::task::ProcessBuilder,
    source: HandleRef<'_, T>,
    purpose: u32,
    rights: Rights,
) -> hyper_os::Result<()> {
    builder.add_handle_duplicate(source, purpose, RightsOffer::Exact(rights))
}
fn move_handle<T: TypedObject>(
    builder: &hyper_os::task::ProcessBuilder,
    source: OwnedHandle<T>,
    purpose: u32,
    rights: Rights,
) -> hyper_os::Result<()> {
    builder
        .add_handle_move(source, purpose, RightsOffer::Exact(rights))
        .map_err(|failure| failure.error())
}
