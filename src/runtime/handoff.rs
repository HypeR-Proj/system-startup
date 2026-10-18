// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Receive core supervision after validating the formal environment's policy.
//! Registering receive declares readiness; only a successful capability
//! rendezvous commits ownership.

mod inventory;
mod metadata;

use hyper_os::capability_channel::CapabilityChannel;
use hyper_os::handle::CapabilityChannelObject;
use hyper_os::startup::{self, Startup};
use std::mem::MaybeUninit;

use super::{Error, Runtime};
use crate::bootstrap_policy::BootstrapPolicy;
use crate::manifest;
use metadata::PreparedOffer;

const COMMIT: &[u8] = b"HYPER-SYSTEM-STARTUP/1";
const ENDPOINT: startup::StartupPurpose<CapabilityChannelObject> =
    startup::StartupPurpose::new(0x8008_0001);

pub(super) fn run_system(startup: &mut Startup<'_>) -> Result<(), Error> {
    hyper_os::require_core_abi().map_err(|error| {
        report_failure("checking the Native ABI", &error);
        Error::OperatingSystem
    })?;
    let mut offer = PreparedOffer::read(startup).map_err(|error| {
        report_failure("reading the handoff offer", &error);
        Error::Source
    })?;
    hyper_os::memory::lock_current_memory(
        startup
            .borrow(startup::ROOT_VMAR)
            .map_err(|_| Error::OperatingSystem)?,
    )
    .map_err(|error| {
        report_failure("locking supervisor mappings", &error);
        Error::OperatingSystem
    })?;
    let root = startup
        .borrow(startup::ROOT_DIRECTORY)
        .map_err(|_| Error::OperatingSystem)?;
    if hyper_os::fs::Directory::from_handle(
        root.duplicate(root.info().map_err(|_| Error::OperatingSystem)?.rights)
            .map_err(|_| Error::OperatingSystem)?,
    )
    .info()
    .map_err(|_| Error::OperatingSystem)?
    .location()
    .mount()
    .get()
        != offer.root_mount
    {
        return Err(Error::Source);
    }
    let providers = offer.providers().map_err(|_| Error::Source)?;
    let configuration = crate::configuration::Configuration::load().map_err(|error| {
        report_failure("validating startup configuration", &error);
        Error::Source
    })?;
    let text = configuration.launch_manifest().map_err(|_| Error::Source)?;
    configuration
        .validate_export_inventory(offer.slots.iter().map(|s| (s.key, s.rights)))
        .map_err(|error| {
            report_failure("validating realm authority exports", &error);
            Error::Source
        })?;
    let supervision = offer.supervision_manifest().map_err(|_| Error::Source)?;
    let core = manifest::parse(&supervision).map_err(|_| Error::Source)?;
    let core_count = core.service_count();
    let system = manifest::parse(&text).map_err(|_| Error::Source)?;
    inventory::validate_core_sources(&offer.slots, &core, providers, offer.storage_ready)
        .map_err(|_| Error::Source)?;
    let manifest = core.append_system(system).ok_or(Error::Source)?;
    let plan = manifest::validate(&manifest, &BootstrapPolicy).map_err(|error| {
        report_failure("validating launch authority", &error);
        Error::Source
    })?;
    Runtime::preflight(&manifest).map_err(|_| Error::Source)?;
    inventory::validate_service_sources(&offer.slots, &plan, core_count, providers).map_err(
        |error| {
            report_failure("validating offered service authority", &error);
            Error::Source
        },
    )?;
    inventory::prepare_receive(&offer.slots, core_count).map_err(|error| {
        report_failure("validating the handoff inventory", &error);
        Error::Source
    })?;
    offer.slots.retain(|slot| slot.key != 37);
    let mut slots = offer
        .slots
        .iter()
        .map(|slot| {
            hyper_component::objects::Object::receive_slot(
                hyper_bootstrap_handoff::kind(slot.key)?,
                hyper_os::handle::Rights::from_bits(slot.rights)
                    .ok_or(hyper_os::Error::InvalidResponse)?,
            )
        })
        .collect::<hyper_os::Result<Vec<_>>>()
        .map_err(|_| Error::Source)?;
    let endpoint = CapabilityChannel::from_handle(startup.take(ENDPOINT).map_err(|error| {
        report_failure("obtaining the handoff endpoint", &error);
        Error::OperatingSystem
    })?);
    let mut bytes = [MaybeUninit::uninit(); COMMIT.len()];
    // Registering this exact receive is READY. Until the syscall returns OK,
    // this process owns no core supervisors and cannot interfere with recovery.
    let message = endpoint
        .receive(hyper_os::DEADLINE_INFINITE, &mut bytes, &mut slots)
        .map_err(|error| {
            report_failure("receiving core supervision", &error);
            Error::OperatingSystem
        })?;
    if message.bytes() != COMMIT || message.capability_count() != slots.len() {
        return Err(Error::Source);
    }
    let mut runtime = inventory::adopt(
        &offer.slots,
        &mut slots,
        startup
            .take(hyper_component::installation::INSTALLER)
            .map_err(|_| Error::Source)?,
    )
    .map_err(|error| {
        report_failure("adopting core supervision", &error);
        Error::OperatingSystem
    })?;
    runtime.bootstrap_storage_ready = offer.storage_ready;
    runtime.providers = providers;
    runtime.core_count = core_count;
    eprintln!("HypeR system-startup: core supervision adopted");
    runtime.retirement_path = Some(offer.boot_root);
    runtime
        .run_sequence(&manifest, &plan, &configuration)
        .map_err(|error| {
            let _ = runtime
                .launcher
                .authorities
                .console
                .as_emergency_console()
                .write_all(error.diagnostic());
            Error::Bootstrap
        })
}

fn report_failure(context: &str, error: &impl std::fmt::Debug) {
    if let Ok(console) = hyper_rt::process::console() {
        let _ = console
            .as_emergency_console()
            .write_all(format!("HypeR system-startup: failed {context}: {error:?}\n").as_bytes());
    }
}
