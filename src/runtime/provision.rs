// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! One-shot VM fleet configuration and admission acknowledgement.

use crate::manifest::Manifest;
use hyper_os::capability_channel::{CapabilityChannel, CapabilityDisposition};
use hyper_os::fs::{Directory, FileRights};
use hyper_os::handle::{
    ByteChannelObject, CapabilityChannelObject, ConsoleObject, OwnedHandle, Rights, RightsOffer,
};
use hyper_os::wait::{ObjectSignals, WaitItem};
use hyper_service::vm as vm_contract;
use std::io::Write;

use super::LaunchError;
use super::report::report_fleet_configured;
use super::supervisor::SupervisorSet;

const UNAVAILABLE_HANDSHAKE_SECONDS: u64 = 5;
const CONFIGURATION_HANDSHAKE_SECONDS: u64 = 60;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum FleetConfiguration {
    Configured,
    Unavailable,
}

/// Owns the coordinator's single opportunity to configure the fleet manager.
pub(super) struct FleetProvisioner {
    pub(super) channel: CapabilityChannel,
}

impl FleetProvisioner {
    /// Transfers configuration once and waits only for its admission result.
    /// Guest startup and lifetime remain the manager's responsibility.
    pub(super) fn configure_fleet(
        self,
        manifest: &Manifest<'_>,
        manager_index: usize,
        config_path: &str,
        root_directory: &Directory,
        console: &OwnedHandle<ConsoleObject>,
        supervisors: &mut SupervisorSet,
    ) -> Result<FleetConfiguration, LaunchError> {
        let requested =
            FileRights::from_rights(vm_contract::PROVISIONED_CONFIG_RIGHTS.union(Rights::TRANSFER))
                .ok_or(LaunchError::InvalidPlan)?;
        let config = match root_directory.open(config_path, requested) {
            Ok(config) => config,
            Err(error) if crate::supervision::service_unavailable(&error) => {
                eprintln!("HypeR system-startup: cannot open VM fleet configuration");
                return self.configuration_unavailable(
                    manifest,
                    manager_index,
                    console,
                    supervisors,
                );
            }
            Err(_) => return Err(LaunchError::OperatingSystem),
        };
        let mut config = Some(config.into_handle());
        let (result_reader, result_writer) =
            hyper_os::channel::create_pair().map_err(|_| LaunchError::OperatingSystem)?;
        let result_reader = result_reader
            .replace(Rights::READ.union(Rights::WAIT))
            .map_err(|_| LaunchError::OperatingSystem)?;
        let mut result_writer = Some(result_writer);
        // Delivery and admission share one deadline; lost readiness races do
        // not grant a fresh timeout to an unresponsive manager.
        let deadline = deadline_after(CONFIGURATION_HANDSHAKE_SECONDS)?;

        loop {
            // Readiness is not a reservation. A lost rendezvous race retains
            // both capabilities and returns to the complete service wait set.
            if !self.wait_for_receiver(manifest, manager_index, console, supervisors, deadline)? {
                return Ok(FleetConfiguration::Unavailable);
            }
            let config_disposition = CapabilityDisposition::move_handle(
                &mut config,
                RightsOffer::Exact(vm_contract::PROVISIONED_CONFIG_RIGHTS),
            )
            .map_err(|_| LaunchError::OperatingSystem)?;
            let result_disposition = CapabilityDisposition::move_handle(
                &mut result_writer,
                RightsOffer::Exact(vm_contract::PROVISIONED_RESULT_RIGHTS),
            )
            .map_err(|_| LaunchError::OperatingSystem)?;
            match self.channel.try_send(
                &vm_contract::ProvisionRequest::ConfigureFleet.encode(),
                &mut [config_disposition, result_disposition],
            ) {
                Ok(()) => break,
                Err(hyper_os::Error::Status(hyper_os::Status::WOULD_BLOCK)) => {}
                Err(hyper_os::Error::Status(hyper_os::Status::PEER_CLOSED)) => {
                    return manager_failure(
                        manifest,
                        manager_index,
                        LaunchError::VmProvisioningClosed,
                        console,
                        supervisors,
                    );
                }
                Err(_) => return Err(LaunchError::OperatingSystem),
            }
            if let Err(error) = check_deadline(deadline) {
                return manager_failure(manifest, manager_index, error, console, supervisors);
            }
        }
        drop(self);
        wait_for_result(
            manifest,
            manager_index,
            &result_reader,
            deadline,
            console,
            supervisors,
        )
    }

    /// Explicitly ends provisioning without reading configuration or allowing
    /// the manager to discover an unavailable I/O broker. No reply is needed:
    /// the capability-channel rendezvous itself proves request delivery.
    pub(super) fn configuration_unavailable(
        self,
        manifest: &Manifest<'_>,
        manager_index: usize,
        console: &OwnedHandle<ConsoleObject>,
        supervisors: &mut SupervisorSet,
    ) -> Result<FleetConfiguration, LaunchError> {
        let deadline = deadline_after(UNAVAILABLE_HANDSHAKE_SECONDS)?;
        loop {
            if !self.wait_for_receiver(manifest, manager_index, console, supervisors, deadline)? {
                return Ok(FleetConfiguration::Unavailable);
            }
            match self.channel.try_send(
                &vm_contract::ProvisionRequest::ConfigurationUnavailable.encode(),
                &mut [],
            ) {
                Ok(()) => return Ok(FleetConfiguration::Unavailable),
                Err(hyper_os::Error::Status(hyper_os::Status::WOULD_BLOCK)) => {}
                Err(hyper_os::Error::Status(hyper_os::Status::PEER_CLOSED)) => {
                    return manager_failure(
                        manifest,
                        manager_index,
                        LaunchError::VmProvisioningClosed,
                        console,
                        supervisors,
                    );
                }
                Err(_) => return Err(LaunchError::OperatingSystem),
            }
            if let Err(error) = check_deadline(deadline) {
                return manager_failure(manifest, manager_index, error, console, supervisors);
            }
        }
    }

    fn wait_for_receiver(
        &self,
        manifest: &Manifest<'_>,
        manager_index: usize,
        console: &OwnedHandle<ConsoleObject>,
        supervisors: &mut SupervisorSet,
        deadline: u64,
    ) -> Result<bool, LaunchError> {
        let observed = match supervisors.wait_for_service_event(
            manifest,
            manager_index,
            WaitItem::new(
                self.channel.as_handle_ref(),
                ObjectSignals::<CapabilityChannelObject>::PEER_RECEIVING
                    .union(ObjectSignals::<CapabilityChannelObject>::PEER_CLOSED),
            ),
            deadline,
            console,
        ) {
            Ok(observed) => observed,
            Err(error) => {
                return manager_failure(manifest, manager_index, error, console, supervisors)
                    .map(|_| false);
            }
        };
        if ObjectSignals::<CapabilityChannelObject>::PEER_RECEIVING.is_present_in(observed) {
            Ok(true)
        } else {
            manager_failure(
                manifest,
                manager_index,
                LaunchError::VmProvisioningClosed,
                console,
                supervisors,
            )
            .map(|_| false)
        }
    }
}

/// Only failures attributable to this manager may degrade to unavailability.
/// A critical core exit or a local syscall/authority failure must still escape.
fn recover_manager_failure(
    critical: bool,
    error: LaunchError,
    stop_manager: impl FnOnce(&LaunchError) -> Result<(), LaunchError>,
) -> Result<FleetConfiguration, LaunchError> {
    if !critical
        && matches!(
            error,
            LaunchError::RequiredServiceUnavailable
                | LaunchError::VmProvisioningClosed
                | LaunchError::VmFleetReplyClosed
                | LaunchError::VmFleetReplyInvalid
                | LaunchError::WaitTimedOut
        )
    {
        stop_manager(&error)?;
        Ok(FleetConfiguration::Unavailable)
    } else {
        Err(error)
    }
}

fn manager_failure(
    manifest: &Manifest<'_>,
    manager_index: usize,
    error: LaunchError,
    _console: &OwnedHandle<ConsoleObject>,
    supervisors: &SupervisorSet,
) -> Result<FleetConfiguration, LaunchError> {
    let service = manifest
        .service(manager_index)
        .ok_or(LaunchError::InvalidPlan)?;
    recover_manager_failure(service.critical(), error, |error| {
        let _ = std::io::stderr().write_all(error.diagnostic());
        // Process termination and pipe closure are separate observations. A
        // failed manager might still be running when EOF arrives; withdraw it
        // so a timed-out admission cannot later start guests unexpectedly.
        supervisors.stop(manager_index)?;
        Ok(())
    })
}

fn deadline_after(seconds: u64) -> Result<u64, LaunchError> {
    hyper_os::time::deadline_after(std::time::Duration::from_secs(seconds))
        .map(|value| value.as_raw())
        .map_err(|_| LaunchError::OperatingSystem)
}

fn check_deadline(deadline: u64) -> Result<(), LaunchError> {
    let now = hyper_os::time::monotonic_now().map_err(|_| LaunchError::OperatingSystem)?;
    if now.as_nanoseconds() >= deadline {
        Err(LaunchError::WaitTimedOut)
    } else {
        Ok(())
    }
}

fn wait_for_result(
    manifest: &Manifest<'_>,
    manager_index: usize,
    reader: &OwnedHandle<ByteChannelObject>,
    deadline: u64,
    console: &OwnedHandle<ConsoleObject>,
    supervisors: &mut SupervisorSet,
) -> Result<FleetConfiguration, LaunchError> {
    loop {
        let observed = supervisors.wait_for_service_event(
            manifest,
            manager_index,
            WaitItem::new(
                reader.as_handle_ref(),
                ObjectSignals::<ByteChannelObject>::READABLE
                    .union(ObjectSignals::<ByteChannelObject>::PEER_CLOSED),
            ),
            deadline,
            console,
        );
        let result = poll_result(observed, |buffer| {
            reader.as_byte_channel().try_receive(buffer)
        });
        match result {
            Ok(None) => {
                if let Err(error) = check_deadline(deadline) {
                    return manager_failure(manifest, manager_index, error, console, supervisors);
                }
            }
            Ok(Some(FleetConfiguration::Configured)) => {
                report_fleet_configured(console);
                return Ok(FleetConfiguration::Configured);
            }
            Ok(Some(FleetConfiguration::Unavailable)) => {
                eprintln!("HypeR system-startup: VM fleet configuration rejected");
                return Ok(FleetConfiguration::Unavailable);
            }
            Err(error) => {
                return manager_failure(manifest, manager_index, error, console, supervisors);
            }
        }
    }
}

/// Interpret one supervised readiness observation. Reading takes precedence
/// over EOF, but an already observed process/core failure takes precedence over
/// both. The caller supplies one nonblocking read and retains the deadline.
fn poll_result(
    observed: Result<u64, LaunchError>,
    receive: impl FnOnce(&mut [u8]) -> hyper_os::Result<usize>,
) -> Result<Option<FleetConfiguration>, LaunchError> {
    let observed = observed?;
    if !ObjectSignals::<ByteChannelObject>::READABLE.is_present_in(observed) {
        return Err(LaunchError::VmFleetReplyClosed);
    }
    let mut message = [0; vm_contract::MESSAGE_BYTES];
    let length = match receive(&mut message) {
        Ok(length) => length,
        Err(hyper_os::Error::Status(hyper_os::Status::WOULD_BLOCK)) => return Ok(None),
        Err(hyper_os::Error::Status(hyper_os::Status::PEER_CLOSED)) => {
            return Err(LaunchError::VmFleetReplyClosed);
        }
        Err(hyper_os::Error::MessageTooLarge { .. }) => {
            return Err(LaunchError::VmFleetReplyInvalid);
        }
        Err(_) => return Err(LaunchError::OperatingSystem),
    };
    match message
        .get(..length)
        .and_then(vm_contract::ProvisionResult::decode)
    {
        Some(vm_contract::ProvisionResult::Configured) => Ok(Some(FleetConfiguration::Configured)),
        Some(vm_contract::ProvisionResult::Rejected) => Ok(Some(FleetConfiguration::Unavailable)),
        None => Err(LaunchError::VmFleetReplyInvalid),
    }
}

#[cfg(test)]
#[path = "../../tests/provision.rs"]
mod tests;
