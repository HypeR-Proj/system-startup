// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Observe predecessors and component generations during startup handshakes.

use crate::manifest::{MAX_SERVICES, Manifest};
use hyper_os::handle::{ConsoleObject, OwnedHandle, ProcessObject};
use hyper_os::wait::{ObjectSignals, WaitItem, wait_many};

use super::LaunchError;
use super::report::report_service_termination;

const _: () = assert!(MAX_SERVICES < hyper_os::wait::MAX_ITEMS);

/// Stable service-index ownership and wait-set mapping.
pub(super) struct SupervisorSet {
    pub(super) installer: OwnedHandle<hyper_os::handle::CapabilityChannelObject>,
    pub(super) managed_paths: [Option<String>; MAX_SERVICES],
    pub(super) processes: [Option<OwnedHandle<ProcessObject>>; MAX_SERVICES],
}

impl SupervisorSet {
    pub(super) fn stop(&self, index: usize) -> Result<(), LaunchError> {
        if let Some(path) = self.managed_paths.get(index).and_then(Option::as_ref) {
            hyper_component::installation::abort(self.installer.as_handle_ref(), path)
                .map_err(LaunchError::service_operation)
        } else if let Some(process) = self.processes.get(index).and_then(Option::as_ref) {
            process
                .as_process_supervisor()
                .request_stop()
                .map_err(LaunchError::service_operation)
        } else {
            Ok(())
        }
    }

    /// Waits for one startup endpoint while continuing to supervise every
    /// service. The endpoint's provider must remain alive until completion.
    pub(super) fn wait_for_service_event(
        &mut self,
        manifest: &Manifest<'_>,
        required_service: usize,
        event: WaitItem<'_>,
        deadline: u64,
        console: &OwnedHandle<ConsoleObject>,
    ) -> Result<u64, LaunchError> {
        let _provider = manifest
            .service(required_service)
            .ok_or(LaunchError::InvalidPlan)?;
        if self
            .processes
            .get(required_service)
            .and_then(Option::as_ref)
            .is_none()
        {
            return Err(LaunchError::RequiredServiceUnavailable);
        }
        let mut observed = [false; MAX_SERVICES];
        loop {
            let selected = {
                let mut items = Vec::with_capacity(MAX_SERVICES + 1);
                let mut services = Vec::with_capacity(MAX_SERVICES);
                // Observe process exits before accepting an endpoint response.
                for critical in [true, false] {
                    for (index, process) in self.processes.iter().enumerate() {
                        if let Some(process) = process
                            && !observed[index]
                        {
                            let service =
                                manifest.service(index).ok_or(LaunchError::InvalidPlan)?;
                            if service.critical() != critical {
                                continue;
                            }
                            items.push(WaitItem::new(
                                process.as_handle_ref(),
                                ObjectSignals::<ProcessObject>::TERMINATED,
                            ));
                            services.push(index);
                        }
                    }
                }
                // Process events precede endpoint readiness, so a queued
                // successful reply cannot hide an observed critical failure.
                items.push(event);
                let observation = wait_many(&items, deadline).map_err(|error| match error {
                    hyper_os::Error::Status(hyper_os::Status::TIMED_OUT) => {
                        LaunchError::WaitTimedOut
                    }
                    _ => LaunchError::OperatingSystem,
                })?;
                if observation.index == services.len() {
                    return Ok(observation.observed);
                }
                *services
                    .get(observation.index)
                    .ok_or(LaunchError::InvalidPlan)?
            };
            observed[selected] = true;
            let service = manifest.service(selected).ok_or(LaunchError::InvalidPlan)?;
            let process = self.processes[selected]
                .as_ref()
                .ok_or(LaunchError::InvalidPlan)?;
            // Prepared children return WAIT-only observers. Their real owner
            // reports terminal information; do not attempt privileged inspection.
            if self.managed_paths[selected].is_none() {
                report_service_termination(console, service.name(), service.critical(), process);
            }
            if selected == required_service {
                return Err(LaunchError::RequiredServiceUnavailable);
            }
            // Unrelated formal exits remain owned until the component manager
            // joins their teardown. Predecessors remain retained for retirement.
        }
    }
}
