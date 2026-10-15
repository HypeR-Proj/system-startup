// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Validate ownership before handing retirement to its independent oneshot.
use super::{Runtime, move_handle};
use crate::manifest::Manifest;
use hyper_bootstrap_handoff::retirement as contract;
use hyper_os::{capability_channel::*, handle::*, task::ProcessPhase};

impl Runtime {
    pub(in crate::runtime) fn launch_retirement(
        &mut self,
        manifest: &Manifest<'_>,
        name: &str,
        program: &hyper_component_config::Program,
    ) -> hyper_os::Result<OwnedHandle<ProcessObject>> {
        if !self.retirement_ready || !self.unconfirmed_providers.is_empty() {
            return Err(hyper_os::Error::Status(hyper_os::Status::BUSY));
        }
        if retirement_blocker(self.core_count, &self.providers, |index| {
            let service = manifest
                .service(index)
                .ok_or(hyper_os::Error::InvalidResponse)?;
            self.supervisors.processes[index]
                .as_ref()
                .map(|p| {
                    p.as_process_supervisor()
                        .info()
                        .map(|info| (service.critical(), info.phase))
                })
                .transpose()
        })?
        .is_some()
        {
            return Err(hyper_os::Error::Status(hyper_os::Status::BUSY));
        }
        for index in 0..self.core_count {
            if !self.providers.contains(&Some(index))
                && let Some(old) = self.supervisors.processes[index].take()
            {
                self.retired_processes.push(old);
            }
        }
        let console_index = self
            .old_console
            .as_ref()
            .map(|_| self.retired_processes.len());
        let count = self.retired_processes.len() + usize::from(console_index.is_some());
        if count > contract::MAX_PREDECESSORS {
            return Err(hyper_os::Error::Status(hyper_os::Status::RESOURCE_LIMIT));
        }
        let (sender, receiver) = CapabilityChannel::create()?;
        // The retirement protocol reserves argv[1] for inventory sizing;
        // deployment arguments follow it, as with the other role parameters.
        let mut program = program.clone();
        program.arguments.insert(0, count.to_string());
        let builder = self.provider_builder(name, &program, Some(name))?;
        move_handle(
            &builder,
            receiver.into_handle(),
            contract::ENDPOINT.as_raw(),
            Rights::READ.union(Rights::WAIT),
        )?;
        let process = self.start_managed(builder)?;
        let result = (|| {
            let offer = contract::Offer {
                path: self
                    .retirement_path
                    .clone()
                    .ok_or(hyper_os::Error::MissingHandle)?,
                processes: count,
                console: console_index,
                drain: self.launcher.authorities.console_drain.is_some(),
            };
            let bytes = serde_json::to_vec(&offer).map_err(|_| hyper_os::Error::InvalidResponse)?;
            let (dummy, _) = hyper_os::channel::create_pair()?;
            let mut processes: Vec<_> = self.retired_processes.drain(..).map(Some).collect();
            let result = (|| {
                let mut dispositions = vec![
                    CapabilityDisposition::duplicate(
                        self.launcher.authorities.root_directory.as_handle_ref(),
                        RightsOffer::Exact(contract::ROOT),
                    )?,
                    CapabilityDisposition::duplicate(
                        self._boot_group.as_handle_ref(),
                        RightsOffer::Exact(contract::GROUP),
                    )?,
                    CapabilityDisposition::duplicate(
                        self.launcher
                            .authorities
                            .console_drain
                            .as_ref()
                            .unwrap_or(&dummy)
                            .as_handle_ref(),
                        RightsOffer::Exact(contract::DRAIN),
                    )?,
                ];
                for p in &mut processes {
                    dispositions.push(CapabilityDisposition::move_handle(
                        p,
                        RightsOffer::Exact(contract::PROCESS),
                    )?);
                }
                if self.old_console.is_some() {
                    dispositions.push(CapabilityDisposition::move_handle(
                        &mut self.old_console,
                        RightsOffer::Exact(contract::PROCESS),
                    )?);
                }
                let result = hyper_service_ipc::send(
                    &sender,
                    hyper_service_ipc::deadline()?,
                    &bytes,
                    &mut dispositions,
                );
                drop(dispositions);
                result
            })();
            self.retired_processes
                .extend(processes.into_iter().flatten());
            result?;
            // The oneshot owns predecessor supervisors. Release every local
            // archive reference before it attempts the normal, non-forced unmount.
            self.launcher.authorities.console_drain.take();
            self.launcher.authorities.boot_environment.take();
            self.retirement_ready = false;
            Ok(())
        })();
        if let Err(error) = result {
            let _ = hyper_component::installation::abort(self.installer.as_handle_ref(), name);
            self.unconfirmed_providers.push(process);
            return Err(error);
        }
        Ok(process)
    }
}

/// Only completed, noncritical one-shots may retire without a replacement.
/// Stopped is quiescent and cannot admit threads again; `wait_retired` still
/// joins its resource teardown. Critical exits stay visible to supervision.
fn retirement_blocker(
    core_count: usize,
    providers: &[Option<usize>; 3],
    mut inspect: impl FnMut(usize) -> hyper_os::Result<Option<(bool, ProcessPhase)>>,
) -> hyper_os::Result<Option<usize>> {
    for index in 0..core_count {
        if providers.contains(&Some(index)) {
            continue;
        }
        if let Some((critical, phase)) = inspect(index)?
            && (critical
                || !matches!(
                    phase,
                    ProcessPhase::Stopped | ProcessPhase::Retiring | ProcessPhase::Retired
                ))
        {
            return Ok(Some(index));
        }
    }
    Ok(None)
}

#[cfg(test)]
#[path = "../../../tests/retirement.rs"]
mod tests;
