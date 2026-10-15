// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! One finite ownership migration. The manager never executes these protocols;
//! new processes are installed there and only WAIT observers come back here.

use super::{LaunchError, Runtime};
use crate::{
    configuration::Configuration,
    manifest::{LaunchPlan, Manifest},
};
use hyper_component::Notification;
use hyper_os::{capability_channel::CapabilityChannel, handle::*, wait::*};
use std::time::Duration;

impl Runtime {
    pub(super) fn run_sequence(
        &mut self,
        manifest: &Manifest<'_>,
        plan: &LaunchPlan<'_>,
        config: &Configuration,
    ) -> Result<(), LaunchError> {
        let result = self.start_environment(manifest, plan, config);
        if let Err(error) = result {
            let _ = hyper_component::installation::progress(
                self.installer.as_handle_ref(),
                "startup-failed",
            );
            let _ = hyper_component::installation::finish_display(
                self.installer.as_handle_ref(),
                false,
            );
            let diagnostic =
                format!("HypeR system-startup: {error:?}; retaining unretired owners\n");
            if self.launcher.authorities.journal_active {
                eprint!("{diagnostic}");
            } else {
                // Journal startup itself may have failed. End the display first,
                // then use the coordinator's emergency Console directly.
                let _ = self
                    .launcher
                    .authorities
                    .console
                    .as_emergency_console()
                    .write_all(diagnostic.as_bytes());
            }
            self.release_sessions();
            // Ownership may already have crossed a provider's MOVE boundary.
            // Preserve those owners; no timeout fabricates a rollback.
            loop {
                std::thread::park();
            }
        }
        Ok(())
    }

    fn progress(&self, fact: &str) -> Result<(), LaunchError> {
        hyper_component::installation::progress(self.installer.as_handle_ref(), fact)
            .map_err(LaunchError::service_operation)
    }

    fn start_environment(
        &mut self,
        manifest: &Manifest<'_>,
        plan: &LaunchPlan<'_>,
        config: &Configuration,
    ) -> Result<(), LaunchError> {
        let (observe, control) =
            hyper_component::installation::management(self.installer.as_handle_ref())
                .map_err(LaunchError::service_operation)?;
        self.launcher.authorities.observe = Some(observe);
        self.launcher.authorities.control = Some(control);
        self.export_authorities(config)?;
        self.prepare_system_libraries()?;
        hyper_os::filesystem::mount_ramfs(
            self.launcher.authorities.root_directory.as_handle_ref(),
            "/tmp",
        )
        .map_err(LaunchError::service_operation)?;
        self.progress("ownership-transferred")?;
        let provider = |role: &str| config.policy.providers.iter().find(|p| p.role == role);
        let mut adopted = true;
        if let Some(console) = provider("console") {
            let p = config
                .program(&console.component)
                .map_err(|_| LaunchError::InvalidPlan)?;
            adopted &= self.adopt_provider(0, &console.component, p).is_ok();
        }
        let journal = config
            .program(&config.policy.journal)
            .map_err(|_| LaunchError::InvalidPlan)?;
        let journal_owner = self.launch_journal(&config.policy.journal, journal)?;
        // Observer only; component-manager retains the actual Process owner.
        drop(journal_owner);
        hyper_component::installation::logging(
            self.installer.as_handle_ref(),
            self.launcher.authorities.log_connector.as_handle_ref(),
        )
        .map_err(LaunchError::service_operation)?;
        let manager = plan.unique_service_for_purpose(hyper_service::vm::PROVISIONING.as_raw());
        if manager.is_none() {
            self.launcher.authorities.close_unstarted_vm_manager()?;
        }
        // Prepare the terminal early, alongside ordinary service logging.
        // The first shell is gated separately and cannot race provider adoption.
        for app in config.policy.applications.iter().filter(|a| a.interactive) {
            self.launch_application(app, manifest, plan, config, manager, false)?;
        }
        let mut storage_adopted = self.bootstrap_storage_ready;
        for (role, name) in [(1, "io"), (2, "filesystem")] {
            if let Some(provider) = provider(name) {
                let p = config
                    .program(&provider.component)
                    .map_err(|_| LaunchError::InvalidPlan)?;
                storage_adopted =
                    storage_adopted && self.adopt_provider(role, &provider.component, p).is_ok();
                adopted &= storage_adopted;
            }
        }
        self.retirement_ready = adopted
            && self.providers.iter().enumerate().all(|(role, index)| {
                index.is_none()
                    || config
                        .policy
                        .providers
                        .iter()
                        .any(|p| p.role == ["console", "io", "filesystem"][role])
            });
        self.progress(if self.retirement_ready {
            "core-providers-adopted"
        } else {
            "core-adoption-incomplete"
        })?;
        // Retained predecessors can still serve the already mounted root. Only
        // a confirmed replacement may perform the automatic formal mounts.
        let mut storage_available = self.bootstrap_storage_ready;
        if storage_adopted && let Some(path) = &config.policy.mounts {
            let p = config.program(path).map_err(|_| LaunchError::InvalidPlan)?;
            let builder = self
                .provider_builder(path, p, Some(path))
                .map_err(LaunchError::service_operation)?;
            builder
                .add_handle_duplicate(
                    self.launcher.authorities.root_directory.as_handle_ref(),
                    hyper_os::startup::ROOT_DIRECTORY.as_raw(),
                    RightsOffer::SameRights,
                )
                .map_err(LaunchError::service_operation)?;
            builder
                .add_handle_duplicate(
                    self.launcher
                        .authorities
                        .filesystem_control_client
                        .as_ref()
                        .ok_or(LaunchError::UnsupportedAuthority)?
                        .as_handle_ref(),
                    hyper_service::filesystem::CONTROL_CLIENT.as_raw(),
                    RightsOffer::Exact(hyper_service_ipc::CLIENT_RIGHTS),
                )
                .map_err(LaunchError::service_operation)?;
            let process = self
                .start_managed(builder)
                .map_err(LaunchError::service_operation)?;
            storage_available = self.wait_completed(path, &process, p.timeout_ms).is_ok();
        }
        self.progress(if storage_available {
            "filesystems-mounted"
        } else {
            "storage-unavailable"
        })?;
        for app in config.policy.applications.iter().filter(|a| !a.interactive) {
            self.launch_application(app, manifest, plan, config, manager, storage_available)?;
        }
        if !self.retirement_ready {
            self.progress("retirement-blocked")?;
            hyper_component::installation::finish_display(self.installer.as_handle_ref(), false)
                .map_err(LaunchError::service_operation)?;
            self.release_sessions();
            // A live predecessor may still own root backing or device state.
            loop {
                std::thread::park();
            }
        }
        let p = config
            .program(&config.policy.retirement)
            .map_err(|_| LaunchError::InvalidPlan)?;
        let retired = self
            .launch_retirement(manifest, &config.policy.retirement, p)
            .map_err(LaunchError::service_operation)?;
        self.wait_completed(&config.policy.retirement, &retired, p.timeout_ms)?;
        self.progress("bootstrap-retired")?;
        hyper_component::installation::finish_display(self.installer.as_handle_ref(), true)
            .map_err(LaunchError::service_operation)?;
        self.release_sessions();
        Ok(())
    }

    fn launch_application(
        &mut self,
        app: &crate::configuration::Application,
        manifest: &Manifest<'_>,
        plan: &LaunchPlan<'_>,
        config: &Configuration,
        manager: Option<usize>,
        storage_available: bool,
    ) -> Result<(), LaunchError> {
        let name = app.component.as_str();
        let index = manifest
            .services()
            .position(|s| s.name() == name)
            .ok_or(LaunchError::InvalidPlan)?;
        let service = manifest.service(index).ok_or(LaunchError::InvalidPlan)?;
        let p = config
            .program(&app.component)
            .map_err(|_| LaunchError::InvalidPlan)?;
        let group = hyper_os::task::create_task_group(
            self.launcher.authorities.factory.as_handle_ref(),
            self.launcher.authorities.domain.as_handle_ref(),
        )
        .map_err(LaunchError::service_resources)?;
        let (notify, reader) =
            hyper_os::channel::create_pair().map_err(LaunchError::service_resources)?;
        self.supervisors.managed_paths[index] = Some(app.component.clone());
        let (release, session_start) = if app.interactive {
            let (release, start) =
                hyper_os::channel::create_pair().map_err(LaunchError::service_resources)?;
            (Some(release), Some(start))
        } else {
            (None, None)
        };
        let result = self.launcher.launch_service(
            service,
            index,
            manager,
            plan,
            super::launcher::LaunchInstance {
                program: p,
                component: &app.component,
                installer: self.installer.as_handle_ref(),
                number: 1,
                group: &group,
                notify,
                session_start,
            },
        );
        match result {
            Ok(process) => {
                self.supervisors.processes[index] = Some(process);
                if let Some(release) = release {
                    self.session_releases.push(release);
                }
            }
            Err(error) => {
                eprintln!("HypeR system-startup: {name}: {error:?}");
                if Some(index) == manager {
                    self.launcher.authorities.close_unstarted_vm_manager()?;
                }
                if app.critical {
                    return Err(error);
                }
                return Ok(());
            }
        }
        if Some(index) == manager {
            self.configure_vm_fleet(manifest, plan, manager, storage_available)?;
        }
        // Terminal readiness is independent of physical output. The shell
        // waits on its separate release until the startup sequence finishes.
        if app.interactive {
            let until = hyper_os::time::deadline_after(Duration::from_millis(p.timeout_ms))
                .map_err(LaunchError::service_operation)?
                .as_raw();
            wait_many(
                &[WaitItem::new(
                    reader.as_handle_ref(),
                    ObjectSignals::<ByteChannelObject>::READABLE
                        .union(ObjectSignals::<ByteChannelObject>::PEER_CLOSED),
                )],
                until,
            )
            .map_err(LaunchError::service_operation)?;
            let mut bytes = [0; 1024];
            let n = reader
                .as_byte_channel()
                .try_receive(&mut bytes)
                .map_err(LaunchError::service_operation)?;
            if !matches!(
                serde_json::from_slice::<Notification>(&bytes[..n]),
                Ok(Notification::Ready)
            ) {
                return Err(LaunchError::InvalidPlan);
            }
            self.progress("interactive-ready")?;
        }
        Ok(())
    }

    fn release_sessions(&mut self) {
        for channel in self.session_releases.drain(..) {
            let _ = channel
                .as_byte_channel()
                .try_send(hyper_service::session::START_MESSAGE);
        }
    }

    fn export_authorities(&self, config: &Configuration) -> Result<(), LaunchError> {
        use hyper_component::objects::Object;
        for export in &config.policy.exports {
            let index = config
                .topology
                .index(&export.realm)
                .ok_or(LaunchError::InvalidPlan)?;
            let capability = config.topology.instances[index]
                .declaration
                .capabilities
                .iter()
                .find(|c| c.name == export.name)
                .ok_or(LaunchError::InvalidPlan)?;
            let hyper_component_config::CapabilityType::Object { rights, .. } = capability.kind
            else {
                return Err(LaunchError::InvalidPlan);
            };
            let rights = Rights::from_bits(rights)
                .ok_or(LaunchError::InvalidPlan)?
                .union(Rights::TRANSFER)
                .union(Rights::DUPLICATE);
            let a = &self.launcher.authorities;
            macro_rules! duplicate {
                ($variant:ident, $handle:expr) => {
                    Object::$variant(Some(
                        $handle
                            .duplicate(rights)
                            .map_err(LaunchError::service_resources)?,
                    ))
                };
            }
            let mut object = match export.source.as_str() {
                "component.observe" => duplicate!(
                    CapabilityChannel,
                    a.observe
                        .as_ref()
                        .ok_or(LaunchError::UnsupportedAuthority)?
                ),
                "component.control" => duplicate!(
                    CapabilityChannel,
                    a.control
                        .as_ref()
                        .ok_or(LaunchError::UnsupportedAuthority)?
                ),
                "bootstrap.root-directory" => {
                    duplicate!(Directory, a.root_directory.as_handle_ref())
                }
                "bootstrap.task-inspector" => duplicate!(TaskInspector, a.task_inspector),
                "bootstrap.object-inspector" => duplicate!(ObjectInspector, a.object_inspector),
                "bootstrap.memory-inspector" => duplicate!(MemoryInspector, a.memory_inspector),
                "bootstrap.cpu-inspector" => duplicate!(CpuInspector, a.cpu_inspector),
                _ => return Err(LaunchError::InvalidPlan),
            };
            hyper_component::installation::export(
                self.installer.as_handle_ref(),
                &export.realm,
                &export.name,
                rights,
                &mut object,
            )
            .map_err(LaunchError::service_operation)?;
        }
        Ok(())
    }

    fn wait_completed(
        &self,
        path: &str,
        process: &OwnedHandle<ProcessObject>,
        timeout_ms: u64,
    ) -> Result<(), LaunchError> {
        let deadline = hyper_os::time::deadline_after(Duration::from_millis(timeout_ms))
            .map_err(LaunchError::service_operation)?
            .as_raw();
        process
            .as_process_supervisor()
            .wait_terminated(deadline)
            .map_err(LaunchError::service_operation)?;
        loop {
            let reply: hyper_component::Reply = hyper_service_ipc::request(
                self.launcher
                    .authorities
                    .observe
                    .as_ref()
                    .ok_or(LaunchError::UnsupportedAuthority)?
                    .as_handle_ref(),
                &hyper_component::Request::Status {
                    path: Some(path.into()),
                },
            )
            .map_err(LaunchError::service_operation)?;
            let state = reply
                .snapshot
                .components
                .first()
                .ok_or(LaunchError::InvalidPlan)?
                .state;
            if state == hyper_component::State::Completed {
                return Ok(());
            }
            if state == hyper_component::State::Failed {
                return Err(LaunchError::ServiceUnavailable);
            }
            if hyper_os::time::monotonic_now()
                .map_err(LaunchError::service_operation)?
                .as_nanoseconds()
                >= deadline
            {
                return Err(LaunchError::WaitTimedOut);
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn launch_journal(
        &mut self,
        name: &str,
        program: &hyper_component_config::Program,
    ) -> Result<OwnedHandle<ProcessObject>, LaunchError> {
        let result = (|| {
            let (listener, connector) = CapabilityChannel::create()?;
            let (mirror, reader) = hyper_os::channel::create_pair()?;
            hyper_service::console::register_log(
                self.launcher.authorities.log_connector.as_handle_ref(),
                "journal",
                reader,
            )?;
            let (notify, ready) = hyper_os::channel::create_pair()?;
            let builder = self.provider_builder(name, program, None)?;
            self.launcher.journal_stdio(&builder, name)?;
            {
                let (handle, purpose) = (
                    listener.into_handle(),
                    hyper_service::console::LOG_CONNECTOR,
                );
                builder
                    .add_handle_move(
                        handle,
                        purpose.as_raw(),
                        RightsOffer::Exact(Rights::READ.union(Rights::WAIT)),
                    )
                    .map_err(|f| f.error())?;
            }
            builder
                .add_handle_move(
                    mirror,
                    hyper_journal::MIRROR.as_raw(),
                    RightsOffer::Exact(Rights::WRITE.union(Rights::WAIT)),
                )
                .map_err(|f| f.error())?;
            builder
                .add_handle_move(
                    notify,
                    hyper_component::NOTIFY.as_raw(),
                    RightsOffer::Exact(Rights::WRITE.union(Rights::WAIT).union(Rights::DUPLICATE)),
                )
                .map_err(|f| f.error())?;
            let process = self.start_managed(builder)?;
            let result = (|| {
                wait_many(
                    &[WaitItem::new(
                        ready.as_handle_ref(),
                        ObjectSignals::<ByteChannelObject>::READABLE
                            .union(ObjectSignals::<ByteChannelObject>::PEER_CLOSED),
                    )],
                    hyper_os::time::deadline_after(Duration::from_millis(program.timeout_ms))?
                        .as_raw(),
                )?;
                let mut bytes = [0; 1024];
                let n = ready.as_byte_channel().try_receive(&mut bytes)?;
                if !matches!(
                    serde_json::from_slice::<Notification>(&bytes[..n]),
                    Ok(Notification::Ready)
                ) {
                    return Err(hyper_os::Error::InvalidResponse);
                }
                Ok(())
            })();
            if let Err(e) = result {
                let _ = hyper_component::installation::abort(self.installer.as_handle_ref(), name);
                self.unconfirmed_providers.push(process);
                return Err(e);
            }
            self.launcher.authorities.log_connector = connector.into_handle();
            self.launcher.authorities.journal_active = true;
            Ok(process)
        })();
        result.map_err(LaunchError::service_resources)
    }
}
