// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Capability-scoped adapter from a validated manifest to `ProcessBuilder`.

mod adoption;
mod authority;
mod fleet;
mod handoff;
mod launcher;
mod provision;
mod report;
mod sequence;
mod stdio;
mod supervisor;

use launcher::ServiceLauncher;
use provision::FleetConfiguration;
use supervisor::SupervisorSet;

use crate::manifest::{LaunchPlan, Manifest};
use crate::supervision::{self, SupportError};
use hyper_os::startup::Startup;

/// Receives the boot supervisor's committed inventory before launching services.
pub fn run_system(startup: &mut Startup<'_>) -> Result<(), Error> {
    handoff::run_system(startup)
}

pub enum Error {
    Bootstrap,
    OperatingSystem,
    Source,
}

impl Error {
    pub const fn diagnostic(&self) -> &'static [u8] {
        match self {
            Self::Bootstrap => b"HypeR system-startup: bootstrap failed\n",
            Self::OperatingSystem => b"HypeR system-startup: startup capability operation failed\n",
            Self::Source => b"HypeR system-startup: invalid service manifest source\n",
        }
    }
}

/// Finite startup state. Subobjects own disjoint authority and lifecycle roles.
struct Runtime {
    launcher: ServiceLauncher,
    installer: hyper_os::OwnedHandle<hyper_os::handle::CapabilityChannelObject>,
    supervisors: SupervisorSet,
    bootstrap_storage_ready: bool,
    providers: [Option<usize>; 3],
    storage_successor: Option<String>,
    core_count: usize,
    retired_processes: Vec<hyper_os::OwnedHandle<hyper_os::handle::ProcessObject>>,
    // Started replacements are not mandatory services until READY confirms
    // adoption. An unconfirmed transfer keeps both process owners for recovery.
    pending_provider: Option<(
        usize,
        hyper_os::OwnedHandle<hyper_os::handle::ProcessObject>,
    )>,
    unconfirmed_providers: Vec<hyper_os::OwnedHandle<hyper_os::handle::ProcessObject>>,
    retirement_path: Option<String>,
    retirement_ready: bool,
    session_releases: Vec<hyper_os::OwnedHandle<hyper_os::handle::ByteChannelObject>>,
    old_console: Option<hyper_os::OwnedHandle<hyper_os::handle::ProcessObject>>,
    // Kept separate from the formal launcher group so stopping the predecessor
    // cannot terminate the coordinator or any newly started formal services.
    _boot_group: hyper_os::OwnedHandle<hyper_os::handle::TaskGroupObject>,
}

impl Runtime {
    fn preflight(manifest: &Manifest<'_>) -> Result<(), LaunchError> {
        match supervision::validate(manifest) {
            Ok(()) => Ok(()),
            Err(SupportError::RestartPolicy) => Err(LaunchError::UnsupportedRestartPolicy),
            Err(SupportError::MissingCriticalService) => {
                Err(LaunchError::UnsupportedSupervisionGraph)
            }
        }
    }
}

impl Runtime {
    /// Finish only the business-service handshake. Storage ownership never
    /// depends on a manager being configured, started, or successfully admitted.
    fn configure_vm_fleet(
        &mut self,
        manifest: &Manifest<'_>,
        plan: &LaunchPlan<'_>,
        vm_manager_index: Option<usize>,
        storage_available: bool,
    ) -> Result<(), LaunchError> {
        if let Some(manager) = vm_manager_index {
            let configuration = if self.supervisors.processes[manager].is_none() {
                // A system-volume failure must not wait for an unstarted
                // manager. Close its retained endpoints so clients fail
                // promptly while bootstrap services remain supervised.
                self.launcher.authorities.close_unstarted_vm_manager()?;
                FleetConfiguration::Unavailable
            } else if let Some(path) = plan.vm_config_path().filter(|_| storage_available) {
                self.take_fleet_provisioner()?.configure_fleet(
                    manifest,
                    manager,
                    path,
                    &self.launcher.authorities.root_directory,
                    &self.launcher.authorities.console,
                    &mut self.supervisors,
                )?
            } else {
                self.take_fleet_provisioner()?.configuration_unavailable(
                    manifest,
                    manager,
                    &self.launcher.authorities.console,
                    &mut self.supervisors,
                )?
            };
            if configuration == FleetConfiguration::Unavailable {
                report::report_fleet_unavailable(&self.launcher.authorities.console);
            }
        } else {
            self.launcher.authorities.close_unstarted_vm_manager()?;
        }
        Ok(())
    }

    fn take_fleet_provisioner(&mut self) -> Result<provision::FleetProvisioner, LaunchError> {
        self.launcher
            .authorities
            .vm_fleet
            .as_mut()
            .and_then(|fleet| fleet.provisioner.take())
            .ok_or(LaunchError::InvalidPlan)
    }

    fn prepare_system_libraries(&mut self) -> Result<bool, LaunchError> {
        let prepared = (|| {
            let environment = hyper_service::process::open_environment(
                &self.launcher.authorities.root_directory,
                "/",
            )?;
            let libraries = hyper_service::process::open_library_directory(&environment)?;
            Ok((environment, libraries))
        })();
        match prepared {
            Ok((environment, libraries)) => {
                self.launcher.authorities.system_environment = Some(environment);
                self.launcher.authorities.library_directory = libraries;
                Ok(true)
            }
            Err(error) if supervision::service_unavailable(&error) => {
                let _ = self
                    .launcher
                    .authorities
                    .console
                    .as_emergency_console()
                    .write_all(
                        format!("HypeR system-startup: cannot open system libraries: {error:?}\n")
                            .as_bytes(),
                    );
                Ok(false)
            }
            Err(_) => Err(LaunchError::OperatingSystem),
        }
    }
}

#[derive(Debug)]
pub(super) enum LaunchError {
    AuthorityConsumed,
    InvalidPlan,
    OperatingSystem,
    RequiredServiceUnavailable,
    ServiceUnavailable,
    UnsupportedAuthority,
    UnsupportedRestartPolicy,
    UnsupportedSupervisionGraph,
    VmFleetReplyClosed,
    VmFleetReplyInvalid,
    VmProvisioningClosed,
    WaitTimedOut,
}

impl LaunchError {
    fn service_operation(error: hyper_os::Error) -> Self {
        eprintln!("HypeR system-startup: operation failed: {error:?}");
        if supervision::service_unavailable(&error) {
            Self::ServiceUnavailable
        } else {
            Self::OperatingSystem
        }
    }

    fn service_resources(error: hyper_os::Error) -> Self {
        eprintln!("HypeR system-startup: preparing resources failed: {error:?}");
        if supervision::service_resources_unavailable(&error) {
            Self::ServiceUnavailable
        } else {
            Self::OperatingSystem
        }
    }

    const fn diagnostic(&self) -> &'static [u8] {
        match self {
            Self::AuthorityConsumed => {
                b"HypeR system-startup: service authority was already consumed\n"
            }
            Self::InvalidPlan => b"HypeR system-startup: invalid launch plan\n",
            Self::OperatingSystem => b"HypeR system-startup: service launch operation failed\n",
            Self::RequiredServiceUnavailable => {
                b"HypeR system-startup: startup provider unavailable\n"
            }
            Self::ServiceUnavailable => {
                b"HypeR system-startup: service image or resources unavailable\n"
            }
            Self::UnsupportedAuthority => b"HypeR system-startup: unsupported service authority\n",
            Self::UnsupportedRestartPolicy => b"HypeR system-startup: unsupported restart policy\n",
            Self::UnsupportedSupervisionGraph => {
                b"HypeR system-startup: unsupported critical-service supervision graph\n"
            }
            Self::VmFleetReplyClosed => {
                b"HypeR system-startup: VM fleet result channel closed without a reply\n"
            }
            Self::VmFleetReplyInvalid => {
                b"HypeR system-startup: VM fleet configuration reply is invalid\n"
            }
            Self::VmProvisioningClosed => b"HypeR system-startup: VM provisioning channel closed\n",
            Self::WaitTimedOut => b"HypeR system-startup: service handshake timed out\n",
        }
    }
}
