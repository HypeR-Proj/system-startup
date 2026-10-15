// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Finite bootstrap-resource adoption and formal-service preparation.
//!
//! Parsing and planning deliberately depend on no operating-system binding.
//! The runtime adapter must obtain real root-`Directory` and process-construction
//! capabilities before it can apply a validated launch plan.
//! The component manager commits the namespace switch and forwards the original
//! inventory. This coordinator migrates domain resources and prepares services;
//! their ongoing process supervision belongs to the component manager.

pub mod bootstrap_policy;
pub mod configuration;
pub mod diagnostics;
pub mod manifest;
pub mod supervision;

use std::convert::Infallible;

use manifest::{AuthorityPolicy, LaunchPlan, Manifest, ParseError, ValidationError};

/// Read-only source for the complete service-manifest image.
///
/// The production implementation must load bytes through the real root
/// `Directory` capability; embedding a second manifest in the coordinator
/// would bypass the deployment's service configuration.
pub trait ManifestSource {
    type Error;

    fn manifest(&self) -> Result<&str, Self::Error>;
}

/// Runtime owner which applies one fully validated launch plan.
///
/// `LaunchPlan` contains declarations only. An implementation must resolve
/// every live source handle again, prepare every `ProcessBuilder`, and let the
/// kernel revalidate type and attenuated rights at the final commit.
pub trait ServiceGraphLauncher {
    type Error;

    fn launch(
        &mut self,
        manifest: &Manifest<'_>,
        plan: &LaunchPlan<'_>,
    ) -> Result<Infallible, Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootstrapError<SourceError, LaunchError> {
    Source(SourceError),
    Parse(ParseError),
    Validate(ValidationError),
    Launch(LaunchError),
}

/// Parses and validates the whole graph before crossing the launch boundary.
#[inline(never)]
pub fn bootstrap<Source, Policy, Launcher>(
    source: &Source,
    policy: &Policy,
    launcher: &mut Launcher,
) -> Result<Infallible, BootstrapError<Source::Error, Launcher::Error>>
where
    Source: ManifestSource,
    Policy: AuthorityPolicy,
    Launcher: ServiceGraphLauncher,
{
    let text = source.manifest().map_err(BootstrapError::Source)?;
    let mut manifest = Manifest::empty();
    manifest::parse_into(text, &mut manifest).map_err(BootstrapError::Parse)?;
    let plan = manifest::validate(&manifest, policy).map_err(BootstrapError::Validate)?;
    launcher
        .launch(&manifest, &plan)
        .map_err(BootstrapError::Launch)
}

#[cfg(test)]
#[path = "../tests/bootstrap.rs"]
mod tests;

#[cfg(all(target_os = "hyper", feature = "shared"))]
extern crate hyper_vm_policy_shared as hyper_vm_policy;

pub mod runtime;
