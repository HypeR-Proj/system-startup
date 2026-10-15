// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Strict, bounded service-manifest parsing and launch planning.

mod model;
mod parse;
mod plan;

pub use model::{
    CapabilityBinding, CapabilityOperation, MAX_CAPABILITIES_PER_SERVICE,
    MAX_DEPENDENCIES_PER_SERVICE, MAX_DEPENDENCY_EDGES, MAX_MANIFEST_BYTES,
    MAX_RIGHTS_PER_CAPABILITY, MAX_SERVICES, Manifest, RestartPolicy, Service, ServicePhase,
    VmConfiguration,
};
pub(crate) use parse::parse_into;
pub use parse::{ParseError, ParseErrorKind, parse};
pub use plan::{
    AuthorityDeclaration, AuthorityKey, AuthorityPolicy, CapabilityGrant, LaunchPlan,
    StartupPurposeDeclaration, ValidationError, ValidationErrorKind, validate,
};

#[cfg(test)]
#[path = "../../tests/manifest.rs"]
mod tests;
