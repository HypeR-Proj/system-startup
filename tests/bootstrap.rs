// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

use std::cell::Cell;
use std::convert::Infallible;

use super::manifest::{
    AuthorityDeclaration, AuthorityPolicy, LaunchPlan, Manifest, StartupPurposeDeclaration,
};
use super::{BootstrapError, ManifestSource, ServiceGraphLauncher, bootstrap};

const EMPTY_GRAPH: &str = r#"{"format":"hyper.service-manifest","services":[]}"#;
const ONE_SERVICE: &str = r#"{
    "format":"hyper.service-manifest",
    "services":[{
        "name":"session",
        "image":"/svc/session-manager",
        "critical":true,
        "restart":"on-failure",
        "after":[],
        "capabilities":[]
    }]
}"#;

struct Source(&'static str);

impl ManifestSource for Source {
    type Error = Infallible;

    fn manifest(&self) -> Result<&str, Self::Error> {
        Ok(self.0)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LaunchStopped;

struct Policy;

struct Launcher {
    launches: Cell<usize>,
}

impl AuthorityPolicy for Policy {
    fn authority<'policy>(&'policy self, _source: &str) -> Option<AuthorityDeclaration<'policy>> {
        None
    }

    fn startup_purpose(&self, _image: &str, _name: &str) -> Option<StartupPurposeDeclaration> {
        None
    }

    fn right(&self, _name: &str) -> Option<u64> {
        None
    }
}

impl ServiceGraphLauncher for Launcher {
    type Error = LaunchStopped;

    fn launch(
        &mut self,
        _manifest: &Manifest<'_>,
        _plan: &LaunchPlan<'_>,
    ) -> Result<Infallible, Self::Error> {
        self.launches.set(self.launches.get() + 1);
        Err(LaunchStopped)
    }
}

#[test]
fn validation_failure_never_crosses_the_launch_boundary() {
    let mut launcher = Launcher {
        launches: Cell::new(0),
    };
    let result = bootstrap(&Source(EMPTY_GRAPH), &Policy, &mut launcher);
    assert!(matches!(result, Err(BootstrapError::Validate(_))));
    assert_eq!(launcher.launches.get(), 0);
}

#[test]
fn a_validated_plan_reaches_the_launch_boundary_once() {
    let mut launcher = Launcher {
        launches: Cell::new(0),
    };
    let result = bootstrap(&Source(ONE_SERVICE), &Policy, &mut launcher);
    assert_eq!(result, Err(BootstrapError::Launch(LaunchStopped)));
    assert_eq!(launcher.launches.get(), 1);
}
