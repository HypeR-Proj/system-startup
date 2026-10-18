// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

use super::BootstrapPolicy;
use crate::manifest::{self, AuthorityPolicy, ValidationErrorKind};
use hyper_os::handle::Rights;

const POLICY_SERVICE: &str = r#"{
  "format": "hyper.service-manifest",
  "services": [{
    "name": "policy", "image": "/svc/power-policy", "critical": true,
    "restart": "never", "after": [], "capabilities": [
      {"source":"bootstrap.service-output-channel", "purpose":"stdio.output",
       "operation":"duplicate", "rights":["wait","write"]},
      {"source":"bootstrap.root-directory", "purpose":"process.root-directory",
       "operation":"duplicate", "rights":["read"]},
      {"source":"bootstrap.cpu-inspector", "purpose":"process.cpu-inspector",
       "operation":"duplicate", "rights":["inspect"]}
    ]
  }]
}"#;

#[test]
fn ordinary_policy_service_gets_only_explicit_attenuated_authority() -> Result<(), String> {
    let manifest = manifest::parse(POLICY_SERVICE).map_err(|e| format!("{e:?}"))?;
    let plan = manifest::validate(&manifest, &BootstrapPolicy).map_err(|e| format!("{e:?}"))?;
    for (index, rights) in [
        Rights::WAIT.union(Rights::WRITE),
        Rights::READ,
        Rights::INSPECT,
    ]
    .into_iter()
    .enumerate()
    {
        assert_eq!(
            plan.capability_grant(0, index).map(|grant| grant.rights()),
            Some(rights.bits())
        );
    }
    assert!(plan.capability_grant(0, 3).is_none());
    Ok(())
}

#[test]
fn custom_supervisor_requires_an_explicit_retention_grant() -> Result<(), String> {
    let text = r#"{"format":"hyper.service-manifest","services":[{
        "name":"supervisor", "image":"/svc/custom-supervisor", "critical":false,
        "restart":"never", "after":[], "capabilities":[{
            "source":"bootstrap.task-factory", "purpose":"process.task-factory",
            "operation":"duplicate", "rights":["create-process","create-task-group","retain-process"]
        }]
    }]}"#;
    for (text, expected) in [
        (text.to_owned(), true),
        (text.replace(",\"retain-process\"", ""), false),
    ] {
        let manifest = manifest::parse(&text).map_err(|error| format!("{error:?}"))?;
        let plan = manifest::validate(&manifest, &BootstrapPolicy)
            .map_err(|error| format!("{error:?}"))?;
        let grant = plan.capability_grant(0, 0).ok_or("missing task factory")?;
        assert_eq!(
            grant.rights() & Rights::RETAIN_PROCESS.bits() != 0,
            expected
        );
    }
    Ok(())
}

#[test]
fn existing_installed_manifests_still_validate_against_real_bootstrap_policy() -> Result<(), String>
{
    for text in [
        include_str!("../../../bootstrap/stage1/init/tests/config/services.json"),
        include_str!("../../../bootstrap/stage1/init/config/services-with-vms.json"),
        include_str!("../../../bootstrap/stage1/init/config/services-console-only.json"),
    ] {
        let manifest = manifest::parse(text).map_err(|e| format!("{e:?}"))?;
        manifest::validate(&manifest, &BootstrapPolicy).map_err(|e| format!("{e:?}"))?;
    }
    Ok(())
}

#[test]
fn generated_board_services_preserve_bootstrap_authority_bounds() -> Result<(), String> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let output = std::process::Command::new("python3")
        .args([
            "-B",
            "-c",
            r#"import json, sys
from pathlib import Path
sys.path.insert(0, 'scripts')
from board_bootstrap import services
from board_config import Board
root = Path.cwd()
print(json.dumps({path.stem: services(Board.load(path), root)
                  for path in sorted((root / 'boards').glob('*.json'))}))
"#,
        ])
        .current_dir(root)
        .output()
        .map_err(|error| error.to_string())?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).into_owned());
    }
    let boards: std::collections::BTreeMap<String, serde_json::Value> =
        serde_json::from_slice(&output.stdout).map_err(|error| error.to_string())?;
    assert!(!boards.is_empty());
    for (name, generated) in boards {
        let text = generated.to_string();
        let manifest = manifest::parse(&text).map_err(|error| format!("{name}: {error:?}"))?;
        let plan = manifest::validate(&manifest, &BootstrapPolicy)
            .map_err(|error| format!("{name}: {error:?}"))?;
        for (service_index, service) in manifest.services().enumerate() {
            if service.image() != super::FS_BACKEND_IMAGE {
                continue;
            }
            let index = service
                .capabilities()
                .position(|cap| cap.purpose() == hyper_service::process::TASK_FACTORY_NAME)
                .ok_or_else(|| format!("{name}: missing filesystem task factory"))?;
            let grant = plan
                .capability_grant(service_index, index)
                .ok_or_else(|| format!("{name}: missing filesystem launch grant"))?;
            assert_eq!(grant.rights() & Rights::RETAIN_PROCESS.bits(), 0, "{name}");
        }
    }
    Ok(())
}

#[test]
fn only_the_bootstrap_filesystem_predecessor_omits_retention() -> Result<(), String> {
    for (phase, loader, retention, expected) in [
        ("boot", "bootstrap", false, None),
        (
            "boot",
            "bootstrap",
            true,
            Some(ValidationErrorKind::ExcessPurposeRights),
        ),
        (
            "system",
            "dynamic",
            false,
            Some(ValidationErrorKind::MissingRequiredRights),
        ),
        (
            "system",
            "bootstrap",
            false,
            Some(ValidationErrorKind::MissingRequiredRights),
        ),
        (
            "boot",
            "dynamic",
            false,
            Some(ValidationErrorKind::MissingRequiredRights),
        ),
        ("system", "dynamic", true, None),
    ] {
        let mut rights = vec!["create-process", "create-task-group"];
        if retention {
            rights.push("retain-process");
        }
        let text = serde_json::json!({
            "format": "hyper.service-manifest",
            "services": [{
                "name": "filesystem", "image": "/svc/fs-backend",
                "critical": false, "restart": "never", "after": [],
                "phase": phase, "loader": loader,
                "capabilities": [{
                    "source": "bootstrap.task-factory", "purpose": "process.task-factory",
                    "operation": "duplicate", "rights": rights,
                }],
            }],
        })
        .to_string();
        let manifest = manifest::parse(&text).map_err(|error| format!("{error:?}"))?;
        assert_eq!(
            manifest::validate(&manifest, &BootstrapPolicy)
                .err()
                .map(|error| error.kind()),
            expected,
            "phase={phase} loader={loader} retention={retention}",
        );
    }
    Ok(())
}

#[test]
fn common_contracts_do_not_expose_private_service_roles_or_weaken_required_rights()
-> Result<(), String> {
    for purpose in [
        "console.system",
        "io.device-authority",
        "filesystem.attach",
        "filesystem.provider",
        "vm.provisioning",
        "vm.creation-authority",
        "session.client-input",
    ] {
        assert!(
            BootstrapPolicy
                .startup_purpose("/svc/power-policy", purpose)
                .is_none()
        );
    }
    for (old, new, expected) in [
        (
            "[\"wait\",\"write\"]",
            "[\"wait\"]",
            ValidationErrorKind::MissingRequiredRights,
        ),
        (
            "[\"wait\",\"write\"]",
            "[\"wait\",\"write\",\"read\"]",
            ValidationErrorKind::RightsEscalation,
        ),
    ] {
        let text = POLICY_SERVICE.replace(old, new);
        let manifest = manifest::parse(&text).map_err(|e| format!("{e:?}"))?;
        assert_eq!(
            manifest::validate(&manifest, &BootstrapPolicy)
                .err()
                .map(|e| e.kind()),
            Some(expected)
        );
    }
    Ok(())
}

#[test]
fn filesystem_requires_both_distinct_explicit_owners() -> Result<(), String> {
    const MANIFEST: &str = r#"{"format":"hyper.service-manifest","services":[
      {"name":"filesystem","image":"/svc/fs-backend","critical":false,"restart":"never","after":[],"capabilities":[
        {"source":"bootstrap.filesystem-attach","purpose":"filesystem.attach","operation":"move","rights":["wait","read"]}]},
      {"name":"storage","image":"/svc/io-runtime","critical":false,"restart":"never","after":[],"capabilities":[
        {"source":"bootstrap.filesystem-provider","purpose":"filesystem.provider","operation":"move","rights":["wait","write"]}]}
    ]}"#;
    let manifest = manifest::parse(MANIFEST).map_err(|e| format!("{e:?}"))?;
    let plan = manifest::validate(&manifest, &BootstrapPolicy).map_err(|e| format!("{e:?}"))?;
    assert_eq!(super::filesystem_enabled(&plan), Ok(true));
    let missing_peer = MANIFEST.replace(
        r#"{"source":"bootstrap.filesystem-provider","purpose":"filesystem.provider","operation":"move","rights":["wait","write"]}"#,
        "",
    );
    let manifest = manifest::parse(&missing_peer).map_err(|e| format!("{e:?}"))?;
    let plan = manifest::validate(&manifest, &BootstrapPolicy).map_err(|e| format!("{e:?}"))?;
    assert_eq!(
        super::filesystem_enabled(&plan),
        Err(super::IoReadyPlanError::InvalidGrant)
    );
    Ok(())
}

const IO_READY_SERVICE: &str = r#"{
  "format": "hyper.service-manifest",
  "services": [{
    "name": "storage", "image": "/svc/io-runtime", "critical": true,
    "restart": "never", "after": [], "capabilities": [
      {"source":"bootstrap.io-ready-channel", "purpose":"io.ready",
       "operation":"move", "rights":["wait","write"]}
    ]
  }]
}"#;

#[test]
fn storage_readiness_requires_the_dedicated_moved_authority() -> Result<(), String> {
    let manifest = manifest::parse(IO_READY_SERVICE).map_err(|e| format!("{e:?}"))?;
    let plan = manifest::validate(&manifest, &BootstrapPolicy).map_err(|e| format!("{e:?}"))?;
    assert_eq!(super::io_ready_service(&plan), Ok(Some(0)));
    for text in [IO_READY_SERVICE.replace("io.ready", "stdio.output")] {
        let manifest = manifest::parse(&text).map_err(|e| format!("{e:?}"))?;
        let plan = manifest::validate(&manifest, &BootstrapPolicy).map_err(|e| format!("{e:?}"))?;
        assert_eq!(
            super::io_ready_service(&plan),
            Err(super::IoReadyPlanError::InvalidGrant)
        );
    }
    Ok(())
}

#[test]
fn legacy_manifests_do_not_wait_for_storage() -> Result<(), String> {
    for text in [
        include_str!("../../../bootstrap/stage1/init/tests/config/services.json"),
        include_str!("../../../bootstrap/stage1/init/config/services-console-only.json"),
        include_str!("../../../bootstrap/stage1/init/config/services-with-vms.json"),
    ] {
        let manifest = manifest::parse(text).map_err(|e| format!("{e:?}"))?;
        let plan = manifest::validate(&manifest, &BootstrapPolicy).map_err(|e| format!("{e:?}"))?;
        assert_eq!(super::io_ready_service(&plan), Ok(None));
    }
    assert!(
        BootstrapPolicy
            .startup_purpose("/svc/power-policy", "io.ready")
            .is_none()
    );
    Ok(())
}

#[test]
fn virtual_console_owns_shell_launch_and_bootstrap_rejects_old_client_endpoints() {
    for source in [
        "bootstrap.shell-input-channel",
        "bootstrap.session-client-input-channel",
    ] {
        assert!(BootstrapPolicy.authority(source).is_none());
    }
}

#[test]
fn ordinary_services_cannot_receive_namespace_management_authority() {
    assert!(!super::root_directory_rights().contains(Rights::MANAGE_NAMESPACE));
}
