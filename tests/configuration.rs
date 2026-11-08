// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

use crate::configuration::{Configuration, Policy};
use hyper_component_config::Topology;
use hyper_os::handle::{DirectoryObject, Rights, TypedObject};
use serde_json::json;

fn configuration() -> Result<Configuration, Box<dyn std::error::Error>> {
    configuration_with(Vec::new())
}

fn configuration_with(
    extra: Vec<serde_json::Value>,
) -> Result<Configuration, Box<dyn std::error::Error>> {
    let kind = json!({"type":"object", "object_type": DirectoryObject::KIND.as_raw(), "rights":Rights::READ.bits()});
    let mut children = vec![
        json!({"name":"journal","component":"job"}),
        json!({"name":"retire","component":"job"}),
        json!({"name":"client","component":"client"}),
    ];
    children.extend(
        extra
            .iter()
            .map(|v| json!({"name":v["name"],"component":v["name"]})),
    );
    let root = json!({"name":"root", "children":children,
        "capabilities":[{"name":"files","kind":kind}],
        "offer":[{"name":"files","to":"client","from":"self","source":"files","kind":kind}]});
    let job = json!({"name":"job", "program":{"image":"/svc/job","prepared":true}});
    let client = json!({"name":"client","program":{"image":"/bin/client"},
        "use":[{"name":"files","kind":kind,"purpose":123}]});
    let topology = Topology::parse(
        "root",
        [root, job, client].into_iter().chain(extra).map(|v| {
            (
                format!("{}.json", v["name"].as_str().unwrap_or("")),
                v.to_string().into_bytes(),
            )
        }),
    )?;
    let policy: Policy = serde_json::from_value(
        json!({"providers":[],"journal":"/journal","retirement":"/retire","applications":[],
        "exports":[{"realm":"/","name":"files","source":"bootstrap.root-directory"}]}),
    )?;
    Ok(Configuration { topology, policy })
}

#[test]
fn routed_object_requires_an_actual_startup_export() -> Result<(), Box<dyn std::error::Error>> {
    let mut c = configuration()?;
    c.validate()?;
    c.policy.exports.clear();
    assert!(
        c.validate()
            .is_err_and(|e| e.contains("routed object has no startup export"))
    );
    Ok(())
}

#[test]
fn every_prepared_instance_requires_one_installer() -> Result<(), Box<dyn std::error::Error>> {
    let mut c = configuration_with(vec![
        json!({"name":"orphan", "program":{"image":"/svc/job","prepared":true}}),
    ])?;
    assert!(
        c.validate()
            .is_err_and(|e| e.contains("prepared component has no startup installer"))
    );
    c.policy.applications = serde_json::from_value(json!([{"component":"/orphan"}]))?;
    c.validate()?;
    Ok(())
}

#[test]
fn adoption_requires_residency_before_ownership_commit() -> Result<(), Box<dyn std::error::Error>> {
    for resident in [false, true] {
        let mut c = configuration_with(vec![
            json!({"name":"io", "program":{"image":"/svc/io-runtime","prepared":true,"resident":resident}}),
        ])?;
        c.policy.providers = serde_json::from_value(json!([{"role":"storage","component":"/io"}]))?;
        if resident {
            c.validate()?;
        } else {
            assert!(
                c.validate()
                    .is_err_and(|e| e.contains("adoption provider requires resident permission"))
            );
        }
    }
    Ok(())
}

#[test]
fn random_provider_requires_a_storage_role_and_boolean_declaration()
-> Result<(), Box<dyn std::error::Error>> {
    for role in ["storage", "console", "filesystem"] {
        let mut c = configuration_with(vec![
            json!({"name":"io", "program":{"image":"/svc/io-runtime","prepared":true,"resident":true}}),
        ])?;
        c.policy.providers = serde_json::from_value(json!([
            {"role":role,"component":"/io","random":true}
        ]))?;
        assert_eq!(c.validate().is_ok(), role == "storage");
    }
    for invalid in [json!(0), json!(1), json!("true"), json!(null), json!([])] {
        assert!(
            serde_json::from_value::<crate::configuration::Provider>(json!({
                "role":"storage","component":"/io","random":invalid
            }))
            .is_err()
        );
    }
    let omitted: crate::configuration::Provider = serde_json::from_value(json!({
        "role":"storage","component":"/io"
    }))?;
    assert!(!omitted.random);
    Ok(())
}

#[test]
fn storage_profiles_select_only_declared_resident_replacements()
-> Result<(), Box<dyn std::error::Error>> {
    let mut c = configuration_with(vec![
        json!({"name":"io", "program":{"image":"/svc/io-runtime","prepared":true,"resident":true}}),
        json!({"name":"driver", "program":{"image":"/svc/block-driver","prepared":true,"resident":true}}),
    ])?;
    c.policy.providers = serde_json::from_value(json!([
        {"role":"storage","component":"/io"},
        {"role":"storage","component":"/driver"}
    ]))?;
    c.validate()?;
    for component in ["/io", "/driver"] {
        c.validate_adoption([None, Some(0), None], Some(component))?;
        assert_eq!(
            c.provider("storage", Some(component))
                .map(|p| p.component.as_str()),
            Some(component)
        );
    }
    c.validate_adoption([None; 3], None)?;
    assert!(c.provider("storage", None).is_none());
    for (offered, successor) in [
        ([None, Some(0), None], None),
        ([None, Some(0), None], Some("/undeclared")),
        ([None; 3], Some("/io")),
        ([Some(0), None, None], None),
        ([None, None, Some(0)], None),
    ] {
        assert!(c.validate_adoption(offered, successor).is_err());
    }
    c.policy.mounts = Some("/mounts".into());
    assert!(c.validate_adoption([None; 3], None).is_err());
    Ok(())
}

#[test]
fn interactive_readiness_is_an_explicit_unique_role() -> Result<(), Box<dyn std::error::Error>> {
    let mut c = configuration_with(vec![
        json!({"name":"session", "program":{"image":"/custom/session","prepared":true}}),
        json!({"name":"other", "program":{"image":"/custom/other","prepared":true}}),
    ])?;
    c.policy.applications = serde_json::from_value(json!([
        {"component":"/session", "interactive":true}, {"component":"/other"}
    ]))?;
    c.validate()?;
    c.policy.applications[1].interactive = true;
    assert!(
        c.validate()
            .is_err_and(|e| e.contains("multiple interactive"))
    );
    Ok(())
}

#[test]
fn exports_require_actual_source_propagation_rights_before_commit()
-> Result<(), Box<dyn std::error::Error>> {
    let c = configuration()?;
    c.validate()?;
    assert!(c.validate_export_inventory([]).is_err());
    assert!(
        c.validate_export_inventory([(1, Rights::READ.bits())])
            .is_err()
    );
    c.validate_export_inventory([(
        1,
        Rights::READ
            .union(Rights::DUPLICATE)
            .union(Rights::TRANSFER)
            .bits(),
    )])?;
    Ok(())
}

#[test]
fn export_policy_cannot_use_consumed_migration_endpoints_or_lie_about_types()
-> Result<(), Box<dyn std::error::Error>> {
    let mut c = configuration()?;
    c.policy.exports[0].source = "bootstrap.io-broker-server".into();
    assert!(c.validate().is_err());
    c.policy.exports[0].source = "component.control".into();
    assert!(c.validate().is_err());
    Ok(())
}

#[test]
fn launch_inventory_identifies_instances_instead_of_reused_declarations()
-> Result<(), Box<dyn std::error::Error>> {
    let mut c = configuration()?;
    c.policy.applications = serde_json::from_value(json!([
        {"component":"/journal"}, {"component":"/retire"}
    ]))?;
    // Both paths instantiate the same "job" declaration. The launch inventory
    // must not collapse their identities even before resource planning.
    let bytes = c.launch_manifest()?;
    let manifest = crate::manifest::parse(&bytes).map_err(|e| format!("{e:?}"))?;
    let names: Vec<_> = manifest.services().map(|s| s.name()).collect();
    assert_eq!(names, ["/journal", "/retire"]);
    Ok(())
}

#[test]
fn executable_export_requires_real_authority_before_handoff()
-> Result<(), Box<dyn std::error::Error>> {
    use hyper_os::handle::ExecutableAuthorityObject;
    let mut c = configuration()?;
    let kind = hyper_component_config::CapabilityType::Object {
        object_type: ExecutableAuthorityObject::KIND.as_raw(),
        rights: Rights::CREATE_EXECUTABLE.bits(),
    };
    c.policy.exports[0].source = "bootstrap.executable-authority".into();
    // The topology is already resolved; update both declaration and resolved
    // route so this exercises export source/type/rights and live inventory.
    for instance in &mut c.topology.instances {
        for capability in &mut instance.declaration.capabilities {
            capability.kind = kind.clone();
        }
    }
    for route in &mut c.topology.routes {
        route.kind = kind.clone();
    }
    c.validate()?;
    assert!(c.validate_export_inventory([]).is_err());
    assert!(
        c.validate_export_inventory([(38, Rights::CREATE_EXECUTABLE.bits())])
            .is_err()
    );
    c.validate_export_inventory([(
        38,
        Rights::CREATE_EXECUTABLE
            .union(Rights::DUPLICATE)
            .union(Rights::TRANSFER)
            .bits(),
    )])?;
    Ok(())
}

#[test]
fn construction_exports_require_explicit_matching_inventory()
-> Result<(), Box<dyn std::error::Error>> {
    use hyper_os::handle::{ResourceDomainObject, TaskFactoryObject, TaskGroupObject};
    for (source, key, object_type, rights) in [
        (
            "bootstrap.task-factory",
            3,
            TaskFactoryObject::KIND.as_raw(),
            Rights::CREATE_PROCESS,
        ),
        (
            "bootstrap.task-group",
            30,
            TaskGroupObject::KIND.as_raw(),
            Rights::TASK_GROUP_ATTACH_PROCESS,
        ),
        (
            "bootstrap.resource-domain",
            5,
            ResourceDomainObject::KIND.as_raw(),
            Rights::RESOURCE_DOMAIN_SPONSOR,
        ),
    ] {
        let mut c = configuration()?;
        let kind = hyper_component_config::CapabilityType::Object {
            object_type,
            rights: rights.bits(),
        };
        c.policy.exports[0].source = source.into();
        for instance in &mut c.topology.instances {
            for capability in &mut instance.declaration.capabilities {
                capability.kind = kind.clone();
            }
        }
        for route in &mut c.topology.routes {
            route.kind = kind.clone();
        }
        c.validate()?;
        assert!(c.validate_export_inventory([]).is_err());
        assert!(c.validate_export_inventory([(key, rights.bits())]).is_err());
        c.validate_export_inventory([(
            key,
            rights
                .union(Rights::DUPLICATE)
                .union(Rights::TRANSFER)
                .bits(),
        )])?;
    }
    Ok(())
}
