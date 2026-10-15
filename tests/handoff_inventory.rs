// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

use super::*;

fn basic() -> Vec<Slot> {
    [
        ROOT_TRANSITION,
        BOOT_ENVIRONMENT,
        SYSTEM_ENVIRONMENT,
        ROOT_DIRECTORY,
        LIBRARY_DIRECTORY,
        FACTORY,
        GROUP,
        DOMAIN,
        TASK_INSPECTOR,
        OBJECT_INSPECTOR,
        MEMORY_INSPECTOR,
        CPU_INSPECTOR,
        LOG_CONNECTOR,
        SYSTEM_GROUP,
        CONSOLE,
    ]
    .into_iter()
    .map(|key| Slot {
        key,
        rights: role_rights(key).bits(),
    })
    .collect()
}

fn role_rights(key: u16) -> Rights {
    let propagate = Rights::DUPLICATE.union(Rights::TRANSFER);
    match key {
        ROOT_TRANSITION => Rights::WRITE.union(Rights::TRANSFER),
        BOOT_ENVIRONMENT | SYSTEM_ENVIRONMENT | LIBRARY_DIRECTORY => {
            hyper_service::process::ENVIRONMENT_DIRECTORY_CONTRACT.required_rights()
        }
        ROOT_DIRECTORY => hyper_service::process::SHELL_ROOT_DIRECTORY_CONTRACT
            .required_rights()
            .union(Rights::MANAGE_NAMESPACE),
        FACTORY => Rights::CREATE_PROCESS
            .union(Rights::CREATE_TASK_GROUP)
            .union(Rights::LOCK_MEMORY)
            .union(propagate),
        GROUP | SYSTEM_GROUP => Rights::WAIT
            .union(Rights::INSPECT)
            .union(Rights::TASK_GROUP_ATTACH_PROCESS)
            .union(Rights::REQUEST_STOP)
            .union(propagate),
        DOMAIN => Rights::RESOURCE_DOMAIN_SPONSOR
            .union(Rights::CREATE_RESOURCE_DOMAIN)
            .union(propagate),
        TASK_INSPECTOR | OBJECT_INSPECTOR => Rights::INSPECT
            .union(Rights::INSPECT_DETAILS)
            .union(Rights::DERIVE)
            .union(propagate),
        MEMORY_INSPECTOR | CPU_INSPECTOR => Rights::INSPECT.union(propagate),
        VM_AUTHORITY => Rights::CREATE_VIRTUAL_MACHINE
            .union(Rights::DERIVE)
            .union(Rights::INSPECT)
            .union(propagate),
        key if key >= PROCESS_BASE => Rights::WAIT
            .union(Rights::INSPECT)
            .union(Rights::REQUEST_STOP)
            .union(Rights::TRANSFER),
        _ => Rights::READ
            .union(Rights::WRITE)
            .union(Rights::WAIT)
            .union(propagate),
    }
}

fn formal_services(text: &str) -> Result<String, String> {
    let mut graph: serde_json::Value =
        serde_json::from_str(text).map_err(|error| error.to_string())?;
    let services = graph["services"].as_array_mut().ok_or("services")?;
    services.retain(|service| service["loader"] != "bootstrap");
    for service in services {
        service["after"] = serde_json::json!([]);
    }
    serde_json::to_string(&graph).map_err(|error| error.to_string())
}

#[test]
fn receive_rejects_missing_duplicate_or_unknown_roles_before_accepting_any_owner() {
    let slots = basic();
    assert!(validate_inventory(&slots, 3).is_ok());
    assert!(validate_inventory(&slots[1..], 3).is_err());
    let mut slots = basic();
    slots.push(Slot {
        key: ROOT_DIRECTORY,
        rights: Rights::TRANSFER.bits(),
    });
    assert!(validate_inventory(&slots, 3).is_err());
    if let Some(slot) = slots.last_mut() {
        slot.key = LAST_ROLE + 1;
    }
    assert!(validate_inventory(&slots, 3).is_err());
}

#[test]
fn supervisor_keys_are_bounded_by_the_exact_core_manifest() {
    let mut slots = basic();
    slots.push(Slot {
        key: PROCESS_BASE + 2,
        rights: role_rights(PROCESS_BASE + 2).bits(),
    });
    assert!(validate_inventory(&slots, 3).is_ok());
    assert!(validate_inventory(&slots, 2).is_err());
}

fn with_roles(keys: &[u16]) -> Vec<Slot> {
    let mut slots = basic();
    slots.extend(keys.iter().map(|key| Slot {
        key: *key,
        rights: role_rights(*key).bits(),
    }));
    slots
}

#[test]
fn io_vm_authority_does_not_require_a_business_fleet() {
    assert!(validate_inventory(&with_roles(&[VM_AUTHORITY]), 3).is_ok());
}

#[test]
fn removed_fleet_roles_and_reserved_gaps_are_rejected() {
    for role in [15, 23, 24, 26, 27, 28, 29] {
        assert!(validate_inventory(&with_roles(&[role]), 3).is_err());
    }
}

#[test]
fn root_switch_authority_must_be_offered_before_adopting_supervision() -> Result<(), String> {
    let mut slots = basic();
    assert!(validate_namespace_source(&slots).is_ok());
    let root = slots
        .iter_mut()
        .find(|slot| slot.key == ROOT_DIRECTORY)
        .ok_or("root role")?;
    root.rights = Rights::MANAGE_NAMESPACE.union(Rights::READ).bits();
    assert!(validate_namespace_source(&slots).is_err());
    let root = slots
        .iter_mut()
        .find(|slot| slot.key == ROOT_DIRECTORY)
        .ok_or("root role")?;
    root.rights = role_rights(ROOT_DIRECTORY).bits();
    assert!(validate_namespace_source(&slots).is_ok());
    Ok(())
}

#[test]
fn vm_authority_is_checked_before_handoff_even_without_a_prepared_fleet() -> Result<(), String> {
    let text = formal_services(include_str!(
        "../../../bootstrap/stage1/init/config/services-with-vms.json"
    ))?;
    let manifest = crate::manifest::parse(&text).map_err(|error| format!("{error:?}"))?;
    let plan = crate::manifest::validate(&manifest, &crate::bootstrap_policy::BootstrapPolicy)
        .map_err(|error| format!("{error:?}"))?;
    assert!(
        validate_service_sources(
            &with_roles(&[RAW_CONTROLLER, FILESYSTEM_CONTROL_CLIENT, IO_BROKER_CLIENT]),
            &plan,
            0,
            [None; 3]
        )
        .is_err()
    );
    assert!(
        validate_service_sources(
            &with_roles(&[
                RAW_CONTROLLER,
                FILESYSTEM_CONTROL_CLIENT,
                VM_AUTHORITY,
                IO_BROKER_CLIENT
            ]),
            &plan,
            0,
            [None; 3]
        )
        .is_ok()
    );
    Ok(())
}

#[test]
fn environment_rights_are_checked_before_accepting_supervision() {
    for key in [BOOT_ENVIRONMENT, SYSTEM_ENVIRONMENT] {
        let mut slots = basic();
        for slot in &mut slots {
            if slot.key == key {
                slot.rights = Rights::READ.union(Rights::TRANSFER).bits();
            }
        }
        assert!(validate_inventory(&slots, 0).is_err());
    }
}

#[test]
fn formal_session_requires_raw_controller_across_handoff() -> Result<(), String> {
    let text = formal_services(include_str!(
        "../../../bootstrap/stage1/init/config/services-console-only.json"
    ))?;
    let manifest = crate::manifest::parse(&text).map_err(|error| format!("{error:?}"))?;
    let plan = crate::manifest::validate(&manifest, &crate::bootstrap_policy::BootstrapPolicy)
        .map_err(|error| format!("{error:?}"))?;
    let mut slots = basic();
    assert!(validate_service_sources(&slots, &plan, 0, [None; 3]).is_err());
    slots.push(Slot {
        key: RAW_CONTROLLER,
        rights: Rights::READ.bits(),
    });
    assert!(validate_service_sources(&slots, &plan, 0, [None; 3]).is_err());
    let writer = slots.last_mut().ok_or("writer")?;
    writer.rights = Rights::WRITE
        .union(Rights::WAIT)
        .union(Rights::DUPLICATE)
        .union(Rights::TRANSFER)
        .bits();
    assert!(validate_service_sources(&slots, &plan, 0, [None; 3]).is_ok());
    Ok(())
}

#[test]
fn root_transition_and_resident_provider_permissions_precede_commit() -> Result<(), String> {
    for key in [ROOT_TRANSITION, FACTORY] {
        let mut slots = basic();
        let slot = slots
            .iter_mut()
            .find(|slot| slot.key == key)
            .ok_or("required slot")?;
        slot.rights = Rights::TRANSFER.bits();
        assert!(validate_inventory(&slots, 0).is_err());
    }
    Ok(())
}

#[test]
fn admission_rejects_each_missing_baseline_operation_right() -> Result<(), String> {
    for (key, right) in [
        (GROUP, Rights::REQUEST_STOP),
        (SYSTEM_GROUP, Rights::TASK_GROUP_ATTACH_PROCESS),
        (DOMAIN, Rights::RESOURCE_DOMAIN_SPONSOR),
        (LIBRARY_DIRECTORY, Rights::PROTECT),
        (LIBRARY_DIRECTORY, Rights::DUPLICATE),
        (LIBRARY_DIRECTORY, Rights::TRANSFER),
        (LOG_CONNECTOR, Rights::WRITE),
        (CONSOLE, Rights::WRITE),
        (PROCESS_BASE, Rights::WAIT),
        (PROCESS_BASE, Rights::INSPECT),
        (PROCESS_BASE, Rights::REQUEST_STOP),
    ] {
        let mut slots = with_roles(&[PROCESS_BASE]);
        let slot = slots
            .iter_mut()
            .find(|slot| slot.key == key)
            .ok_or("slot")?;
        slot.rights &= !right.bits();
        assert!(validate_inventory(&slots, 1).is_err(), "key={key}");
    }
    Ok(())
}

#[test]
fn critical_core_owner_is_required_but_failed_optional_service_is_valid() -> Result<(), String> {
    let core = crate::manifest::parse(r#"{
        "format":"hyper.service-manifest",
        "services":[
            {"name":"raw","image":"/svc/console-raw","critical":true,"restart":"never","phase":"boot","after":[],"capabilities":[]},
            {"name":"io","image":"/svc/io-runtime","critical":false,"restart":"never","phase":"boot","after":[],"capabilities":[]}
        ]}"#).map_err(|error| format!("{error:?}"))?;
    assert!(validate_core_sources(&basic(), &core, [None; 3], false).is_err());
    let slots = with_roles(&[PROCESS_BASE]);
    assert!(validate_core_sources(&slots, &core, [None; 3], false).is_ok());
    assert!(validate_core_sources(&slots, &core, [None, Some(1), None], false).is_ok());
    assert!(validate_core_sources(&slots, &core, [None, Some(1), None], true).is_err());
    Ok(())
}

#[test]
fn ready_provider_requires_both_owner_and_handoff_endpoint() -> Result<(), String> {
    let core = crate::manifest::parse(r#"{
        "format":"hyper.service-manifest",
        "services":[{"name":"provider","image":"/svc/io-runtime","critical":false,"restart":"never","phase":"boot","after":[],"capabilities":[]}]}
    "#).map_err(|error| format!("{error:?}"))?;
    for (role, endpoint) in [(0, CONSOLE_DRAIN), (1, IO_HANDOFF), (2, FILESYSTEM_HANDOFF)] {
        let mut providers = [None; 3];
        providers[role] = Some(0);
        assert!(
            validate_core_sources(&with_roles(&[PROCESS_BASE]), &core, providers, true).is_err()
        );
        assert!(validate_core_sources(&with_roles(&[endpoint]), &core, providers, true).is_err());
        let mut slots = with_roles(&[PROCESS_BASE, endpoint]);
        assert!(validate_core_sources(&slots, &core, providers, true).is_ok());
        let slot = slots
            .iter_mut()
            .find(|slot| slot.key == endpoint)
            .ok_or("endpoint")?;
        slot.rights = Rights::TRANSFER.bits();
        assert!(validate_core_sources(&slots, &core, providers, true).is_err());
    }
    Ok(())
}

#[test]
fn planned_delegation_requires_actual_source_rights_before_move() -> Result<(), String> {
    let text = formal_services(include_str!(
        "../../../bootstrap/stage1/init/config/services-console-only.json"
    ))?;
    let manifest = crate::manifest::parse(&text).map_err(|error| format!("{error:?}"))?;
    let plan = crate::manifest::validate(&manifest, &crate::bootstrap_policy::BootstrapPolicy)
        .map_err(|error| format!("{error:?}"))?;
    for (key, right) in [
        (RAW_CONTROLLER, Rights::TRANSFER),
        (TASK_INSPECTOR, Rights::INSPECT),
        (OBJECT_INSPECTOR, Rights::INSPECT_DETAILS),
        (DOMAIN, Rights::DUPLICATE),
    ] {
        let mut slots = with_roles(&[RAW_CONTROLLER]);
        assert!(validate_service_sources(&slots, &plan, 0, [None; 3]).is_ok());
        let slot = slots
            .iter_mut()
            .find(|slot| slot.key == key)
            .ok_or("slot")?;
        slot.rights &= !right.bits();
        assert!(
            validate_service_sources(&slots, &plan, 0, [None; 3]).is_err(),
            "key={key}"
        );
    }
    Ok(())
}

#[test]
fn fresh_console_clients_are_not_limited_by_predecessor_propagation_rights() -> Result<(), String> {
    let text = formal_services(include_str!(
        "../../../bootstrap/stage1/init/config/services-console-only.json"
    ))?;
    let manifest = crate::manifest::parse(&text).map_err(|error| format!("{error:?}"))?;
    let plan = crate::manifest::validate(&manifest, &crate::bootstrap_policy::BootstrapPolicy)
        .map_err(|error| format!("{error:?}"))?;
    let mut slots = with_roles(&[RAW_CONTROLLER]);
    for slot in &mut slots {
        if matches!(slot.key, RAW_CONTROLLER | LOG_CONNECTOR) {
            slot.rights = Rights::WRITE.union(Rights::WAIT).bits();
        }
    }
    assert!(validate_service_sources(&slots, &plan, 0, [Some(0), None, None]).is_ok());
    assert!(validate_service_sources(&slots, &plan, 0, [None; 3]).is_err());
    slots.retain(|slot| slot.key != RAW_CONTROLLER);
    assert!(validate_service_sources(&slots, &plan, 0, [Some(0), None, None]).is_ok());
    assert!(validate_service_sources(&slots, &plan, 0, [None; 3]).is_err());
    Ok(())
}
