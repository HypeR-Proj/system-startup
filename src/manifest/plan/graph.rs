// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Service identities, dependency validation, and deterministic launch order.

use super::super::model::{
    MAX_DEPENDENCY_EDGES, MAX_IMAGE_PATH_BYTES, MAX_SERVICE_NAME_BYTES, MAX_SERVICES, Manifest,
    ServicePhase,
};
use super::{LaunchPlan, ValidationError, ValidationErrorKind, error, valid_identifier};

pub(super) fn validate_service_identities(manifest: &Manifest<'_>) -> Result<(), ValidationError> {
    for (index, service) in manifest.services.iter().enumerate() {
        // Core inventory uses bootstrap-local names. Formal launch plans use
        // instance paths, so two instances may share the same declaration.
        let instance_path = service.name.starts_with('/')
            && service.name.len() <= MAX_SERVICE_NAME_BYTES
            && service.name[1..]
                .split('/')
                .all(hyper_component_config::valid_name);
        if !valid_identifier(service.name, MAX_SERVICE_NAME_BYTES) && !instance_path {
            return Err(error(
                ValidationErrorKind::InvalidServiceName,
                Some(index),
                None,
            ));
        }
        if !valid_image_path(service.image, MAX_IMAGE_PATH_BYTES) {
            return Err(error(
                ValidationErrorKind::InvalidImagePath,
                Some(index),
                None,
            ));
        }
        for previous in 0..index {
            if manifest
                .services
                .get(previous)
                .map(|candidate| candidate.name)
                == Some(service.name)
            {
                return Err(error(
                    ValidationErrorKind::DuplicateServiceName,
                    Some(index),
                    None,
                ));
            }
        }
    }
    Ok(())
}

pub(super) fn validate_vm_configuration(manifest: &Manifest<'_>) -> Result<(), ValidationError> {
    if manifest.vm_configuration().is_some_and(|vm_configuration| {
        !valid_image_path(vm_configuration.config(), MAX_IMAGE_PATH_BYTES)
    }) {
        return Err(error(ValidationErrorKind::InvalidVmConfigPath, None, None));
    }
    Ok(())
}

pub(super) fn validate_dependencies(manifest: &Manifest<'_>) -> Result<(), ValidationError> {
    let mut edge_count = 0_usize;
    for (service_index, service) in manifest.services.iter().enumerate() {
        for (dependency_index, dependency) in service.dependencies.iter().enumerate() {
            if !valid_identifier(dependency, MAX_SERVICE_NAME_BYTES) {
                return Err(error(
                    ValidationErrorKind::InvalidDependencyName,
                    Some(service_index),
                    None,
                ));
            }
            if *dependency == service.name {
                return Err(error(
                    ValidationErrorKind::SelfDependency,
                    Some(service_index),
                    None,
                ));
            }
            if service
                .dependencies
                .iter()
                .take(dependency_index)
                .any(|candidate| candidate == dependency)
            {
                return Err(error(
                    ValidationErrorKind::DuplicateDependency,
                    Some(service_index),
                    None,
                ));
            }
            if find_service(manifest, dependency).is_none() {
                return Err(error(
                    ValidationErrorKind::UnknownDependency,
                    Some(service_index),
                    None,
                ));
            }
            if service.phase == ServicePhase::Boot
                && find_service(manifest, dependency)
                    .and_then(|index| manifest.service(index))
                    .is_some_and(|provider| provider.phase() == ServicePhase::System)
            {
                return Err(error(
                    ValidationErrorKind::BootDependsOnSystem,
                    Some(service_index),
                    None,
                ));
            }
            edge_count = edge_count.checked_add(1).ok_or_else(|| {
                error(
                    ValidationErrorKind::TooManyDependencyEdges,
                    Some(service_index),
                    None,
                )
            })?;
            if edge_count > MAX_DEPENDENCY_EDGES {
                return Err(error(
                    ValidationErrorKind::TooManyDependencyEdges,
                    Some(service_index),
                    None,
                ));
            }
        }
    }
    Ok(())
}

pub(super) fn build_topological_order(
    manifest: &Manifest<'_>,
    plan: &mut LaunchPlan<'_>,
) -> Result<(), ValidationError> {
    let mut emitted = [false; MAX_SERVICES];
    for position in 0..manifest.services.len() {
        let next = (0..manifest.services.len()).find(|candidate| {
            !emitted[*candidate]
                && manifest.services.get(*candidate).is_some_and(|service| {
                    service.dependencies.iter().all(|dependency| {
                        find_service(manifest, dependency).is_some_and(|index| emitted[index])
                    })
                })
        });
        let Some(next) = next else {
            return Err(error(ValidationErrorKind::DependencyCycle, None, None));
        };
        emitted[next] = true;
        plan.order[position] = next;
    }
    Ok(())
}

pub(super) fn find_service(manifest: &Manifest<'_>, name: &str) -> Option<usize> {
    manifest
        .services
        .iter()
        .position(|service| service.name == name)
}

fn valid_image_path(path: &str, maximum_length: usize) -> bool {
    if path.len() < 2
        || path.len() > maximum_length
        || !path.starts_with('/')
        || path.ends_with('/')
    {
        return false;
    }
    path.get(1..).is_some_and(|relative| {
        relative.split('/').all(|component| {
            !component.is_empty()
                && component != "."
                && component != ".."
                && component.bytes().all(|byte| {
                    matches!(byte, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'.' | b'_' | b'-')
                })
        })
    })
}
