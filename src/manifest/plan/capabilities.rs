// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Resolve each capability grant against authority and startup-purpose ceilings.

use super::super::model::{
    CapabilityBinding, CapabilityOperation, MAX_BINDING_NAME_BYTES, MAX_PURPOSE_NAME_BYTES,
    MAX_RIGHT_NAME_BYTES, Manifest, RestartPolicy,
};
use super::graph::find_service;
use super::{
    AuthorityDeclaration, AuthorityKey, AuthorityPolicy, CapabilityGrant, LaunchPlan,
    ValidationError, ValidationErrorKind, error, valid_identifier,
};

pub(super) fn validate(
    manifest: &Manifest<'_>,
    policy: &impl AuthorityPolicy,
    plan: &mut LaunchPlan<'_>,
) -> Result<(), ValidationError> {
    for (service_index, service) in manifest.services.iter().enumerate() {
        for (capability_index, capability) in service.capabilities.iter().enumerate() {
            validate_binding_names(capability, service_index, capability_index)?;
            reject_reused_move_source(manifest, service_index, capability_index, capability)?;
            let declaration = policy.authority(capability.source).ok_or_else(|| {
                error(
                    ValidationErrorKind::UnknownAuthority,
                    Some(service_index),
                    Some(capability_index),
                )
            })?;
            reject_conflicting_authority_key(
                manifest,
                plan,
                service_index,
                capability_index,
                capability.source,
                declaration.key,
            )?;
            validate_provider_dependency(
                manifest,
                service_index,
                capability_index,
                declaration.provider,
            )?;
            validate_operation(
                capability,
                declaration,
                service.restart,
                service_index,
                capability_index,
            )?;
            let purpose = policy
                .startup_purpose(service.image, capability.purpose)
                .ok_or_else(|| {
                    error(
                        ValidationErrorKind::UnknownCapabilityPurpose,
                        Some(service_index),
                        Some(capability_index),
                    )
                })?;
            if purpose.value == 0
                || purpose.object_kind == 0
                || purpose.required_rights & !purpose.allowed_rights != 0
            {
                return Err(error(
                    ValidationErrorKind::InvalidPurposeDeclaration,
                    Some(service_index),
                    Some(capability_index),
                ));
            }
            if plan.grants[service_index][..capability_index]
                .iter()
                .flatten()
                .any(|grant| grant.purpose() == purpose.value)
            {
                return Err(error(
                    ValidationErrorKind::DuplicateCapabilityPurpose,
                    Some(service_index),
                    Some(capability_index),
                ));
            }
            if purpose.object_kind != declaration.object_kind {
                return Err(error(
                    ValidationErrorKind::ObjectKindMismatch,
                    Some(service_index),
                    Some(capability_index),
                ));
            }
            let requested_rights =
                resolve_rights(policy, capability, service_index, capability_index)?;
            if requested_rights & !declaration.rights != 0 {
                return Err(error(
                    ValidationErrorKind::RightsEscalation,
                    Some(service_index),
                    Some(capability_index),
                ));
            }
            if purpose.required_rights & !requested_rights != 0 {
                return Err(error(
                    ValidationErrorKind::MissingRequiredRights,
                    Some(service_index),
                    Some(capability_index),
                ));
            }
            if requested_rights & !purpose.allowed_rights != 0 {
                return Err(error(
                    ValidationErrorKind::ExcessPurposeRights,
                    Some(service_index),
                    Some(capability_index),
                ));
            }
            plan.grants[service_index][capability_index] = Some(CapabilityGrant {
                authority: declaration.key,
                operation: capability.operation,
                object_kind: purpose.object_kind,
                purpose: purpose.value,
                rights: requested_rights,
            });
        }
    }
    Ok(())
}

fn reject_conflicting_authority_key(
    manifest: &Manifest<'_>,
    plan: &LaunchPlan<'_>,
    service_index: usize,
    capability_index: usize,
    source: &str,
    key: AuthorityKey,
) -> Result<(), ValidationError> {
    for previous_service in 0..=service_index {
        let Some(service) = manifest.services.get(previous_service) else {
            return Err(error(
                ValidationErrorKind::ConflictingAuthorityKey,
                Some(service_index),
                Some(capability_index),
            ));
        };
        let limit = if previous_service == service_index {
            capability_index
        } else {
            service.capabilities.len()
        };
        for previous_capability in 0..limit {
            if plan.grants[previous_service][previous_capability].map(CapabilityGrant::authority)
                != Some(key)
            {
                continue;
            }
            let Some(previous) = service.capabilities.get(previous_capability) else {
                return Err(error(
                    ValidationErrorKind::ConflictingAuthorityKey,
                    Some(service_index),
                    Some(capability_index),
                ));
            };
            if previous.source != source {
                return Err(error(
                    ValidationErrorKind::ConflictingAuthorityKey,
                    Some(service_index),
                    Some(capability_index),
                ));
            }
        }
    }
    Ok(())
}

fn validate_binding_names(
    capability: &CapabilityBinding<'_>,
    service: usize,
    index: usize,
) -> Result<(), ValidationError> {
    if !valid_identifier(capability.source, MAX_BINDING_NAME_BYTES) {
        return Err(error(
            ValidationErrorKind::InvalidBindingName,
            Some(service),
            Some(index),
        ));
    }
    if !valid_identifier(capability.purpose, MAX_PURPOSE_NAME_BYTES) {
        return Err(error(
            ValidationErrorKind::InvalidPurposeName,
            Some(service),
            Some(index),
        ));
    }
    Ok(())
}

fn validate_provider_dependency(
    manifest: &Manifest<'_>,
    service_index: usize,
    capability_index: usize,
    provider: Option<&str>,
) -> Result<(), ValidationError> {
    let Some(provider) = provider else {
        return Ok(());
    };
    let Some(provider_index) = find_service(manifest, provider) else {
        return Err(error(
            ValidationErrorKind::UnknownAuthorityProvider,
            Some(service_index),
            Some(capability_index),
        ));
    };
    if provider_index == service_index
        || !manifest.services.get(service_index).is_some_and(|service| {
            service
                .dependencies
                .iter()
                .any(|dependency| *dependency == provider)
        })
    {
        return Err(error(
            ValidationErrorKind::MissingProviderDependency,
            Some(service_index),
            Some(capability_index),
        ));
    }
    Ok(())
}

fn validate_operation(
    capability: &CapabilityBinding<'_>,
    declaration: AuthorityDeclaration<'_>,
    restart: RestartPolicy,
    service: usize,
    index: usize,
) -> Result<(), ValidationError> {
    match capability.operation {
        CapabilityOperation::Move if !declaration.movable => {
            return Err(error(
                ValidationErrorKind::TransferForbidden,
                Some(service),
                Some(index),
            ));
        }
        CapabilityOperation::Move if restart != RestartPolicy::Never => {
            return Err(error(
                ValidationErrorKind::RestartConsumesAuthority,
                Some(service),
                Some(index),
            ));
        }
        CapabilityOperation::Duplicate if !declaration.duplicable => {
            return Err(error(
                ValidationErrorKind::DuplicateForbidden,
                Some(service),
                Some(index),
            ));
        }
        CapabilityOperation::Create if !declaration.creatable => {
            return Err(error(
                ValidationErrorKind::CreateForbidden,
                Some(service),
                Some(index),
            ));
        }
        CapabilityOperation::Move
        | CapabilityOperation::Duplicate
        | CapabilityOperation::Create => {}
    }
    Ok(())
}

fn resolve_rights(
    policy: &impl AuthorityPolicy,
    capability: &CapabilityBinding<'_>,
    service: usize,
    index: usize,
) -> Result<u64, ValidationError> {
    let mut requested = 0_u64;
    for name in capability.rights.iter() {
        if !valid_identifier(name, MAX_RIGHT_NAME_BYTES) {
            return Err(error(
                ValidationErrorKind::InvalidRightName,
                Some(service),
                Some(index),
            ));
        }
        let bit = policy.right(name).ok_or_else(|| {
            error(
                ValidationErrorKind::UnknownRight,
                Some(service),
                Some(index),
            )
        })?;
        if bit == 0 || !bit.is_power_of_two() {
            return Err(error(
                ValidationErrorKind::InvalidRightDeclaration,
                Some(service),
                Some(index),
            ));
        }
        if requested & bit != 0 {
            return Err(error(
                ValidationErrorKind::DuplicateRight,
                Some(service),
                Some(index),
            ));
        }
        requested |= bit;
    }
    Ok(requested)
}

fn reject_reused_move_source(
    manifest: &Manifest<'_>,
    service_index: usize,
    capability_index: usize,
    current: &CapabilityBinding<'_>,
) -> Result<(), ValidationError> {
    for earlier_service_index in 0..=service_index {
        let Some(service) = manifest.services.get(earlier_service_index) else {
            continue;
        };
        let limit = if earlier_service_index == service_index {
            capability_index
        } else {
            service.capabilities.len()
        };
        for earlier_index in 0..limit {
            let Some(earlier) = service.capabilities.get(earlier_index) else {
                continue;
            };
            if earlier.source == current.source
                && (earlier.operation == CapabilityOperation::Move
                    || (current.operation == CapabilityOperation::Move
                        && !(earlier_service_index == service_index
                            && earlier.operation == CapabilityOperation::Duplicate)))
            {
                return Err(error(
                    ValidationErrorKind::MoveSourceReused,
                    Some(service_index),
                    Some(capability_index),
                ));
            }
        }
    }
    Ok(())
}
