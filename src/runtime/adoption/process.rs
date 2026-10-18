// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Resident replacement construction while predecessor filesystem workers run.
use super::{Runtime, duplicate};
use hyper_os::{handle::*, startup, task::ProcessBuilder};
use hyper_service::process as contract;

pub(in crate::runtime) struct ManagedBuilder {
    pub builder: ProcessBuilder,
    pub group: OwnedHandle<TaskGroupObject>,
    pub path: String,
}
impl core::ops::Deref for ManagedBuilder {
    type Target = ProcessBuilder;
    fn deref(&self) -> &Self::Target {
        &self.builder
    }
}

impl Runtime {
    pub(in crate::runtime) fn provider_builder(
        &self,
        name: &str,
        program: &hyper_component_config::Program,
        log: Option<&str>,
    ) -> hyper_os::Result<ManagedBuilder> {
        let a = &self.launcher.authorities;
        let environment = a
            .system_environment
            .as_ref()
            .ok_or(hyper_os::Error::MissingHandle)?;
        let image = a
            .root_directory
            .open(&program.image, contract::EXECUTABLE_FILE_RIGHTS)?;
        let loader = contract::open_loader(environment, contract::LoaderKind::Dynamic)?;
        let group =
            hyper_os::task::create_task_group(a.factory.as_handle_ref(), a.domain.as_handle_ref())?;
        let builder = ProcessBuilder::create(
            a.factory.as_handle_ref(),
            group.as_handle_ref(),
            a.domain.as_handle_ref(),
            image.as_handle_ref(),
            loader.as_handle_ref(),
        )?;
        builder.set_name(name.rsplit('/').next().unwrap_or(name))?;
        builder.add_argument(&program.image)?;
        for argument in &program.arguments {
            builder.add_argument(argument)?;
        }
        builder.set_memory_lock_allowed(program.resident)?;
        duplicate(
            &builder,
            a.library_directory.as_handle_ref(),
            startup::DYNAMIC_LIBRARY_DIRECTORY.as_raw(),
            Rights::READ.union(Rights::EXECUTE).union(Rights::PROTECT),
        )?;
        if let Some(name) = log {
            self.launcher.stdio(&builder, name, 1)?;
        }
        Ok(ManagedBuilder {
            builder,
            group,
            path: name.into(),
        })
    }

    pub(super) fn delegate_filesystem_launch(
        &self,
        builder: &ManagedBuilder,
    ) -> hyper_os::Result<()> {
        let a = &self.launcher.authorities;
        let environment = a
            .system_environment
            .as_ref()
            .ok_or(hyper_os::Error::MissingHandle)?;
        let loader = contract::open_loader(environment, contract::LoaderKind::Dynamic)?;
        duplicate(
            builder,
            a.factory.as_handle_ref(),
            startup::TASK_FACTORY.as_raw(),
            Rights::CREATE_PROCESS
                .union(Rights::RETAIN_PROCESS)
                .union(Rights::LOCK_MEMORY)
                .union(Rights::CREATE_TASK_GROUP)
                .union(Rights::DUPLICATE)
                .union(Rights::TRANSFER),
        )?;
        duplicate(
            builder,
            a.domain.as_handle_ref(),
            startup::RESOURCE_DOMAIN.as_raw(),
            Rights::CREATE_RESOURCE_DOMAIN
                .union(Rights::RESOURCE_DOMAIN_SPONSOR)
                .union(Rights::DUPLICATE)
                .union(Rights::TRANSFER),
        )?;
        duplicate(
            builder,
            builder.group.as_handle_ref(),
            startup::TASK_GROUP.as_raw(),
            Rights::TASK_GROUP_ATTACH_PROCESS
                .union(Rights::DUPLICATE)
                .union(Rights::TRANSFER),
        )?;
        duplicate(
            builder,
            a.root_directory.as_handle_ref(),
            startup::ROOT_DIRECTORY.as_raw(),
            a.root_directory.as_handle_ref().info()?.rights,
        )?;
        duplicate(
            builder,
            environment.as_handle_ref(),
            contract::ENVIRONMENT_DIRECTORY.as_raw(),
            contract::ENVIRONMENT_DIRECTORY_CONTRACT.required_rights(),
        )?;
        duplicate(
            builder,
            loader.as_handle_ref(),
            startup::CHILD_LOADER.as_raw(),
            contract::CHILD_LOADER_CONTRACT.required_rights(),
        )?;
        duplicate(
            builder,
            a.library_directory.as_handle_ref(),
            contract::CHILD_LIBRARY_DIRECTORY.as_raw(),
            contract::CHILD_LIBRARY_DIRECTORY_CONTRACT.required_rights(),
        )
    }

    pub(super) fn start_provider(
        &mut self,
        index: usize,
        builder: ManagedBuilder,
    ) -> hyper_os::Result<()> {
        if index >= self.supervisors.processes.len() || self.pending_provider.is_some() {
            return Err(hyper_os::Error::InvalidResponse);
        }
        self.supervisors.managed_paths[index] = Some(builder.path.clone());
        let candidate = self.start_managed(builder)?;
        self.pending_provider = Some((index, candidate));
        Ok(())
    }

    pub(in crate::runtime) fn start_managed(
        &self,
        prepared: ManagedBuilder,
    ) -> hyper_os::Result<OwnedHandle<ProcessObject>> {
        hyper_component::installation::prepared(
            self.installer.as_handle_ref(),
            &prepared.path,
            prepared.builder,
            prepared.group,
        )
    }

    /// READY confirms ownership. Only now may this process take the original
    /// service's critical-supervision slot, with the predecessor held for retire.
    pub(super) fn confirm_provider(&mut self, index: usize) -> hyper_os::Result<()> {
        if self
            .pending_provider
            .as_ref()
            .is_none_or(|(pending, _)| *pending != index)
        {
            return Err(hyper_os::Error::InvalidResponse);
        }
        let (_, candidate) = self
            .pending_provider
            .take()
            .ok_or(hyper_os::Error::MissingHandle)?;
        if let Some(old) = self.supervisors.processes[index].replace(candidate) {
            if Some(index) == self.providers[0] {
                self.old_console = Some(old);
            } else {
                self.retired_processes.push(old);
            }
        }
        Ok(())
    }

    pub(super) fn retain_unconfirmed_provider(&mut self, independent: bool) {
        if let Some((index, candidate)) = self.pending_provider.take() {
            if independent {
                // Raw console owns fresh endpoints only. It cannot have taken
                // resources from its predecessor, so its stop is rollback-safe.
                let _ = self.supervisors.stop(index);
            }
            // A stateful provider's timeout does not prove that MOVE failed.
            // Preserve its candidate and predecessor without claiming rollback.
            self.unconfirmed_providers.push(candidate);
        }
    }
}
