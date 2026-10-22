// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Finite bootstrap adoption policy. Component topology owns executable identity;
//! this file names only migration roles and the Native resources they require.

use hyper_component_config::{Program, Topology};
use serde::{Deserialize, Serialize};
use std::io::Read;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub source: String,
    pub purpose: String,
    pub operation: String,
    pub rights: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Application {
    pub component: String,
    #[serde(default)]
    pub critical: bool,
    /// Wait for this application's READY before publishing interactive-ready.
    #[serde(default)]
    pub interactive: bool,
    #[serde(default)]
    pub capabilities: Vec<Grant>,
    #[serde(default)]
    pub fleet: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Provider {
    pub role: String,
    pub component: String,
}

/// Bind existing startup authority to an explicitly declared realm capability.
/// Rights come from that declaration; routes may attenuate them further.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Export {
    pub realm: String,
    pub name: String,
    pub source: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    #[serde(default)]
    pub exports: Vec<Export>,
    pub providers: Vec<Provider>,
    pub journal: String,
    pub retirement: String,
    #[serde(default)]
    pub mounts: Option<String>,
    pub applications: Vec<Application>,
}

pub struct Configuration {
    pub policy: Policy,
    pub topology: Topology,
}

fn read(path: &str, limit: usize) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .map_err(|e| format!("{path}: {e}"))?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("{path}: {e}"))?;
    if bytes.len() > limit {
        return Err(format!("{path}: configuration too large"));
    }
    Ok(bytes)
}

impl Configuration {
    pub fn load() -> Result<Self, String> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Root {
            root: String,
            configuration_directory: String,
            startup: String,
        }
        let root: Root = serde_json::from_slice(&read("/etc/hyper/components.json", 4096)?)
            .map_err(|e| e.to_string())?;
        if !hyper_component_config::absolute_path(&root.configuration_directory) {
            return Err("invalid configuration directory".into());
        }
        let mut docs = Vec::new();
        let mut total = 0;
        for entry in std::fs::read_dir(&root.configuration_directory).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| "invalid filename")?;
            if !name.ends_with(".json") {
                continue;
            }
            if docs.len() >= hyper_component_config::MAX_COMPONENTS {
                return Err("too many component declarations".into());
            }
            let path = entry.path();
            let bytes = read(
                path.to_str().ok_or("invalid path")?,
                hyper_component_config::MAX_DOCUMENT_BYTES,
            )?;
            total += bytes.len();
            if total > hyper_component_config::MAX_CONFIGURATION_BYTES {
                return Err("configuration too large".into());
            }
            docs.push((name, bytes));
        }
        let topology = Topology::parse(&root.root, docs)?;
        let index = topology
            .index(&root.startup)
            .ok_or("startup component missing")?;
        let program = topology.instances[index]
            .declaration
            .program
            .as_ref()
            .ok_or("startup program missing")?;
        let path = program
            .arguments
            .first()
            .ok_or("startup policy path missing")?;
        let policy: Policy =
            serde_json::from_slice(&read(path, 64 * 1024)?).map_err(|e| e.to_string())?;
        let result = Self { policy, topology };
        result.validate()?;
        Ok(result)
    }

    pub fn program(&self, path: &str) -> Result<&Program, String> {
        self.topology
            .index(path)
            .and_then(|i| self.topology.instances[i].declaration.program.as_ref())
            .ok_or_else(|| format!("{path}: missing program"))
    }
    pub fn validate(&self) -> Result<(), String> {
        use crate::manifest::AuthorityPolicy;
        use hyper_component_config::CapabilityType;
        let mut exports = std::collections::BTreeSet::new();
        if self.policy.exports.len() > 64 {
            return Err("too many authority exports".into());
        }
        for export in &self.policy.exports {
            let realm = self
                .topology
                .index(&export.realm)
                .ok_or("export realm missing")?;
            let declaration = &self.topology.instances[realm].declaration;
            let cap = declaration
                .capabilities
                .iter()
                .find(|c| c.name == export.name)
                .ok_or("export capability missing")?;
            let CapabilityType::Object {
                object_type,
                rights,
            } = cap.kind
            else {
                return Err("export must name an object capability".into());
            };
            let source = crate::bootstrap_policy::BootstrapPolicy
                .authority(&export.source)
                .ok_or("export source missing")?;
            if declaration.program.is_some()
                || !exports.insert((&export.realm, &export.name))
                || !exportable(&export.source)
                || !source.duplicable
                || object_type != source.object_kind
                || rights & !source.rights != 0
            {
                return Err(format!(
                    "{}:{}: invalid authority export",
                    export.realm, export.name
                ));
            }
        }
        for route in &self.topology.routes {
            if matches!(route.kind, CapabilityType::Object { .. })
                && !exports.contains(&(
                    &self.topology.instances[route.provider].path,
                    &route.capability,
                ))
            {
                return Err(format!(
                    "{}:{}: routed object has no startup export",
                    self.topology.instances[route.provider].path, route.capability
                ));
            }
        }
        let mut paths = std::collections::BTreeSet::new();
        let mut roles = std::collections::BTreeSet::new();
        for provider in &self.policy.providers {
            if !matches!(provider.role.as_str(), "console" | "storage" | "filesystem")
                || (provider.role != "storage" && !roles.insert(&provider.role))
            {
                return Err("duplicate or unknown provider role".into());
            }
            if !self.program(&provider.component)?.resident {
                return Err(format!(
                    "{}: adoption provider requires resident permission",
                    provider.component
                ));
            }
        }
        for path in self
            .policy
            .providers
            .iter()
            .map(|p| &p.component)
            .chain([&self.policy.journal, &self.policy.retirement])
            .chain(self.policy.mounts.iter())
            .chain(self.policy.applications.iter().map(|a| &a.component))
        {
            if !paths.insert(path) || !self.program(path)?.prepared {
                return Err(format!("{path}: startup requires one prepared component"));
            }
        }
        if self.policy.applications.len() > crate::manifest::MAX_SERVICES {
            return Err("too many startup applications".into());
        }
        if self
            .policy
            .applications
            .iter()
            .filter(|app| app.interactive)
            .count()
            > 1
        {
            return Err("multiple interactive startup applications".into());
        }
        for instance in &self.topology.instances {
            if instance
                .declaration
                .program
                .as_ref()
                .is_some_and(|p| p.prepared)
                && !paths.contains(&instance.path)
            {
                return Err(format!(
                    "{}: prepared component has no startup installer",
                    instance.path
                ));
            }
        }
        Ok(())
    }

    /// A profile selects only a declared formal storage replacement. Unused
    /// candidates stay stopped; every offered owner requires an exact match.
    pub(crate) fn validate_adoption(
        &self,
        offered: [Option<usize>; 3],
        storage_successor: Option<&str>,
    ) -> Result<(), String> {
        if offered[1].is_some() != storage_successor.is_some() {
            return Err("storage owner and successor must be offered together".into());
        }
        if self.policy.mounts.is_some() && offered[2].is_none() {
            return Err("formal mounts require an offered filesystem provider".into());
        }
        for (index, role) in ["console", "storage", "filesystem"].into_iter().enumerate() {
            if offered[index].is_some() && self.provider(role, storage_successor).is_none() {
                return Err(format!(
                    "{role}: no permitted replacement for offered provider"
                ));
            }
        }
        Ok(())
    }

    pub(crate) fn provider(
        &self,
        role: &str,
        storage_successor: Option<&str>,
    ) -> Option<&Provider> {
        self.policy.providers.iter().find(|provider| {
            provider.role == role
                && (role != "storage" || Some(provider.component.as_str()) == storage_successor)
        })
    }

    /// Check export ceilings against the actual offered inventory before the
    /// root manager accepts the irreversible ownership rendezvous.
    pub fn validate_export_inventory(
        &self,
        slots: impl IntoIterator<Item = (u16, u64)>,
    ) -> Result<(), String> {
        use hyper_os::handle::Rights;
        let slots: std::collections::BTreeMap<_, _> = slots.into_iter().collect();
        for export in &self.policy.exports {
            let key = match export.source.as_str() {
                "component.observe" | "component.control" => continue,
                "bootstrap.root-directory" => 1,
                "bootstrap.task-inspector" => 6,
                "bootstrap.object-inspector" => 7,
                "bootstrap.memory-inspector" => 8,
                "bootstrap.cpu-inspector" => 9,
                _ => return Err("unsupported object export source".into()),
            };
            let index = self
                .topology
                .index(&export.realm)
                .ok_or("export realm missing")?;
            let cap = self.topology.instances[index]
                .declaration
                .capabilities
                .iter()
                .find(|c| c.name == export.name)
                .ok_or("export missing")?;
            let hyper_component_config::CapabilityType::Object { rights, .. } = cap.kind else {
                return Err("not an object export".into());
            };
            let required = rights | Rights::DUPLICATE.bits() | Rights::TRANSFER.bits();
            if slots.get(&key).is_none_or(|actual| required & !actual != 0) {
                return Err(format!(
                    "{}:{}: offered inventory cannot supply export rights",
                    export.realm, export.name
                ));
            }
        }
        Ok(())
    }
    pub fn launch_manifest(&self) -> Result<String, String> {
        let mut fleet = None;
        let mut services = Vec::new();
        for app in &self.policy.applications {
            if let Some(path) = &app.fleet
                && fleet.replace(path).is_some()
            {
                return Err("multiple fleet configurations".into());
            }
            services.push(serde_json::json!({"name":app.component, "image":self.program(&app.component)?.image,
                "critical":app.critical,"restart":"never","phase":"system","after":[],"capabilities":app.capabilities}));
        }
        let mut value = serde_json::json!({"format":"hyper.service-manifest","services":services});
        if let Some(path) = fleet {
            value["virtual-machines"] = serde_json::json!({"config":path});
        }
        serde_json::to_string(&value).map_err(|e| e.to_string())
    }
}

fn exportable(source: &str) -> bool {
    matches!(
        source,
        "component.observe"
            | "component.control"
            | "bootstrap.root-directory"
            | "bootstrap.task-inspector"
            | "bootstrap.object-inspector"
            | "bootstrap.memory-inspector"
            | "bootstrap.cpu-inspector"
    )
}

#[cfg(test)]
#[path = "../tests/configuration.rs"]
mod tests;
