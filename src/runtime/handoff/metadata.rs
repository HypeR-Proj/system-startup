// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Immutable handoff description travels separately from live authority.

use super::inventory::Slot;
use hyper_os::handle::VmoObject;
use hyper_os::memory::SnapshotVmo;
use hyper_os::startup::{Startup, StartupPurpose};
use serde::{Deserialize, Serialize};

pub(super) const SNAPSHOT: StartupPurpose<VmoObject> = StartupPurpose::new(0x8008_0002);
const MAX_OFFER_BYTES: usize = 32 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PreparedOffer {
    version: u32,
    pub(super) root_mount: u64,
    pub(super) boot_root: String,
    services: Vec<CoreService>,
    pub(super) storage_successor: Option<String>,
    pub(super) storage_ready: bool,
    pub(super) slots: Vec<Slot>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CoreService {
    name: String,
    image: String,
    critical: bool,
    provider: Option<String>,
}

impl PreparedOffer {
    pub(super) fn providers(&self) -> hyper_os::Result<[Option<usize>; 3]> {
        let mut indices = [None; 3];
        for (index, service) in self.services.iter().enumerate() {
            let Some(role) = &service.provider else {
                continue;
            };
            let slot = match role.as_str() {
                "console" => 0,
                "storage" => 1,
                "filesystem" => 2,
                _ => return Err(hyper_os::Error::InvalidResponse),
            };
            if indices[slot].replace(index).is_some() {
                return Err(hyper_os::Error::InvalidResponse);
            }
        }
        if indices[1].is_some() != self.storage_successor.is_some() {
            return Err(hyper_os::Error::InvalidResponse);
        }
        Ok(indices)
    }

    /// Reconstruct only supervisor labels. Bootstrap's launch configuration,
    /// dependency graph and capability-grant policy never cross this boundary.
    pub(super) fn supervision_manifest(&self) -> hyper_os::Result<String> {
        let services: Vec<_> = self
            .services
            .iter()
            .map(|service| {
                serde_json::json!({
                    "name": service.name,
                    "image": service.image,
                    "critical": service.critical,
                    "restart": "never",
                    "phase": "boot",
                    "after": [],
                    "capabilities": [],
                })
            })
            .collect();
        serde_json::to_string(&serde_json::json!({
            "format": "hyper.service-manifest",
            "services": services,
        }))
        .map_err(|_| hyper_os::Error::InvalidResponse)
    }

    pub(super) fn read(startup: &mut Startup<'_>) -> hyper_os::Result<Self> {
        let handle = startup.take(SNAPSHOT)?;
        let snapshot = SnapshotVmo::from_vmo(handle.as_handle_ref())?;
        let mut length = [0; 8];
        snapshot.read_exact_at(0, &mut length)?;
        let length = usize::try_from(u64::from_le_bytes(length))
            .map_err(|_| hyper_os::Error::InvalidResponse)?;
        if length > MAX_OFFER_BYTES {
            return Err(hyper_os::Error::InvalidResponse);
        }
        let mut bytes = vec![0; length];
        snapshot.read_exact_at(8, &mut bytes)?;
        let offer: Self =
            serde_json::from_slice(&bytes).map_err(|_| hyper_os::Error::InvalidResponse)?;
        if offer.version != 4 || offer.services.len() > crate::manifest::MAX_SERVICES {
            return Err(hyper_os::Error::InvalidResponse);
        }
        if offer.root_mount == 0
            || !offer.boot_root.starts_with('/')
            || offer.boot_root == "/"
            || offer.boot_root.as_bytes().contains(&0)
        {
            return Err(hyper_os::Error::InvalidResponse);
        }
        Ok(offer)
    }
}
