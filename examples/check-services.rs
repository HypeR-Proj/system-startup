// SPDX-FileCopyrightText: 2026 roolrz
// SPDX-License-Identifier: Apache-2.0

//! Host admission using the component and startup production parsers and policy.
use hyper_system_startup::{bootstrap_policy::BootstrapPolicy, manifest, supervision};
use std::{env, fs, process::ExitCode};

fn check() -> Result<(), String> {
    let mut args = env::args().skip(1);
    let path = args
        .next()
        .ok_or("usage: check-services MANIFEST [ARCHIVE_PATH ...]")?;
    let mut core_path = None;
    let mut components = false;
    let mut startup_path = None;
    let mut images = Vec::new();
    while let Some(argument) = args.next() {
        if argument == "--components" {
            components = true;
        } else if argument == "--startup" {
            startup_path = Some(args.next().ok_or("--startup requires a path")?);
        } else if argument == "--core" {
            core_path = Some(args.next().ok_or("--core requires a manifest path")?);
        } else {
            images.push(argument);
        }
    }
    let text = if components {
        let mut documents = Vec::new();
        for entry in fs::read_dir(&path).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| "non-UTF8 filename")?;
            if name.ends_with(".json") {
                documents.push((name, fs::read(entry.path()).map_err(|e| e.to_string())?));
            }
        }
        let topology = hyper_component_config::Topology::parse("root", documents)?;
        for instance in &topology.instances {
            if let Some(program) = &instance.declaration.program
                && !images.is_empty()
                && !images
                    .iter()
                    .any(|p| p.trim_start_matches('/') == program.image.trim_start_matches('/'))
            {
                return Err(format!(
                    "{}: image {} is absent",
                    instance.path, program.image
                ));
            }
        }
        let policy = serde_json::from_slice(
            &fs::read(startup_path.ok_or("--startup is required")?).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        let config = hyper_system_startup::configuration::Configuration { topology, policy };
        config.validate()?;
        config.launch_manifest()?
    } else {
        fs::read_to_string(&path).map_err(|error| format!("{path}: {error}"))?
    };
    let system = manifest::parse(&text).map_err(|error| format!("{path}: {error:?}"))?;
    let core_text = core_path
        .as_ref()
        .map(fs::read_to_string)
        .transpose()
        .map_err(|error| error.to_string())?;
    let manifest = match core_text.as_ref() {
        Some(core) => manifest::parse(core)
            .map_err(|error| format!("core: {error:?}"))?
            .append_system(system)
            .ok_or("invalid boot/system service separation")?,
        None => system,
    };
    manifest::validate(&manifest, &BootstrapPolicy)
        .map_err(|error| format!("{path}: {error:?}"))?;
    supervision::validate(&manifest).map_err(|error| format!("{path}: {error:?}"))?;
    if !images.is_empty() {
        for service in manifest.services() {
            if !images.iter().any(|image| {
                image.trim_start_matches('/') == service.image().trim_start_matches('/')
            }) {
                return Err(format!(
                    "{path}: service {:?}: image {:?} is absent from the archive",
                    service.name(),
                    service.image()
                ));
            }
        }
    }
    Ok(())
}

fn main() -> ExitCode {
    match check() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("service manifest: {error}");
            ExitCode::FAILURE
        }
    }
}
