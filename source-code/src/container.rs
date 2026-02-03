use std::fs::{self, File};
use std::path::PathBuf;
use nix::sched::CloneFlags;
use nix::sys::signal::Signal;
use nix::sys::wait::waitpid;
use nix::unistd::Pid;
use owo_colors::OwoColorize;
use serde::{Deserialize, Serialize};

use crate::config::{HkConfig, Specs};
use crate::image::ImageManager;
use crate::sandbox::{setup_overlayfs, setup_cgroups, ChildConfig, child_entrypoint};
use crate::network::{setup_bridge, create_veth_pair, setup_port_forwarding, cleanup_port_forwarding};
use miette::{IntoDiagnostic, Result};

pub const HACKEROS_LIB: &str = "/var/lib/hackeros";
pub const HACKEROS_RUN: &str = "/var/run/hackeros";
pub const HACKEROS_LOG: &str = "/var/log/hackeros";
pub const CGROUP_ROOT: &str = "/sys/fs/cgroup/hackeros";

#[derive(Serialize, Deserialize, Debug)]
pub struct ContainerState {
    pub id: String,
    pub pid: i32,
    pub name: String,
    pub status: String,
    pub ip_address: Option<String>,
    pub bundle_path: String,
    pub ports: Vec<String>,
}

pub fn ensure_directories() -> Result<()> {
    fs::create_dir_all(HACKEROS_RUN).into_diagnostic()?;
    fs::create_dir_all(format!("{}/containers", HACKEROS_LIB)).into_diagnostic()?;
    Ok(())
}

pub fn start_container(config: HkConfig, detached: bool) -> Result<()> {
    ensure_directories()?;
    let container_id = uuid::Uuid::new_v4().to_string();
    
    // 1. Prepare Storage (Pull/Overlay)
    let layers = ImageManager::resolve_image_layers(&config.specs.base_image)?;
    let rootfs = setup_overlayfs(&container_id, &layers)?;
    setup_bridge("hkbr0", "10.10.0.1/24")?;

    // 2. Cgroups
    setup_cgroups(&container_id, &config.specs)?;

    // 3. Clone Process
    let stack = &mut [0; 2 * 1024 * 1024];
    let flags = CloneFlags::CLONE_NEWUTS | CloneFlags::CLONE_NEWPID | CloneFlags::CLONE_NEWNS | CloneFlags::CLONE_NEWNET | CloneFlags::CLONE_NEWIPC;

    let ip_suffix = (container_id.as_bytes()[0] as u8 % 250) + 2;
    
    let child_cfg = ChildConfig {
        rootfs: rootfs.clone(),
        hostname: config.metadata.name.clone(),
        ip_addr: format!("10.10.0.{}", ip_suffix),
        mounts: config.specs.mounts.clone(),
    };

    let cb = Box::new(move || child_entrypoint(child_cfg));
    let pid = unsafe { nix::sched::clone(cb, stack, flags, Some(Signal::SIGCHLD as i32)).into_diagnostic()? };

    // 4. Network Plumbing (Host Side)
    let (ip_addr, _veth_host) = create_veth_pair(pid, ip_suffix)?;
    setup_port_forwarding(&config.specs.port_mappings, &ip_addr)?;

    // 5. State
    let state = ContainerState {
        id: container_id.clone(),
        pid: pid.as_raw(),
        name: config.metadata.name.clone(),
        status: "Running".into(),
        ip_address: Some(ip_addr),
        bundle_path: rootfs.to_string_lossy().to_string(),
        ports: config.specs.port_mappings.clone(),
    };
    
    let state_file = File::create(format!("{}/{}.json", HACKEROS_RUN, container_id)).into_diagnostic()?;
    serde_json::to_writer_pretty(state_file, &state).into_diagnostic()?;

    println!("{} Started {} (PID: {})", "[OK]".bold().green(), config.metadata.name, pid);

    if !detached {
        waitpid(pid, None).into_diagnostic()?;
        cleanup_container(&state);
    }

    Ok(())
}

pub fn cleanup_container(state: &ContainerState) {
    cleanup_port_forwarding(&state.ports, state.ip_address.as_deref().unwrap_or(""));
    let _ = fs::remove_file(format!("{}/{}.json", HACKEROS_RUN, state.id));
    let _ = fs::remove_dir(format!("{}/{}", CGROUP_ROOT, state.id));
    let _ = nix::mount::umount2(&format!("{}/containers/{}/merged", HACKEROS_LIB, state.id), nix::mount::MntFlags::MNT_DETACH);
}

pub fn stop_container(id_prefix: &str) -> Result<()> {
    let (path, state) = find_container(id_prefix)?;
    println!("Stopping {}...", state.name);
    let _ = nix::sys::signal::kill(Pid::from_raw(state.pid), Signal::SIGTERM);
    
    cleanup_container(&state);
    let _ = fs::remove_file(path);
    Ok(())
}

pub fn find_container(prefix: &str) -> Result<(PathBuf, ContainerState)> {
    let paths = fs::read_dir(HACKEROS_RUN).into_diagnostic()?;
    for path in paths {
        let path = path.into_diagnostic()?.path();
        if path.extension().map_or(false, |e| e == "json") {
            let content = fs::read_to_string(&path).into_diagnostic()?;
            if let Ok(state) = serde_json::from_str::<ContainerState>(&content) {
                if state.id.starts_with(prefix) || state.name == prefix {
                    return Ok((path, state));
                }
            }
        }
    }
    Err(miette::miette!("Container not found: {}", prefix))
}
