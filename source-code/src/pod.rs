use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use miette::{miette, IntoDiagnostic, Result};
use owo_colors::OwoColorize;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::config::HkConfig;
use crate::db::{self, PodRow};
use crate::validation::validate_name;

// ── DTOs ──────────────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PodSpec {
    pub name: String,
    pub containers: Vec<HkConfig>,
    pub shared_network: bool,
    pub shared_pid: bool,
    pub shared_ipc: bool,
}

impl Default for PodSpec {
    fn default() -> Self {
        Self {
            name: "default".into(),
            containers: vec![],
            shared_network: true,
            shared_pid: true,
            shared_ipc: true,
        }
    }
}

impl PodSpec {
    pub fn from_file(path: PathBuf) -> Result<Self> {
        let content = fs::read_to_string(&path)
        .into_diagnostic()
        .map_err(|e| miette!("Cannot read pod spec {:?}: {}", path, e))?;
        let spec: PodSpec = serde_yaml::from_str(&content)
        .map_err(|e| miette!("Cannot parse pod spec: {}", e))?;
        validate_name(&spec.name)?;
        Ok(spec)
    }
}

// ── Start ─────────────────────────────────────────────────────────────────────

pub fn start_pod(name: &str, spec: PodSpec) -> Result<()> {
    validate_name(name)?;

    if db::find_pod(name).is_ok() {
        return Err(miette!("Pod '{}' already exists", name));
    }

    // Create shared network namespace
    let netns_path: Option<String> = if spec.shared_network {
        let netns_name = format!("pod-{}", name);
        let netns = format!("/var/run/netns/{}", netns_name);
        fs::create_dir_all("/var/run/netns").ok();
        let out = Command::new("ip")
        .args(&["netns", "add", &netns_name])
        .output()
        .into_diagnostic()?;
        if !out.status.success() {
            warn!(
                "ip netns add {}: {}",
                netns_name,
                String::from_utf8_lossy(&out.stderr)
            );
        }
        Some(netns)
    } else {
        None
    };

    // Start pause process to hold shared namespaces
    let pause_pid: Option<u32> =
    if spec.shared_pid || spec.shared_ipc || spec.shared_network {
        Some(start_pause_process(name, netns_path.as_deref())?)
    } else {
        None
    };

    let mut container_ids: Vec<String> = Vec::new();
    let mut rollback_ids: Vec<String> = Vec::new();

    for mut cfg in spec.containers.iter().cloned() {
        let cname = format!("{}-{}", name, cfg.metadata.name);
        validate_name(&cname)?;
        cfg.metadata.name = cname.clone();

        if spec.shared_network {
            cfg.runtime.network_mode = "none".into();
        }

        match crate::container::start_container(cfg, true) {
            Ok(()) => {
                if let Ok(row) = db::find_container(&cname) {
                    rollback_ids.push(row.id.clone());
                    container_ids.push(row.id);
                }
            }
            Err(e) => {
                for rid in &rollback_ids {
                    let _ = crate::container::stop_container(rid);
                }
                if let Some(netns) = &netns_path {
                    cleanup_netns(netns);
                }
                if let Some(pid) = pause_pid {
                    let _ = nix::sys::signal::kill(
                        nix::unistd::Pid::from_raw(pid as i32),
                                                   nix::sys::signal::Signal::SIGKILL,
                    );
                }
                return Err(e);
            }
        }
    }

    let spec_json = serde_json::to_string(&spec).unwrap_or_default();
    let container_ids_json = serde_json::to_string(&container_ids).unwrap_or_default();

    db::insert_pod(&PodRow {
        name: name.to_string(),
                   container_ids_json,
                   status: "Running".into(),
                   shared_network: spec.shared_network,
                   shared_pid: spec.shared_pid,
                   shared_ipc: spec.shared_ipc,
                   netns_path,
                   spec_json,
                   created_at: chrono::Utc::now(),
    })?;

    info!(name, containers = container_ids.len(), "Pod started");
    println!(
        "{} Pod {} started ({} containers)",
             "[OK]".bold().green(),
             name.cyan(),
             container_ids.len()
    );
    Ok(())
}

// ── Pause process ─────────────────────────────────────────────────────────────

fn start_pause_process(pod_name: &str, netns: Option<&str>) -> Result<u32> {
    let pause_binary = "/usr/libexec/hco/pause";

    let child = if Path::new(pause_binary).exists() {
        let mut cmd = Command::new(pause_binary);
        cmd.arg(pod_name);
        if let Some(ns) = netns {
            cmd = pre_exec_netns(cmd, ns);
        }
        cmd.spawn()
        .into_diagnostic()
        .map_err(|e| miette!("Failed to start pause binary: {}", e))?
    } else {
        warn!(
            pod = pod_name,
            "pause binary not found at {}; using 'sleep infinity' fallback",
            pause_binary
        );
        Command::new("sleep")
        .arg("infinity")
        .spawn()
        .into_diagnostic()
        .map_err(|e| miette!("Failed to spawn pause fallback: {}", e))?
    };

    Ok(child.id())
}

#[cfg(target_os = "linux")]
fn pre_exec_netns(mut cmd: Command, netns: &str) -> Command {
    use std::os::unix::process::CommandExt;
    let netns = netns.to_string();
    unsafe {
        cmd.pre_exec(move || {
            let f = std::fs::File::open(&netns)?;
            nix::sched::setns(f, nix::sched::CloneFlags::CLONE_NEWNET)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
            Ok(())
        });
    }
    cmd
}

#[cfg(not(target_os = "linux"))]
fn pre_exec_netns(cmd: Command, _netns: &str) -> Command {
    cmd
}

// ── Stop ──────────────────────────────────────────────────────────────────────

pub fn stop_pod(name: &str) -> Result<()> {
    validate_name(name)?;
    let row = db::find_pod(name)?;

    let mut errors: Vec<String> = Vec::new();
    for id in row.container_ids() {
        if let Err(e) = crate::container::stop_container(&id) {
            errors.push(format!(
                "  container {}: {}",
                &id[..8.min(id.len())],
                                e
            ));
        }
    }

    if let Some(netns) = &row.netns_path {
        cleanup_netns(netns);
    }

    db::delete_pod(name)?;

    if errors.is_empty() {
        println!("{} Pod {} stopped", "[OK]".bold().green(), name.cyan());
        Ok(())
    } else {
        Err(miette!(
            "Pod {} stopped with errors:\n{}",
            name,
            errors.join("\n")
        ))
    }
}

// ── Restart ───────────────────────────────────────────────────────────────────

pub fn restart_pod(name: &str) -> Result<()> {
    validate_name(name)?;
    let row = db::find_pod(name)?;

    for id in row.container_ids() {
        match db::find_container(&id) {
            Ok(crow) if crow.status == "Running" => {
                info!(container = %id, "already running, skipping");
            }
            Ok(crow) => {
                if let Some(config) = crow.config() {
                    if let Err(e) = crate::container::start_container(config, true) {
                        warn!(container = %id, "restart failed: {}", e);
                    }
                } else {
                    warn!(container = %id, "cannot deserialise config, skipping");
                }
            }
            Err(_) => {
                warn!(container = %id, "container record gone, cannot restart");
            }
        }
    }

    println!("{} Pod {} restarted", "[OK]".bold().green(), name.cyan());
    Ok(())
}

// ── List (CLI) ────────────────────────────────────────────────────────────────

pub fn list_pods() -> Result<()> {
    let (rows, _) = db::list_pods_paged(1, 200)?;
    if rows.is_empty() {
        println!("{}", "No pods found.".dimmed());
        return Ok(());
    }
    println!(
        "{}",
        format!(
            "{:<24} {:<12} {:<10} {}",
            "NAME", "CONTAINERS", "STATUS", "CREATED"
        )
            .bold()
            .underline()
    );
    for r in rows {
        let ids: Vec<String> =
        serde_json::from_str(&r.container_ids_json).unwrap_or_default();
        println!(
            "{:<24} {:<12} {:<10} {}",
            r.name.cyan().to_string(),
                 ids.len(),
                 r.status.green().to_string(),
                 r.created_at.format("%Y-%m-%d %H:%M"),
        );
    }
    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn cleanup_netns(netns: &str) {
    let name = Path::new(netns)
    .file_name()
    .unwrap_or_default()
    .to_string_lossy()
    .into_owned();
    let _ = Command::new("ip").args(&["netns", "del", &name]).status();
}
