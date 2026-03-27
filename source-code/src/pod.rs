use std::process::Command;
use std::fs;
use std::path::PathBuf;
use serde::{Deserialize, Serialize};
use miette::{miette, IntoDiagnostic, Result};
use crate::container::{self, ContainerState, HACKEROS_RUN};
use crate::config::HkConfig;

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
            name: "default".to_string(),
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
        .map_err(|e| miette!("Failed to read pod spec file: {}", e))?;
        serde_yaml::from_str(&content)
        .map_err(|e| miette!("Failed to parse pod spec: {}", e))
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PodState {
    pub name: String,
    pub container_ids: Vec<String>,
    pub status: String,
    pub shared_network: bool,
    pub shared_pid: bool,
    pub shared_ipc: bool,
    pub netns_path: Option<String>,
}

pub fn pods_dir() -> PathBuf {
    PathBuf::from(HACKEROS_RUN).join("pods")
}

pub fn start_pod(name: &str, spec: PodSpec) -> Result<()> {
    let pod_state_path = pods_dir().join(format!("{}.json", name));
    if pod_state_path.exists() {
        return Err(miette!("Pod {} already exists", name));
    }

    let netns_path: Option<String>;
    let mut container_ids = Vec::new();

    if spec.shared_network {
        let netns = format!("/var/run/netns/pod-{}", name);
        fs::create_dir_all("/var/run/netns").ok();
        Command::new("ip")
        .args(&["netns", "add", &format!("pod-{}", name)])
        .status()
        .into_diagnostic()?;
        netns_path = Some(netns);
    } else {
        netns_path = None;
    }

    for mut container_cfg in spec.containers {
        container_cfg.metadata.name = format!("{}-{}", name, container_cfg.metadata.name);
        if spec.shared_network {
            container_cfg.runtime.network_mode = "none".to_string();
        }
        crate::container::start_container(container_cfg, true)?;
        let (_, state) = crate::container::find_container(&container_cfg.metadata.name)?;
        container_ids.push(state.id.clone());
    }

    let pod_state = PodState {
        name: name.to_string(),
        container_ids,
        status: "Running".to_string(),
        shared_network: spec.shared_network,
        shared_pid: spec.shared_pid,
        shared_ipc: spec.shared_ipc,
        netns_path,
    };

    let state_json = serde_json::to_string_pretty(&pod_state).into_diagnostic()?;
    fs::write(&pod_state_path, state_json).into_diagnostic()?;

    println!("Pod {} started with {} containers", name, pod_state.container_ids.len());
    Ok(())
}

pub fn stop_pod(name: &str) -> Result<()> {
    let pod_state_path = pods_dir().join(format!("{}.json", name));
    if !pod_state_path.exists() {
        return Err(miette!("Pod {} not found", name));
    }

    let content = fs::read_to_string(&pod_state_path).into_diagnostic()?;
    let pod_state: PodState = serde_json::from_str(&content).into_diagnostic()?;

    for id in &pod_state.container_ids {
        let _ = crate::container::stop_container(id);
    }

    if let Some(netns) = &pod_state.netns_path {
        let _ = Command::new("ip").args(&["netns", "del", netns]).status();
    }

    fs::remove_file(pod_state_path).into_diagnostic()?;

    println!("Pod {} stopped", name);
    Ok(())
}

pub fn list_pods() -> Result<()> {
    let pod_dir = pods_dir();
    if !pod_dir.exists() {
        println!("No pods found");
        return Ok(());
    }

    println!("{0: <20} {1: <10} {2: <15}", "NAME", "CONTAINERS", "STATUS");
    for entry in fs::read_dir(pod_dir).into_diagnostic()? {
        let entry = entry.into_diagnostic()?;
        let path = entry.path();
        if path.extension().map_or(false, |e| e == "json") {
            let content = fs::read_to_string(&path).into_diagnostic()?;
            if let Ok(state) = serde_json::from_str::<PodState>(&content) {
                println!(
                    "{0: <20} {1: <10} {2: <15}",
                    state.name,
                    state.container_ids.len(),
                         state.status
                );
            }
        }
    }
    Ok(())
}
