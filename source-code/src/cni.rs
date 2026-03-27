use std::process::Command;
use std::fs;
use std::path::{Path, PathBuf};
use serde_json::Value;
use miette::{miette, IntoDiagnostic, WrapErr, Result};

pub struct CNI;

impl CNI {
    pub fn add(network_name: &str, container_id: &str, netns_path: &str) -> Result<String> {
        if !Path::new(netns_path).exists() {
            Command::new("ip")
            .args(&["netns", "add", container_id])
            .status()
            .into_diagnostic()
            .wrap_err("Failed to create network namespace")?;
        }

        let output = Command::new("cnitool")
        .args(&["add", network_name, netns_path])
        .output()
        .into_diagnostic()
        .wrap_err("Failed to execute cnitool add")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(miette!("CNI add failed: {}", stderr));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let json: Value = serde_json::from_str(&stdout)
        .map_err(|e| miette!("Failed to parse CNI output: {}", e))?;

        let ip = json["ips"]
        .as_array()
        .and_then(|ips| ips.first())
        .and_then(|ip| ip["address"].as_str())
        .map(|s| s.split('/').next().unwrap_or(s))
        .unwrap_or("")
        .to_string();

        Ok(ip)
    }

    pub fn del(network_name: &str, container_id: &str, netns_path: &str) -> Result<()> {
        let output = Command::new("cnitool")
        .args(&["del", network_name, netns_path])
        .output()
        .into_diagnostic()
        .wrap_err("Failed to execute cnitool del")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(miette!("CNI del failed: {}", stderr));
        }

        let _ = Command::new("ip").args(&["netns", "del", container_id]).status();
        Ok(())
    }

    pub fn list_networks() -> Result<Vec<String>> {
        let cni_dir = PathBuf::from("/etc/cni/net.d");
        if !cni_dir.exists() {
            return Ok(vec![]);
        }

        let mut networks = Vec::new();
        for entry in fs::read_dir(cni_dir).into_diagnostic()? {
            let entry = entry.into_diagnostic()?;
            let path = entry.path();
            if path.extension().map_or(false, |e| e == "conf" || e == "conflist") {
                let content = fs::read_to_string(&path).into_diagnostic()?;
                if let Ok(json) = serde_json::from_str::<Value>(&content) {
                    if let Some(name) = json["name"].as_str() {
                        networks.push(name.to_string());
                    }
                }
            }
        }
        Ok(networks)
    }
}
