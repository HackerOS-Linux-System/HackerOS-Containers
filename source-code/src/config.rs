use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use serde::{Deserialize, Serialize};
use miette::{miette, IntoDiagnostic, WrapErr, Result};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HkConfig {
    pub metadata: Metadata,
    pub specs: Specs,
    pub runtime: Runtime,
    pub security: Security,
    pub network: NetworkConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Metadata {
    pub name: String,
    pub version: String,
    pub authors: String,
    pub license: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Specs {
    pub base_image: String,
    pub memory_limit: Option<String>,
    pub cpu_percent: Option<u64>,
    pub mounts: Vec<String>,
    pub port_mappings: Vec<String>,
    pub env: Vec<String>,
    pub cmd: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Runtime {
    pub auto_restart: bool,
    pub network_mode: String,
    pub cni_network: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Security {
    pub drop_caps: Vec<String>,
    pub readonly_root: bool,
    pub allow_raw_sockets: bool,
    pub rootless: bool,
    pub seccomp_profile: Option<String>,
}

impl Default for Security {
    fn default() -> Self {
        Self {
            drop_caps: vec!["CAP_SYS_ADMIN".to_string()],
            readonly_root: false,
            allow_raw_sockets: true,
            rootless: false,
            seccomp_profile: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NetworkConfig {
    pub bridge_name: String,
    pub subnet: String,
    pub gateway: String,
    pub ip_range: String,
    pub dns_servers: Vec<String>,
}

impl HkConfig {
    pub fn create_ephemeral(name: &str, image: &str, mounts: Vec<String>, ports: Vec<String>) -> Self {
        HkConfig {
            metadata: Metadata {
                name: name.to_string(),
                version: "0.0.1".to_string(),
                authors: "User".to_string(),
                license: "None".to_string(),
            },
            specs: Specs {
                base_image: image.to_string(),
                memory_limit: None,
                cpu_percent: None,
                mounts,
                port_mappings: ports,
                env: vec![],
                cmd: vec![],
            },
            runtime: Runtime {
                auto_restart: false,
                network_mode: "bridge".to_string(),
                cni_network: None,
            },
            security: Security::default(),
            network: NetworkConfig::default(),
        }
    }

    pub fn from_file(path: PathBuf) -> Result<Self> {
        let content = fs::read_to_string(&path)
        .into_diagnostic()
        .wrap_err_with(|| format!("Failed to read config file: {}", path.display()))?;
        parse_hk_file(&content)
    }
}

fn parse_hk_file(input: &str) -> Result<HkConfig> {
    let mut sections: HashMap<String, HashMap<String, String>> = HashMap::new();
    let mut current_section = String::new();

    for line in input.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('!') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            current_section = line[1..line.len() - 1].to_string();
            sections.entry(current_section.clone()).or_default();
        } else if let Some(eq_pos) = line.find('=') {
            let key = line[..eq_pos].trim().to_string();
            let value = line[eq_pos + 1..].trim().trim_matches('"').to_string();
            if let Some(map) = sections.get_mut(&current_section) {
                map.insert(key, value);
            }
        }
    }

    let metadata = sections.get("Metadata").ok_or_else(|| miette!("Missing [Metadata] section"))?;
    let specs_map = sections.get("Specs").unwrap_or(&HashMap::new());
    let runtime_map = sections.get("Runtime").unwrap_or(&HashMap::new());
    let security_map = sections.get("Security").unwrap_or(&HashMap::new());
    let network_map = sections.get("Network").unwrap_or(&HashMap::new());

    let mounts = specs_map
    .get("mounts")
    .map(|s| s.split(',').map(|x| x.trim().to_string()).collect())
    .unwrap_or_default();
    let port_mappings = specs_map
    .get("port_mappings")
    .map(|s| s.split(',').map(|x| x.trim().to_string()).collect())
    .unwrap_or_default();
    let env = specs_map
    .get("env")
    .map(|s| s.split(',').map(|x| x.trim().to_string()).collect())
    .unwrap_or_default();
    let cmd = specs_map
    .get("cmd")
    .map(|s| s.split(',').map(|x| x.trim().to_string()).collect())
    .unwrap_or_default();

    let memory_limit = specs_map.get("memory_limit").cloned();
    let cpu_percent = specs_map
    .get("cpu_percent")
    .and_then(|s| s.parse::<u64>().ok());

    let auto_restart = runtime_map
    .get("auto_restart")
    .map(|s| s == "true")
    .unwrap_or(false);
    let network_mode = runtime_map
    .get("network_mode")
    .cloned()
    .unwrap_or_else(|| "bridge".to_string());
    let cni_network = runtime_map.get("cni_network").cloned();

    let drop_caps = security_map
    .get("drop_caps")
    .map(|s| s.split(',').map(|x| x.trim().to_string()).collect())
    .unwrap_or_default();
    let readonly_root = security_map
    .get("readonly_root")
    .map(|s| s == "true")
    .unwrap_or(false);
    let allow_raw_sockets = security_map
    .get("allow_raw_sockets")
    .map(|s| s != "false")
    .unwrap_or(true);
    let rootless = security_map
    .get("rootless")
    .map(|s| s == "true")
    .unwrap_or(false);
    let seccomp_profile = security_map.get("seccomp_profile").cloned();

    let bridge_name = network_map
    .get("bridge_name")
    .cloned()
    .unwrap_or_else(|| "hkbr0".to_string());
    let subnet = network_map
    .get("subnet")
    .cloned()
    .unwrap_or_else(|| "10.10.0.0/24".to_string());
    let gateway = network_map
    .get("gateway")
    .cloned()
    .unwrap_or_else(|| "10.10.0.1".to_string());
    let ip_range = network_map
    .get("ip_range")
    .cloned()
    .unwrap_or_else(|| "10.10.0.2-10.10.0.254".to_string());
    let dns_servers = network_map
    .get("dns_servers")
    .map(|s| s.split(',').map(|x| x.trim().to_string()).collect())
    .unwrap_or_default();

    Ok(HkConfig {
        metadata: Metadata {
            name: metadata.get("name").cloned().unwrap_or_else(|| "unknown".to_string()),
       version: metadata.get("version").cloned().unwrap_or_else(|| "0.1".to_string()),
       authors: metadata.get("authors").cloned().unwrap_or_default(),
       license: metadata.get("license").cloned().unwrap_or_default(),
        },
       specs: Specs {
           base_image: specs_map.get("base_image").cloned().unwrap_or_else(|| "alpine:latest".to_string()),
       memory_limit,
       cpu_percent,
       mounts,
       port_mappings,
       env,
       cmd,
       },
       runtime: Runtime {
           auto_restart,
           network_mode,
           cni_network,
       },
       security: Security {
           drop_caps,
           readonly_root,
           allow_raw_sockets,
           rootless,
           seccomp_profile,
       },
       network: NetworkConfig {
           bridge_name,
           subnet,
           gateway,
           ip_range,
           dns_servers,
       },
    })
}
