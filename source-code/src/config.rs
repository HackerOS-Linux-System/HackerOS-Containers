use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use miette::{miette, IntoDiagnostic, WrapErr, Result};
use serde::{Deserialize, Serialize};

// ── Top-level config ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HkConfig {
    pub metadata: Metadata,
    pub specs:    Specs,
    pub runtime:  Runtime,
    pub security: Security,
    pub network:  NetworkConfig,
}

// ── Sections ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Metadata {
    pub name:    String,
    pub version: String,
    pub authors: String,
    pub license: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Specs {
    pub base_image:    String,
    pub memory_limit:  Option<String>,
    pub cpu_percent:   Option<u64>,
    pub mounts:        Vec<String>,
    pub port_mappings: Vec<String>,
    pub env:           Vec<String>,
    pub cmd:           Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Runtime {
    pub auto_restart:  bool,
    pub network_mode:  String,
    pub cni_network:   Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Security {
    pub drop_caps:       Vec<String>,
    pub readonly_root:   bool,
    pub allow_raw_sockets: bool,
    pub rootless:        bool,
    pub seccomp_profile: Option<String>,
}

impl Default for Security {
    fn default() -> Self {
        Self {
            drop_caps:         vec!["CAP_SYS_ADMIN".to_string()],
            readonly_root:     false,
            allow_raw_sockets: true,
            rootless:          false,
            seccomp_profile:   None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NetworkConfig {
    pub bridge_name: String,
    pub subnet:      String,
    pub gateway:     String,
    pub ip_range:    String,
    pub dns_servers: Vec<String>,
}

// ── Factory methods ───────────────────────────────────────────────────────────

impl HkConfig {
    /// Build a minimal ephemeral config (used by CLI `hco run`).
    pub fn create_ephemeral(
        name: &str,
        image: &str,
        mounts: Vec<String>,
        ports: Vec<String>,
    ) -> Self {
        HkConfig {
            metadata: Metadata {
                name:    name.to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                authors: String::new(),
                license: String::new(),
            },
            specs: Specs {
                base_image:    image.to_string(),
                memory_limit:  None,
                cpu_percent:   None,
                mounts,
                port_mappings: ports,
                env:           vec![],
                cmd:           vec![],
            },
            runtime: Runtime {
                auto_restart: false,
                network_mode: "bridge".to_string(),
                cni_network:  None,
            },
            security: Security::default(),
            network: NetworkConfig {
                bridge_name: "hkbr0".to_string(),
                subnet:      "10.10.0.0/24".to_string(),
                gateway:     "10.10.0.1".to_string(),
                ip_range:    "10.10.0.2-10.10.0.254".to_string(),
                dns_servers: vec![],
            },
        }
    }

    /// Parse from a `.hk` config file on disk.
    pub fn from_file(path: PathBuf) -> Result<Self> {
        let content = fs::read_to_string(&path)
        .into_diagnostic()
        .wrap_err_with(|| format!("Cannot read config file: {}", path.display()))?;
        parse_hk_file(&content)
    }
}

// ── .hk file parser ───────────────────────────────────────────────────────────

fn parse_hk_file(input: &str) -> Result<HkConfig> {
    let mut sections: HashMap<String, HashMap<String, String>> = HashMap::new();
    let mut current = String::new();

    for line in input.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('!') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            current = line[1..line.len() - 1].to_string();
            sections.entry(current.clone()).or_default();
        } else if let Some(eq) = line.find('=') {
            let key   = line[..eq].trim().to_string();
            let value = line[eq + 1..].trim().trim_matches('"').to_string();
            if let Some(map) = sections.get_mut(&current) {
                map.insert(key, value);
            }
        }
    }

    let metadata = sections
    .get("Metadata")
    .ok_or_else(|| miette!("Missing [Metadata] section"))?;

    let empty = HashMap::new();
    let specs_map    = sections.get("Specs").unwrap_or(&empty);
    let runtime_map  = sections.get("Runtime").unwrap_or(&empty);
    let security_map = sections.get("Security").unwrap_or(&empty);
    let network_map  = sections.get("Network").unwrap_or(&empty);

    let csv = |map: &HashMap<String, String>, key: &str| -> Vec<String> {
        map.get(key)
        .map(|s| s.split(',').map(|x| x.trim().to_string()).filter(|s| !s.is_empty()).collect())
        .unwrap_or_default()
    };

    Ok(HkConfig {
        metadata: Metadata {
            name:    metadata.get("name").cloned().unwrap_or_else(|| "unknown".into()),
       version: metadata.get("version").cloned().unwrap_or_else(|| "0.3.0".into()),
       authors: metadata.get("authors").cloned().unwrap_or_default(),
       license: metadata.get("license").cloned().unwrap_or_default(),
        },
       specs: Specs {
           base_image:    specs_map.get("base_image").cloned().unwrap_or_else(|| "alpine:latest".into()),
       memory_limit:  specs_map.get("memory_limit").cloned(),
       cpu_percent:   specs_map.get("cpu_percent").and_then(|s| s.parse().ok()),
       mounts:        csv(specs_map, "mounts"),
       port_mappings: csv(specs_map, "port_mappings"),
       env:           csv(specs_map, "env"),
       cmd:           csv(specs_map, "cmd"),
       },
       runtime: Runtime {
           auto_restart: runtime_map.get("auto_restart").map(|s| s == "true").unwrap_or(false),
       network_mode: runtime_map.get("network_mode").cloned().unwrap_or_else(|| "bridge".into()),
       cni_network:  runtime_map.get("cni_network").cloned(),
       },
       security: Security {
           drop_caps:         csv(security_map, "drop_caps"),
       readonly_root:     security_map.get("readonly_root").map(|s| s == "true").unwrap_or(false),
       allow_raw_sockets: security_map.get("allow_raw_sockets").map(|s| s != "false").unwrap_or(true),
       rootless:          security_map.get("rootless").map(|s| s == "true").unwrap_or(false),
       seccomp_profile:   security_map.get("seccomp_profile").cloned(),
       },
       network: NetworkConfig {
           bridge_name: network_map.get("bridge_name").cloned().unwrap_or_else(|| "hkbr0".into()),
       subnet:      network_map.get("subnet").cloned().unwrap_or_else(|| "10.10.0.0/24".into()),
       gateway:     network_map.get("gateway").cloned().unwrap_or_else(|| "10.10.0.1".into()),
       ip_range:    network_map.get("ip_range").cloned().unwrap_or_else(|| "10.10.0.2-10.10.0.254".into()),
       dns_servers: csv(network_map, "dns_servers"),
       },
    })
}
