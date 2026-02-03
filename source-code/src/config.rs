use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use nom::{
    bytes::complete::{is_not, take_while},
    character::complete::{alphanumeric1, char, space0},
    combinator::recognize,
    multi::separated_list0,
    sequence::{delimited, preceded},
    IResult,
};
use miette::{miette, Result};

// --- CONFIG STRUCTS ---
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HkConfig {
    pub metadata: Metadata,
    pub description: Description,
    pub specs: Specs,
    pub runtime: Runtime,
    pub security: Security,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Metadata {
    pub name: String,
    pub version: String,
    pub authors: String,
    pub license: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Description {
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Specs {
    pub base_image: String,
    pub memory_limit: Option<String>,
    pub cpu_percent: Option<u64>,
    /// Format: "host_path:container_path:opts" (e.g. "/home/user:/home/user:rw")
    pub mounts: Vec<String>,
    /// Format: "host_port:container_port"
    pub port_mappings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Runtime {
    pub priority: Option<String>,
    pub auto_restart: bool,
    pub network_mode: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Security {
    pub drop_caps: Vec<String>,
    pub readonly_root: bool,
    pub allow_raw_sockets: bool,
    pub rootless: bool, // Support for user namespaces
}

impl Default for Security {
    fn default() -> Self {
        Self {
            drop_caps: vec!["CAP_SYS_ADMIN".to_string()],
            readonly_root: false,
            allow_raw_sockets: true,
            rootless: false,
        }
    }
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
            description: Description { summary: "Created via CLI".to_string() },
            specs: Specs {
                base_image: image.to_string(),
                memory_limit: None,
                cpu_percent: None,
                mounts,
                port_mappings: ports,
            },
            runtime: Runtime {
                priority: None,
                auto_restart: false,
                network_mode: "bridge".to_string(),
            },
            security: Security::default(),
        }
    }
}

// --- PARSER LOGIC (Simplified for brevity, same as before) ---

fn parse_section_header(input: &str) -> IResult<&str, &str> {
    delimited(char('['), take_while(|c| c != ']'), char(']'))(input)
}

fn parse_key_value(input: &str) -> IResult<&str, (String, String)> {
    let (input, key) = recognize(separated_list0(char('-'), alphanumeric1))(input)?;
    let (input, _) = delimited(space0, char('='), space0)(input)?;
    let (input, val) = take_while(|c| c != '\n' && c != '\r')(input)?;
    Ok((input, (key.to_string(), val.trim().trim_matches('"').to_string())))
}

pub fn parse_hk_file(input: &str) -> Result<HkConfig> {
    // Simplified parsing reconstruction
    let mut config_map: HashMap<String, HashMap<String, String>> = HashMap::new();
    let mut current_section = String::new();

    for line in input.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('!') { continue; }
        if let Ok((_, section)) = parse_section_header(line) {
            current_section = section.to_string();
            config_map.entry(current_section.clone()).or_default();
        } else if let Ok((_, (k, v))) = parse_key_value(line) {
            if let Some(section_map) = config_map.get_mut(&current_section) {
                section_map.insert(k, v);
            }
        }
    }
    
    // Map construction
    let meta = config_map.get("Metadata").ok_or(miette!("Missing Metadata"))?;
    let specs_map = config_map.get("Specs");
    
    // Parse mounts/ports from comma lists if in file (simplified)
    let mounts = specs_map.and_then(|m| m.get("mounts")).map(|s| s.split(',').map(|x| x.trim().to_string()).collect()).unwrap_or_default();

    Ok(HkConfig {
        metadata: Metadata { name: meta.get("name").unwrap_or(&"u".into()).clone(), ..Default::default() },
        description: Description::default(),
        specs: Specs {
            base_image: specs_map.and_then(|m| m.get("base-image")).cloned().unwrap_or("alpine".into()),
            memory_limit: specs_map.and_then(|m| m.get("memory")).cloned(),
            mounts,
            ..Default::default()
        },
        runtime: Runtime::default(),
        security: Security::default(),
    })
}
