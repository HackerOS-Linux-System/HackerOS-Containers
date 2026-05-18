use std::path::Path;
use miette::{miette, Result};
use regex::Regex;

pub fn validate_name(name: &str) -> Result<()> {
    if name.is_empty() { return Err(miette!("Name cannot be empty")); }
    if name.len() > 128 { return Err(miette!("Name too long (max 128 chars)")); }
    let re = Regex::new(r"^[a-zA-Z0-9_\-]+$").unwrap();
    if !re.is_match(name) {
        return Err(miette!("Invalid name '{}': only alphanumeric, dash, underscore allowed", name));
    }
    Ok(())
}

pub fn validate_image_ref(image: &str) -> Result<()> {
    if image.is_empty() { return Err(miette!("Image reference cannot be empty")); }
    if image.len() > 512 { return Err(miette!("Image reference too long")); }
    for ch in &['`', '$', ';', '&', '|', '>', '<', '(', ')', '{', '}', '\\'] {
        if image.contains(*ch) {
            return Err(miette!("Invalid character '{}' in image reference", ch));
        }
    }
    Ok(())
}

pub fn validate_mount(mount_spec: &str) -> Result<(String, String, Option<String>)> {
    let parts: Vec<&str> = mount_spec.splitn(3, ':').collect();
    if parts.len() < 2 {
        return Err(miette!("Invalid mount spec '{}': expected host:container", mount_spec));
    }
    let host_path = canonicalize_host_path(parts[0])?;
    let container_path = sanitize_container_path(parts[1])?;
    let options = parts.get(2).map(|s| s.to_string());

    let blocked = ["/proc", "/sys", "/dev", "/run/hackeros", "/etc/shadow", "/etc/passwd", "/root"];
    for b in &blocked {
        if host_path.starts_with(b) {
            return Err(miette!("Mount of sensitive path '{}' is not allowed", host_path));
        }
    }
    Ok((host_path, container_path, options))
}

fn canonicalize_host_path(path_str: &str) -> Result<String> {
    if path_str.is_empty() { return Err(miette!("Empty host path")); }
    let p = Path::new(path_str);
    if !p.is_absolute() { return Err(miette!("Mount host path must be absolute: '{}'", path_str)); }
    for c in p.components() {
        if matches!(c, std::path::Component::ParentDir) {
            return Err(miette!("Path traversal in host path: '{}'", path_str));
        }
    }
    Ok(path_str.to_string())
}

fn sanitize_container_path(path_str: &str) -> Result<String> {
    if path_str.is_empty() { return Err(miette!("Empty container path")); }
    let p = Path::new(path_str);
    for c in p.components() {
        if matches!(c, std::path::Component::ParentDir) {
            return Err(miette!("Path traversal in container path: '{}'", path_str));
        }
    }
    Ok(if p.is_absolute() { path_str.to_string() } else { format!("/{}", path_str) })
}

pub fn validate_port_mapping(port_spec: &str) -> Result<()> {
    let re = Regex::new(r"^(\d{1,5}):(\d{1,5})(/(?:tcp|udp))?$").unwrap();
    if !re.is_match(port_spec) {
        return Err(miette!("Invalid port mapping '{}': use host:container[/tcp|udp]", port_spec));
    }
    let parts: Vec<&str> = port_spec.split(':').collect();
    let hp: u16 = parts[0].parse().map_err(|_| miette!("Invalid host port in '{}'", port_spec))?;
    let cp_str = parts[1].split('/').next().unwrap_or(parts[1]);
    let cp: u16 = cp_str.parse().map_err(|_| miette!("Invalid container port in '{}'", port_spec))?;
    if hp == 0 || cp == 0 { return Err(miette!("Port numbers must be > 0")); }
    Ok(())
}

pub fn validate_env_var(env_spec: &str) -> Result<()> {
    let eq = env_spec.find('=').ok_or_else(|| miette!("Invalid env var '{}': must be KEY=VALUE", env_spec))?;
    let key = &env_spec[..eq];
    if key.is_empty() { return Err(miette!("Env var key cannot be empty")); }
    let re = Regex::new(r"^[A-Za-z_][A-Za-z0-9_]*$").unwrap();
    if !re.is_match(key) { return Err(miette!("Invalid env var key '{}'", key)); }
    Ok(())
}

pub fn validate_cni_network_name(name: &str) -> Result<()> {
    if name.is_empty() { return Err(miette!("CNI network name cannot be empty")); }
    let re = Regex::new(r"^[a-zA-Z0-9_\-]+$").unwrap();
    if !re.is_match(name) { return Err(miette!("Invalid CNI network name '{}'", name)); }
    Ok(())
}

pub fn validate_memory_limit(limit: &str) -> Result<()> {
    let re = Regex::new(r"^\d+(B|KB|MB|GB)$").unwrap();
    if !re.is_match(&limit.to_uppercase()) {
        return Err(miette!("Invalid memory limit '{}': use e.g. 512MB or 2GB", limit));
    }
    Ok(())
}

pub fn validate_cpu_percent(pct: u64) -> Result<()> {
    if pct == 0 || pct > 100 {
        return Err(miette!("cpu_percent must be 1-100, got {}", pct));
    }
    Ok(())
}
