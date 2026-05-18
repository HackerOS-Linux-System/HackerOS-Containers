use std::fs;
use std::path::Path;
use rand::Rng;

pub fn parse_bytes(s: &str) -> u64 {
    let s = s.to_uppercase();
    if let Some(n) = s.strip_suffix("GB") { return n.parse::<u64>().unwrap_or(0) * 1_073_741_824; }
    if let Some(n) = s.strip_suffix("MB") { return n.parse::<u64>().unwrap_or(0) * 1_048_576; }
    if let Some(n) = s.strip_suffix("KB") { return n.parse::<u64>().unwrap_or(0) * 1_024; }
    if let Some(n) = s.strip_suffix('B')  { return n.parse::<u64>().unwrap_or(0); }
    s.parse::<u64>().unwrap_or(0)
}

pub fn random_mac() -> String {
    let mut rng = rand::thread_rng();
    let mac = [
        0x02u8,
        rng.gen(), rng.gen(), rng.gen(), rng.gen(), rng.gen(),
    ];
    mac.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(":")
}

pub fn write_to_file(path: &Path, content: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent() { fs::create_dir_all(parent)?; }
    fs::write(path, content)
}

pub fn read_file(path: &Path) -> std::io::Result<String> {
    fs::read_to_string(path)
}
