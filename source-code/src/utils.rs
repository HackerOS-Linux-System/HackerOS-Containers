use std::fs;
use std::path::Path;
use rand::Rng;

pub fn parse_bytes(s: &str) -> u64 {
    let s = s.to_uppercase();
    if let Some(mb) = s.strip_suffix("MB") {
        mb.parse::<u64>().unwrap_or(0) * 1024 * 1024
    } else if let Some(gb) = s.strip_suffix("GB") {
        gb.parse::<u64>().unwrap_or(0) * 1024 * 1024 * 1024
    } else if let Some(kb) = s.strip_suffix("KB") {
        kb.parse::<u64>().unwrap_or(0) * 1024
    } else if let Some(b) = s.strip_suffix("B") {
        b.parse::<u64>().unwrap_or(0)
    } else {
        s.parse::<u64>().unwrap_or(0)
    }
}

pub fn random_mac() -> String {
    let mut rng = rand::thread_rng();
    let mac = [
        0x02, // locally administered
        rng.gen::<u8>(),
        rng.gen::<u8>(),
        rng.gen::<u8>(),
        rng.gen::<u8>(),
        rng.gen::<u8>(),
    ];
    mac.iter()
    .map(|b| format!("{:02x}", b))
    .collect::<Vec<_>>()
    .join(":")
}

pub fn file_exists(path: &Path) -> bool {
    path.exists() && path.is_file()
}

pub fn write_to_file(path: &Path, content: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, content)
}

pub fn read_file(path: &Path) -> std::io::Result<String> {
    fs::read_to_string(path)
}
