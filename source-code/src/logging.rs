use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::thread;

use nix::unistd::Pid;
use tracing::warn;

use crate::container::HACKEROS_LOG;

const LOG_ROTATE_KEEP: u32 = 3;

pub struct ContainerLogger {
    container_id: String,
    log_path: PathBuf,
    max_bytes: u64,
}

impl ContainerLogger {
    pub fn new(container_id: &str, max_bytes: u64) -> std::io::Result<Self> {
        let log_path = PathBuf::from(HACKEROS_LOG).join(format!("{}.log", container_id));
        Ok(Self { container_id: container_id.to_string(), log_path, max_bytes })
    }

    pub fn start_capture(self, pid: Pid) -> thread::JoinHandle<()> {
        thread::spawn(move || {
            let stdout_path = format!("/proc/{}/fd/1", pid);
            let stdout = match File::open(&stdout_path) {
                Ok(f) => BufReader::new(f),
                      Err(e) => {
                          warn!(container = %&self.container_id[..8], "Cannot open {}: {}", stdout_path, e);
                          return;
                      }
            };

            let mut written: u64 = 0;
            let mut rot_count: u32 = 0;
            let mut log_file = match open_log(&self.log_path) {
                Ok(f) => f,
                      Err(e) => { warn!("Cannot open log: {}", e); return; }
            };

            for line in stdout.lines() {
                let line = match line { Ok(l) => l, Err(_) => break };
                let entry = format!("[{}] {}\n",
                                    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ"), line);
                let len = entry.len() as u64;

                if written + len > self.max_bytes {
                    if let Err(e) = rotate(&self.log_path, &mut rot_count) {
                        warn!("Log rotation failed: {}", e);
                        written = 0;
                        if let Ok(f) = File::create(&self.log_path) { log_file = f; }
                    } else {
                        written = 0;
                        match open_log(&self.log_path) { Ok(f) => log_file = f, Err(_) => break }
                    }
                }

                if log_file.write_all(entry.as_bytes()).is_err() { break; }
                written += len;
            }
        })
    }
}

fn open_log(path: &PathBuf) -> std::io::Result<File> {
    OpenOptions::new().create(true).append(true).open(path)
}

fn rotate(base: &PathBuf, count: &mut u32) -> std::io::Result<()> {
    let _ = fs::remove_file(rotated(base, LOG_ROTATE_KEEP));
    for i in (1..LOG_ROTATE_KEEP).rev() {
        let from = rotated(base, i);
        if from.exists() { fs::rename(&from, rotated(base, i + 1))?; }
    }
    if base.exists() { fs::rename(base, rotated(base, 1))?; }
    *count += 1;
    Ok(())
}

fn rotated(base: &PathBuf, n: u32) -> PathBuf {
    let name = base.file_name().unwrap_or_default().to_string_lossy().into_owned();
    let mut p = base.clone();
    p.set_file_name(format!("{}.{}", name, n));
    p
}
