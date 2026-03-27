use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::thread;
use nix::unistd::Pid;
use crate::container::HACKEROS_LOG;

pub struct ContainerLogger {
    container_id: String,
    log_file: File,
}

impl ContainerLogger {
    pub fn new(container_id: &str) -> std::io::Result<Self> {
        let log_path = PathBuf::from(HACKEROS_LOG).join(format!("{}.log", container_id));
        let log_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)?;
        Ok(ContainerLogger {
            container_id: container_id.to_string(),
           log_file,
        })
    }

    pub fn start_capture(self, pid: Pid) -> thread::JoinHandle<()> {
        thread::spawn(move || {
            let stdout_path = format!("/proc/{}/fd/1", pid);
            let stdout = match File::open(stdout_path) {
                Ok(f) => BufReader::new(f),
                      Err(_) => return,
            };
            let mut log_file = self.log_file;
            for line in stdout.lines() {
                if let Ok(line) = line {
                    let _ = writeln!(log_file, "[{}] {}", chrono::Utc::now(), line);
                }
            }
        })
    }
}
