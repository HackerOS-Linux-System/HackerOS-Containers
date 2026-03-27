use std::fs::{self, File};
use std::io::Read;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

use nix::sched::CloneFlags;
use nix::sys::signal::{kill, Signal};
use nix::sys::wait::waitpid;
use nix::unistd::Pid;
use owo_colors::OwoColorize;
use serde::{Deserialize, Serialize};
use miette::{IntoDiagnostic, WrapErr, Result, Context};

use crate::config::HkConfig;
use crate::image::ImageManager;
use crate::sandbox::{setup_overlayfs, setup_cgroups, setup_namespaces, seccomp_setup, child_entrypoint, ChildConfig};
use crate::network::{setup_bridge, create_veth_pair, setup_port_forwarding, cleanup_port_forwarding, setup_cni};
use crate::logging::ContainerLogger;
use crate::metrics::record_container_metrics;
use crate::utils::parse_bytes;

pub const HACKEROS_LIB: &str = "/var/lib/hackeros";
pub const HACKEROS_RUN: &str = "/var/run/hackeros";
pub const HACKEROS_LOG: &str = "/var/log/hackeros";
pub const CGROUP_ROOT: &str = "/sys/fs/cgroup/hackeros";

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ContainerState {
    pub id: String,
    pub pid: i32,
    pub name: String,
    pub status: String,
    pub ip_address: Option<String>,
    pub bundle_path: String,
    pub ports: Vec<String>,
    pub pod_id: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub auto_restart: bool,
}

impl ContainerState {
    fn image(&self) -> String {
        "unknown".to_string()
    }
}

pub fn ensure_directories() -> Result<()> {
    fs::create_dir_all(HACKEROS_RUN).into_diagnostic()?;
    fs::create_dir_all(format!("{}/containers", HACKEROS_LIB)).into_diagnostic()?;
    fs::create_dir_all(HACKEROS_LOG).into_diagnostic()?;
    fs::create_dir_all(CGROUP_ROOT).into_diagnostic()?;
    Ok(())
}

pub fn start_container(config: HkConfig, detached: bool) -> Result<()> {
    let container_id = uuid::Uuid::new_v4().to_string();
    ensure_directories()?;

    let layers = ImageManager::resolve_image_layers(&config.specs.base_image)?;
    let rootfs = setup_overlayfs(&container_id, &layers)?;

    if config.runtime.network_mode == "bridge" {
        setup_bridge(&config.network.bridge_name, &config.network.gateway)?;
    } else if config.runtime.network_mode == "cni" {
        if let Some(net) = &config.runtime.cni_network {
            setup_cni(net, &container_id)?;
        }
    }

    setup_cgroups(&container_id, &config.specs)?;

    let ip_suffix = (container_id.as_bytes()[0] as u8 % 250) + 2;
    let ip_addr = if config.runtime.network_mode == "bridge" {
        format!("{}.{}", config.network.subnet.split('/').next().unwrap_or("10.10.0"), ip_suffix)
    } else {
        "10.10.0.2".to_string()
    };
    let child_cfg = ChildConfig {
        rootfs: rootfs.clone(),
        hostname: config.metadata.name.clone(),
        ip_addr: ip_addr.clone(),
        mounts: config.specs.mounts.clone(),
        env: config.specs.env.clone(),
        cmd: config.specs.cmd.clone(),
        seccomp_profile: config.security.seccomp_profile.clone(),
        rootless: config.security.rootless,
    };

    let mut flags = CloneFlags::CLONE_NEWUTS
    | CloneFlags::CLONE_NEWPID
    | CloneFlags::CLONE_NEWNS
    | CloneFlags::CLONE_NEWNET
    | CloneFlags::CLONE_NEWIPC;
    if config.security.rootless {
        flags |= CloneFlags::CLONE_NEWUSER;
    }

    let stack = &mut [0; 2 * 1024 * 1024];
    // Use a raw pointer to pass config (avoid closure move issues)
    let cfg_ptr = Box::into_raw(Box::new(child_cfg));
    let cb = Box::new(move || {
        // Reconstruct ChildConfig from raw pointer
        let cfg = unsafe { Box::from_raw(cfg_ptr) };
        if let Err(e) = setup_namespaces(cfg.rootless) {
            eprintln!("Namespace setup failed: {}", e);
            return 1;
        }
        if let Err(e) = seccomp_setup(&cfg.seccomp_profile) {
            eprintln!("Seccomp setup failed: {}", e);
            return 1;
        }
        child_entrypoint(*cfg)
    });

    let pid = unsafe {
        nix::sched::clone(cb, stack, flags, Some(Signal::SIGCHLD as i32))
        .into_diagnostic()
        .wrap_err("Failed to clone container process")?
    };

    let ip_address = if config.runtime.network_mode == "bridge" {
        let (ip, _) = create_veth_pair(pid, ip_suffix)?;
        setup_port_forwarding(&config.specs.port_mappings, &ip)?;
        Some(ip)
    } else if config.runtime.network_mode == "cni" {
        Some(ip_addr)
    } else {
        None
    };

    let logger = ContainerLogger::new(&container_id).into_diagnostic()?;
    let logger_handle = logger.start_capture(pid);

    let state = ContainerState {
        id: container_id.clone(),
        pid: pid.as_raw(),
        name: config.metadata.name.clone(),
        status: "Running".into(),
        ip_address,
        bundle_path: rootfs.to_string_lossy().to_string(),
        ports: config.specs.port_mappings.clone(),
        pod_id: None,
        created_at: chrono::Utc::now(),
        auto_restart: config.runtime.auto_restart,
    };
    let state_path = format!("{}/{}.json", HACKEROS_RUN, container_id);
    let state_file = File::create(&state_path).into_diagnostic()?;
    serde_json::to_writer_pretty(state_file, &state).into_diagnostic()?;

    println!("{} Started {} (PID: {})", "[OK]".bold().green(), config.metadata.name, pid);
    record_container_metrics(&state, true);

    if !detached {
        waitpid(pid, None).into_diagnostic()?;
        cleanup_container(&state);
        logger_handle.join().unwrap_or(());
        record_container_metrics(&state, false);
        if config.runtime.auto_restart {
            println!("Auto-restarting container {}...", state.name);
            thread::sleep(Duration::from_secs(1));
            start_container(config, detached)?;
        }
    } else if config.runtime.auto_restart {
        thread::spawn(move || {
            let _ = waitpid(pid, None);
            cleanup_container(&state);
            logger_handle.join().unwrap_or(());
            record_container_metrics(&state, false);
            thread::sleep(Duration::from_secs(1));
            let _ = start_container(config, true);
        });
    }

    Ok(())
}

pub fn cleanup_container(state: &ContainerState) {
    cleanup_port_forwarding(&state.ports, state.ip_address.as_deref().unwrap_or(""));
    let _ = fs::remove_file(format!("{}/{}.json", HACKEROS_RUN, state.id));
    let _ = fs::remove_dir_all(format!("{}/containers/{}/merged", HACKEROS_LIB, state.id));
    let _ = fs::remove_dir_all(format!("{}/containers/{}/upper", HACKEROS_LIB, state.id));
    let _ = fs::remove_dir_all(format!("{}/containers/{}/work", HACKEROS_LIB, state.id));
    let _ = nix::mount::umount2(Path::new(&format!("{}/containers/{}/merged", HACKEROS_LIB, state.id)), nix::mount::MntFlags::MNT_DETACH);
    let _ = fs::remove_dir_all(format!("{}/{}", CGROUP_ROOT, state.id));
}

pub fn stop_container(id_prefix: &str) -> Result<()> {
    let (path, state) = find_container(id_prefix)?;
    println!("Stopping {}...", state.name);
    let _ = kill(Pid::from_raw(state.pid), Signal::SIGTERM);
    thread::sleep(Duration::from_secs(5));
    let _ = kill(Pid::from_raw(state.pid), Signal::SIGKILL);
    cleanup_container(&state);
    let _ = fs::remove_file(path);
    Ok(())
}

pub fn find_container(prefix: &str) -> Result<(PathBuf, ContainerState)> {
    let paths = fs::read_dir(HACKEROS_RUN).into_diagnostic()?;
    for entry in paths {
        let path = entry.into_diagnostic()?.path();
        if path.extension().map_or(false, |e| e == "json") {
            let content = fs::read_to_string(&path).into_diagnostic()?;
            if let Ok(state) = serde_json::from_str::<ContainerState>(&content) {
                if state.id.starts_with(prefix) || state.name == prefix {
                    return Ok((path, state));
                }
            }
        }
    }
    Err(miette::miette!("Container not found: {}", prefix))
}

pub fn list_containers() -> Result<()> {
    ensure_directories()?;
    println!("{0: <10} {1: <15} {2: <20} {3: <10} {4: <10}", "ID", "NAME", "IMAGE", "STATUS", "POD");
    for entry in fs::read_dir(HACKEROS_RUN).into_diagnostic()? {
        let path = entry.into_diagnostic()?.path();
        if path.extension().map_or(false, |e| e == "json") {
            let s: ContainerState = serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
            println!(
                "{0: <10} {1: <15} {2: <20} {3: <10} {4: <10}",
                &s.id[0..8],
                s.name.cyan(),
                     s.image(),
                     s.status.green(),
                     s.pod_id.as_deref().unwrap_or("-")
            );
        }
    }
    Ok(())
}

pub fn enter_container_pty(state: &ContainerState) -> Result<()> {
    use std::io::Write;
    use nix::pty::openpty;
    use nix::unistd::{fork, ForkResult, setsid, dup2};
    use termion::raw::IntoRawMode;

    println!("{} Entering {} (PTY)...", "[ENTER]".bold().green(), state.name);

    let result = openpty(None, None).into_diagnostic()?;
    let master = result.master;
    let slave = result.slave;

    match unsafe { fork() } {
        Ok(ForkResult::Parent { child: _ }) => {
            let mut raw_stdout = std::io::stdout().into_raw_mode().into_diagnostic()?;
            let mut master_file = unsafe { fs::File::from_raw_fd(master.as_raw_fd()) };
            let mut master_reader = master_file.try_clone().unwrap();

            thread::spawn(move || {
                let mut buf = [0; 1024];
                while let Ok(n) = master_reader.read(&mut buf) {
                    if n == 0 { break; }
                    let _ = raw_stdout.write_all(&buf[..n]);
                    let _ = raw_stdout.flush();
                }
            });

            let mut stdin = std::io::stdin();
            let mut buf = [0; 1024];
            while let Ok(n) = stdin.read(&mut buf) {
                if n == 0 { break; }
                if master_file.write_all(&buf[..n]).is_err() { break; }
            }
        }
        Ok(ForkResult::Child) => {
            attach_namespaces(state.pid)?;
            setsid().into_diagnostic()?;
            unsafe {
                for i in 0..3 {
                    dup2(slave.as_raw_fd(), i).into_diagnostic()?;
                }
            }
            let cmd = std::ffi::CString::new("/bin/sh").unwrap();
            let args = [cmd.clone()];
            let env = [std::ffi::CString::new("PATH=/bin:/usr/bin:/sbin").unwrap()];
            let _ = nix::unistd::execvp(&cmd, &args);
            std::process::exit(1);
        }
        Err(_) => return Err(miette::miette!("Fork failed")),
    }
    Ok(())
}

fn attach_namespaces(pid: i32) -> Result<()> {
    let pid_fd = nix::unistd::Pid::from_raw(pid);
    for ns in &["ipc", "uts", "net", "pid", "mnt"] {
        let p = format!("/proc/{}/ns/{}", pid_fd, ns);
        let f = fs::File::open(p).into_diagnostic().context("ns open")?;
        nix::sched::setns(f, nix::sched::CloneFlags::empty()).into_diagnostic()?;
    }
    Ok(())
}

pub fn show_stats_loop(state: &ContainerState) -> Result<()> {
    let cg_path = PathBuf::from(format!("{}/{}", CGROUP_ROOT, state.id));
    println!("Monitoring {} (Ctrl+C to stop)...", state.name.cyan());

    loop {
        print!("\x1B[2J\x1B[1;1H");
        println!("{} Stats", state.name.bold());
        println!("-------------------------");

        if let Ok(c) = fs::read_to_string(cg_path.join("memory.current")) {
            let bytes: u64 = c.trim().parse().unwrap_or(0);
            println!("Memory: {:.2} MB", bytes as f64 / 1024.0 / 1024.0);
        }

        if let Ok(c) = fs::read_to_string(cg_path.join("cpu.stat")) {
            println!("CPU Stat:\n{}", c);
        }

        thread::sleep(Duration::from_secs(1));
    }
}
