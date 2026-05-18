use std::fs::{self, File};
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

use nix::sched::CloneFlags;
use nix::sys::signal::{kill, Signal};
use nix::sys::wait::{waitpid, WaitPidFlag};
use nix::unistd::Pid;
use owo_colors::OwoColorize;
use miette::{IntoDiagnostic, WrapErr, Result};
use tracing::{error, info, warn};

use crate::config::HkConfig;
use crate::db::{self, ContainerRow};
use crate::image::ImageManager;
use crate::logging::ContainerLogger;
use crate::metrics::{record_container_started, record_container_stopped};
use crate::network::{
    cleanup_port_forwarding, create_veth_pair, setup_bridge, setup_cni,
    setup_port_forwarding,
};
use crate::sandbox::{
    child_entrypoint, seccomp_setup, setup_cgroups, setup_namespaces,
    setup_overlayfs, ChildConfig,
};

pub const HACKEROS_LIB: &str = "/var/lib/hackeros";
pub const HACKEROS_RUN: &str = "/var/run/hackeros";
pub const HACKEROS_LOG: &str = "/var/log/hackeros";
pub const CGROUP_ROOT: &str = "/sys/fs/cgroup/hackeros";
pub const STATE_DB: &str = "/var/lib/hackeros/state.db";

// ── Directories ───────────────────────────────────────────────────────────────

pub fn ensure_directories() -> Result<()> {
    for dir in &[
        HACKEROS_RUN,
        &format!("{}/containers", HACKEROS_LIB),
        &format!("{}/images", HACKEROS_LIB),
        &format!("{}/layers", HACKEROS_LIB),
        HACKEROS_LOG,
        CGROUP_ROOT,
        &format!("{}/pods", HACKEROS_RUN),
    ] {
        fs::create_dir_all(dir).into_diagnostic()?;
    }
    Ok(())
}

// ── Rollback guard ────────────────────────────────────────────────────────────

struct StartResources {
    container_id: String,
    rootfs_mounted: bool,
    cgroups_created: bool,
    veth_host: Option<String>,
    port_rules: Vec<String>,
    ip_address: Option<String>,
    db_inserted: bool,
}

impl StartResources {
    fn new(id: &str) -> Self {
        Self {
            container_id: id.to_string(),
            rootfs_mounted: false,
            cgroups_created: false,
            veth_host: None,
            port_rules: vec![],
            ip_address: None,
            db_inserted: false,
        }
    }

    fn rollback(&self) {
        warn!(id = %&self.container_id[..8], "Rolling back failed container start");

        if !self.port_rules.is_empty() {
            cleanup_port_forwarding(
                &self.port_rules,
                self.ip_address.as_deref().unwrap_or(""),
            );
        }
        if let Some(veth) = &self.veth_host {
            let _ = std::process::Command::new("ip")
            .args(&["link", "del", veth])
            .status();
        }
        if self.rootfs_mounted {
            let merged = format!(
                "{}/containers/{}/merged",
                HACKEROS_LIB, self.container_id
            );
            let _ = nix::mount::umount2(
                Path::new(&merged),
                                        nix::mount::MntFlags::MNT_DETACH,
            );
        }
        let _ = fs::remove_dir_all(format!(
            "{}/containers/{}",
            HACKEROS_LIB, self.container_id
        ));
        if self.cgroups_created {
            let _ = fs::remove_dir_all(format!(
                "{}/{}",
                CGROUP_ROOT, self.container_id
            ));
        }
        if self.db_inserted {
            let _ = db::delete_container(&self.container_id);
        }
        let _ = db::ipam_release(&self.container_id);
    }
}

// ── Start ─────────────────────────────────────────────────────────────────────

pub fn start_container(config: HkConfig, detached: bool) -> Result<()> {
    let container_id = uuid::Uuid::new_v4().to_string();
    ensure_directories()?;

    let mut res = StartResources::new(&container_id);

    // Image layers
    let layers = ImageManager::resolve_image_layers(&config.specs.base_image)
    .map_err(|e| { res.rollback(); e })?;

    // Overlayfs
    let rootfs = setup_overlayfs(&container_id, &layers)
    .map_err(|e| { res.rollback(); e })?;
    res.rootfs_mounted = true;

    // Network bridge / CNI
    if config.runtime.network_mode == "bridge" {
        setup_bridge(&config.network.bridge_name, &config.network.gateway)
        .map_err(|e| { res.rollback(); e })?;
    } else if config.runtime.network_mode == "cni" {
        if let Some(net) = &config.runtime.cni_network {
            setup_cni(net, &container_id)
            .map_err(|e| { res.rollback(); e })?;
        }
    }

    // Cgroups
    setup_cgroups(&container_id, &config.specs)
    .map_err(|e| { res.rollback(); e })?;
    res.cgroups_created = true;

    // IPAM — allocate a unique IP from the pool
    let subnet_prefix = config
    .network
    .subnet
    .split('/')
    .next()
    .and_then(|s| s.rsplitn(2, '.').nth(1))
    .unwrap_or("10.10.0")
    .to_string();

    let ip_addr = if config.runtime.network_mode == "bridge" {
        db::ipam_allocate(&container_id, &subnet_prefix)
        .map_err(|e| { res.rollback(); e })?
    } else {
        "10.10.0.2".to_string()
    };

    // Clone child process
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

    let stack = &mut [0u8; 2 * 1024 * 1024];
    let cfg_ptr = Box::into_raw(Box::new(child_cfg));

    let cb = Box::new(move || {
        // SAFETY: cfg_ptr was created by Box::into_raw immediately above and
        // is consumed exactly once here. The parent never touches it again.
        let cfg = unsafe { Box::from_raw(cfg_ptr) };
        if let Err(e) = setup_namespaces(cfg.rootless) {
            eprintln!("namespace setup failed: {}", e);
            return 1;
        }
        if let Err(e) = seccomp_setup(&cfg.seccomp_profile) {
            eprintln!("seccomp setup failed: {}", e);
            return 1;
        }
        child_entrypoint(*cfg)
    });

    let pid = match unsafe {
        nix::sched::clone(cb, stack, flags, Some(Signal::SIGCHLD as i32))
    } {
        Ok(p) => p,
        Err(e) => {
            res.rollback();
            return Err(miette::miette!("clone() failed: {}", e));
        }
    };

    // Veth + port forwarding
    let (final_ip, veth_host_opt) = if config.runtime.network_mode == "bridge" {
        let suffix: u8 = ip_addr
        .split('.')
        .last()
        .and_then(|s| s.parse().ok())
        .unwrap_or(2);
        let (ip, veth_host) = create_veth_pair(pid, suffix)
        .map_err(|e| { res.rollback(); e })?;
        res.veth_host = Some(veth_host.clone());
        setup_port_forwarding(&config.specs.port_mappings, &ip)
        .map_err(|e| { res.rollback(); e })?;
        res.port_rules = config.specs.port_mappings.clone();
        res.ip_address = Some(ip.clone());
        (Some(ip), Some(veth_host))
    } else if config.runtime.network_mode == "cni" {
        (Some(ip_addr), None)
    } else {
        (None, None)
    };

    // Logger (100 MB limit, 3-file rotation)
    let logger =
    ContainerLogger::new(&container_id, 100 * 1024 * 1024).into_diagnostic()?;
    let logger_handle = logger.start_capture(pid);

    // Persist to DB (includes full config for future restarts)
    let config_json = serde_json::to_string(&config).unwrap_or_default();
    let ports_json =
    serde_json::to_string(&config.specs.port_mappings).unwrap_or_default();

    let row = ContainerRow {
        id: container_id.clone(),
        name: config.metadata.name.clone(),
        image: config.specs.base_image.clone(),
        pid: pid.as_raw(),
        status: "Running".into(),
        ip_address: final_ip.clone(),
        veth_host: veth_host_opt.clone(),
        bundle_path: rootfs.to_string_lossy().into_owned(),
        ports_json,
        pod_id: None,
        auto_restart: config.runtime.auto_restart,
        config_json,
        created_at: chrono::Utc::now(),
    };
    db::insert_container(&row).map_err(|e| { res.rollback(); e })?;
    res.db_inserted = true;

    record_container_started(&row);

    // Fix E0599: convert &str slice to String before calling .dimmed()
    let short_id = container_id[..8].to_string();
    info!(
        id = %short_id,
        name = %config.metadata.name,
        pid = pid.as_raw(),
          ip = ?final_ip,
          "Container started"
    );
    println!(
        "{} Started {} [{}] (PID: {}, IP: {})",
             "[OK]".bold().green(),
             config.metadata.name.cyan(),
             short_id.dimmed(),
             pid,
             final_ip.as_deref().unwrap_or("-"),
    );

    let auto_restart = config.runtime.auto_restart;

    if !detached {
        let _ = waitpid(pid, None);
        cleanup_container_by_row(&row);
        logger_handle.join().unwrap_or(());
        if auto_restart {
            info!(name = %config.metadata.name, "Auto-restarting");
            thread::sleep(Duration::from_secs(1));
            start_container(config, false)?;
        }
    } else if auto_restart {
        thread::spawn(move || {
            let _ = waitpid(pid, None);
            cleanup_container_by_row(&row);
            logger_handle.join().unwrap_or(());
            thread::sleep(Duration::from_secs(1));
            if let Err(e) = start_container(config, true) {
                error!("Auto-restart failed: {}", e);
            }
        });
    }

    Ok(())
}

// ── Cleanup ───────────────────────────────────────────────────────────────────

pub fn cleanup_container_by_row(row: &ContainerRow) {
    cleanup_port_forwarding(
        &row.ports(),
                            row.ip_address.as_deref().unwrap_or(""),
    );
    if let Some(veth) = &row.veth_host {
        let _ = std::process::Command::new("ip")
        .args(&["link", "del", veth])
        .status();
    }
    let _ = nix::mount::umount2(
        Path::new(&format!(
            "{}/containers/{}/merged",
            HACKEROS_LIB, row.id
        )),
        nix::mount::MntFlags::MNT_DETACH,
    );
    let _ = fs::remove_dir_all(format!("{}/containers/{}", HACKEROS_LIB, row.id));
    let _ = fs::remove_dir_all(format!("{}/{}", CGROUP_ROOT, row.id));
    let _ = db::ipam_release(&row.id);
    let _ = db::delete_container(&row.id);
    record_container_stopped(&row.id, &row.name);
}

// ── Stop ──────────────────────────────────────────────────────────────────────

pub fn stop_container(id_prefix: &str) -> Result<()> {
    let row = db::find_container(id_prefix)?;
    info!(name = %row.name, "Stopping container");
    println!("Stopping {}...", row.name.yellow());

    let pid = Pid::from_raw(row.pid);
    let _ = kill(pid, Signal::SIGTERM);

    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while std::time::Instant::now() < deadline {
        thread::sleep(Duration::from_millis(100));
        if waitpid(pid, Some(WaitPidFlag::WNOHANG)).is_ok() {
            break;
        }
    }
    let _ = kill(pid, Signal::SIGKILL);

    cleanup_container_by_row(&row);
    println!("{} Stopped {}", "[OK]".bold().green(), row.name.green());
    Ok(())
}

// ── Find ──────────────────────────────────────────────────────────────────────

pub fn find_container(prefix: &str) -> Result<ContainerRow> {
    db::find_container(prefix)
}

// ── Restart (used by API /containers/:id/start) ───────────────────────────────

pub fn restart_container(id_prefix: &str) -> Result<()> {
    let row = db::find_container(id_prefix)?;
    let config: HkConfig = serde_json::from_str(&row.config_json)
    .map_err(|e| miette::miette!("Cannot deserialise config for {}: {}", id_prefix, e))?;
    start_container(config, true)
}

// ── List (CLI) ────────────────────────────────────────────────────────────────

pub fn list_containers() -> Result<()> {
    ensure_directories()?;
    println!(
        "{}",
        format!(
            "{:<12} {:<20} {:<28} {:<10} {:<16} {}",
            "ID", "NAME", "IMAGE", "STATUS", "IP", "POD"
        )
            .bold()
            .underline()
    );

    let (rows, _) = db::list_containers_paged(1, 200)?;
    if rows.is_empty() {
        println!("{}", "No containers running.".dimmed());
        return Ok(());
    }
    for s in rows {
        let status_str = if s.status == "Running" {
            s.status.green().to_string()
        } else {
            s.status.yellow().to_string()
        };
        println!(
            "{:<12} {:<20} {:<28} {:<10} {:<16} {}",
            &s.id[..8],
            s.name.cyan().to_string(),
                 s.image,
                 status_str,
                 s.ip_address.as_deref().unwrap_or("-"),
                 s.pod_id.as_deref().unwrap_or("-"),
        );
    }
    Ok(())
}

// ── PTY enter ─────────────────────────────────────────────────────────────────

pub fn enter_container_pty(row: &ContainerRow) -> Result<()> {
    use nix::pty::openpty;
    use nix::unistd::{dup2, fork, setsid, ForkResult};
    use std::io::Write;
    use termion::raw::IntoRawMode;

    println!(
        "{} Entering {} (PTY)...",
             "[ENTER]".bold().green(),
             row.name.cyan()
    );

    let result = openpty(None, None).into_diagnostic()?;
    let master = result.master;
    let slave = result.slave;

    match unsafe { fork() } {
        Ok(ForkResult::Parent { .. }) => {
            let mut raw_stdout =
            std::io::stdout().into_raw_mode().into_diagnostic()?;
            let mut master_file =
            unsafe { File::from_raw_fd(master.as_raw_fd()) };
            let mut master_reader = master_file.try_clone().unwrap();

            thread::spawn(move || {
                let mut buf = [0u8; 1024];
                while let Ok(n) = master_reader.read(&mut buf) {
                    if n == 0 { break; }
                    let _ = raw_stdout.write_all(&buf[..n]);
                    let _ = raw_stdout.flush();
                }
            });

            let mut stdin = std::io::stdin();
            let mut buf = [0u8; 1024];
            while let Ok(n) = stdin.read(&mut buf) {
                if n == 0 { break; }
                if master_file.write_all(&buf[..n]).is_err() { break; }
            }
        }
        Ok(ForkResult::Child) => {
            attach_namespaces(row.pid)?;
            setsid().into_diagnostic()?;
            for i in 0..3i32 {
                dup2(slave.as_raw_fd(), i).into_diagnostic()?;
            }
            let cmd = std::ffi::CString::new("/bin/sh").unwrap();
            let _ = nix::unistd::execvp(&cmd, &[cmd.clone()]);
            std::process::exit(1);
        }
        Err(_) => return Err(miette::miette!("fork() failed")),
    }
    Ok(())
}

fn attach_namespaces(pid: i32) -> Result<()> {
    for ns in &["ipc", "uts", "net", "pid", "mnt"] {
        let p = format!("/proc/{}/ns/{}", pid, ns);
        let f = fs::File::open(&p)
        .into_diagnostic()
        .wrap_err_with(|| format!("Cannot open namespace {}", p))?;
        nix::sched::setns(f, nix::sched::CloneFlags::empty())
        .into_diagnostic()?;
    }
    Ok(())
}

// ── Stats ─────────────────────────────────────────────────────────────────────

pub fn show_stats(row: &ContainerRow) -> Result<()> {
    let cg_path = PathBuf::from(format!("{}/{}", CGROUP_ROOT, row.id));
    let mem: u64 = fs::read_to_string(cg_path.join("memory.current"))
    .ok()
    .and_then(|s| s.trim().parse().ok())
    .unwrap_or(0);
    let cpu_stat =
    fs::read_to_string(cg_path.join("cpu.stat")).unwrap_or_default();

    println!("{}", format!("── Stats: {} ──", row.name).bold());
    println!("  Memory : {:.2} MB", mem as f64 / 1_048_576.0);
    println!("  CPU:\n{}", cpu_stat);
    Ok(())
}

pub fn show_stats_loop(row: &ContainerRow) -> Result<()> {
    println!("Monitoring {} (Ctrl+C to stop)...", row.name.cyan());
    loop {
        print!("\x1B[H");
        show_stats(row)?;
        thread::sleep(Duration::from_secs(1));
    }
}
