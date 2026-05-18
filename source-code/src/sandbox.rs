use std::ffi::CString;
use std::fs;
use std::path::{Path, PathBuf};

use miette::{IntoDiagnostic, WrapErr, Result};
use nix::mount::{mount, umount2, MntFlags, MsFlags};
use nix::sched::{unshare, CloneFlags};
use nix::unistd::{chdir, execve, pivot_root, sethostname, setgid, setuid, Gid, Uid};

use crate::config::Specs;
use crate::container::{CGROUP_ROOT, HACKEROS_LIB};
use crate::seccomp::apply_seccomp;

// ── Child config ──────────────────────────────────────────────────────────────

pub struct ChildConfig {
    pub rootfs:          PathBuf,
    pub hostname:        String,
    pub ip_addr:         String,
    pub mounts:          Vec<String>,
    pub env:             Vec<String>,
    pub cmd:             Vec<String>,
    pub seccomp_profile: Option<String>,
    pub rootless:        bool,
}

// ── Namespace setup (called in child before exec) ─────────────────────────────

pub fn setup_namespaces(rootless: bool) -> Result<()> {
    if rootless {
        unshare(CloneFlags::CLONE_NEWUSER).into_diagnostic()?;
        let uid = nix::unistd::getuid();
        let gid = nix::unistd::getgid();
        fs::write("/proc/self/uid_map", format!("0 {} 1", uid))
        .into_diagnostic()
        .wrap_err("Failed to write uid_map")?;
        fs::write("/proc/self/setgroups", "deny").ok();
        fs::write("/proc/self/gid_map", format!("0 {} 1", gid))
        .into_diagnostic()
        .wrap_err("Failed to write gid_map")?;
        setuid(Uid::from_raw(0)).into_diagnostic()?;
        setgid(Gid::from_raw(0)).into_diagnostic()?;
    }
    Ok(())
}

pub fn seccomp_setup(profile: &Option<String>) -> Result<()> {
    if let Some(path) = profile {
        apply_seccomp(path)?;
    }
    Ok(())
}

// ── Child entrypoint (runs inside new namespaces) ─────────────────────────────

pub fn child_entrypoint(config: ChildConfig) -> isize {
    // Set up network interface inside the container's netns
    crate::network::setup_container_interface(&config.ip_addr, "10.10.0.1");

    if let Err(e) = sethostname(&config.hostname) {
        eprintln!("sethostname failed: {}", e);
        return 1;
    }

    // Bind-mount host volumes into rootfs
    for spec in &config.mounts {
        let parts: Vec<&str> = spec.splitn(3, ':').collect();
        if parts.len() < 2 { continue; }
        let host   = Path::new(parts[0]);
        let target = config.rootfs.join(parts[1].trim_start_matches('/'));
        if let Err(e) = fs::create_dir_all(&target) {
            eprintln!("mkdir {:?}: {}", target, e);
            continue;
        }
        if let Err(e) = mount(
            Some(host), &target, None::<&str>,
                              MsFlags::MS_BIND | MsFlags::MS_REC, None::<&str>,
        ) {
            eprintln!("bind mount {} -> {:?}: {}", host.display(), target, e);
        }
    }

    // pivot_root
    let old_root = config.rootfs.join(".old_root");
    if let Err(e) = fs::create_dir_all(&old_root) {
        eprintln!("mkdir old_root: {}", e);
        return 1;
    }
    if let Err(e) = mount(
        Some(&config.rootfs), &config.rootfs, None::<&str>,
                          MsFlags::MS_BIND | MsFlags::MS_REC, None::<&str>,
    ) {
        eprintln!("bind rootfs: {}", e);
        return 1;
    }
    if let Err(e) = pivot_root(&config.rootfs, &old_root) {
        eprintln!("pivot_root: {}", e);
        return 1;
    }
    if let Err(e) = chdir("/") {
        eprintln!("chdir: {}", e);
        return 1;
    }

    // Mount essential pseudo-filesystems
    let _ = fs::create_dir_all("/proc");
    let _ = mount(Some("proc"),    "/proc", Some("proc"),    MsFlags::empty(), None::<&str>);
    let _ = fs::create_dir_all("/sys");
    let _ = mount(Some("sysfs"),   "/sys",  Some("sysfs"),   MsFlags::empty(), None::<&str>);
    let _ = fs::create_dir_all("/dev");
    let _ = mount(Some("devtmpfs"),"/dev",  Some("devtmpfs"), MsFlags::empty(), None::<&str>);
    let _ = fs::create_dir_all("/dev/pts");
    let _ = mount(Some("devpts"), "/dev/pts", Some("devpts"), MsFlags::empty(), None::<&str>);

    // Detach old root
    let _ = umount2(Path::new("/.old_root"), MntFlags::MNT_DETACH);
    let _ = fs::remove_dir("/.old_root");

    // Set environment variables
    for ev in &config.env {
        let mut parts = ev.splitn(2, '=');
        if let (Some(k), Some(v)) = (parts.next(), parts.next()) {
            std::env::set_var(k, v);
        }
    }

    // exec the command
    let cmd_str = config.cmd.first().map(|s| s.as_str()).unwrap_or("/bin/sh");
    let cmd = match CString::new(cmd_str) {
        Ok(c) => c,
        Err(e) => { eprintln!("Invalid command: {}", e); return 1; }
    };
    let args: Vec<CString> = if config.cmd.is_empty() {
        vec![cmd.clone()]
    } else {
        config.cmd.iter()
        .map(|s| CString::new(s.as_str()).unwrap_or_else(|_| CString::new("").unwrap()))
        .collect()
    };
    let env_c = [
        CString::new("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin").unwrap(),
        CString::new("TERM=xterm-256color").unwrap(),
    ];

    let _ = execve(&cmd, &args, &env_c);
    eprintln!("execve '{}' failed", cmd_str);
    1
}

// ── Overlayfs ─────────────────────────────────────────────────────────────────

pub fn setup_overlayfs(container_id: &str, layers: &[PathBuf]) -> Result<PathBuf> {
    let base     = PathBuf::from(format!("{}/containers/{}", HACKEROS_LIB, container_id));
    let upper    = base.join("upper");
    let work     = base.join("work");
    let merged   = base.join("merged");

    fs::create_dir_all(&upper).into_diagnostic()?;
    fs::create_dir_all(&work).into_diagnostic()?;
    fs::create_dir_all(&merged).into_diagnostic()?;

    let lowerdir = layers.iter().rev()
    .map(|p| p.to_string_lossy().into_owned())
    .collect::<Vec<_>>()
    .join(":");

    let opts = format!(
        "lowerdir={},upperdir={},workdir={}",
        lowerdir,
        upper.display(),
                       work.display()
    );

    mount(
        Some("overlay"), &merged, Some("overlay"),
          MsFlags::empty(), Some(opts.as_str()),
    )
    .into_diagnostic()
    .wrap_err("Failed to mount overlayfs")?;

    Ok(merged)
}

// ── Cgroups v2 ────────────────────────────────────────────────────────────────

pub fn setup_cgroups(container_id: &str, specs: &Specs) -> Result<()> {
    let cg = PathBuf::from(format!("{}/{}", CGROUP_ROOT, container_id));
    fs::create_dir_all(&cg).into_diagnostic()?;

    // Memory limit
    if let Some(mem) = &specs.memory_limit {
        let bytes = crate::utils::parse_bytes(mem);
        if bytes > 0 {
            fs::write(cg.join("memory.max"), bytes.to_string()).ok();
            // Also set swap to 0
            fs::write(cg.join("memory.swap.max"), "0").ok();
        }
    }

    // CPU quota: cpu_percent → microseconds per 100 ms period
    if let Some(pct) = specs.cpu_percent {
        let quota = (pct as u64) * 1_000; // e.g. 50% → 50000 µs
        fs::write(cg.join("cpu.max"), format!("{} 100000", quota)).ok();
    }

    // Add current process to cgroup
    let pid = nix::unistd::Pid::this();
    fs::write(cg.join("cgroup.procs"), pid.as_raw().to_string())
    .into_diagnostic()
    .wrap_err("Failed to write cgroup.procs")?;

    Ok(())
}
