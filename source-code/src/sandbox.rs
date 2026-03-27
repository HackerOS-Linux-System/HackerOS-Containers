use std::ffi::CString;
use std::fs;
use std::path::{Path, PathBuf};
use nix::mount::{mount, umount2, MntFlags, MsFlags};
use nix::sched::{unshare, CloneFlags};
use nix::unistd::{chdir, pivot_root, sethostname, execve, setuid, setgid, Uid, Gid};
use miette::{IntoDiagnostic, WrapErr, Result};

use crate::container::{HACKEROS_LIB, CGROUP_ROOT};
use crate::config::Specs;
use crate::seccomp::apply_seccomp;

pub struct ChildConfig {
    pub rootfs: PathBuf,
    pub hostname: String,
    pub ip_addr: String,
    pub mounts: Vec<String>,
    pub env: Vec<String>,
    pub cmd: Vec<String>,
    pub seccomp_profile: Option<String>,
    pub rootless: bool,
}

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
    if let Some(profile_path) = profile {
        apply_seccomp(profile_path)?;
    }
    Ok(())
}

pub fn child_entrypoint(config: ChildConfig) -> isize {
    crate::network::setup_container_interface(&config.ip_addr, "10.10.0.1");

    if let Err(e) = sethostname(&config.hostname) {
        eprintln!("Failed to set hostname: {}", e);
        return 1;
    }

    for mount_spec in &config.mounts {
        let parts: Vec<&str> = mount_spec.split(':').collect();
        if parts.len() >= 2 {
            let host_path = Path::new(parts[0]);
            let target_path = config.rootfs.join(parts[1].trim_start_matches('/'));
            if let Err(e) = fs::create_dir_all(&target_path) {
                eprintln!("Failed to create target dir for mount: {}", e);
                continue;
            }
            if let Err(e) = mount(
                Some(host_path),
                                  &target_path,
                                  None::<&str>,
                                  MsFlags::MS_BIND | MsFlags::MS_REC,
                                  None::<&str>,
            ) {
                eprintln!("Failed to bind mount {} -> {}: {}", host_path.display(), target_path.display(), e);
            }
        }
    }

    let old_root = config.rootfs.join(".old_root");
    if let Err(e) = fs::create_dir_all(&old_root) {
        eprintln!("Failed to create old_root: {}", e);
        return 1;
    }
    if let Err(e) = mount(
        Some(&config.rootfs),
                          &config.rootfs,
                          None::<&str>,
                          MsFlags::MS_BIND | MsFlags::MS_REC,
                          None::<&str>,
    ) {
        eprintln!("Failed to bind mount rootfs: {}", e);
        return 1;
    }
    if let Err(e) = pivot_root(&config.rootfs, &old_root) {
        eprintln!("Pivot root failed: {}", e);
        return 1;
    }
    if let Err(e) = chdir("/") {
        eprintln!("Chdir failed: {}", e);
        return 1;
    }

    let _ = fs::create_dir_all("/proc");
    let _ = mount(Some("proc"), "/proc", Some("proc"), MsFlags::empty(), None::<&str>);
    let _ = fs::create_dir_all("/sys");
    let _ = mount(Some("sysfs"), "/sys", Some("sysfs"), MsFlags::empty(), None::<&str>);
    let _ = fs::create_dir_all("/dev");
    let _ = mount(Some("devtmpfs"), "/dev", Some("devtmpfs"), MsFlags::empty(), None::<&str>);

    let _ = umount2(Path::new("/.old_root"), MntFlags::MNT_DETACH);
    let _ = fs::remove_dir("/.old_root");

    for env_var in &config.env {
        let parts: Vec<&str> = env_var.splitn(2, '=').collect();
        if parts.len() == 2 {
            std::env::set_var(parts[0], parts[1]);
        }
    }

    let cmd_str = if config.cmd.is_empty() {
        "/bin/sh"
    } else {
        &config.cmd[0]
    };
    let cmd = match CString::new(cmd_str) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Invalid command: {}", e);
            return 1;
        }
    };
    let args: Vec<CString> = config.cmd
    .iter()
    .map(|s| CString::new(s.as_str()).unwrap_or_else(|_| CString::new("").unwrap()))
    .collect();
    let env = [
        CString::new("PATH=/bin:/usr/bin:/sbin").unwrap(),
        CString::new("TERM=xterm-256color").unwrap(),
    ];

    let _ = execve(&cmd, &args, &env);
    eprintln!("Failed to execute {}", cmd_str);
    1
}

pub fn setup_overlayfs(container_id: &str, layers: &[PathBuf]) -> Result<PathBuf> {
    let base_dir = PathBuf::from(format!("{}/containers/{}", HACKEROS_LIB, container_id));
    let upper_dir = base_dir.join("upper");
    let work_dir = base_dir.join("work");
    let merged_dir = base_dir.join("merged");

    fs::create_dir_all(&upper_dir).into_diagnostic()?;
    fs::create_dir_all(&work_dir).into_diagnostic()?;
    fs::create_dir_all(&merged_dir).into_diagnostic()?;

    let lowerdir_str = layers.iter().rev()
    .map(|p| p.to_string_lossy().into_owned())
    .collect::<Vec<String>>()
    .join(":");

    let mount_opts = format!("lowerdir={},upperdir={},workdir={}", lowerdir_str, upper_dir.display(), work_dir.display());

    mount(Some("overlay"), &merged_dir, Some("overlay"), MsFlags::empty(), Some(mount_opts.as_str()))
    .into_diagnostic()?;

    Ok(merged_dir)
}

pub fn setup_cgroups(container_id: &str, specs: &Specs) -> Result<()> {
    let cgroup_path = PathBuf::from(format!("{}/{}", CGROUP_ROOT, container_id));
    if !cgroup_path.exists() {
        fs::create_dir_all(&cgroup_path).into_diagnostic()?;
    }

    if let Some(mem) = &specs.memory_limit {
        let bytes = crate::utils::parse_bytes(mem);
        fs::write(cgroup_path.join("memory.max"), bytes.to_string())
        .ok();
    }

    if let Some(cpu) = specs.cpu_percent {
        let quota = (cpu as u64) * 1000;
        fs::write(cgroup_path.join("cpu.max"), format!("{} 100000", quota))
        .ok();
    }

    let pid = nix::unistd::Pid::this();
    fs::write(cgroup_path.join("cgroup.procs"), pid.as_raw().to_string())
    .into_diagnostic()?;

    Ok(())
}
