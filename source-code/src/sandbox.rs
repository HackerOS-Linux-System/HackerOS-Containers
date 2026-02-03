use std::ffi::CString;
use std::fs;
use std::path::{Path, PathBuf};
use nix::mount::{mount, umount2, MntFlags, MsFlags};
use nix::sched::{CloneFlags, unshare};
use nix::unistd::{chdir, pivot_root, sethostname, execve};
use miette::{IntoDiagnostic, Result};
use crate::container::{HACKEROS_LIB, CGROUP_ROOT};
use crate::config::Specs;

pub struct ChildConfig {
    pub rootfs: PathBuf,
    pub hostname: String,
    pub ip_addr: String,
    pub mounts: Vec<String>,
}

pub fn child_entrypoint(config: ChildConfig) -> isize {
    // 1. Network setup is done inside via 'ip' commands calling system, 
    // but since we are in new net namespace, we need to do it here
    // However, 'ip' command might not exist in busybox if not in path yet.
    // We assume the parent configured the veth-pair, but the child 
    // side needs configuration. Since we pivoted, we rely on busybox or host tools mapped? 
    // *Simplified*: We run setup network BEFORE pivot root relying on host tools visible?
    // No, we are in a namespace. The 'mount' namespace is cloned. 
    // We typically use netlink logic here in pure Rust to avoid 'ip' binary dependency.
    // For this version, we assume /bin/ip exists in the rootfs or we static link it.
    // OR we just set it up via `crate::network::setup_container_interface`.
    
    crate::network::setup_container_interface(&config.ip_addr, "10.10.0.1");
    let _ = sethostname(&config.hostname);

    // 2. Custom Bind Mounts (e.g., -v /home:/home)
    for mount_spec in &config.mounts {
        // "host:target:opts"
        let parts: Vec<&str> = mount_spec.split(':').collect();
        if parts.len() >= 2 {
            let host_path = Path::new(parts[0]);
            let target_path = config.rootfs.join(parts[1].trim_start_matches('/'));
            
            // Ensure target exists
            fs::create_dir_all(&target_path).unwrap_or(());
            
            // Bind
            mount(
                Some(host_path),
                &target_path,
                None::<&str>,
                MsFlags::MS_BIND | MsFlags::MS_REC,
                None::<&str>,
            ).expect("Failed to bind mount");
        }
    }

    // 3. Pivot Root
    let old_root = config.rootfs.join(".old_root");
    fs::create_dir_all(&old_root).unwrap_or(());
    mount(Some(&config.rootfs), &config.rootfs, None::<&str>, MsFlags::MS_BIND | MsFlags::MS_REC, None::<&str>).expect("Bind mount root failed");
    pivot_root(&config.rootfs, &old_root).expect("Pivot root failed");
    chdir("/").expect("Chdir failed");

    // 4. API Filesystems
    fs::create_dir_all("/proc").unwrap_or(());
    mount(Some("proc"), "/proc", Some("proc"), MsFlags::empty(), None::<&str>).unwrap_or(());
    fs::create_dir_all("/sys").unwrap_or(());
    mount(Some("sysfs"), "/sys", Some("sysfs"), MsFlags::empty(), None::<&str>).unwrap_or(());
    fs::create_dir_all("/dev").unwrap_or(());
    mount(Some("devtmpfs"), "/dev", Some("devtmpfs"), MsFlags::empty(), None::<&str>).unwrap_or(());

    umount2("/.old_root", MntFlags::MNT_DETACH).unwrap_or(());
    fs::remove_dir("/.old_root").unwrap_or(());

    // 5. Execute Shell
    let cmd = CString::new("/bin/sh").unwrap();
    let args = [CString::new("sh").unwrap()];
    let env = [CString::new("PATH=/bin:/usr/bin:/sbin").unwrap(), CString::new("TERM=xterm-256color").unwrap()];
    
    let _ = execve(&cmd, &args, &env);
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
    
    // Limits
    if let Some(mem) = &specs.memory_limit {
        fs::write(cgroup_path.join("memory.max"), parse_bytes(mem).to_string()).ok();
    }
    if let Some(cpu) = specs.cpu_percent {
        let quota = cpu * 1000;
        fs::write(cgroup_path.join("cpu.max"), format!("{} 100000", quota)).ok();
    }

    // Add current process (the child before pivot) to cgroup
    let pid = nix::unistd::Pid::this();
    fs::write(cgroup_path.join("cgroup.procs"), pid.as_raw().to_string()).into_diagnostic()?;
    Ok(())
}

fn parse_bytes(s: &str) -> u64 {
    let s = s.to_uppercase();
    if let Some(mb) = s.strip_suffix("MB") { mb.parse::<u64>().unwrap_or(0) * 1024 * 1024 }
    else { s.parse::<u64>().unwrap_or(0) }
  }
