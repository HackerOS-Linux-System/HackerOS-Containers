use std::collections::HashMap;
use std::ffi::CString;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

use lexopt::{Arg, Parser, ValueExt};
use miette::{miette, Context, IntoDiagnostic, Result};
use nix::mount::{mount, umount2, MntFlags, MsFlags};
use nix::sched::{clone, CloneFlags};
use nix::sys::signal::Signal;
use nix::sys::wait::waitpid;
use nix::unistd::{chdir, pivot_root, sethostname, Pid};
use owo_colors::OwoColorize;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

// --- NOM PARSER IMPORTS ---
use nom::{
    bytes::complete::{is_not, take_while},
    character::complete::{alphanumeric1, char, space0},
    combinator::recognize,
    multi::separated_list0,
    sequence::{delimited, preceded},
    IResult,
};

// --- CONSTANTS ---
const HACKEROS_LIB: &str = "/var/lib/hackeros";
const HACKEROS_RUN: &str = "/var/run/hackeros";
const CGROUP_ROOT: &str = "/sys/fs/cgroup/hackeros";

// --- ERRORS ---
#[derive(Debug, Error, miette::Diagnostic)]
#[error("HackerOS Container Error: {message}")]
struct ContainerError {
    message: String,
    #[help]
    help: Option<String>,
    #[source_code]
    source_code: String,
}

// --- CONFIG STRUCTS ---
#[derive(Debug, Clone, Serialize, Deserialize)]
struct HkConfig {
    metadata: Metadata,
    description: Description,
    specs: Specs,
    runtime: Runtime,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct Metadata {
    name: String,
    version: String,
    authors: String,
    license: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct Description {
    summary: String,
    long: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct Specs {
    base_image: String, // Renamed from rust/deps for clarity in new logic
    memory_limit: Option<String>,
    cpu_shares: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct Runtime {
    priority: Option<String>,
    auto_restart: bool,
    network_bridge: Option<String>,
}

// --- STATE MANAGEMENT ---
#[derive(Serialize, Deserialize, Debug)]
struct ContainerState {
    id: String,
    pid: i32,
    name: String,
    status: String,
    ip_address: Option<String>,
    bundle_path: String,
    start_time: u64,
}

// --- NOM PARSER IMPLEMENTATION ---

fn parse_comment(input: &str) -> IResult<&str, &str> {
    preceded(char('!'), is_not("\n"))(input)
}

fn parse_key_value(input: &str) -> IResult<&str, (String, String)> {
    let (input, key) = recognize(separated_list0(char('-'), alphanumeric1))(input)?;
    let (input, _) = delimited(space0, char('='), space0)(input)?;
    let (input, val) = take_while(|c| c != '\n' && c != '\r')(input)?;
    Ok((input, (key.to_string(), val.trim().trim_matches('"').to_string())))
}

fn parse_section_header(input: &str) -> IResult<&str, &str> {
    delimited(char('['), take_while(|c| c != ']'), char(']'))(input)
}

fn parse_hk_file(input: &str) -> Result<HkConfig> {
    let mut current_section = String::new();
    let mut config_map: HashMap<String, HashMap<String, String>> = HashMap::new();

    for line in input.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('!') {
            continue;
        }

        if let Ok((_, section)) = parse_section_header(line) {
            current_section = section.to_string();
            config_map.entry(current_section.clone()).or_default();
        } else if let Ok((_, (k, v))) = parse_key_value(line) {
            if let Some(section_map) = config_map.get_mut(&current_section) {
                section_map.insert(k, v);
            }
        }
    }

    // Map HashMap to Structs (Simplified mapping logic)
    let meta = config_map.get("Metadata").ok_or_else(|| miette!("Missing Metadata section"))?;
    let metadata = Metadata {
        name: meta.get("name").unwrap_or(&"unknown".to_string()).clone(),
        version: meta.get("version").unwrap_or(&"0.1.0".to_string()).clone(),
        authors: meta.get("authors").unwrap_or(&"".to_string()).clone(),
        license: meta.get("license").unwrap_or(&"MIT".to_string()).clone(),
    };

    let desc_map = config_map.get("Description");
    let description = Description {
        summary: desc_map.and_then(|m| m.get("summary")).cloned().unwrap_or_default(),
        long: vec![], // Simplified for this demo
    };

    let specs_map = config_map.get("Specs");
    let specs = Specs {
        base_image: specs_map.and_then(|m| m.get("base-image")).cloned().unwrap_or_else(|| "alpine-latest".to_string()),
        memory_limit: specs_map.and_then(|m| m.get("memory")).cloned(),
        cpu_shares: specs_map.and_then(|m| m.get("cpu")).and_then(|v| v.parse().ok()),
    };

    let run_map = config_map.get("Runtime");
    let runtime = Runtime {
        priority: run_map.and_then(|m| m.get("priority")).cloned(),
        auto_restart: run_map.and_then(|m| m.get("auto-restart")).map(|v| v == "true").unwrap_or(false),
        network_bridge: run_map.and_then(|m| m.get("bridge")).cloned(),
    };

    Ok(HkConfig { metadata, description, specs, runtime })
}

// --- CLI ---
enum CommandType {
    Run { config_path: PathBuf, detached: bool },
    List,
    Status { name: String },
    Help,
    Cleanup, // Internal dev helper
}

fn parse_args() -> Result<CommandType> {
    let mut parser = Parser::from_env();
    let mut config_path = None;
    let mut detached = false;

    while let Some(arg) = parser.next().into_diagnostic()? {
        match arg {
            Arg::Short('c') | Arg::Long("config") => {
                let val = parser.value().into_diagnostic()?.string().into_diagnostic()?;
                config_path = Some(PathBuf::from(val));
            }
            Arg::Short('d') | Arg::Long("detached") => {
                detached = true;
            }
            Arg::Long("list") => return Ok(CommandType::List),
            Arg::Long("cleanup") => return Ok(CommandType::Cleanup),
            Arg::Long("status") => {
                let name = parser.value().into_diagnostic()?.string().into_diagnostic()?;
                return Ok(CommandType::Status { name });
            }
            Arg::Short('h') | Arg::Long("help") => return Ok(CommandType::Help),
            Arg::Value(val) => {
                if config_path.is_none() {
                    let path_str = val.string().into_diagnostic()?;
                    config_path = Some(PathBuf::from(path_str));
                }
            }
            _ => return Err(miette!("Unknown argument: {:?}", arg)),
        }
    }

    if let Some(path) = config_path {
        Ok(CommandType::Run { config_path: path, detached })
    } else {
        Ok(CommandType::Help)
    }
}

// --- SYSTEM LOGIC ---

fn ensure_directories() -> Result<()> {
    fs::create_dir_all(format!("{}/containers", HACKEROS_LIB)).into_diagnostic()?;
    fs::create_dir_all(format!("{}/images", HACKEROS_LIB)).into_diagnostic()?;
    fs::create_dir_all(HACKEROS_RUN).into_diagnostic()?;
    Ok(())
}

fn download_image(image_name: &str) -> Result<PathBuf> {
    let image_path = PathBuf::from(format!("{}/images/{}", HACKEROS_LIB, image_name));

    if image_path.exists() {
        println!("{} Image {} already exists locally.", "[CACHE]".bold().blue(), image_name);
        return Ok(image_path);
    }

    println!("{} Downloading image: {}", "[NET]".bold().cyan(), image_name);

    // MOCK: In real life, fetch from registry. Here we create a dummy Alpine-like rootfs
    fs::create_dir_all(&image_path).into_diagnostic()?;

    // Simulate bin/sh
    let bin_dir = image_path.join("bin");
    fs::create_dir_all(&bin_dir).into_diagnostic()?;

    // Copy host busybox or sh to simulate a rootfs binary
    // NOTE: This assumes the host is Linux and has /bin/sh
    fs::copy("/bin/sh", bin_dir.join("sh")).into_diagnostic()
    .context("Failed to copy host /bin/sh to rootfs image. Is this Linux?")?;

    // Create other standard dirs
    for dir in &["proc", "sys", "dev", "tmp", "etc", "home"] {
        fs::create_dir_all(image_path.join(dir)).into_diagnostic()?;
    }

    println!("{} Image downloaded and extracted.", "[OK]".bold().green());
    Ok(image_path)
}

fn setup_overlayfs(container_id: &str, image_path: &Path) -> Result<PathBuf> {
    let base_dir = PathBuf::from(format!("{}/containers/{}", HACKEROS_LIB, container_id));
    let lower_dir = image_path;
    let upper_dir = base_dir.join("upper");
    let work_dir = base_dir.join("work");
    let merged_dir = base_dir.join("merged");

    fs::create_dir_all(&upper_dir).into_diagnostic()?;
    fs::create_dir_all(&work_dir).into_diagnostic()?;
    fs::create_dir_all(&merged_dir).into_diagnostic()?;

    let mount_opts = format!(
        "lowerdir={},upperdir={},workdir={}",
        lower_dir.display(),
                             upper_dir.display(),
                             work_dir.display()
    );

    mount(
        Some("overlay"),
          &merged_dir,
          Some("overlay"),
          MsFlags::empty(),
          Some(mount_opts.as_str()),
    ).into_diagnostic().context("Failed to mount OverlayFS")?;

    Ok(merged_dir)
}

fn setup_cgroups(container_id: &str, specs: &Specs) -> Result<()> {
    let cgroup_path = PathBuf::from(format!("{}/{}", CGROUP_ROOT, container_id));

    if !Path::new(CGROUP_ROOT).exists() {
        // Mock check for cgroup v2 mount, assume it exists or create simple dir structure for demo
        // In reality, this requires mounting cgroup2 filesystem
    }

    fs::create_dir_all(&cgroup_path).into_diagnostic().context("Failed to create cgroup directory. Are you root?")?;

    if let Some(mem) = &specs.memory_limit {
        // Simplified parsing, assuming bytes or naive string
        let limit_bytes = if mem.ends_with("MB") {
            mem.replace("MB", "").parse::<u64>().unwrap_or(100) * 1024 * 1024
        } else {
            100 * 1024 * 1024
        };
        fs::write(cgroup_path.join("memory.max"), limit_bytes.to_string()).into_diagnostic()?;
    }

    if let Some(cpu) = specs.cpu_shares {
        fs::write(cgroup_path.join("cpu.weight"), cpu.to_string()).into_diagnostic()?;
    }

    // Add current process (which will be the parent of the container) to the cgroup
    // The child will inherit this.
    // Note: Better to add the child PID after clone, but adding parent before clone works for demo
    let pid = Pid::this();
    fs::write(cgroup_path.join("cgroup.procs"), pid.as_raw().to_string()).into_diagnostic()?;

    Ok(())
}

fn setup_network(container_pid: Pid) -> Result<()> {
    // Uses ip command for simplicity over raw netlink
    let veth_host = format!("veth{}", container_pid);
    // let veth_peer = "veth0"; // Inside container (unused var in parent scope)

    // 1. Create pair
    Command::new("ip")
    .args(&["link", "add", &veth_host, "type", "veth", "peer", "name", "veth-tmp"])
    .status().into_diagnostic()?;

    // 2. Move peer to container namespace
    Command::new("ip")
    .args(&["link", "set", "veth-tmp", "netns", &container_pid.to_string()])
    .status().into_diagnostic()?;

    // 3. Rename peer inside container (Must be done inside child usually, or via 'ip netns exec' but we don't have named netns)
    // For this simple demo, we skip complex renaming logic which requires netns-exec or setns
    // Instead, we just bring up the host side

    Command::new("ip")
    .args(&["link", "set", &veth_host, "up"])
    .status().into_diagnostic()?;

    // Bridge connection (assuming br0 exists, otherwise just up)
    // Command::new("ip").args(&["link", "set", &veth_host, "master", "br0"]).status().ok();

    Ok(())
}

// Struct to pass data to child process
struct ChildConfig {
    rootfs: PathBuf,
    hostname: String,
}

fn child_entrypoint(config: ChildConfig) -> isize {
    // 1. Hostname
    if let Err(e) = sethostname(&config.hostname) {
        eprintln!("Failed to set hostname: {}", e);
        return 1;
    }

    // 2. Mount /proc
    let proc_path = config.rootfs.join("proc");
    if let Err(e) = mount(
        Some("proc"),
                          &proc_path,
                          Some("proc"),
                          MsFlags::empty(),
                          None::<&str>,
    ) {
        // It might fail if /proc doesn't exist in the image or if already mounted
        // eprintln!("Warning: Failed to mount proc: {}", e);
    }

    // 3. Pivot Root logic
    // We need a place for the old root
    let old_root = config.rootfs.join("old_root");
    if let Err(_) = fs::create_dir_all(&old_root) {
        return 1;
    }

    // Make new root a mount point
    if let Err(_) = mount(
        Some(&config.rootfs),
                          &config.rootfs,
                          None::<&str>,
                          MsFlags::MS_BIND | MsFlags::MS_REC,
                          None::<&str>,
    ) {
        eprintln!("Failed to bind mount rootfs");
        return 1;
    }

    if let Err(e) = pivot_root(&config.rootfs, &old_root) {
        eprintln!("Failed to pivot_root: {}. Ensure running as root.", e);
        // Fallback to chroot for demo if pivot fails (e.g. inside Docker)
        if let Err(e) = chdir("/") { eprintln!("{}", e); return 1; }
        if let Err(e) = nix::unistd::chroot(".") { eprintln!("{}", e); return 1; }
    } else {
        // Unmount old root
        let _ = chdir("/");
        let _ = umount2("/old_root", MntFlags::MNT_DETACH);
        let _ = fs::remove_dir("/old_root");
    }

    // 4. Exec
    let cmd = CString::new("/bin/sh").unwrap();
    let args = [CString::new("sh").unwrap()];

    // Drop env vars just in case

    if let Err(e) = nix::unistd::execvp(&cmd, &args) {
        eprintln!("Exec failed: {}", e);
        return 1;
    }

    0
}

fn save_state(id: &str, state: &ContainerState) -> Result<()> {
    let path = PathBuf::from(format!("{}/{}.json", HACKEROS_RUN, id));
    let f = File::create(path).into_diagnostic()?;
    serde_json::to_writer(f, state).into_diagnostic()?;
    Ok(())
}

fn run_container(config_path: &Path, detached: bool) -> Result<()> {
    // 1. Parse Config
    let mut file_content = String::new();
    File::open(config_path).into_diagnostic()?.read_to_string(&mut file_content).into_diagnostic()?;
    let config = parse_hk_file(&file_content)?;

    let container_id = Uuid::new_v4().to_string();
    let short_id = &container_id[0..8];

    println!("{} Initializing container {}", "[INIT]".bold().green(), config.metadata.name.bold().white());
    println!("   ID: {}", short_id);
    println!("   Image: {}", config.specs.base_image);

    ensure_directories()?;

    // 2. Prepare Storage
    let image_path = download_image(&config.specs.base_image)?;
    let rootfs = setup_overlayfs(&container_id, &image_path)?;

    // 3. Setup Cgroups
    setup_cgroups(&container_id, &config.specs)?;

    // 4. Prepare Child Process
    // Increase stack size for child
    const STACK_SIZE: usize = 1024 * 1024;
    let ref mut stack = [0; STACK_SIZE];

    let flags = CloneFlags::CLONE_NEWUTS
    | CloneFlags::CLONE_NEWPID
    | CloneFlags::CLONE_NEWNS
    | CloneFlags::CLONE_NEWNET
    | CloneFlags::CLONE_NEWIPC;

    // We can't pass closures capturing environment easily to raw clone in safe Rust without boxing overhead/unsafe casting
    // For this demo, we use a workaround struct or careful pointer usage.
    // However, the nix::sched::clone accepts a FnMut() -> isize.

    let rootfs_clone = rootfs.clone();
    let hostname_clone = config.metadata.name.clone();

    let cb = Box::new(move || {
        child_entrypoint(ChildConfig {
            rootfs: rootfs_clone.clone(),
                         hostname: hostname_clone.clone(),
        })
    });

    let pid = unsafe {
        clone(
            cb,
            stack,
            flags,
            Some(Signal::SIGCHLD as i32),
        ).into_diagnostic().context("Clone failed. Are you running as Root?")?
    };

    // 5. Setup Network (from Parent)
    setup_network(pid)?;

    println!("{} Container started with PID {}", "[RUN]".bold().green(), pid);

    // 6. Save State
    let state = ContainerState {
        id: container_id.clone(),
        pid: pid.as_raw(),
        name: config.metadata.name.clone(),
        status: "Running".to_string(),
        ip_address: Some("10.0.0.2 (mock)".to_string()),
        bundle_path: rootfs.to_string_lossy().to_string(),
        start_time: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
    };
    save_state(&container_id, &state)?;

    if !detached {
        println!("{} Attaching to container output...", "[ATTACH]".bold().blue());
        waitpid(pid, None).into_diagnostic()?;

        // Cleanup after exit
        println!("{} Container exited.", "[STOP]".bold().yellow());
        let _ = fs::remove_file(format!("{}/{}.json", HACKEROS_RUN, container_id));
        // Also remove overlay mount in real implementation
    } else {
        println!("{} Running in background.", "[DETACH]".bold().blue());
    }

    Ok(())
}

fn list_containers() -> Result<()> {
    ensure_directories()?;

    println!("{0: <12} {1: <20} {2: <10} {3: <15} {4: <15}",
             "ID".bold(), "NAME".bold(), "PID".bold(), "STATUS".bold(), "IP".bold());
    println!("{}", "-".repeat(72).dimmed());

    let paths = fs::read_dir(HACKEROS_RUN).into_diagnostic()?;
    let mut count = 0;

    for path in paths {
        let path = path.into_diagnostic()?.path();
        if path.extension().and_then(|s| s.to_str()) == Some("json") {
            let content = fs::read_to_string(&path).into_diagnostic()?;
            if let Ok(state) = serde_json::from_str::<ContainerState>(&content) {
                let short_id = &state.id[0..8];
                println!("{0: <12} {1: <20} {2: <10} {3: <15} {4: <15}",
                         short_id,
                         state.name.cyan(),
                         state.pid,
                         state.status.green(),
                         state.ip_address.unwrap_or_default()
                );
                count += 1;
            }
        }
    }

    if count == 0 {
        println!("No running containers found.");
    }

    Ok(())
}

fn status_container(name_or_id: &str) -> Result<()> {
    ensure_directories()?;
    let paths = fs::read_dir(HACKEROS_RUN).into_diagnostic()?;

    for path in paths {
        let path = path.into_diagnostic()?.path();
        if path.extension().and_then(|s| s.to_str()) == Some("json") {
            let content = fs::read_to_string(&path).into_diagnostic()?;
            if let Ok(state) = serde_json::from_str::<ContainerState>(&content) {
                if state.name == name_or_id || state.id.starts_with(name_or_id) {
                    println!("{} Container Details", "[INFO]".bold().blue());
                    println!("  ID: {}", state.id);
                    println!("  Name: {}", state.name);
                    println!("  PID: {}", state.pid);
                    println!("  Status: {}", state.status);
                    println!("  Path: {}", state.bundle_path);
                    return Ok(());
                }
            }
        }
    }
    Err(miette!("Container not found: {}", name_or_id))
}

fn print_help() {
    println!("{}", "HackerOS Containers CLI".bold().green());
    println!("Advanced container management with full isolation.\n");
    println!("Usage: hackeros-containers [COMMAND] [OPTIONS]");
    println!("\nCommands:");
    println!("  -c, --config <path>    Run a container from .hk file");
    println!("  --list                 List active containers");
    println!("  --status <id/name>     Show container details");
    println!("  --cleanup              Remove temporary dirs (dev)");
    println!("\nOptions:");
    println!("  -d, --detached         Run in background");
    println!("  -h, --help             Show this message");
}

fn main() -> Result<()> {
    env_logger::init();

    // Root check
    if !nix::unistd::Uid::effective().is_root() {
        println!("{} Warning: You are not running as root. Functionality will be limited.", "[WARN]".bold().yellow());
    }

    match parse_args() {
        Ok(cmd) => match cmd {
            CommandType::Run { config_path, detached } => {
                run_container(&config_path, detached)?;
            }
            CommandType::List => list_containers()?,
            CommandType::Status { name } => status_container(&name)?,
            CommandType::Cleanup => {
                let _ = fs::remove_dir_all(HACKEROS_LIB);
                let _ = fs::remove_dir_all(HACKEROS_RUN);
                let _ = fs::remove_dir_all(CGROUP_ROOT);
                println!("Cleanup done.");
            }
            CommandType::Help => print_help(),
        },
        Err(e) => return Err(e),
    }

    Ok(())
}
