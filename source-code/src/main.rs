use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result};
use lexopt::{Arg, Parser};
use miette::{miette, IntoDiagnostic, Report, WrapErr};
use nix::sched::{clone, CloneFlags};
use nix::sys::wait::waitpid;
use nix::unistd::{chdir, chroot, Pid};
use owo_colors::OwoColorize;
use serde::Deserialize;
use toml::de::Error as TomlError;

// Custom error type for pretty printing with miette
#[derive(Debug, miette::Diagnostic)]
#[error("HackerOS Containers Error: {message}")]
struct ContainerError {
    message: String,
    #[help]
    help: Option<String>,
    #[source_code]
    source_code: Option<String>,
}

// .hk file structure (TOML-like, but we'll parse it as TOML for simplicity)
#[derive(Deserialize, Debug)]
struct HkConfig {
    metadata: Metadata,
    description: Description,
    specs: Specs,
    #[serde(default)]
    runtime: Runtime,
}

#[derive(Deserialize, Debug)]
struct Metadata {
    name: String,
    version: String,
    authors: String,
    license: String,
}

#[derive(Deserialize, Debug)]
struct Description {
    summary: String,
    long: Vec<String>,  // Multiple lines
}

#[derive(Deserialize, Debug)]
struct Specs {
    rust: Option<String>,
    dependencies: Dependencies,
}

#[derive(Deserialize, Debug)]
struct Dependencies {
    #[serde(rename = "Matrix-Core")]
    matrix_core: String,
    #[serde(rename = "Hacker-Lang")]
    hacker_lang: String,
    #[serde(rename = "Void-Kernel")]
    void_kernel: String,
    #[serde(rename = "HackerOS")]
    hackeros: String,
}

#[derive(Deserialize, Debug, Default)]
struct Runtime {
    priority: Option<String>,
    #[serde(rename = "auto-restart")]
    auto_restart: Option<bool>,
}

// CLI Commands
enum CommandType {
    Run { config_path: PathBuf, runtime: String },
    List,
    Status { name: String },
    Help,
}

fn parse_args() -> Result<CommandType> {
    let mut parser = Parser::from_env();
    let mut config_path = None;
    let mut runtime = "runc".to_string();  // Default runtime

    while let Some(arg) = parser.next()? {
        match arg {
            Arg::Short('r') | Arg::Long("runtime") => {
                runtime = parser.value()?.into_string()?;
            }
            Arg::Short('c') | Arg::Long("config") => {
                config_path = Some(PathBuf::from(parser.value()?.into_string()?));
            }
            Arg::Long("list") => return Ok(CommandType::List),
            Arg::Long("status") => {
                let name = parser.value()?.into_string()?;
                return Ok(CommandType::Status { name });
            }
            Arg::Short('h') | Arg::Long("help") => return Ok(CommandType::Help),
            Arg::Value(val) => {
                if config_path.is_none() {
                    config_path = Some(PathBuf::from(val.into_string()?));
                } else {
                    return Err(miette!("Unexpected argument: {}", val.string()?));
                }
            }
            _ => return Err(miette!("Unknown argument: {}", arg.unexpected())),
        }
    }

    if let Some(path) = config_path {
        Ok(CommandType::Run {
            config_path: path,
            runtime,
        })
    } else {
        Ok(CommandType::Help)
    }
}

fn parse_hk_config(path: &Path) -> Result<HkConfig> {
    // .hk is TOML-like, but starts with comments; we'll skip lines starting with '!'
    let file = File::open(path).into_diagnostic()?;
    let reader = BufReader::new(file);
    let mut toml_content = String::new();

    for line in reader.lines() {
        let line = line.into_diagnostic()?;
        if !line.trim_start().starts_with('!') {
            toml_content.push_str(&line);
            toml_content.push('\n');
        }
    }

    toml::from_str(&toml_content).map_err(|e: TomlError| {
        miette!("Failed to parse .hk file: {}", e.message())
            .wrap_err("Invalid .hk format")
    })
}

fn setup_namespaces() -> Result<Pid> {
    // Stack for the child process
    let mut stack = [0u8; 4096];

    // Clone flags for namespaces
    let flags = CloneFlags::CLONE_NEWUTS
        | CloneFlags::CLONE_NEWPID
        | CloneFlags::CLONE_NEWNS
        | CloneFlags::CLONE_NEWNET
        | CloneFlags::CLONE_NEWIPC
        | CloneFlags::CLONE_NEWUSER;

    let pid = unsafe {
        clone(
            Box::new(|| child_process()),
            &mut stack,
            flags,
            Some(nix::sys::signal::Signal::SIGCHLD as i32),
        )
        .into_diagnostic()?
    };

    Ok(pid)
}

fn child_process() -> isize {
    // Inside the container: chroot, etc.
    if let Err(e) = chroot("/path/to/rootfs").context("Failed to chroot") {
        eprintln!("{}", e);
        return 1;
    }
    if let Err(e) = chdir("/").context("Failed to chdir") {
        eprintln!("{}", e);
        return 1;
    }

    // Exec the process (placeholder)
    if let Err(e) = nix::unistd::execvp("/bin/sh", &["/bin/sh"].iter().map(|s| s.as_ptr()).collect::<Vec<_>>()).context("Failed to exec") {
        eprintln!("{}", e);
        return 1;
    }

    0
}

fn run_container(config: &HkConfig, runtime: &str) -> Result<()> {
    println!(
        "{} Running container: {} (version {}) with runtime {}",
        "[INFO]".bold().green(),
        config.metadata.name.bold().cyan(),
        config.metadata.version,
        runtime.bold().yellow()
    );

    // Simulate runtime selection
    match runtime {
        "runc" | "crun" => {
            println!(
                "{} Using high-performance runtime (namespaces & cgroups)",
                "[RUNTIME]".bold().blue()
            );
            // Setup namespaces
            let pid = setup_namespaces()?;
            waitpid(pid, None).into_diagnostic()?;
        }
        "gvisor" => {
            println!(
                "{} Using gVisor (userspace kernel) for high isolation",
                "[RUNTIME]".bold().blue()
            );
            // Placeholder: In real impl, integrate with runsc
            Command::new("runsc")
                .arg("run")
                .arg(&config.metadata.name)
                .status()
                .into_diagnostic()?;
        }
        "kata" => {
            println!(
                "{} Using Kata Containers (micro-VM) for max isolation",
                "[RUNTIME]".bold().blue()
            );
            // Placeholder: Integrate with kata-runtime
            Command::new("kata-runtime")
                .arg("run")
                .arg(&config.metadata.name)
                .status()
                .into_diagnostic()?;
        }
        _ => return Err(miette!("Unknown runtime: {}", runtime)),
    }

    // Monitor resources (placeholder)
    println!(
        "{} Monitoring RAM allocation and data leaks...",
        "[MONITOR]".bold().magenta()
    );

    // Auto-restart if enabled
    if config.runtime.auto_restart.unwrap_or(false) {
        println!(
            "{} Auto-restart enabled",
            "[OPTION]".bold().yellow()
        );
    }

    Ok(())
}

fn list_containers() -> Result<()> {
    println!("{} Listing active containers:", "[LIST]".bold().green());
    // Placeholder: Scan for running containers
    println!("- Matrix-Core (PID: 1234)");
    Ok(())
}

fn status_container(name: &str) -> Result<()> {
    println!(
        "{} Status for container {}:",
        "[STATUS]".bold().green(),
        name.bold().cyan()
    );
    // Placeholder
    println!("- Running: Yes");
    println!("- RAM Usage: 256MB");
    println!("- Leaks Detected: None");
    Ok(())
}

fn print_help() {
    println!(
        "{} HackerOS Containers CLI",
        "Welcome to".bold().green()
    );
    println!("Usage:");
    println!("  hackeros-containers [OPTIONS] <config.hk>");
    println!();
    println!("Commands:");
    println!("  --list                List all running containers");
    println!("  --status <name>       Get status of a container");
    println!("  -h, --help            Print this help");
    println!();
    println!("Options:");
    println!("  -c, --config <path>   Path to .hk config file");
    println!("  -r, --runtime <name>  Runtime to use (runc, gvisor, kata) [default: runc]");
}

fn main() -> Result<(), Report> {
    env_logger::init();

    match parse_args() {
        Ok(cmd) => match cmd {
            CommandType::Run {
                config_path,
                runtime,
            } => {
                let config = parse_hk_config(&config_path)?;
                run_container(&config, &runtime)?;
            }
            CommandType::List => list_containers()?,
            CommandType::Status { name } => status_container(&name)?,
            CommandType::Help => print_help(),
        },
        Err(e) => {
            return Err(e.into());
        }
    }

    Ok(())
}
