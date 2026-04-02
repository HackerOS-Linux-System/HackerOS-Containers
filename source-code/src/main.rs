use lexopt::{Arg, Parser, ValueExt};
use miette::{miette, IntoDiagnostic, Result};
use owo_colors::OwoColorize;
use tokio::runtime::Runtime;

mod config;
mod container;
mod image;
mod network;
mod sandbox;
mod pod;
mod api;
mod metrics;
mod cni;
mod seccomp;
mod logging;
mod utils;

use config::HkConfig;
use container::{start_container, stop_container, find_container};
use pod::{start_pod, stop_pod, PodSpec};

enum CommandType {
    Run { detached: bool, name: String, image: String, mounts: Vec<String>, ports: Vec<String> },
    Enter { target: String },
    Stats { target: String },
    List,
    Stop { target: String },
    Pod { subcommand: PodCommand },
    Api { addr: String },
    Help,
}

enum PodCommand {
    Create { name: String, spec_file: std::path::PathBuf },
    Start { name: String },
    Stop { name: String },
    List,
}

fn parse_args() -> Result<CommandType> {
    let mut parser = Parser::from_env();
    let mut command = None;
    let mut detached = false;
    let mut target_val = None;
    let mut image_val = None;
    let mut mounts = Vec::new();
    let mut ports = Vec::new();
    let mut api_addr = String::from("127.0.0.1:8080");
    let mut pod_spec = None;

    while let Some(arg) = parser.next().into_diagnostic()? {
        match arg {
            Arg::Value(val) if command.is_none() => command = Some(val.string().into_diagnostic()?),
            Arg::Short('d') | Arg::Long("detached") => detached = true,
            Arg::Short('v') | Arg::Long("volume") => mounts.push(parser.value().into_diagnostic()?.string().into_diagnostic()?),
            Arg::Short('p') | Arg::Long("publish") => ports.push(parser.value().into_diagnostic()?.string().into_diagnostic()?),
            Arg::Short('i') | Arg::Long("image") => image_val = Some(parser.value().into_diagnostic()?.string().into_diagnostic()?),
            Arg::Long("api-addr") => api_addr = parser.value().into_diagnostic()?.string().into_diagnostic()?,
            Arg::Short('f') | Arg::Long("file") => pod_spec = Some(std::path::PathBuf::from(parser.value().into_diagnostic()?.string().into_diagnostic()?)),
            Arg::Value(val) => target_val = Some(val.string().into_diagnostic()?),
            _ => {}
        }
    }

    match command.as_deref() {
        Some("run") => Ok(CommandType::Run {
            detached,
            name: target_val.unwrap_or_else(|| "hacker_container".into()),
                          image: image_val.unwrap_or("alpine:latest".into()),
                          mounts,
                          ports,
        }),
        Some("enter") => Ok(CommandType::Enter { target: target_val.ok_or(miette!("ID needed"))? }),
        Some("stats") => Ok(CommandType::Stats { target: target_val.ok_or(miette!("ID needed"))? }),
        Some("stop") => Ok(CommandType::Stop { target: target_val.ok_or(miette!("ID needed"))? }),
        Some("list") => Ok(CommandType::List),
        Some("pod") => {
            let sub = match target_val.as_deref() {
                Some("create") => PodCommand::Create { name: target_val.ok_or(miette!("Pod name needed"))?, spec_file: pod_spec.ok_or(miette!("Pod spec file needed"))? },
                Some("start") => PodCommand::Start { name: target_val.ok_or(miette!("Pod name needed"))? },
                Some("stop") => PodCommand::Stop { name: target_val.ok_or(miette!("Pod name needed"))? },
                Some("list") => PodCommand::List,
                _ => return Err(miette!("Pod subcommand: create, start, stop, list")),
            };
            Ok(CommandType::Pod { subcommand: sub })
        }
        Some("api") => Ok(CommandType::Api { addr: api_addr }),
        _ => Ok(CommandType::Help),
    }
}

fn main() -> Result<()> {
    env_logger::init();

    if !nix::unistd::Uid::effective().is_root() {
        eprintln!("{} Warning: Not running as root. Some features may not work.", "[WARN]".yellow());
    }

    container::ensure_directories()?;

    match parse_args()? {
        CommandType::Run { detached, name, image, mounts, ports } => {
            let config = HkConfig::create_ephemeral(&name, &image, mounts, ports);
            start_container(config, detached)?;
        }
        CommandType::Enter { target } => {
            let (_, state) = find_container(&target)?;
            container::enter_container_pty(&state)?;
        }
        CommandType::Stats { target } => {
            let (_, state) = find_container(&target)?;
            container::show_stats_loop(&state)?;
        }
        CommandType::Stop { target } => stop_container(&target)?,
        CommandType::List => container::list_containers()?,
        CommandType::Pod { subcommand } => match subcommand {
            PodCommand::Create { name, spec_file } => {
                let spec = PodSpec::from_file(spec_file)?;
                start_pod(&name, spec)?;
            }
            PodCommand::Start { name } => start_pod(&name, PodSpec::default())?,
            PodCommand::Stop { name } => stop_pod(&name)?,
            PodCommand::List => pod::list_pods()?,
        },
        CommandType::Api { addr } => {
            println!("Starting REST API on {}", addr);
            let rt = Runtime::new().into_diagnostic()?;
            rt.block_on(api::run_server(addr))?;
        }
        CommandType::Help => print_help(),
    }
    Ok(())
}

fn print_help() {
    println!("hco v0.3 – HackerOS Containers");
    println!("Usage:");
    println!("  run <name> -i 镜像 [-p host:container] [-v host:path] [-d]");
    println!("  enter <name>");
    println!("  stats <name>");
    println!("  stop <name>");
    println!("  list");
    println!("  pod create <name> -f <pod.yaml>");
    println!("  pod start <name>");
    println!("  pod stop <name>");
    println!("  pod list");
    println!("  api --api-addr 0.0.0.0:8080");
}
