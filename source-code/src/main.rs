use std::fs;
use std::path::PathBuf;
use std::io::{Read, Write, stdout};
use std::thread;
use std::time::Duration;

use lexopt::{Arg, Parser, ValueExt};
use miette::{miette, IntoDiagnostic, Result, Context};
use owo_colors::OwoColorize;
use nix::pty::openpty;
use nix::unistd::{fork, ForkResult, setsid, dup2};
use nix::fcntl::OFlag;
use termion::raw::IntoRawMode;

mod config;
mod container;
mod image;
mod network;
mod sandbox;

use config::{HkConfig, Specs};
use container::{start_container, stop_container, find_container, ContainerState, CGROUP_ROOT};

enum CommandType {
    Run { detached: bool, name: String, image: String, mounts: Vec<String>, ports: Vec<String> },
    Enter { target: String },
    Stats { target: String },
    List,
    Stop { target: String },
    Help,
}

fn parse_args() -> Result<CommandType> {
    let mut parser = Parser::from_env();
    let mut command = None;
    let mut detached = false;
    let mut target_val = None;
    let mut image_val = None;
    let mut mounts = Vec::new();
    let mut ports = Vec::new();

    while let Some(arg) = parser.next().into_diagnostic()? {
        match arg {
            Arg::Value(val) if command.is_none() => command = Some(val.string().into_diagnostic()?),
            Arg::Short('d') | Arg::Long("detached") => detached = true,
            Arg::Short('v') | Arg::Long("volume") => mounts.push(parser.value().into_diagnostic()?.string().into_diagnostic()?),
            Arg::Short('p') | Arg::Long("publish") => ports.push(parser.value().into_diagnostic()?.string().into_diagnostic()?),
            Arg::Short('i') | Arg::Long("image") => image_val = Some(parser.value().into_diagnostic()?.string().into_diagnostic()?),
            Arg::Value(val) => target_val = Some(val.string().into_diagnostic()?),
            _ => {},
        }
    }

    match command.as_deref() {
        Some("run") => {
            Ok(CommandType::Run { 
                detached, 
                name: target_val.unwrap_or_else(|| "hacker_container".into()), 
                image: image_val.unwrap_or("alpine:latest".into()),
                mounts,
                ports
            })
        },
        Some("enter") => Ok(CommandType::Enter { target: target_val.ok_or(miette!("ID needed"))? }),
        Some("stats") => Ok(CommandType::Stats { target: target_val.ok_or(miette!("ID needed"))? }),
        Some("stop") => Ok(CommandType::Stop { target: target_val.ok_or(miette!("ID needed"))? }),
        Some("list") => Ok(CommandType::List),
        _ => Ok(CommandType::Help),
    }
}

fn main() -> Result<()> {
    if !nix::unistd::Uid::effective().is_root() {
        return Err(miette!("Root privileges required."));
    }

    match parse_args()? {
        CommandType::Run { detached, name, image, mounts, ports } => {
            let config = HkConfig::create_ephemeral(&name, &image, mounts, ports);
            start_container(config, detached)?;
        },
        CommandType::Enter { target } => {
            // PTY Based Enter
            let (_, state) = find_container(&target)?;
            enter_with_pty(&state)?;
        },
        CommandType::Stats { target } => {
            let (_, state) = find_container(&target)?;
            show_stats_loop(&state)?;
        },
        CommandType::List => {
            let _ = fs::create_dir_all(container::HACKEROS_RUN);
            println!("{0: <10} {1: <15} {2: <20} {3: <10}", "ID", "NAME", "IMAGE", "STATUS");
            for entry in fs::read_dir(container::HACKEROS_RUN).into_diagnostic()? {
                let path = entry.into_diagnostic()?.path();
                if path.extension().map_or(false, |e| e == "json") {
                    let s: ContainerState = serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
                    println!("{0: <10} {1: <15} {2: <20} {3: <10}", &s.id[0..8], s.name.cyan(), s.image, s.status.green());
                }
            }
        },
        CommandType::Stop { target } => stop_container(&target)?,
        CommandType::Help => print_help(),
    }
    Ok(())
}

fn enter_with_pty(state: &ContainerState) -> Result<()> {
    println!("{} Entering {} (PTY)...", "[ENTER]".bold().green(), state.name);
    
    let result = openpty(None, None).into_diagnostic()?;
    let master = result.master;
    let slave = result.slave;

    match unsafe { fork() } {
        Ok(ForkResult::Parent { .. }) => {
            // Parent: Pump data between stdin/stdout and master PTY
            let mut raw_stdout = stdout().into_raw_mode().into_diagnostic()?;
            let mut master_file = unsafe { fs::File::from_raw_fd(master) };
            let mut master_reader = master_file.try_clone().unwrap();
            
            // Thread for reading master PTY -> stdout
            thread::spawn(move || {
                let mut buf = [0; 1024];
                while let Ok(n) = master_reader.read(&mut buf) {
                    if n == 0 { break; }
                    let _ = raw_stdout.write_all(&buf[..n]);
                    let _ = raw_stdout.flush();
                }
            });

            // Main thread: stdin -> master PTY
            let mut stdin = std::io::stdin();
            let mut buf = [0; 1024];
            while let Ok(n) = stdin.read(&mut buf) {
                if n == 0 { break; }
                if master_file.write_all(&buf[..n]).is_err() { break; }
            }
        }
        Ok(ForkResult::Child) => {
            // Child: Join namespaces, attach PTY
            attach_namespaces(state.pid)?;
            
            setsid().into_diagnostic()?;
            unsafe {
                for i in 0..3 { dup2(slave, i); }
            }
            // Execute Shell
            let cmd = std::ffi::CString::new("/bin/sh").unwrap();
            let _ = nix::unistd::execvp(&cmd, &[cmd.clone()]);
        }
        Err(_) => return Err(miette!("Fork failed")),
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

fn show_stats_loop(state: &ContainerState) -> Result<()> {
    let cg_path = PathBuf::from(format!("{}/{}", CGROUP_ROOT, state.id));
    println!("Monitoring {} (Ctrl+C to stop)...", state.name.cyan());
    
    loop {
        print!("\x1B[2J\x1B[1;1H"); // Clear screen
        println!("{} Stats", state.name.bold());
        println!("-------------------------");
        
        if let Ok(c) = fs::read_to_string(cg_path.join("memory.current")) {
             let bytes: u64 = c.trim().parse().unwrap_or(0);
             println!("Memory: {:.2} MB", bytes as f64 / 1024.0 / 1024.0);
        }
        
        if let Ok(c) = fs::read_to_string(cg_path.join("cpu.stat")) {
             // simplified parsing
             println!("CPU Stat:\n{}", c);
        }

        thread::sleep(Duration::from_secs(1));
    }
}

fn print_help() {
    println!("hco v0.6.0");
    println!("  run <name> -i <image> -p 80:80 -v /mnt:/mnt");
    println!("  enter <name>");
    println!("  stats <name>");
    println!("  stop <name>");
    println!("  list");
}
