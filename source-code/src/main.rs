use lexopt::{Arg, Parser, ValueExt};
use miette::{miette, IntoDiagnostic, Result};
use owo_colors::OwoColorize;
use tokio::runtime::Runtime;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

mod api;
mod cni;
mod config;
mod container;
mod db;
mod image;
mod logging;
mod metrics;
mod network;
mod pod;
mod sandbox;
mod seccomp;
mod tls;
mod utils;
mod validation;

use config::HkConfig;
use container::{find_container, start_container, stop_container};
use pod::{start_pod, stop_pod, PodSpec};

// ── Tracing / OpenTelemetry ───────────────────────────────────────────────────

fn init_tracing(otlp_endpoint: Option<&str>, json_logs: bool) -> Result<()> {
    use tracing_subscriber::fmt;

    let env_filter = EnvFilter::try_from_default_env()
    .unwrap_or_else(|_| EnvFilter::new("warn,hco=info"));

    if let Some(endpoint) = otlp_endpoint {
        use opentelemetry_otlp::WithExportConfig;

        // Build the runtime needed for the batch exporter
        let tracer = opentelemetry_otlp::new_pipeline()
        .tracing()
        .with_exporter(
            opentelemetry_otlp::new_exporter()
            .tonic()
            .with_endpoint(endpoint),
        )
        .install_batch(opentelemetry_sdk::runtime::Tokio)
        .map_err(|e| miette!("Cannot init OTel pipeline: {}", e))?;

        let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer);

        // IMPORTANT: OTel layer requires JsonFields — always use .json() when
        // OTel is active so the subscriber stack satisfies the trait bounds.
        tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt::layer().json())
        .with(otel_layer)
        .init();
    } else if json_logs {
        tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt::layer().json())
        .init();
    } else {
        tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt::layer())
        .init();
    }

    Ok(())
}

// ── Banner ────────────────────────────────────────────────────────────────────

fn print_banner() {
    println!(
        "{}",
        r#"
        ██╗  ██╗ ██████╗ ██████╗
        ██║  ██║██╔════╝██╔═══██╗
        ███████║██║     ██║   ██║
        ██╔══██║██║     ██║   ██║
        ██║  ██║╚██████╗╚██████╔╝
        ╚═╝  ╚═╝ ╚═════╝ ╚═════╝   HackerOS Container Runtime"#
        .bright_cyan()
    );
    println!(
        "  {} {}\n",
        format!("v{}", env!("CARGO_PKG_VERSION")).bold(),
            "── lightweight OCI container engine".dimmed()
    );
}

fn print_help() {
    print_banner();

    let section = |s: &str| println!("\n  {}", s.bold().underline().bright_white());
    let cmd = |name: &str, desc: &str| {
        println!("    {:<38} {}", name.bright_yellow(), desc.dimmed())
    };
    let flag =
    |name: &str, desc: &str| println!("    {:<38} {}", name.cyan(), desc.dimmed());

    section("USAGE");
    println!(
        "    {} {} {}",
        "hco".bright_cyan(),
             "<COMMAND>".yellow(),
             "[FLAGS]".dimmed()
    );

    section("CONTAINER COMMANDS");
    cmd("run <name>", "Create and start a container");
    cmd("stop <name|id>", "Stop a container (SIGTERM → SIGKILL after 10 s)");
    cmd("list  (ps)", "List all running containers");
    cmd("enter <name|id>", "Attach a PTY shell to a running container");
    cmd("stats <name|id>", "Show resource usage once  (add -w for live loop)");

    section("POD COMMANDS");
    cmd("pod create <name> -f <spec.yaml>", "Create a pod from YAML spec");
    cmd("pod start  <name>", "Restart stopped containers in a pod");
    cmd("pod stop   <name>", "Stop all containers in a pod");
    cmd("pod list", "List all pods");

    section("IMAGE COMMANDS");
    cmd("image gc", "Remove unused image layer directories");
    cmd("image import <name> -f <tar>", "Import a Docker save tarball");

    section("API SERVER");
    cmd("api", "Start the REST API server");

    section("RUN FLAGS");
    flag("-i, --image <ref>", "Container image  [default: alpine:latest]");
    flag("-p, --publish <h:c>", "Port mapping  e.g. 8080:80/tcp");
    flag("-v, --volume <h:c>", "Bind mount   e.g. /data:/mnt/data");
    flag("-e, --env <KEY=VAL>", "Set environment variable (repeatable)");
    flag("-d, --detached", "Run in background");
    flag("    --memory <limit>", "Memory limit  e.g. 512MB, 2GB");
    flag("    --cpu <pct>", "CPU quota 1-100");
    flag("    --auto-restart", "Restart on exit");
    flag("    --rootless", "Use user namespaces");

    section("STATS FLAGS");
    flag("-w, --watch", "Refresh live (Ctrl+C to quit)");

    section("API FLAGS");
    flag("    --api-addr  <addr>", "Listen addr  [default: 127.0.0.1:8080]");
    flag(
        "    --api-token <token>",
        "Require Bearer token for all write endpoints",
    );
    flag("    --tls-cert  <path>", "PEM certificate file (enables HTTPS)");
    flag("    --tls-key   <path>", "PEM private key file");

    section("OBSERVABILITY FLAGS");
    flag("    --json-logs", "Emit structured JSON logs");
    flag(
        "    --otlp <endpoint>",
        "OpenTelemetry OTLP gRPC endpoint  e.g. http://localhost:4317",
    );

    section("EXAMPLES");
    println!(
        "    {}",
        "hco run web -i nginx:latest -p 80:80 -d".bright_green()
    );
    println!(
        "    {}",
        "hco run db -i postgres:15 -e POSTGRES_PASSWORD=secret -d".bright_green()
    );
    println!(
        "    {}",
        "hco pod create myapp -f ./myapp.yaml".bright_green()
    );
    println!(
        "    {}",
        "hco api --api-addr 0.0.0.0:8080 --api-token s3cr3t \\"
        .bright_green()
    );
    println!(
        "    {}",
        "         --tls-cert /etc/hco/tls.crt --tls-key /etc/hco/tls.key"
        .bright_green()
    );
    println!();
}

// ── Command types ─────────────────────────────────────────────────────────────

enum CommandType {
    Run {
        detached: bool,
        name: String,
        image: String,
        mounts: Vec<String>,
        ports: Vec<String>,
        env: Vec<String>,
        memory: Option<String>,
        cpu: Option<u64>,
        auto_restart: bool,
        rootless: bool,
    },
    Enter {
        target: String,
    },
    Stats {
        target: String,
        watch: bool,
    },
    List,
    Stop {
        target: String,
    },
    Pod {
        subcommand: PodCommand,
    },
    Image {
        subcommand: ImageCommand,
    },
    Api {
        addr: String,
        token: Option<String>,
        tls_cert: Option<String>,
        tls_key: Option<String>,
    },
    Help,
}

enum PodCommand {
    Create {
        name: String,
        spec_file: std::path::PathBuf,
    },
    Start {
        name: String,
    },
    Stop {
        name: String,
    },
    List,
}

enum ImageCommand {
    Gc,
    Import {
        name: String,
        path: std::path::PathBuf,
    },
}

// ── Global flags ──────────────────────────────────────────────────────────────

struct GlobalFlags {
    json_logs: bool,
    otlp: Option<String>,
    db_path: Option<String>,
}

// ── Arg parsing ───────────────────────────────────────────────────────────────

fn parse_args() -> Result<(CommandType, GlobalFlags)> {
    let mut parser = Parser::from_env();
    let mut command: Option<String> = None;
    let mut sub_cmd: Option<String> = None;
    let mut target: Option<String> = None;
    let mut image: Option<String> = None;
    let mut mounts: Vec<String> = vec![];
    let mut ports: Vec<String> = vec![];
    let mut env: Vec<String> = vec![];
    let mut memory: Option<String> = None;
    let mut cpu: Option<u64> = None;
    let mut detached = false;
    let mut auto_restart = false;
    let mut rootless = false;
    let mut watch = false;
    let mut api_addr = "127.0.0.1:8080".to_string();
    let mut api_token: Option<String> = None;
    let mut tls_cert: Option<String> = None;
    let mut tls_key: Option<String> = None;
    let mut file_path: Option<std::path::PathBuf> = None;
    let mut json_logs = false;
    let mut otlp: Option<String> = None;
    let mut db_path: Option<String> = None;

    while let Some(arg) = parser.next().into_diagnostic()? {
        match arg {
            Arg::Value(v) if command.is_none() => {
                command = Some(v.string().into_diagnostic()?)
            }
            Arg::Value(v)
            if sub_cmd.is_none()
                && matches!(
                    command.as_deref(),
                            Some("pod") | Some("image") | Some("images")
                ) =>
                {
                    sub_cmd = Some(v.string().into_diagnostic()?)
                }
                Arg::Value(v) if target.is_none() => {
                    target = Some(v.string().into_diagnostic()?)
                }
                Arg::Value(_) => {}

                Arg::Short('d') | Arg::Long("detached") => detached = true,
                Arg::Short('w') | Arg::Long("watch") => watch = true,
                Arg::Long("auto-restart") => auto_restart = true,
                Arg::Long("rootless") => rootless = true,
                Arg::Long("json-logs") => json_logs = true,

                Arg::Short('i') | Arg::Long("image") => {
                    image = Some(parser.value().into_diagnostic()?.string().into_diagnostic()?)
                }
                Arg::Short('p') | Arg::Long("publish") => {
                    ports.push(parser.value().into_diagnostic()?.string().into_diagnostic()?)
                }
                Arg::Short('v') | Arg::Long("volume") => {
                    mounts.push(parser.value().into_diagnostic()?.string().into_diagnostic()?)
                }
                Arg::Short('e') | Arg::Long("env") => {
                    env.push(parser.value().into_diagnostic()?.string().into_diagnostic()?)
                }
                Arg::Short('f') | Arg::Long("file") => {
                    file_path = Some(std::path::PathBuf::from(
                        parser.value().into_diagnostic()?.string().into_diagnostic()?,
                    ))
                }
                Arg::Long("memory") => {
                    memory =
                    Some(parser.value().into_diagnostic()?.string().into_diagnostic()?)
                }
                Arg::Long("cpu") => {
                    let s =
                    parser.value().into_diagnostic()?.string().into_diagnostic()?;
                    cpu = Some(
                        s.parse::<u64>()
                        .map_err(|_| miette!("--cpu must be 1-100"))?,
                    );
                }
                Arg::Long("api-addr") => {
                    api_addr =
                    parser.value().into_diagnostic()?.string().into_diagnostic()?
                }
                Arg::Long("api-token") => {
                    api_token =
                    Some(parser.value().into_diagnostic()?.string().into_diagnostic()?)
                }
                Arg::Long("tls-cert") => {
                    tls_cert =
                    Some(parser.value().into_diagnostic()?.string().into_diagnostic()?)
                }
                Arg::Long("tls-key") => {
                    tls_key =
                    Some(parser.value().into_diagnostic()?.string().into_diagnostic()?)
                }
                Arg::Long("otlp") => {
                    otlp =
                    Some(parser.value().into_diagnostic()?.string().into_diagnostic()?)
                }
                Arg::Long("db") => {
                    db_path =
                    Some(parser.value().into_diagnostic()?.string().into_diagnostic()?)
                }
                Arg::Short('h') | Arg::Long("help") => {
                    return Ok((
                        CommandType::Help,
                        GlobalFlags { json_logs, otlp, db_path },
                    ))
                }
                _ => {}
        }
    }

    let gf = GlobalFlags { json_logs, otlp, db_path };

    let cmd = match command.as_deref() {
        Some("run") => CommandType::Run {
            detached,
            auto_restart,
            rootless,
            name: target.unwrap_or_else(|| "container".into()),
            image: image.unwrap_or_else(|| "alpine:latest".into()),
            mounts,
            ports,
            env,
            memory,
            cpu,
        },
        Some("enter") => CommandType::Enter {
            target: target.ok_or_else(|| miette!("Usage: hco enter <name|id>"))?,
        },
        Some("stats") => CommandType::Stats {
            target: target.ok_or_else(|| miette!("Usage: hco stats <name|id>"))?,
            watch,
        },
        Some("stop") => CommandType::Stop {
            target: target.ok_or_else(|| miette!("Usage: hco stop <name|id>"))?,
        },
        Some("list") | Some("ps") => CommandType::List,
        Some("pod") => {
            let sub = match sub_cmd.as_deref() {
                Some("create") => PodCommand::Create {
                    name: target.ok_or_else(|| {
                        miette!("Usage: hco pod create <name> -f <spec>")
                    })?,
                    spec_file: file_path
                    .ok_or_else(|| miette!("-f <spec.yaml> required"))?,
                },
                Some("start") => PodCommand::Start {
                    name: target
                    .ok_or_else(|| miette!("Usage: hco pod start <name>"))?,
                },
                Some("stop") => PodCommand::Stop {
                    name: target
                    .ok_or_else(|| miette!("Usage: hco pod stop <name>"))?,
                },
                Some("list") | Some("ls") => PodCommand::List,
                _ => return Err(miette!("Pod subcommand: create, start, stop, list")),
            };
            CommandType::Pod { subcommand: sub }
        }
        Some("image") | Some("images") => {
            let sub = match sub_cmd.as_deref() {
                Some("gc") => ImageCommand::Gc,
                Some("import") => ImageCommand::Import {
                    name: target.ok_or_else(|| {
                        miette!("Usage: hco image import <name> -f <tar>")
                    })?,
                    path: file_path.ok_or_else(|| miette!("-f <tarball> required"))?,
                },
                _ => return Err(miette!("Image subcommand: gc, import")),
            };
            CommandType::Image { subcommand: sub }
        }
        Some("api") => CommandType::Api {
            addr: api_addr,
            token: api_token,
            tls_cert,
            tls_key,
        },
        Some("version") | Some("--version") | Some("-V") => {
            println!("hco {}", env!("CARGO_PKG_VERSION"));
            std::process::exit(0);
        }
        _ => CommandType::Help,
    };

    Ok((cmd, gf))
}

// ── Main ──────────────────────────────────────────────────────────────────────

fn main() -> Result<()> {
    let (cmd, gf) = parse_args()?;

    // Tracing init — OTel needs a tokio runtime for the batch exporter
    if gf.otlp.is_some() {
        let rt = Runtime::new().into_diagnostic()?;
        rt.block_on(async { init_tracing(gf.otlp.as_deref(), gf.json_logs) })?;
    } else {
        init_tracing(None, gf.json_logs)?;
    }

    if !nix::unistd::Uid::effective().is_root() {
        eprintln!(
            "{} Not running as root — privileged features (namespaces, cgroups) will fail.",
                  "[WARN]".yellow().bold()
        );
    }

    // Init directories + DB
    let db_path = gf.db_path.as_deref().unwrap_or(container::STATE_DB);
    container::ensure_directories()?;
    db::init_db(db_path)?;

    match cmd {
        CommandType::Run {
            detached,
            name,
            image,
            mounts,
            ports,
            env,
            memory,
            cpu,
            auto_restart,
            rootless,
        } => {
            validation::validate_name(&name)?;
            validation::validate_image_ref(&image)?;
            for m in &mounts {
                validation::validate_mount(m)?;
            }
            for p in &ports {
                validation::validate_port_mapping(p)?;
            }
            for e in &env {
                validation::validate_env_var(e)?;
            }
            if let Some(ref m) = memory {
                validation::validate_memory_limit(m)?;
            }
            if let Some(c) = cpu {
                validation::validate_cpu_percent(c)?;
            }

            let mut config = HkConfig::create_ephemeral(&name, &image, mounts, ports);
            config.specs.env = env;
            config.specs.memory_limit = memory;
            config.specs.cpu_percent = cpu;
            config.runtime.auto_restart = auto_restart;
            config.security.rootless = rootless;

            info!(name, image, detached, "Starting container");
            start_container(config, detached)?;
        }

        CommandType::Enter { target } => {
            let row = find_container(&target)?;
            container::enter_container_pty(&row)?;
        }

        CommandType::Stats { target, watch } => {
            let row = find_container(&target)?;
            if watch {
                container::show_stats_loop(&row)?;
            } else {
                container::show_stats(&row)?;
            }
        }

        CommandType::Stop { target } => stop_container(&target)?,

        CommandType::List => container::list_containers()?,

        CommandType::Pod { subcommand } => match subcommand {
            PodCommand::Create { name, spec_file } => {
                let spec = PodSpec::from_file(spec_file)?;
                start_pod(&name, spec)?;
            }
            PodCommand::Start { name } => pod::restart_pod(&name)?,
            PodCommand::Stop { name } => stop_pod(&name)?,
            PodCommand::List => pod::list_pods()?,
        },

        CommandType::Image { subcommand } => match subcommand {
            ImageCommand::Gc => image::ImageManager::gc_unused_layers()?,
            ImageCommand::Import { name, path } => {
                image::ImageManager::import_tar(&path, &name)?;
            }
        },

        CommandType::Api {
            addr,
            token,
            tls_cert,
            tls_key,
        } => {
            print_banner();
            println!(
                "  {} REST API on {}",
                "Starting".bold().green(),
                     addr.cyan()
            );
            if token.is_some() {
                println!(
                    "  {} Bearer token auth   {}",
                    "●".green(),
                         "enabled".green()
                );
            } else {
                println!(
                    "  {} Bearer token auth   {}",
                    "●".yellow(),
                         "disabled (dev mode)".yellow()
                );
            }
            if tls::tls_files_present(&tls_cert, &tls_key) {
                println!(
                    "  {} TLS/HTTPS           {}",
                    "●".green(),
                         "enabled".green()
                );
            } else {
                println!(
                    "  {} TLS/HTTPS           {}",
                    "●".yellow(),
                         "disabled (plain HTTP)".yellow()
                );
            }
            println!();

            let rt = Runtime::new().into_diagnostic()?;
            rt.block_on(async {
                metrics::spawn_metrics_collector();
                api::run_server(addr, token, tls_cert, tls_key).await
            })?;
        }

        CommandType::Help => print_help(),
    }

    Ok(())
}
