use std::path::Path;
use std::process::Command;

use miette::{miette, IntoDiagnostic, WrapErr, Result};
use nix::unistd::Pid;
use tracing::info;

// ── Bridge ────────────────────────────────────────────────────────────────────

pub fn setup_bridge(bridge_name: &str, gateway: &str) -> Result<()> {
    let exists = Command::new("ip")
    .args(&["link", "show", bridge_name])
    .output()
    .map(|o| o.status.success())
    .unwrap_or(false);

    if !exists {
        Command::new("ip")
        .args(&["link", "add", "name", bridge_name, "type", "bridge"])
        .status()
        .into_diagnostic()
        .wrap_err("Failed to create bridge")?;
        info!(bridge = bridge_name, "Bridge created");
    }

    Command::new("ip")
    .args(&["link", "set", bridge_name, "up"])
    .status()
    .into_diagnostic()
    .wrap_err("Failed to bring bridge up")?;

    // Assign gateway IP; ignore error if already assigned
    let _ = Command::new("ip")
    .args(&["addr", "add", gateway, "dev", bridge_name])
    .status();

    Command::new("sysctl")
    .args(&["-w", "net.ipv4.ip_forward=1"])
    .status()
    .into_diagnostic()
    .wrap_err("Failed to enable IP forwarding")?;

    let rule_ok = Command::new("iptables")
    .args(&[
        "-t", "nat", "-C", "POSTROUTING",
        "-s", "10.10.0.0/24", "!", "-d", "10.10.0.0/24",
        "-j", "MASQUERADE",
    ])
    .output()
    .map(|o| o.status.success())
    .unwrap_or(false);

    if !rule_ok {
        Command::new("iptables")
        .args(&[
            "-t", "nat", "-A", "POSTROUTING",
            "-s", "10.10.0.0/24", "!", "-d", "10.10.0.0/24",
            "-j", "MASQUERADE",
        ])
        .status()
        .into_diagnostic()
        .wrap_err("Failed to add iptables MASQUERADE rule")?;
    }

    Ok(())
}

// ── Veth pair ─────────────────────────────────────────────────────────────────

pub fn create_veth_pair(pid: Pid, suffix: u8) -> Result<(String, String)> {
    let bridge = "hkbr0";
    let veth_host = format!("veth{}", pid.as_raw());
    let veth_peer = "veth-c";
    let ip_addr = format!("10.10.0.{}", suffix);

    // Remove stale veth if exists (crashed run)
    let _ = Command::new("ip").args(&["link", "del", &veth_host]).output();

    Command::new("ip")
    .args(&["link", "add", &veth_host, "type", "veth", "peer", "name", veth_peer])
    .status()
    .into_diagnostic()
    .wrap_err("Failed to create veth pair")?;

    Command::new("ip")
    .args(&["link", "set", &veth_host, "master", bridge])
    .status()
    .into_diagnostic()
    .wrap_err("Failed to attach veth to bridge")?;

    Command::new("ip")
    .args(&["link", "set", &veth_host, "up"])
    .status()
    .into_diagnostic()
    .wrap_err("Failed to bring up veth host side")?;

    Command::new("ip")
    .args(&["link", "set", veth_peer, "netns", &pid.as_raw().to_string()])
    .status()
    .into_diagnostic()
    .wrap_err("Failed to move veth peer to container netns")?;

    info!(ip = %ip_addr, veth = %veth_host, "veth pair created");
    Ok((ip_addr, veth_host))
}

// ── Container-side network (called inside child process) ──────────────────────

pub fn setup_container_interface(ip_addr: &str, gateway: &str) {
    let _ = Command::new("ip").args(&["link", "set", "lo", "up"]).status();
    let _ = Command::new("ip")
    .args(&["link", "set", "veth-c", "name", "eth0"])
    .status();
    let _ = Command::new("ip")
    .args(&["addr", "add", &format!("{}/24", ip_addr), "dev", "eth0"])
    .status();
    let _ = Command::new("ip").args(&["link", "set", "eth0", "up"]).status();
    let _ = Command::new("ip")
    .args(&["route", "add", "default", "via", gateway])
    .status();
}

// ── Port forwarding ───────────────────────────────────────────────────────────

pub fn setup_port_forwarding(rules: &[String], container_ip: &str) -> Result<()> {
    for rule in rules {
        let (host_port, container_port, proto) = parse_port_rule(rule)?;

        let check = Command::new("iptables")
        .args(&[
            "-t", "nat", "-C", "PREROUTING",
            "-p", &proto, "--dport", &host_port,
            "-j", "DNAT",
            "--to-destination",
            &format!("{}:{}", container_ip, container_port),
        ])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

        if !check {
            Command::new("iptables")
            .args(&[
                "-t", "nat", "-A", "PREROUTING",
                "-p", &proto, "--dport", &host_port,
                "-j", "DNAT",
                "--to-destination",
                &format!("{}:{}", container_ip, container_port),
            ])
            .status()
            .into_diagnostic()
            .wrap_err_with(|| format!("Failed to add port rule {}", rule))?;
            info!(rule, "Port forwarding rule added");
        }

        let fwd_check = Command::new("iptables")
        .args(&[
            "-C", "FORWARD",
            "-d", container_ip,
            "-p", &proto,
            "--dport", &container_port,
            "-j", "ACCEPT",
        ])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

        if !fwd_check {
            let _ = Command::new("iptables")
            .args(&[
                "-A", "FORWARD",
                "-d", container_ip,
                "-p", &proto,
                "--dport", &container_port,
                "-j", "ACCEPT",
            ])
            .status();
        }
    }
    Ok(())
}

pub fn cleanup_port_forwarding(rules: &[String], container_ip: &str) {
    for rule in rules {
        let Ok((host_port, container_port, proto)) = parse_port_rule(rule) else {
            continue;
        };
        let _ = Command::new("iptables")
        .args(&[
            "-t", "nat", "-D", "PREROUTING",
            "-p", &proto, "--dport", &host_port,
            "-j", "DNAT",
            "--to-destination",
            &format!("{}:{}", container_ip, container_port),
        ])
        .status();
        let _ = Command::new("iptables")
        .args(&[
            "-D", "FORWARD",
            "-d", container_ip,
            "-p", &proto,
            "--dport", &container_port,
            "-j", "ACCEPT",
        ])
        .status();
    }
}

fn parse_port_rule(rule: &str) -> Result<(String, String, String)> {
    let parts: Vec<&str> = rule.splitn(2, ':').collect();
    if parts.len() != 2 {
        return Err(miette!(
            "Invalid port rule '{}': expected host:container",
            rule
        ));
    }
    let host_port = parts[0].to_string();
    let (container_port, proto) = if let Some((p, pr)) = parts[1].rsplit_once('/') {
        (p.to_string(), pr.to_lowercase())
    } else {
        (parts[1].to_string(), "tcp".to_string())
    };
    Ok((host_port, container_port, proto))
}

// ── CNI ───────────────────────────────────────────────────────────────────────

pub fn setup_cni(network_name: &str, container_id: &str) -> Result<()> {
    let netns_path = format!("/var/run/netns/{}", container_id);
    if !Path::new(&netns_path).exists() {
        Command::new("ip")
        .args(&["netns", "add", container_id])
        .status()
        .into_diagnostic()
        .wrap_err("Failed to create network namespace")?;
    }
    let output = Command::new("cnitool")
    .args(&["add", network_name, &netns_path])
    .output()
    .into_diagnostic()
    .wrap_err("Failed to execute cnitool add")?;
    if !output.status.success() {
        return Err(miette!(
            "CNI add failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(())
}

pub fn cleanup_cni(network_name: &str, container_id: &str) {
    let netns_path = format!("/var/run/netns/{}", container_id);
    let _ = Command::new("cnitool")
    .args(&["del", network_name, &netns_path])
    .output();
    let _ = Command::new("ip")
    .args(&["netns", "del", container_id])
    .status();
}
