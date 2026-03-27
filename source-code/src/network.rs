use std::process::Command;
use std::path::Path;
use miette::{miette, IntoDiagnostic, WrapErr, Result};
use nix::unistd::Pid;

pub fn setup_bridge(bridge_name: &str, gateway: &str) -> Result<()> {
    let bridge_exists = Command::new("ip")
    .args(&["link", "show", bridge_name])
    .output()
    .map(|o| o.status.success())
    .unwrap_or(false);

    if !bridge_exists {
        Command::new("ip")
        .args(&["link", "add", "name", bridge_name, "type", "bridge"])
        .status()
        .into_diagnostic()
        .wrap_err("Failed to create bridge")?;
    }

    Command::new("ip")
    .args(&["link", "set", bridge_name, "up"])
    .status()
    .into_diagnostic()
    .wrap_err("Failed to bring bridge up")?;

    Command::new("ip")
    .args(&["addr", "add", gateway, "dev", bridge_name])
    .status()
    .into_diagnostic()
    .wrap_err("Failed to assign gateway to bridge")?;

    Command::new("sysctl")
    .args(&["-w", "net.ipv4.ip_forward=1"])
    .status()
    .into_diagnostic()
    .wrap_err("Failed to enable IP forwarding")?;

    let check_rule = Command::new("iptables")
    .args(&["-t", "nat", "-C", "POSTROUTING", "-s", "10.10.0.0/24", "!", "-d", "10.10.0.0/24", "-j", "MASQUERADE"])
    .output()
    .map(|o| o.status.success())
    .unwrap_or(false);

    if !check_rule {
        Command::new("iptables")
        .args(&["-t", "nat", "-A", "POSTROUTING", "-s", "10.10.0.0/24", "!", "-d", "10.10.0.0/24", "-j", "MASQUERADE"])
        .status()
        .into_diagnostic()
        .wrap_err("Failed to add iptables MASQUERADE rule")?;
    }

    Ok(())
}

pub fn create_veth_pair(pid: Pid, suffix: u8) -> Result<(String, String)> {
    let bridge = "hkbr0";
    let veth_host = format!("veth{}", pid);
    let veth_peer = "veth-c";
    let ip_addr = format!("10.10.0.{}", suffix);

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

    Ok((ip_addr, veth_host))
}

pub fn setup_container_interface(ip_addr: &str, gateway: &str) {
    let _ = Command::new("ip").args(&["link", "set", "lo", "up"]).status();
    let _ = Command::new("ip").args(&["link", "set", "veth-c", "name", "eth0"]).status();
    let _ = Command::new("ip")
    .args(&["addr", "add", &format!("{}/24", ip_addr), "dev", "eth0"])
    .status();
    let _ = Command::new("ip").args(&["link", "set", "eth0", "up"]).status();
    let _ = Command::new("ip").args(&["route", "add", "default", "via", gateway]).status();
}

pub fn setup_port_forwarding(rules: &[String], container_ip: &str) -> Result<()> {
    for rule in rules {
        let parts: Vec<&str> = rule.split(':').collect();
        if parts.len() != 2 {
            continue;
        }
        let host_port = parts[0];
        let container_port = parts[1];

        let check = Command::new("iptables")
        .args(&[
            "-t", "nat", "-C", "PREROUTING", "-p", "tcp", "--dport", host_port,
            "-j", "DNAT", "--to-destination", &format!("{}:{}", container_ip, container_port),
        ])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

        if !check {
            Command::new("iptables")
            .args(&[
                "-t", "nat", "-A", "PREROUTING", "-p", "tcp", "--dport", host_port,
                "-j", "DNAT", "--to-destination", &format!("{}:{}", container_ip, container_port),
            ])
            .status()
            .into_diagnostic()
            .wrap_err("Failed to add port forwarding rule")?;
        }
    }
    Ok(())
}

pub fn cleanup_port_forwarding(rules: &[String], container_ip: &str) {
    for rule in rules {
        let parts: Vec<&str> = rule.split(':').collect();
        if parts.len() != 2 {
            continue;
        }
        let host_port = parts[0];
        let container_port = parts[1];
        let _ = Command::new("iptables")
        .args(&[
            "-t", "nat", "-D", "PREROUTING", "-p", "tcp", "--dport", host_port,
            "-j", "DNAT", "--to-destination", &format!("{}:{}", container_ip, container_port),
        ])
        .status();
    }
}

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
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(miette!("CNI add failed: {}", stderr));
    }

    Ok(())
}

pub fn cleanup_cni(network_name: &str, container_id: &str) -> Result<()> {
    let netns_path = format!("/var/run/netns/{}", container_id);
    let output = Command::new("cnitool")
    .args(&["del", network_name, &netns_path])
    .output()
    .into_diagnostic()
    .wrap_err("Failed to execute cnitool del")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(miette!("CNI del failed: {}", stderr));
    }

    let _ = Command::new("ip").args(&["netns", "del", container_id]).status();
    Ok(())
}
