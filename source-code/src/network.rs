use std::process::Command;
use miette::{miette, IntoDiagnostic, Result};
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;

pub fn setup_bridge(bridge_name: &str, gateway: &str) -> Result<()> {
    // ip link add hkbr0 type bridge
    Command::new("ip").args(&["link", "add", "name", bridge_name, "type", "bridge"]).status().ok();
    Command::new("ip").args(&["link", "set", bridge_name, "up"]).status().ok();
    Command::new("ip").args(&["addr", "add", gateway, "dev", bridge_name]).status().ok();
    
    // NAT
    Command::new("sysctl").args(&["-w", "net.ipv4.ip_forward=1"]).status().ok();
    // Simplified Masquerade
    Command::new("iptables").args(&["-t", "nat", "-A", "POSTROUTING", "-s", "10.10.0.0/24", "!", "-d", "10.10.0.0/24", "-j", "MASQUERADE"]).status().ok();
    Ok(())
}

pub fn create_veth_pair(pid: Pid, suffix: u8) -> Result<(String, String)> {
    let bridge = "hkbr0";
    let veth_host = format!("veth{}", pid);
    let veth_peer = "veth-c"; 
    let ip_addr = format!("10.10.0.{}", suffix);

    Command::new("ip").args(&["link", "add", &veth_host, "type", "veth", "peer", "name", veth_peer]).status().into_diagnostic()?;
    Command::new("ip").args(&["link", "set", &veth_host, "master", bridge]).status().into_diagnostic()?;
    Command::new("ip").args(&["link", "set", &veth_host, "up"]).status().into_diagnostic()?;
    Command::new("ip").args(&["link", "set", veth_peer, "netns", &pid.as_raw().to_string()]).status().into_diagnostic()?;

    Ok((ip_addr, veth_host))
}

pub fn setup_container_interface(ip_addr: &str, gateway: &str) {
    Command::new("ip").args(&["link", "set", "lo", "up"]).status().ok();
    Command::new("ip").args(&["link", "set", "veth-c", "name", "eth0"]).status().ok();
    Command::new("ip").args(&["addr", "add", &format!("{}/24", ip_addr), "dev", "eth0"]).status().ok();
    Command::new("ip").args(&["link", "set", "eth0", "up"]).status().ok();
    Command::new("ip").args(&["route", "add", "default", "via", gateway]).status().ok();
}

pub fn setup_port_forwarding(rules: &[String], container_ip: &str) -> Result<()> {
    for rule in rules {
        // rule: "8080:80"
        let parts: Vec<&str> = rule.split(':').collect();
        if parts.len() != 2 { continue; }
        let host_port = parts[0];
        let container_port = parts[1];

        // iptables -t nat -A PREROUTING -p tcp --dport <host> -j DNAT --to-destination <container>:<port>
        Command::new("iptables")
            .args(&["-t", "nat", "-A", "PREROUTING", "-p", "tcp", "--dport", host_port, 
                    "-j", "DNAT", "--to-destination", &format!("{}:{}", container_ip, container_port)])
            .status()
            .into_diagnostic()?;
    }
    Ok(())
}

pub fn cleanup_port_forwarding(rules: &[String], container_ip: &str) {
    for rule in rules {
         let parts: Vec<&str> = rule.split(':').collect();
         if parts.len() != 2 { continue; }
         Command::new("iptables")
            .args(&["-t", "nat", "-D", "PREROUTING", "-p", "tcp", "--dport", parts[0], 
                    "-j", "DNAT", "--to-destination", &format!("{}:{}", container_ip, parts[1])])
            .status().ok();
    }
}
