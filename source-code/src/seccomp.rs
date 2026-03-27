use std::fs;
use libseccomp::{ScmpAction, ScmpFilter};
use miette::{miette, Result};

pub fn apply_seccomp(profile_path: &str) -> Result<()> {
    let content = fs::read_to_string(profile_path)
    .map_err(|e| miette!("Failed to read seccomp profile: {}", e))?;
    let profile: SeccompProfile = serde_json::from_str(&content)
    .map_err(|e| miette!("Invalid seccomp profile: {}", e))?;
    let mut filter = ScmpFilter::new(str_to_scmp_action(&profile.default_action))?;
    for arch in profile.architectures {
        filter.add_arch(str_to_scmp_arch(&arch))?;
    }
    for syscall in profile.syscalls {
        let action = str_to_scmp_action(&syscall.action);
        for name in syscall.names {
            filter.add_rule(action, name)?;
        }
    }
    filter.load()?;
    Ok(())
}

#[derive(serde::Deserialize)]
struct SeccompProfile {
    default_action: String,
        architectures: Vec<String>,
        syscalls: Vec<SyscallRule>,
}

#[derive(serde::Deserialize)]
struct SyscallRule {
    names: Vec<String>,
    action: String,
}

fn str_to_scmp_action(s: &str) -> ScmpAction {
    match s {
        "SCMP_ACT_ALLOW" => ScmpAction::Allow,
        "SCMP_ACT_ERRNO" => ScmpAction::Errno(1),
        _ => ScmpAction::Allow,
    }
}

fn str_to_scmp_arch(s: &str) -> libseccomp::ScmpArch {
    match s {
        "x86_64" => libseccomp::ScmpArch::X86_64,
        "aarch64" => libseccomp::ScmpArch::AARCH64,
        _ => libseccomp::ScmpArch::Native,
    }
}
