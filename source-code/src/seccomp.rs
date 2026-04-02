use std::fs;
use libseccomp::{ScmpAction, ScmpArch, ScmpFilterContext, ScmpSyscall};
use miette::{miette, Result};

pub fn apply_seccomp(profile_path: &str) -> Result<()> {
    let content = fs::read_to_string(profile_path)
    .map_err(|e| miette!("Failed to read seccomp profile: {}", e))?;

    let profile: SeccompProfile = serde_json::from_str(&content)
    .map_err(|e| miette!("Invalid seccomp profile: {}", e))?;

    let default_action = str_to_scmp_action(&profile.default_action);

    let mut filter = ScmpFilterContext::new_filter(default_action)
    .map_err(|e| miette!("Failed to create seccomp filter: {}", e))?;

    for arch in &profile.architectures {
        filter
        .add_arch(str_to_scmp_arch(arch))
        .map_err(|e| miette!("Failed to add arch {}: {}", arch, e))?;
    }

    for syscall_rule in &profile.syscalls {
        let action = str_to_scmp_action(&syscall_rule.action);
        for name in &syscall_rule.names {
            let syscall = ScmpSyscall::from_name(name)
            .map_err(|e| miette!("Unknown syscall '{}': {}", name, e))?;
            filter
            .add_rule(action, syscall)
            .map_err(|e| miette!("Failed to add rule for '{}': {}", name, e))?;
        }
    }

    filter
    .load()
    .map_err(|e| miette!("Failed to load seccomp filter: {}", e))?;

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
        "SCMP_ACT_KILL"  => ScmpAction::KillThread,
        "SCMP_ACT_KILL_PROCESS" => ScmpAction::KillProcess,
        "SCMP_ACT_TRAP"  => ScmpAction::Trap,
        "SCMP_ACT_LOG"   => ScmpAction::Log,
        "SCMP_ACT_ERRNO" => ScmpAction::Errno(libc::EPERM as u32),
        s if s.starts_with("SCMP_ACT_ERRNO(") => {
            let n: u32 = s
            .trim_start_matches("SCMP_ACT_ERRNO(")
            .trim_end_matches(')')
            .parse()
            .unwrap_or(libc::EPERM as u32);
            ScmpAction::Errno(n)
        }
        _ => ScmpAction::Allow,
    }
}

fn str_to_scmp_arch(s: &str) -> ScmpArch {
    match s {
        "SCMP_ARCH_X86"        => ScmpArch::X86,
        "SCMP_ARCH_X86_64" | "x86_64" => ScmpArch::X8664,
        "SCMP_ARCH_X32"        => ScmpArch::X32,
        "SCMP_ARCH_ARM"        => ScmpArch::Arm,
        "SCMP_ARCH_AARCH64" | "aarch64" => ScmpArch::Aarch64,
        "SCMP_ARCH_MIPS"       => ScmpArch::Mips,
        "SCMP_ARCH_MIPS64"     => ScmpArch::Mips64,
        "SCMP_ARCH_PPC64LE"    => ScmpArch::Ppc64Le,
        "SCMP_ARCH_S390X"      => ScmpArch::S390X,
        _ => ScmpArch::Native,
    }
}
