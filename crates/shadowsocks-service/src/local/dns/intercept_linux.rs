//! Linux/OpenWrt DNS interception helpers.
//!
//! This module intentionally keeps interception opt-in. It changes host firewall
//! state and therefore only runs when `route_rules.dns_intercept_mode` requests
//! firewall mode.

use std::{
    fs::{self, File},
    io::{self, Write},
    net::IpAddr,
    path::Path,
    process::{Command, Stdio},
};

use ipnet::IpNet;
use log::{info, warn};

use crate::local::routing::RouteDecision;

const NFT_TABLE: &str = "ssrust_dns";
const DIRECT4_SET: &str = "direct4";
const DIRECT6_SET: &str = "direct6";
const BYPASS4_SET: &str = "bypass4";
const BYPASS6_SET: &str = "bypass6";

pub struct DnsInterceptGuard {
    backend: Backend,
}

enum Backend {
    Nft,
    Iptables { port: u16, exempt_ips: Vec<IpAddr> },
}

impl Drop for DnsInterceptGuard {
    fn drop(&mut self) {
        match self.backend {
            Backend::Nft => {
                let _ = command("nft", &["delete", "table", "inet", NFT_TABLE]);
            }
            Backend::Iptables { port, ref exempt_ips } => {
                cleanup_iptables(port, exempt_ips);
            }
        }
    }
}

pub fn setup_firewall_redirect(port: u16, dns_exempt_ips: &[IpAddr]) -> io::Result<DnsInterceptGuard> {
    match setup_nft(port, dns_exempt_ips) {
        Ok(()) => {
            info!("installed nftables DNS interception rules on local port {}", port);
            Ok(DnsInterceptGuard { backend: Backend::Nft })
        }
        Err(nft_err) => {
            warn!("failed to install nftables DNS interception rules: {}", nft_err);
            setup_iptables(port, dns_exempt_ips)?;
            info!("installed iptables DNS interception rules on local port {}", port);
            Ok(DnsInterceptGuard {
                backend: Backend::Iptables {
                    port,
                    exempt_ips: dns_exempt_ips.to_vec(),
                },
            })
        }
    }
}

pub fn add_route_ips(decision: RouteDecision, ips: &[IpAddr]) -> io::Result<()> {
    if ips.is_empty() {
        return Ok(());
    }
    ensure_nft_sets()?;
    for ip in ips {
        let set_name = match (decision, ip) {
            (RouteDecision::Direct, IpAddr::V4(..)) => DIRECT4_SET,
            (RouteDecision::Direct, IpAddr::V6(..)) => DIRECT6_SET,
            (RouteDecision::Proxy, IpAddr::V4(..)) => BYPASS4_SET,
            (RouteDecision::Proxy, IpAddr::V6(..)) => BYPASS6_SET,
        };
        // Ignore duplicate element errors. The rule files remain the source of truth.
        let _ = command(
            "nft",
            &[
                "add",
                "element",
                "inet",
                NFT_TABLE,
                set_name,
                "{",
                &ip.to_string(),
                "}",
            ],
        );
    }
    Ok(())
}

pub fn add_route_nets(decision: RouteDecision, nets: &[IpNet]) -> io::Result<()> {
    if nets.is_empty() {
        return Ok(());
    }
    ensure_nft_sets()?;
    for net in nets {
        let set_name = match (decision, net) {
            (RouteDecision::Direct, IpNet::V4(..)) => DIRECT4_SET,
            (RouteDecision::Direct, IpNet::V6(..)) => DIRECT6_SET,
            (RouteDecision::Proxy, IpNet::V4(..)) => BYPASS4_SET,
            (RouteDecision::Proxy, IpNet::V6(..)) => BYPASS6_SET,
        };
        let _ = command(
            "nft",
            &[
                "add",
                "element",
                "inet",
                NFT_TABLE,
                set_name,
                "{",
                &net.to_string(),
                "}",
            ],
        );
    }
    Ok(())
}

pub fn remove_route_ips(decision: RouteDecision, ips: &[IpAddr]) -> io::Result<()> {
    if ips.is_empty() {
        return Ok(());
    }
    ensure_nft_sets()?;
    for ip in ips {
        let set_name = match (decision, ip) {
            (RouteDecision::Direct, IpAddr::V4(..)) => DIRECT4_SET,
            (RouteDecision::Direct, IpAddr::V6(..)) => DIRECT6_SET,
            (RouteDecision::Proxy, IpAddr::V4(..)) => BYPASS4_SET,
            (RouteDecision::Proxy, IpAddr::V6(..)) => BYPASS6_SET,
        };
        let _ = command(
            "nft",
            &[
                "delete",
                "element",
                "inet",
                NFT_TABLE,
                set_name,
                "{",
                &ip.to_string(),
                "}",
            ],
        );
    }
    Ok(())
}

pub fn replace_route_nets(work_dir: &Path, direct: &[IpNet], bypass: &[IpNet]) -> io::Result<()> {
    ensure_nft_sets()?;
    let script_path = work_dir.join(format!("ssrust-nft-sync-{}.nft", std::process::id()));
    {
        let mut script = File::create(&script_path)?;
        for set_name in [DIRECT4_SET, DIRECT6_SET, BYPASS4_SET, BYPASS6_SET] {
            writeln!(script, "flush set inet {NFT_TABLE} {set_name}")?;
        }
        write_add_elements(&mut script, RouteDecision::Direct, direct)?;
        write_add_elements(&mut script, RouteDecision::Proxy, bypass)?;
    }
    let result = command("nft", &["-f", &script_path.to_string_lossy()]);
    let _ = fs::remove_file(script_path);
    result
}

fn write_add_elements(file: &mut File, decision: RouteDecision, nets: &[IpNet]) -> io::Result<()> {
    for (set_name, family_nets) in [
        (
            match decision {
                RouteDecision::Direct => DIRECT4_SET,
                RouteDecision::Proxy => BYPASS4_SET,
            },
            nets.iter().filter(|net| matches!(net, IpNet::V4(..))).collect::<Vec<_>>(),
        ),
        (
            match decision {
                RouteDecision::Direct => DIRECT6_SET,
                RouteDecision::Proxy => BYPASS6_SET,
            },
            nets.iter().filter(|net| matches!(net, IpNet::V6(..))).collect::<Vec<_>>(),
        ),
    ] {
        for chunk in family_nets.chunks(512) {
            if chunk.is_empty() {
                continue;
            }
            write!(file, "add element inet {NFT_TABLE} {set_name} {{ ")?;
            for (idx, net) in chunk.iter().enumerate() {
                if idx > 0 {
                    write!(file, ", ")?;
                }
                write!(file, "{net}")?;
            }
            writeln!(file, " }}")?;
        }
    }
    Ok(())
}

fn setup_nft(port: u16, dns_exempt_ips: &[IpAddr]) -> io::Result<()> {
    let _ = command("nft", &["delete", "table", "inet", NFT_TABLE]);
    command("nft", &["add", "table", "inet", NFT_TABLE])?;
    add_nft_sets()?;
    command(
        "nft",
        &[
            "add",
            "chain",
            "inet",
            NFT_TABLE,
            "prerouting",
            "{",
            "type",
            "nat",
            "hook",
            "prerouting",
            "priority",
            "dstnat",
            ";",
            "}",
        ],
    )?;
    command(
        "nft",
        &[
            "add", "chain", "inet", NFT_TABLE, "output", "{", "type", "nat", "hook", "output", "priority", "dstnat",
            ";", "}",
        ],
    )?;
    for proto in ["udp", "tcp"] {
        command(
            "nft",
            &[
                "add",
                "rule",
                "inet",
                NFT_TABLE,
                "prerouting",
                proto,
                "dport",
                "53",
                "redirect",
                "to",
                &format!(":{port}"),
            ],
        )?;
        for ip in dns_exempt_ips {
            let family_expr = match ip {
                IpAddr::V4(..) => "ip",
                IpAddr::V6(..) => "ip6",
            };
            command(
                "nft",
                &[
                    "add",
                    "rule",
                    "inet",
                    NFT_TABLE,
                    "output",
                    family_expr,
                    "daddr",
                    &ip.to_string(),
                    proto,
                    "dport",
                    "53",
                    "return",
                ],
            )?;
        }
        command(
            "nft",
            &[
                "add",
                "rule",
                "inet",
                NFT_TABLE,
                "output",
                proto,
                "dport",
                "53",
                "redirect",
                "to",
                &format!(":{port}"),
            ],
        )?;
    }
    Ok(())
}

fn ensure_nft_sets() -> io::Result<()> {
    if command("nft", &["list", "table", "inet", NFT_TABLE]).is_err() {
        command("nft", &["add", "table", "inet", NFT_TABLE])?;
    }
    add_nft_sets()
}

fn add_nft_sets() -> io::Result<()> {
    for (name, kind) in [
        (DIRECT4_SET, "ipv4_addr"),
        (DIRECT6_SET, "ipv6_addr"),
        (BYPASS4_SET, "ipv4_addr"),
        (BYPASS6_SET, "ipv6_addr"),
    ] {
        let _ = command(
            "nft",
            &[
                "add",
                "set",
                "inet",
                NFT_TABLE,
                name,
                "{",
                "type",
                kind,
                ";",
                "flags",
                "interval",
                ";",
                "}",
            ],
        );
    }
    Ok(())
}

fn setup_iptables(port: u16, dns_exempt_ips: &[IpAddr]) -> io::Result<()> {
    cleanup_iptables(port, dns_exempt_ips);
    for proto in ["udp", "tcp"] {
        command(
            "iptables",
            &[
                "-t",
                "nat",
                "-A",
                "PREROUTING",
                "-p",
                proto,
                "--dport",
                "53",
                "-j",
                "REDIRECT",
                "--to-ports",
                &port.to_string(),
            ],
        )?;
        for ip in dns_exempt_ips {
            command(
                "iptables",
                &[
                    "-t",
                    "nat",
                    "-A",
                    "OUTPUT",
                    "-p",
                    proto,
                    "-d",
                    &ip.to_string(),
                    "--dport",
                    "53",
                    "-j",
                    "RETURN",
                ],
            )?;
        }
        command(
            "iptables",
            &[
                "-t",
                "nat",
                "-A",
                "OUTPUT",
                "-p",
                proto,
                "--dport",
                "53",
                "-j",
                "REDIRECT",
                "--to-ports",
                &port.to_string(),
            ],
        )?;
    }
    Ok(())
}

fn cleanup_iptables(port: u16, dns_exempt_ips: &[IpAddr]) {
    for proto in ["udp", "tcp"] {
        let _ = command(
            "iptables",
            &[
                "-t",
                "nat",
                "-D",
                "PREROUTING",
                "-p",
                proto,
                "--dport",
                "53",
                "-j",
                "REDIRECT",
                "--to-ports",
                &port.to_string(),
            ],
        );
        for ip in dns_exempt_ips {
            let _ = command(
                "iptables",
                &[
                    "-t",
                    "nat",
                    "-D",
                    "OUTPUT",
                    "-p",
                    proto,
                    "-d",
                    &ip.to_string(),
                    "--dport",
                    "53",
                    "-j",
                    "RETURN",
                ],
            );
        }
        let _ = command(
            "iptables",
            &[
                "-t",
                "nat",
                "-D",
                "OUTPUT",
                "-p",
                proto,
                "--dport",
                "53",
                "-j",
                "REDIRECT",
                "--to-ports",
                &port.to_string(),
            ],
        );
    }
}

fn command(program: &str, args: &[&str]) -> io::Result<()> {
    let status = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!("{program} exited with {status}")))
    }
}

