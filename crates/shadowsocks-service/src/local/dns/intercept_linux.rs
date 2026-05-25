//! Linux/OpenWrt DNS interception helpers.
//!
//! This module intentionally keeps interception opt-in. It changes host firewall
//! state and therefore only runs when `route_rules.dns_intercept_mode` requests
//! firewall mode.

use std::{
    io,
    net::IpAddr,
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
    Iptables { port: u16, uid: u32 },
}

impl Drop for DnsInterceptGuard {
    fn drop(&mut self) {
        match self.backend {
            Backend::Nft => {
                let _ = command("nft", &["delete", "table", "inet", NFT_TABLE]);
            }
            Backend::Iptables { port, uid } => {
                cleanup_iptables(port, uid);
            }
        }
    }
}

pub fn setup_firewall_redirect(port: u16) -> io::Result<DnsInterceptGuard> {
    let uid = current_uid();
    match setup_nft(port, uid) {
        Ok(()) => {
            info!("installed nftables DNS interception rules on local port {}", port);
            Ok(DnsInterceptGuard { backend: Backend::Nft })
        }
        Err(nft_err) => {
            warn!("failed to install nftables DNS interception rules: {}", nft_err);
            setup_iptables(port, uid)?;
            info!("installed iptables DNS interception rules on local port {}", port);
            Ok(DnsInterceptGuard {
                backend: Backend::Iptables { port, uid },
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

pub fn replace_route_nets(direct: &[IpNet], bypass: &[IpNet]) -> io::Result<()> {
    ensure_nft_sets()?;
    for set_name in [DIRECT4_SET, DIRECT6_SET, BYPASS4_SET, BYPASS6_SET] {
        let _ = command("nft", &["flush", "set", "inet", NFT_TABLE, set_name]);
    }
    add_route_nets(RouteDecision::Direct, direct)?;
    add_route_nets(RouteDecision::Proxy, bypass)
}

fn add_route_nets(decision: RouteDecision, nets: &[IpNet]) -> io::Result<()> {
    for net in nets {
        let set_name = match (decision, net) {
            (RouteDecision::Direct, IpNet::V4(..)) => DIRECT4_SET,
            (RouteDecision::Direct, IpNet::V6(..)) => DIRECT6_SET,
            (RouteDecision::Proxy, IpNet::V4(..)) => BYPASS4_SET,
            (RouteDecision::Proxy, IpNet::V6(..)) => BYPASS6_SET,
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
                &net.to_string(),
                "}",
            ],
        );
    }
    Ok(())
}

fn setup_nft(port: u16, uid: u32) -> io::Result<()> {
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
        command(
            "nft",
            &[
                "add",
                "rule",
                "inet",
                NFT_TABLE,
                "output",
                "meta",
                "skuid",
                "!=",
                &uid.to_string(),
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

fn setup_iptables(port: u16, uid: u32) -> io::Result<()> {
    cleanup_iptables(port, uid);
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
                "-m",
                "owner",
                "!",
                "--uid-owner",
                &uid.to_string(),
                "-j",
                "REDIRECT",
                "--to-ports",
                &port.to_string(),
            ],
        )?;
    }
    Ok(())
}

fn cleanup_iptables(port: u16, uid: u32) {
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
                "-m",
                "owner",
                "!",
                "--uid-owner",
                &uid.to_string(),
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

fn current_uid() -> u32 {
    unsafe { libc::geteuid() }
}
