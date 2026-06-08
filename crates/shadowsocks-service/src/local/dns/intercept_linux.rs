//! Linux/OpenWrt DNS interception helpers.
//!
//! This module intentionally keeps interception opt-in. It changes host firewall
//! state and therefore only runs when `route_rules.dns_intercept_mode` requests
//! firewall mode.

use std::{
    fmt::Write as _,
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
const PROXY4_SET: &str = "proxy4";
const PROXY6_SET: &str = "proxy6";

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

/// Best-effort removal of any leftover `inet ssrust_dns` nft table from a
/// previous run. Called at startup when the current config does NOT enable
/// firewall-mode DNS interception, so that a SIGKILL'd / panicked previous
/// process can't leave the host in a half-redirected state where every DNS
/// query is steered at a port nothing is listening on.
///
/// Silent if the table doesn't exist or `nft` isn't installed.
pub fn cleanup_stale_nft_table() {
    // Probe first so the common "nothing to clean" case logs nothing.
    let status = Command::new("nft")
        .args(["list", "table", "inet", NFT_TABLE])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    match status {
        Ok(s) if s.success() => {
            if let Err(err) = command("nft", &["delete", "table", "inet", NFT_TABLE]) {
                warn!("failed to delete stale nft table {}: {}", NFT_TABLE, err);
            } else {
                info!("removed stale nft table inet {} from previous run", NFT_TABLE);
            }
        }
        _ => {}
    }
}

pub fn setup_firewall_redirect(
    port: u16,
    redir_port: Option<u16>,
    dns_exempt_ips: &[IpAddr],
    tcp_exempt_endpoints: &[(IpAddr, u16)],
) -> io::Result<DnsInterceptGuard> {
    match setup_nft(port, redir_port, dns_exempt_ips, tcp_exempt_endpoints) {
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
    // Build a single nft script that adds every IP in one fork+exec.
    // Previously this was N separate `nft add element` invocations — at
    // ~30-80ms per fork+exec on this hardware, an A record with 8 IPs
    // could take 600ms of wall clock and saturate the tokio worker that
    // runs the DNS handler. One `nft -f -` call handles the whole batch
    // in roughly the cost of a single invocation.
    let mut script = String::new();
    for (set_name, family_ips) in nft_set_buckets(decision, ips) {
        for chunk in family_ips.chunks(512) {
            if chunk.is_empty() {
                continue;
            }
            let _ = write!(&mut script, "add element inet {NFT_TABLE} {set_name} {{ ");
            for (idx, ip) in chunk.iter().enumerate() {
                if idx > 0 {
                    let _ = script.write_str(", ");
                }
                let _ = write!(&mut script, "{ip}");
            }
            let _ = script.write_str(" }\n");
        }
    }
    // `nft -f -` returns non-zero on any duplicate element. We want
    // duplicates to be ignored (rule files are the source of truth),
    // so map the failure to Ok — same semantics as the per-IP loop.
    let _ = nft_apply_script(&script);
    Ok(())
}

/// Group IPs by the nft set they belong to, returning one bucket per
/// (set_name, ipv4_or_ipv6_subset). Order is stable so the caller can
/// build a deterministic script.
fn nft_set_buckets(decision: RouteDecision, ips: &[IpAddr]) -> Vec<(&'static str, Vec<IpAddr>)> {
    let v4_set = match decision {
        RouteDecision::Direct => DIRECT4_SET,
        RouteDecision::Proxy => PROXY4_SET,
    };
    let v6_set = match decision {
        RouteDecision::Direct => DIRECT6_SET,
        RouteDecision::Proxy => PROXY6_SET,
    };
    let v4: Vec<IpAddr> = ips.iter().copied().filter(|ip| matches!(ip, IpAddr::V4(_))).collect();
    let v6: Vec<IpAddr> = ips.iter().copied().filter(|ip| matches!(ip, IpAddr::V6(_))).collect();
    let mut out = Vec::with_capacity(2);
    if !v4.is_empty() {
        out.push((v4_set, v4));
    }
    if !v6.is_empty() {
        out.push((v6_set, v6));
    }
    out
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
            (RouteDecision::Proxy, IpNet::V4(..)) => PROXY4_SET,
            (RouteDecision::Proxy, IpNet::V6(..)) => PROXY6_SET,
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
    // Same single-script optimisation as add_route_ips — see comment
    // there. `delete` of a missing element returns non-zero, which we
    // intentionally swallow.
    let mut script = String::new();
    for (set_name, family_ips) in nft_set_buckets(decision, ips) {
        for chunk in family_ips.chunks(512) {
            if chunk.is_empty() {
                continue;
            }
            let _ = write!(&mut script, "delete element inet {NFT_TABLE} {set_name} {{ ");
            for (idx, ip) in chunk.iter().enumerate() {
                if idx > 0 {
                    let _ = script.write_str(", ");
                }
                let _ = write!(&mut script, "{ip}");
            }
            let _ = script.write_str(" }\n");
        }
    }
    let _ = nft_apply_script(&script);
    Ok(())
}

/// Single fork+exec of `nft -f -` with the given script piped on stdin.
/// Returns Err if nft itself can't be spawned; non-zero exits are
/// returned as Err so callers can choose to swallow them (most callers
/// do, because duplicate-element errors are benign here).
fn nft_apply_script(script: &str) -> io::Result<()> {
    if script.is_empty() {
        return Ok(());
    }
    let mut child = Command::new("nft")
        .arg("-f")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(script.as_bytes())?;
    }
    let status = child.wait()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!("nft -f - exited with {status}")))
    }
}

pub fn replace_route_nets(work_dir: &Path, direct: &[IpNet], proxy: &[IpNet]) -> io::Result<()> {
    ensure_nft_sets()?;
    let script_path = work_dir.join(format!("ssrust-nft-sync-{}.nft", std::process::id()));
    {
        let mut script = File::create(&script_path)?;
        for set_name in [DIRECT4_SET, DIRECT6_SET, PROXY4_SET, PROXY6_SET] {
            writeln!(script, "flush set inet {NFT_TABLE} {set_name}")?;
        }
        write_add_elements(&mut script, RouteDecision::Direct, direct)?;
        write_add_elements(&mut script, RouteDecision::Proxy, proxy)?;
    }
    let result = command("nft", &["-f", &script_path.to_string_lossy()]);
    let _ = fs::remove_file(script_path);
    result
}

pub fn proxy_set_matches(input: &str) -> io::Result<Vec<String>> {
    let query = parse_debug_ip_query(input)?;
    let set_name = match query.family() {
        IpFamily::V4 => PROXY4_SET,
        IpFamily::V6 => PROXY6_SET,
    };
    let output = Command::new("nft")
        .args(["list", "set", "inet", NFT_TABLE, set_name])
        .stdin(Stdio::null())
        .output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!("nft list set exited with {}", output.status)));
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let mut matches = parse_nft_ip_nets(&text)
        .into_iter()
        .filter(|net| query.matches(net))
        .map(|net| net.to_string())
        .collect::<Vec<_>>();
    matches.sort();
    matches.dedup();
    Ok(matches)
}

#[derive(Clone, Copy, Debug)]
enum IpFamily {
    V4,
    V6,
}

#[derive(Clone, Debug)]
enum DebugIpQuery {
    Ip(IpAddr),
    Net(IpNet),
}

impl DebugIpQuery {
    fn family(&self) -> IpFamily {
        match self {
            DebugIpQuery::Ip(IpAddr::V4(..)) | DebugIpQuery::Net(IpNet::V4(..)) => IpFamily::V4,
            DebugIpQuery::Ip(IpAddr::V6(..)) | DebugIpQuery::Net(IpNet::V6(..)) => IpFamily::V6,
        }
    }

    fn matches(&self, net: &IpNet) -> bool {
        match self {
            DebugIpQuery::Ip(ip) => net.contains(ip),
            DebugIpQuery::Net(query_net) => ip_nets_overlap(query_net, net),
        }
    }
}

fn parse_debug_ip_query(input: &str) -> io::Result<DebugIpQuery> {
    let input = input.trim();
    if input.contains('/') {
        input
            .parse::<IpNet>()
            .map(DebugIpQuery::Net)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, format!("invalid cidr: {err}")))
    } else {
        input
            .parse::<IpAddr>()
            .map(DebugIpQuery::Ip)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, format!("invalid ip: {err}")))
    }
}

fn parse_nft_ip_nets(output: &str) -> Vec<IpNet> {
    output
        .split(|c: char| c.is_ascii_whitespace() || matches!(c, ',' | '{' | '}'))
        .filter_map(|token| {
            let token = token.trim_matches([';', '"']);
            if token.is_empty() || token.contains('-') {
                return None;
            }
            token
                .parse::<IpNet>()
                .ok()
                .or_else(|| token.parse::<IpAddr>().ok().map(IpNet::from))
        })
        .collect()
}

fn ip_nets_overlap(left: &IpNet, right: &IpNet) -> bool {
    match (left, right) {
        (IpNet::V4(left), IpNet::V4(right)) => left.contains(&right.network()) || right.contains(&left.network()),
        (IpNet::V6(left), IpNet::V6(right)) => left.contains(&right.network()) || right.contains(&left.network()),
        _ => false,
    }
}

fn write_add_elements(file: &mut File, decision: RouteDecision, nets: &[IpNet]) -> io::Result<()> {
    for (set_name, family_nets) in [
        (
            match decision {
                RouteDecision::Direct => DIRECT4_SET,
                RouteDecision::Proxy => PROXY4_SET,
            },
            nets.iter()
                .filter(|net| matches!(net, IpNet::V4(..)))
                .collect::<Vec<_>>(),
        ),
        (
            match decision {
                RouteDecision::Direct => DIRECT6_SET,
                RouteDecision::Proxy => PROXY6_SET,
            },
            nets.iter()
                .filter(|net| matches!(net, IpNet::V6(..)))
                .collect::<Vec<_>>(),
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

fn setup_nft(
    port: u16,
    redir_port: Option<u16>,
    dns_exempt_ips: &[IpAddr],
    tcp_exempt_endpoints: &[(IpAddr, u16)],
) -> io::Result<()> {
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
        if proto == "tcp"
            && let Some(redir_port) = redir_port
        {
            command(
                "nft",
                &[
                    "add",
                    "rule",
                    "inet",
                    NFT_TABLE,
                    "prerouting",
                    "ip",
                    "daddr",
                    "@proxy4",
                    "tcp",
                    "dport",
                    "!=",
                    "53",
                    "redirect",
                    "to",
                    &format!(":{redir_port}"),
                ],
            )?;
            command(
                "nft",
                &[
                    "add",
                    "rule",
                    "inet",
                    NFT_TABLE,
                    "prerouting",
                    "ip6",
                    "daddr",
                    "@proxy6",
                    "tcp",
                    "dport",
                    "!=",
                    "53",
                    "redirect",
                    "to",
                    &format!(":{redir_port}"),
                ],
            )?;
        }
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
        if proto == "tcp"
            && let Some(redir_port) = redir_port
        {
            for (ip, exempt_port) in tcp_exempt_endpoints {
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
                        "tcp",
                        "dport",
                        &exempt_port.to_string(),
                        "return",
                    ],
                )?;
            }

            // OUTPUT is required for Ubuntu's local-machine transparent proxy:
            // packets generated on the box itself never traverse PREROUTING.
            // The ssserver endpoint exemptions above keep OpenWrt safe from
            // redirecting sslocal/xray-plugin's own upstream TCP connection
            // back into the local redir listener.
            command(
                "nft",
                &[
                    "add",
                    "rule",
                    "inet",
                    NFT_TABLE,
                    "output",
                    "ip",
                    "daddr",
                    "@proxy4",
                    "tcp",
                    "dport",
                    "!=",
                    "53",
                    "redirect",
                    "to",
                    &format!(":{redir_port}"),
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
                    "ip6",
                    "daddr",
                    "@proxy6",
                    "tcp",
                    "dport",
                    "!=",
                    "53",
                    "redirect",
                    "to",
                    &format!(":{redir_port}"),
                ],
            )?;
        }
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
        (PROXY4_SET, "ipv4_addr"),
        (PROXY6_SET, "ipv6_addr"),
    ] {
        let _ = command(
            "nft",
            &[
                "add", "set", "inet", NFT_TABLE, name, "{", "type", kind, ";", "flags", "interval", ";", "}",
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
