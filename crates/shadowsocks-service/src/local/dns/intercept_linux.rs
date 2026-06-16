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
    sync::atomic::{AtomicBool, Ordering},
};

use ipnet::IpNet;
use log::{info, warn};

#[cfg(feature = "local-web-admin")]
use crate::local::routing::RouteDecision;

#[cfg(not(feature = "local-web-admin"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteDecision {
    Direct,
    Proxy,
}

const NFT_TABLE: &str = "ssrust_dns";
const DIRECT4_SET: &str = "direct4";
const DIRECT6_SET: &str = "direct6";
const PROXY4_SET: &str = "proxy4";
const PROXY6_SET: &str = "proxy6";
const CLIENT_PROXY4_SET: &str = "client_proxy4";
const CLIENT_PROXY6_SET: &str = "client_proxy6";
const CLIENT_DIRECT4_SET: &str = "client_direct4";
const CLIENT_DIRECT6_SET: &str = "client_direct6";
const TPROXY_PREROUTING_CHAIN: &str = "prerouting_tproxy";
const TPROXY_OUTPUT_CHAIN: &str = "output_tproxy";
const TPROXY_MARK: &str = "0x5355";
const TPROXY_TABLE: &str = "100";
const FIXED_DIRECT4_RULES: [&str; 10] = [
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "224.0.0.0/4",
    "240.0.0.0/4",
];
const FIXED_DIRECT6_RULES: [&str; 5] = ["::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8"];

static NFT_SETS_READY: AtomicBool = AtomicBool::new(false);

pub struct DnsInterceptGuard {
    backend: Backend,
}

#[derive(Clone, Debug, Default)]
pub struct ClientIpRules {
    pub global_proxy: Vec<IpAddr>,
    pub direct: Vec<IpAddr>,
}

enum Backend {
    Nft { udp_tproxy: bool },
    Iptables { port: u16, exempt_ips: Vec<IpAddr> },
}

impl Drop for DnsInterceptGuard {
    fn drop(&mut self) {
        match self.backend {
            Backend::Nft { udp_tproxy } => {
                NFT_SETS_READY.store(false, Ordering::Relaxed);
                let _ = command("nft", &["delete", "table", "inet", NFT_TABLE]);
                if udp_tproxy {
                    cleanup_tproxy_policy_routing();
                }
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
            NFT_SETS_READY.store(false, Ordering::Relaxed);
            if let Err(err) = command("nft", &["delete", "table", "inet", NFT_TABLE]) {
                warn!("failed to delete stale nft table {}: {}", NFT_TABLE, err);
            } else {
                info!("removed stale nft table inet {} from previous run", NFT_TABLE);
            }
        }
        _ => {}
    }
    cleanup_tproxy_policy_routing();
}

pub fn setup_firewall_redirect(
    port: u16,
    redir_port: Option<u16>,
    dns_exempt_ips: &[IpAddr],
    proxy_exempt_endpoints: &[(IpAddr, u16)],
    global_proxy: bool,
    proxy_local_output: bool,
    client_ip_rules: &ClientIpRules,
) -> io::Result<DnsInterceptGuard> {
    match setup_nft(
        port,
        redir_port,
        dns_exempt_ips,
        proxy_exempt_endpoints,
        global_proxy,
        proxy_local_output,
        client_ip_rules,
    ) {
        Ok(udp_tproxy) => {
            info!("installed nftables DNS interception rules on local port {}", port);
            if udp_tproxy && let Some(redir_port) = redir_port {
                info!("installed nftables UDP tproxy rules on local redir port {}", redir_port);
            }
            Ok(DnsInterceptGuard {
                backend: Backend::Nft { udp_tproxy },
            })
        }
        Err(nft_err) => {
            warn!("failed to install nftables DNS interception rules: {}", nft_err);
            cleanup_nft_tproxy_chains();
            cleanup_tproxy_policy_routing();
            NFT_SETS_READY.store(false, Ordering::Relaxed);
            let _ = command("nft", &["delete", "table", "inet", NFT_TABLE]);
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
    let _ = nft_apply_script_with_retry(&script);
    Ok(())
}

/// Logged at most once so a router without `conntrack-tools` doesn't spam.
static CONNTRACK_MISSING_WARNED: AtomicBool = AtomicBool::new(false);

/// Best-effort: drop conntrack entries whose original-direction destination is
/// one of `ips`, forcing the next packet of each such flow to be re-evaluated
/// by the prerouting redirect/tproxy rules. Without this, a connection
/// established *before* its destination IP entered the proxy set stays pinned
/// to its original (direct) verdict in conntrack and never switches to redir
/// until the application reconnects.
///
/// Uses the `conntrack` CLI (one `-D -d <ip>` per IP). Returning non-zero
/// (e.g. "0 flow entries deleted") is expected and ignored. If the binary is
/// not installed we log once and skip — on OpenWrt: `opkg install conntrack-tools`.
pub fn flush_conntrack_dst(ips: &[IpAddr]) {
    if ips.is_empty() || CONNTRACK_MISSING_WARNED.load(Ordering::Relaxed) {
        return;
    }
    for ip in ips {
        let ip_str = ip.to_string();
        match Command::new("conntrack")
            .args(["-D", "-d", &ip_str])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
        {
            Ok(_) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                if !CONNTRACK_MISSING_WARNED.swap(true, Ordering::Relaxed) {
                    warn!(
                        "conntrack binary not found; cannot re-evaluate established flows after \
                         proxy-set changes (install conntrack-tools). Newly opened connections are \
                         unaffected."
                    );
                }
                return;
            }
            Err(err) => warn!("failed to flush conntrack for {}: {}", ip_str, err),
        }
    }
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
    let _ = nft_apply_script_with_retry(&script);
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
        .stderr(Stdio::piped())
        .spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(script.as_bytes())?;
    }
    let output = child.wait_with_output()?;
    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stderr = stderr.trim();
        if stderr.is_empty() {
            Err(io::Error::other(format!("nft -f - exited with {}", output.status)))
        } else {
            Err(io::Error::other(format!("nft -f - exited with {}: {stderr}", output.status)))
        }
    }
}

fn nft_apply_script_with_retry(script: &str) -> io::Result<()> {
    match nft_apply_script(script) {
        Ok(()) => Ok(()),
        Err(err) if nft_error_looks_like_missing_table(&err) => {
            NFT_SETS_READY.store(false, Ordering::Relaxed);
            ensure_nft_sets_slow()?;
            nft_apply_script(script)
        }
        Err(err) => Err(err),
    }
}

fn nft_error_looks_like_missing_table(err: &io::Error) -> bool {
    let err = err.to_string();
    err.contains("No such file or directory") || err.contains("does not exist")
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
    let script_arg = script_path.to_string_lossy().to_string();
    let mut result = command("nft", &["-f", &script_arg]);
    if result.is_err() {
        NFT_SETS_READY.store(false, Ordering::Relaxed);
        if ensure_nft_sets_slow().is_ok() {
            result = command("nft", &["-f", &script_arg]);
        }
    }
    if result.is_ok() {
        NFT_SETS_READY.store(true, Ordering::Relaxed);
    }
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RouteSetCounts {
    pub direct4: usize,
    pub direct6: usize,
    pub proxy4: usize,
    pub proxy6: usize,
}

impl RouteSetCounts {
    pub fn direct_total(self) -> usize {
        self.direct4 + self.direct6
    }

    pub fn proxy_total(self) -> usize {
        self.proxy4 + self.proxy6
    }

    pub fn total(self) -> usize {
        self.direct_total() + self.proxy_total()
    }
}

pub fn route_set_counts() -> io::Result<RouteSetCounts> {
    let output = Command::new("nft")
        .args(["list", "table", "inet", NFT_TABLE])
        .stdin(Stdio::null())
        .output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "nft list table {} exited with {}",
            NFT_TABLE, output.status
        )));
    }
    let text = String::from_utf8_lossy(&output.stdout);
    Ok(RouteSetCounts {
        direct4: nft_set_entry_count_from_table(&text, DIRECT4_SET),
        direct6: nft_set_entry_count_from_table(&text, DIRECT6_SET),
        proxy4: nft_set_entry_count_from_table(&text, PROXY4_SET),
        proxy6: nft_set_entry_count_from_table(&text, PROXY6_SET),
    })
}

fn nft_set_entry_count_from_table(table: &str, set_name: &str) -> usize {
    let marker = format!("set {set_name} {{");
    let Some(start) = table.find(&marker) else {
        return 0;
    };
    let section = &table[start..];
    let end = section
        .find("\n\tset ")
        .or_else(|| section.find("\n    set "))
        .or_else(|| section.find("\n\tchain "))
        .or_else(|| section.find("\n    chain "))
        .unwrap_or(section.len());
    parse_nft_ip_nets(&section[..end]).len()
}

#[allow(dead_code)]
fn nft_set_entry_count(set_name: &str) -> io::Result<usize> {
    let output = Command::new("nft")
        .args(["list", "set", "inet", NFT_TABLE, set_name])
        .stdin(Stdio::null())
        .output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "nft list set {set_name} exited with {}",
            output.status
        )));
    }
    let text = String::from_utf8_lossy(&output.stdout);
    Ok(parse_nft_ip_nets(&text).len())
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
    proxy_exempt_endpoints: &[(IpAddr, u16)],
    global_proxy: bool,
    proxy_local_output: bool,
    client_ip_rules: &ClientIpRules,
) -> io::Result<bool> {
    NFT_SETS_READY.store(false, Ordering::Relaxed);
    let _ = command("nft", &["delete", "table", "inet", NFT_TABLE]);
    command("nft", &["add", "table", "inet", NFT_TABLE])?;
    add_nft_sets()?;
    NFT_SETS_READY.store(true, Ordering::Relaxed);
    add_fixed_direct_set_elements()?;
    add_client_ip_set_elements(client_ip_rules)?;
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
            add_proxy_endpoint_return_rules("prerouting", "tcp", proxy_exempt_endpoints)?;
            add_nft_tcp_redir_rule(
                "prerouting",
                "ip",
                "@proxy4",
                "@direct4",
                redir_port,
                global_proxy,
                Some(client_ip_rules),
            )?;
            add_nft_tcp_redir_rule(
                "prerouting",
                "ip6",
                "@proxy6",
                "@direct6",
                redir_port,
                global_proxy,
                Some(client_ip_rules),
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
        add_output_local_dns_return_rule(proto)?;
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
        if proxy_local_output
            && proto == "tcp"
            && let Some(redir_port) = redir_port
        {
            add_proxy_endpoint_return_rules("output", "tcp", proxy_exempt_endpoints)?;

            // OUTPUT is required for local-machine transparent proxy: packets
            // generated on the box itself never traverse PREROUTING. Fixed
            // direct ranges and server endpoint returns above must stay before
            // redirect rules so router management/LAN traffic and the proxy
            // transport itself cannot loop back into sslocal.
            add_nft_tcp_redir_rule("output", "ip", "@proxy4", "@direct4", redir_port, global_proxy, None)?;
            add_nft_tcp_redir_rule("output", "ip6", "@proxy6", "@direct6", redir_port, global_proxy, None)?;
        }
    }
    let udp_tproxy = if let Some(redir_port) = redir_port {
        match setup_nft_udp_tproxy(
            redir_port,
            proxy_exempt_endpoints,
            global_proxy,
            proxy_local_output,
            client_ip_rules,
        ) {
            Ok(()) => true,
            Err(err) => {
                warn!(
                    "failed to install nftables UDP tproxy rules on local redir port {}: {}",
                    redir_port, err
                );
                cleanup_nft_tproxy_chains();
                cleanup_tproxy_policy_routing();
                false
            }
        }
    } else {
        false
    };
    Ok(udp_tproxy)
}

fn add_nft_tcp_redir_rule(
    chain: &'static str,
    family_expr: &'static str,
    proxy_set_name: &'static str,
    direct_set_name: &'static str,
    redir_port: u16,
    global_proxy: bool,
    client_ip_rules: Option<&ClientIpRules>,
) -> io::Result<()> {
    add_fixed_direct_return_rules(chain, family_expr, "tcp")?;
    let redir_port_arg = format!(":{redir_port}");
    if let Some(client_ip_rules) = client_ip_rules {
        add_nft_client_direct_return_rule(chain, family_expr, "tcp", client_ip_rules)?;
        if !global_proxy {
            add_nft_client_tcp_redir_rule(chain, family_expr, redir_port, client_ip_rules)?;
        }
    }
    let mut args = vec!["add", "rule", "inet", NFT_TABLE, chain, family_expr, "daddr"];
    if global_proxy {
        args.extend(["!=", direct_set_name]);
    } else {
        args.push(proxy_set_name);
    }
    args.extend(["tcp", "dport", "!=", "53", "redirect", "to", &redir_port_arg]);
    command("nft", &args)
}

fn add_proxy_endpoint_return_rules(
    chain: &'static str,
    proto: &'static str,
    proxy_exempt_endpoints: &[(IpAddr, u16)],
) -> io::Result<()> {
    for (ip, exempt_port) in proxy_exempt_endpoints {
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
                chain,
                family_expr,
                "daddr",
                &ip.to_string(),
                proto,
                "dport",
                &exempt_port.to_string(),
                "return",
            ],
        )?;
    }
    Ok(())
}

fn add_nft_client_direct_return_rule(
    chain: &'static str,
    family_expr: &'static str,
    proto: &'static str,
    client_ip_rules: &ClientIpRules,
) -> io::Result<()> {
    if !client_rules_have_family(&client_ip_rules.direct, family_expr) {
        return Ok(());
    }
    let Some(set_name) = client_set_name(RouteDecision::Direct, family_expr) else {
        return Ok(());
    };
    command(
        "nft",
        &[
            "add", "rule", "inet", NFT_TABLE, chain, family_expr, "saddr", set_name, proto, "dport", "!=", "53",
            "return",
        ],
    )
}

fn add_output_local_dns_return_rule(proto: &'static str) -> io::Result<()> {
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
            "!=",
            "127.0.0.0/8",
            "fib",
            "daddr",
            "type",
            "local",
            proto,
            "dport",
            "53",
            "return",
        ],
    )?;
    command(
        "nft",
        &[
            "add", "rule", "inet", NFT_TABLE, "output", "ip6", "daddr", "!=", "::1", "fib", "daddr", "type",
            "local", proto, "dport", "53", "return",
        ],
    )
}

fn add_nft_client_tcp_redir_rule(
    chain: &'static str,
    family_expr: &'static str,
    redir_port: u16,
    client_ip_rules: &ClientIpRules,
) -> io::Result<()> {
    if !client_rules_have_family(&client_ip_rules.global_proxy, family_expr) {
        return Ok(());
    }
    let Some(set_name) = client_set_name(RouteDecision::Proxy, family_expr) else {
        return Ok(());
    };
    let redir_port_arg = format!(":{redir_port}");
    command(
        "nft",
        &[
            "add",
            "rule",
            "inet",
            NFT_TABLE,
            chain,
            family_expr,
            "saddr",
            set_name,
            "tcp",
            "dport",
            "!=",
            "53",
            "redirect",
            "to",
            &redir_port_arg,
        ],
    )
}

fn add_fixed_direct_return_rules(
    chain: &'static str,
    family_expr: &'static str,
    proto: &'static str,
) -> io::Result<()> {
    let rules = match family_expr {
        "ip" => &FIXED_DIRECT4_RULES[..],
        "ip6" => &FIXED_DIRECT6_RULES[..],
        _ => return Ok(()),
    };
    for rule in rules {
        command(
            "nft",
            &[
                "add",
                "rule",
                "inet",
                NFT_TABLE,
                chain,
                family_expr,
                "daddr",
                rule,
                proto,
                "dport",
                "!=",
                "53",
                "return",
            ],
        )?;
    }
    Ok(())
}

fn setup_nft_udp_tproxy(
    redir_port: u16,
    proxy_exempt_endpoints: &[(IpAddr, u16)],
    global_proxy: bool,
    proxy_local_output: bool,
    client_ip_rules: &ClientIpRules,
) -> io::Result<()> {
    setup_tproxy_policy_routing()?;
    command(
        "nft",
        &[
            "add",
            "chain",
            "inet",
            NFT_TABLE,
            TPROXY_PREROUTING_CHAIN,
            "{",
            "type",
            "filter",
            "hook",
            "prerouting",
            "priority",
            "mangle",
            ";",
            "}",
        ],
    )?;
    if proxy_local_output {
        command(
            "nft",
            &[
                "add",
                "chain",
                "inet",
                NFT_TABLE,
                TPROXY_OUTPUT_CHAIN,
                "{",
                "type",
                "route",
                "hook",
                "output",
                "priority",
                "mangle",
                ";",
                "}",
            ],
        )?;
    }
    add_proxy_endpoint_return_rules(TPROXY_PREROUTING_CHAIN, "udp", proxy_exempt_endpoints)?;
    add_nft_udp_tproxy_prerouting_rule(
        "ip",
        "@proxy4",
        "@direct4",
        "ip",
        redir_port,
        global_proxy,
        client_ip_rules,
    )?;
    add_nft_udp_tproxy_prerouting_rule(
        "ip6",
        "@proxy6",
        "@direct6",
        "ip6",
        redir_port,
        global_proxy,
        client_ip_rules,
    )?;
    if proxy_local_output {
        command(
            "nft",
            &[
                "add",
                "rule",
                "inet",
                NFT_TABLE,
                TPROXY_OUTPUT_CHAIN,
                "meta",
                "mark",
                TPROXY_MARK,
                "return",
            ],
        )?;
        add_proxy_endpoint_return_rules(TPROXY_OUTPUT_CHAIN, "udp", proxy_exempt_endpoints)?;
        add_nft_udp_tproxy_output_rule("ip", "@proxy4", "@direct4", global_proxy)?;
        add_nft_udp_tproxy_output_rule("ip6", "@proxy6", "@direct6", global_proxy)?;
    }
    Ok(())
}

fn add_nft_udp_tproxy_prerouting_rule(
    family_expr: &'static str,
    set_name: &'static str,
    direct_set_name: &'static str,
    tproxy_family: &'static str,
    redir_port: u16,
    global_proxy: bool,
    client_ip_rules: &ClientIpRules,
) -> io::Result<()> {
    add_fixed_direct_return_rules(TPROXY_PREROUTING_CHAIN, family_expr, "udp")?;
    let redir_port_arg = format!(":{redir_port}");
    add_nft_client_direct_return_rule(TPROXY_PREROUTING_CHAIN, family_expr, "udp", client_ip_rules)?;
    if !global_proxy {
        add_nft_client_udp_tproxy_rule(
            TPROXY_PREROUTING_CHAIN,
            family_expr,
            tproxy_family,
            redir_port,
            client_ip_rules,
        )?;
    }
    let mut args = vec![
        "add",
        "rule",
        "inet",
        NFT_TABLE,
        TPROXY_PREROUTING_CHAIN,
        family_expr,
        "daddr",
    ];
    if global_proxy {
        args.extend(["!=", direct_set_name]);
    } else {
        args.push(set_name);
    }
    args.extend([
        "udp",
        "dport",
        "!=",
        "53",
        "tproxy",
        tproxy_family,
        "to",
        &redir_port_arg,
        "meta",
        "mark",
        "set",
        TPROXY_MARK,
        "accept",
    ]);
    command("nft", &args)
}

fn add_nft_client_udp_tproxy_rule(
    chain: &'static str,
    family_expr: &'static str,
    tproxy_family: &'static str,
    redir_port: u16,
    client_ip_rules: &ClientIpRules,
) -> io::Result<()> {
    if !client_rules_have_family(&client_ip_rules.global_proxy, family_expr) {
        return Ok(());
    }
    let Some(set_name) = client_set_name(RouteDecision::Proxy, family_expr) else {
        return Ok(());
    };
    let redir_port_arg = format!(":{redir_port}");
    command(
        "nft",
        &[
            "add",
            "rule",
            "inet",
            NFT_TABLE,
            chain,
            family_expr,
            "saddr",
            set_name,
            "udp",
            "dport",
            "!=",
            "53",
            "tproxy",
            tproxy_family,
            "to",
            &redir_port_arg,
            "meta",
            "mark",
            "set",
            TPROXY_MARK,
            "accept",
        ],
    )
}

fn add_nft_udp_tproxy_output_rule(
    family_expr: &'static str,
    set_name: &'static str,
    direct_set_name: &'static str,
    global_proxy: bool,
) -> io::Result<()> {
    add_fixed_direct_return_rules(TPROXY_OUTPUT_CHAIN, family_expr, "udp")?;
    let mut args = vec![
        "add",
        "rule",
        "inet",
        NFT_TABLE,
        TPROXY_OUTPUT_CHAIN,
        family_expr,
        "daddr",
    ];
    if global_proxy {
        args.extend(["!=", direct_set_name]);
    } else {
        args.push(set_name);
    }
    args.extend(["udp", "dport", "!=", "53", "meta", "mark", "set", TPROXY_MARK]);
    command("nft", &args)
}

fn setup_tproxy_policy_routing() -> io::Result<()> {
    cleanup_tproxy_policy_routing();
    command("ip", &["rule", "add", "fwmark", TPROXY_MARK, "table", TPROXY_TABLE])?;
    command(
        "ip",
        &["route", "add", "local", "0.0.0.0/0", "dev", "lo", "table", TPROXY_TABLE],
    )?;
    if let Err(err) = command(
        "ip",
        &[
            "-6",
            "route",
            "add",
            "local",
            "::/0",
            "dev",
            "lo",
            "table",
            TPROXY_TABLE,
        ],
    ) {
        warn!("failed to install IPv6 UDP tproxy policy route: {}", err);
    }
    Ok(())
}

fn cleanup_tproxy_policy_routing() {
    while command("ip", &["rule", "del", "fwmark", TPROXY_MARK, "table", TPROXY_TABLE]).is_ok() {}
    let _ = command(
        "ip",
        &["route", "del", "local", "0.0.0.0/0", "dev", "lo", "table", TPROXY_TABLE],
    );
    let _ = command(
        "ip",
        &[
            "-6",
            "route",
            "del",
            "local",
            "::/0",
            "dev",
            "lo",
            "table",
            TPROXY_TABLE,
        ],
    );
}

fn cleanup_nft_tproxy_chains() {
    for chain in [TPROXY_PREROUTING_CHAIN, TPROXY_OUTPUT_CHAIN] {
        let _ = command("nft", &["flush", "chain", "inet", NFT_TABLE, chain]);
        let _ = command("nft", &["delete", "chain", "inet", NFT_TABLE, chain]);
    }
}

fn ensure_nft_sets() -> io::Result<()> {
    if NFT_SETS_READY.load(Ordering::Relaxed) {
        return Ok(());
    }
    ensure_nft_sets_slow()
}

fn ensure_nft_sets_slow() -> io::Result<()> {
    if command("nft", &["list", "table", "inet", NFT_TABLE]).is_err() {
        command("nft", &["add", "table", "inet", NFT_TABLE])?;
    }
    add_nft_sets()?;
    NFT_SETS_READY.store(true, Ordering::Relaxed);
    Ok(())
}

fn add_nft_sets() -> io::Result<()> {
    for (name, kind) in [
        (DIRECT4_SET, "ipv4_addr"),
        (DIRECT6_SET, "ipv6_addr"),
        (PROXY4_SET, "ipv4_addr"),
        (PROXY6_SET, "ipv6_addr"),
        (CLIENT_PROXY4_SET, "ipv4_addr"),
        (CLIENT_PROXY6_SET, "ipv6_addr"),
        (CLIENT_DIRECT4_SET, "ipv4_addr"),
        (CLIENT_DIRECT6_SET, "ipv6_addr"),
    ] {
        let _ = command(
            "nft",
            &[
                "add", "set", "inet", NFT_TABLE, name, "{", "type", kind, ";", "flags", "interval", ";",
                "auto-merge", ";", "}",
            ],
        );
    }
    Ok(())
}

fn add_client_ip_set_elements(client_ip_rules: &ClientIpRules) -> io::Result<()> {
    let mut script = String::new();
    write_add_ip_elements(&mut script, CLIENT_PROXY4_SET, &client_ip_rules.global_proxy, IpFamily::V4);
    write_add_ip_elements(&mut script, CLIENT_PROXY6_SET, &client_ip_rules.global_proxy, IpFamily::V6);
    write_add_ip_elements(&mut script, CLIENT_DIRECT4_SET, &client_ip_rules.direct, IpFamily::V4);
    write_add_ip_elements(&mut script, CLIENT_DIRECT6_SET, &client_ip_rules.direct, IpFamily::V6);
    nft_apply_script(&script)
}

fn write_add_ip_elements(script: &mut String, set_name: &str, ips: &[IpAddr], family: IpFamily) {
    let family_ips = ips
        .iter()
        .filter(|ip| matches!((family, ip), (IpFamily::V4, IpAddr::V4(..)) | (IpFamily::V6, IpAddr::V6(..))))
        .collect::<Vec<_>>();
    for chunk in family_ips.chunks(512) {
        if chunk.is_empty() {
            continue;
        }
        let _ = write!(script, "add element inet {NFT_TABLE} {set_name} {{ ");
        for (idx, ip) in chunk.iter().enumerate() {
            if idx > 0 {
                let _ = script.write_str(", ");
            }
            let _ = write!(script, "{ip}");
        }
        let _ = script.write_str(" }\n");
    }
}

fn client_rules_have_family(ips: &[IpAddr], family_expr: &str) -> bool {
    ips.iter().any(|ip| {
        matches!(
            (family_expr, ip),
            ("ip", IpAddr::V4(..)) | ("ip6", IpAddr::V6(..))
        )
    })
}

fn client_set_name(decision: RouteDecision, family_expr: &str) -> Option<&'static str> {
    match (decision, family_expr) {
        (RouteDecision::Direct, "ip") => Some("@client_direct4"),
        (RouteDecision::Direct, "ip6") => Some("@client_direct6"),
        (RouteDecision::Proxy, "ip") => Some("@client_proxy4"),
        (RouteDecision::Proxy, "ip6") => Some("@client_proxy6"),
        _ => None,
    }
}

fn add_fixed_direct_set_elements() -> io::Result<()> {
    let mut script = String::new();
    write_add_literal_elements(&mut script, DIRECT4_SET, &FIXED_DIRECT4_RULES);
    write_add_literal_elements(&mut script, DIRECT6_SET, &FIXED_DIRECT6_RULES);
    nft_apply_script(&script)
}

fn write_add_literal_elements(script: &mut String, set_name: &str, rules: &[&str]) {
    if rules.is_empty() {
        return;
    }
    let _ = write!(script, "add element inet {NFT_TABLE} {set_name} {{ ");
    for (idx, rule) in rules.iter().enumerate() {
        if idx > 0 {
            let _ = script.write_str(", ");
        }
        let _ = script.write_str(rule);
    }
    let _ = script.write_str(" }\n");
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
