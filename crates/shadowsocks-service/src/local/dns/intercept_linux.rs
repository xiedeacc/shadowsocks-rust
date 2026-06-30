//! Linux/OpenWrt DNS interception helpers.
//!
//! This module intentionally keeps interception opt-in. It changes host firewall
//! state and therefore only runs when `route_rules.dns_intercept_mode` requests
//! firewall mode.

use std::{
    fmt::Write as _,
    fs::{self, File},
    io::{self, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::Path,
    process::{Command, Stdio},
    sync::{
        Mutex, Once,
        atomic::{AtomicBool, Ordering},
    },
};

use ipnet::{IpNet, Ipv4Subnets, Ipv6Subnets};
use log::{info, warn};

#[cfg(feature = "local-web-admin")]
use crate::local::routing::RouteDecision;

#[cfg(not(feature = "local-web-admin"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteDecision {
    Direct,
    Proxy,
}

const NFT_TABLE: &str = "ssrust_redir";
const RESERVED4_SET: &str = "reserved4";
const RESERVED6_SET: &str = "reserved6";
const DIRECT4_SET: &str = "direct4";
const DIRECT6_SET: &str = "direct6";
const PROXY4_SET: &str = "proxy4";
const PROXY6_SET: &str = "proxy6";
const CLIENT_PROXY4_SET: &str = "client_proxy4";
const CLIENT_PROXY6_SET: &str = "client_proxy6";
const CLIENT_DIRECT4_SET: &str = "client_direct4";
const CLIENT_DIRECT6_SET: &str = "client_direct6";
const DNS_PREROUTING_CHAIN: &str = "prerouting_dns";
const DNS_OUTPUT_CHAIN: &str = "output_dns";
const TCP_PREROUTING_CHAIN: &str = "prerouting_tcp_redir";
const TCP_OUTPUT_CHAIN: &str = "output_tcp_redir";
const TPROXY_PREROUTING_CHAIN: &str = "prerouting_tproxy";
const TPROXY_OUTPUT_CHAIN: &str = "output_udp_mark";
const TPROXY_MARK: &str = "0x1";
const TPROXY_TABLE: &str = "100";
/// Dedicated fwmark applied to sslocal's OWN outbound sockets so the output
/// redirect/tproxy chains can exempt them by identity (`meta mark <mark> return`)
/// instead of by the SS server IP — which goes stale for a domain-name server
/// whose address rotates (audit H-5). Distinct from `TPROXY_MARK` so no
/// policy-routing `ip rule` matches it.
pub const LOCAL_OUTPUT_EXEMPT_MARK_DEFAULT: u32 = 0xff;
const FIXED_DIRECT4_RULES: [&str; 18] = [
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.0.2.0/24",
    "192.31.196.0/24",
    "192.52.193.0/24",
    "192.88.99.0/24",
    "192.168.0.0/16",
    "192.175.48.0/24",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "224.0.0.0/4",
    "240.0.0.0/4",
];
const FIXED_DIRECT6_RULES: [&str; 12] = [
    "::/128",
    "::1/128",
    "::ffff:0:0/96",
    "64:ff9b::/96",
    "64:ff9b:1::/48",
    "100::/64",
    "2001::/23",
    "2001:db8::/32",
    "2002::/16",
    "fc00::/7",
    "fe80::/10",
    "ff00::/8",
];

static NFT_SETS_READY: AtomicBool = AtomicBool::new(false);

/// Describes the host firewall state this process installed, so it can be torn
/// down even on an abnormal exit. `DnsInterceptGuard::drop` only runs on a
/// graceful shutdown; the release profile builds with `panic = "abort"`, so a
/// panic SIGABRTs the process *without* unwinding and Drop never fires. Left
/// alone, the `inet ssrust_redir` table would survive with its `dport 53 redirect`
/// / tproxy rules pointing at a now-dead listener — black-holing the whole LAN's
/// DNS. The panic hook below restores the pristine firewall before the abort.
#[derive(Clone)]
enum EmergencyTeardown {
    Nft { udp_tproxy: bool },
}

static EMERGENCY_TEARDOWN: Mutex<Option<EmergencyTeardown>> = Mutex::new(None);
static PANIC_HOOK_INSTALLED: Once = Once::new();

/// Record the firewall state to tear down on a panic, and install the panic
/// hook (once) that performs that teardown. Called whenever a guard is created.
fn arm_emergency_teardown(state: EmergencyTeardown) {
    if let Ok(mut guard) = EMERGENCY_TEARDOWN.lock() {
        *guard = Some(state);
    }
    PANIC_HOOK_INSTALLED.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            run_emergency_teardown();
            previous(info);
        }));
    });
}

/// Forget the recorded firewall state after a clean teardown so a subsequent
/// panic hook invocation becomes a no-op.
fn disarm_emergency_teardown() {
    if let Ok(mut guard) = EMERGENCY_TEARDOWN.lock() {
        *guard = None;
    }
}

/// Best-effort, panic-safe firewall teardown. Clones the descriptor out and
/// drops the lock before shelling out so it can never deadlock from a panic
/// that happened while the lock was held elsewhere. Never panics, never logs.
fn run_emergency_teardown() {
    let state = EMERGENCY_TEARDOWN.lock().ok().and_then(|guard| guard.clone());
    match state {
        Some(EmergencyTeardown::Nft { udp_tproxy }) => {
            NFT_SETS_READY.store(false, Ordering::Relaxed);
            let _ = command("nft", &["delete", "table", "inet", NFT_TABLE]);
            if udp_tproxy {
                cleanup_tproxy_policy_routing();
            }
        }
        None => {}
    }
}

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
}

impl Drop for DnsInterceptGuard {
    fn drop(&mut self) {
        // Graceful teardown is happening now; neutralise the panic-hook fallback.
        disarm_emergency_teardown();
        match self.backend {
            Backend::Nft { udp_tproxy } => {
                NFT_SETS_READY.store(false, Ordering::Relaxed);
                let _ = command("nft", &["delete", "table", "inet", NFT_TABLE]);
                if udp_tproxy {
                    cleanup_tproxy_policy_routing();
                }
            }
        }
    }
}

/// Best-effort removal of any leftover `inet ssrust_redir` nft table from a
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
    client_ip_rules: &ClientIpRules,
    local_output_exempt_mark: Option<u32>,
    dns_ipv4_only: bool,
) -> io::Result<DnsInterceptGuard> {
    match setup_nft(
        port,
        redir_port,
        dns_exempt_ips,
        proxy_exempt_endpoints,
        global_proxy,
        client_ip_rules,
        local_output_exempt_mark,
        dns_ipv4_only,
    ) {
        Ok(udp_tproxy) => {
            info!("installed nftables DNS interception rules on local port {}", port);
            if udp_tproxy && let Some(redir_port) = redir_port {
                info!("installed nftables UDP tproxy rules on local redir port {}", redir_port);
            }
            arm_emergency_teardown(EmergencyTeardown::Nft { udp_tproxy });
            Ok(DnsInterceptGuard {
                backend: Backend::Nft { udp_tproxy },
            })
        }
        Err(nft_err) => {
            // nft is the only supported backend. Scrub any half-installed nft
            // state and propagate the error rather than falling back to iptables.
            warn!("failed to install nftables DNS interception rules: {}", nft_err);
            cleanup_nft_tproxy_chains();
            cleanup_tproxy_policy_routing();
            NFT_SETS_READY.store(false, Ordering::Relaxed);
            let _ = command("nft", &["delete", "table", "inet", NFT_TABLE]);
            Err(nft_err)
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
    nft_apply_script_with_retry(&script)
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

#[derive(Clone, Debug, Default)]
pub struct RouteSetSnapshot {
    pub direct: Vec<IpNet>,
    pub proxy: Vec<IpNet>,
}

pub fn route_set_snapshot() -> io::Result<RouteSetSnapshot> {
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
    let mut direct = nft_set_nets_from_table(&text, DIRECT4_SET);
    direct.extend(nft_set_nets_from_table(&text, DIRECT6_SET));
    let mut proxy = nft_set_nets_from_table(&text, PROXY4_SET);
    proxy.extend(nft_set_nets_from_table(&text, PROXY6_SET));
    Ok(RouteSetSnapshot { direct, proxy })
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
    nft_set_nets_from_table(table, set_name).len()
}

fn nft_set_nets_from_table(table: &str, set_name: &str) -> Vec<IpNet> {
    let marker = format!("set {set_name} {{");
    let Some(start) = table.find(&marker) else {
        return Vec::new();
    };
    let section = &table[start..];
    let end = section
        .find("\n\tset ")
        .or_else(|| section.find("\n    set "))
        .or_else(|| section.find("\n\tchain "))
        .or_else(|| section.find("\n    chain "))
        .unwrap_or(section.len());
    parse_nft_ip_nets(&section[..end])
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
        .flat_map(|token| {
            let token = token.trim_matches([';', '"']);
            if token.is_empty() {
                return Vec::new();
            }
            if let Some((start, end)) = token.split_once('-') {
                return nft_ip_range_to_nets(start, end);
            }
            match token
                .parse::<IpNet>()
                .ok()
                .or_else(|| token.parse::<IpAddr>().ok().map(IpNet::from))
            {
                Some(net) => vec![net],
                None => Vec::new(),
            }
        })
        .collect()
}

fn nft_ip_range_to_nets(start: &str, end: &str) -> Vec<IpNet> {
    match (start.parse::<IpAddr>(), end.parse::<IpAddr>()) {
        (Ok(IpAddr::V4(start)), Ok(IpAddr::V4(end))) => {
            let (start, end) = ordered_ipv4_range(start, end);
            Ipv4Subnets::new(start, end, 0).map(IpNet::from).collect()
        }
        (Ok(IpAddr::V6(start)), Ok(IpAddr::V6(end))) => {
            let (start, end) = ordered_ipv6_range(start, end);
            Ipv6Subnets::new(start, end, 0).map(IpNet::from).collect()
        }
        _ => Vec::new(),
    }
}

fn ordered_ipv4_range(start: Ipv4Addr, end: Ipv4Addr) -> (Ipv4Addr, Ipv4Addr) {
    if u32::from(start) <= u32::from(end) {
        (start, end)
    } else {
        (end, start)
    }
}

fn ordered_ipv6_range(start: Ipv6Addr, end: Ipv6Addr) -> (Ipv6Addr, Ipv6Addr) {
    if u128::from(start) <= u128::from(end) {
        (start, end)
    } else {
        (end, start)
    }
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

fn add_nft_base_chain(
    chain: &'static str,
    chain_type: &'static str,
    hook: &'static str,
    priority: &'static str,
) -> io::Result<()> {
    command(
        "nft",
        &[
            "add", "chain", "inet", NFT_TABLE, chain, "{", "type", chain_type, "hook", hook, "priority", priority,
            ";", "}",
        ],
    )
}

fn setup_nft(
    port: u16,
    redir_port: Option<u16>,
    dns_exempt_ips: &[IpAddr],
    proxy_exempt_endpoints: &[(IpAddr, u16)],
    global_proxy: bool,
    client_ip_rules: &ClientIpRules,
    local_output_exempt_mark: Option<u32>,
    dns_ipv4_only: bool,
) -> io::Result<bool> {
    NFT_SETS_READY.store(false, Ordering::Relaxed);
    let _ = command("nft", &["delete", "table", "inet", NFT_TABLE]);
    command("nft", &["add", "table", "inet", NFT_TABLE])?;
    add_nft_sets()?;
    NFT_SETS_READY.store(true, Ordering::Relaxed);
    add_fixed_direct_set_elements()?;
    add_client_ip_set_elements(client_ip_rules)?;
    add_nft_base_chain(DNS_PREROUTING_CHAIN, "nat", "prerouting", "-101")?;
    add_nft_base_chain(DNS_OUTPUT_CHAIN, "nat", "output", "-101")?;
    add_nft_base_chain(TCP_PREROUTING_CHAIN, "nat", "prerouting", "dstnat")?;
    add_nft_base_chain(TCP_OUTPUT_CHAIN, "nat", "output", "dstnat")?;

    add_proxy_endpoint_return_rules(DNS_PREROUTING_CHAIN, "tcp", proxy_exempt_endpoints)?;
    for proto in ["udp", "tcp"] {
        command(
            "nft",
            &[
                "add",
                "rule",
                "inet",
                NFT_TABLE,
                DNS_PREROUTING_CHAIN,
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
            add_proxy_endpoint_return_rules(TCP_PREROUTING_CHAIN, "tcp", proxy_exempt_endpoints)?;
            add_nft_tcp_redir_rule(
                TCP_PREROUTING_CHAIN,
                "ip",
                "@proxy4",
                "@direct4",
                redir_port,
                global_proxy,
                Some(client_ip_rules),
            )?;
            // SI-2: only steer IPv6 into the proxy when IPv6 is actually in use.
            // Under dns_ipv4_only the local DNS suppresses AAAA, and the redir
            // listener may be IPv4-only, so an IPv6 redirect/tproxy rule would
            // black-hole LAN IPv6 to a dead socket. Skip the v6 proxy rule then.
            if !dns_ipv4_only {
                add_nft_tcp_redir_rule(
                    TCP_PREROUTING_CHAIN,
                    "ip6",
                    "@proxy6",
                    "@direct6",
                    redir_port,
                    global_proxy,
                    Some(client_ip_rules),
                )?;
            }
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
                    DNS_OUTPUT_CHAIN,
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
        add_output_loopback_dns_redirect_rule(proto, port)?;
        if proto == "tcp"
            && let Some(redir_port) = redir_port
        {
            if let Some(mark) = local_output_exempt_mark {
                let mark_arg = format!("{mark:#x}");
                command(
                    "nft",
                    &["add", "rule", "inet", NFT_TABLE, TCP_OUTPUT_CHAIN, "meta", "mark", &mark_arg, "return"],
                )?;
            }
            add_output_loopback_return_rule(TCP_OUTPUT_CHAIN)?;
            add_proxy_endpoint_return_rules(TCP_OUTPUT_CHAIN, "tcp", proxy_exempt_endpoints)?;

            // OUTPUT is required for local-machine transparent proxy: packets
            // generated on the box itself never traverse PREROUTING. Fixed
            // direct ranges and server endpoint returns above must stay before
            // redirect rules so router management/LAN traffic and the proxy
            // transport itself cannot loop back into sslocal.
            add_nft_tcp_redir_rule(TCP_OUTPUT_CHAIN, "ip", "@proxy4", "@direct4", redir_port, global_proxy, None)?;
            if !dns_ipv4_only {
                add_nft_tcp_redir_rule(TCP_OUTPUT_CHAIN, "ip6", "@proxy6", "@direct6", redir_port, global_proxy, None)?;
            }
        }
    }
    if let Some(mark) = local_output_exempt_mark {
        let mark_arg = format!("{mark:#x}");
        command(
            "nft",
            &["add", "rule", "inet", NFT_TABLE, DNS_OUTPUT_CHAIN, "meta", "mark", &mark_arg, "return"],
        )?;
    }
    add_output_loopback_return_rule(DNS_OUTPUT_CHAIN)?;
    add_proxy_endpoint_return_rules(DNS_OUTPUT_CHAIN, "tcp", proxy_exempt_endpoints)?;
    let udp_tproxy = if let Some(redir_port) = redir_port {
        match setup_nft_udp_tproxy(
            redir_port,
            proxy_exempt_endpoints,
            global_proxy,
            client_ip_rules,
            local_output_exempt_mark,
            dns_ipv4_only,
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
    _proto: &'static str,
    proxy_exempt_endpoints: &[(IpAddr, u16)],
) -> io::Result<()> {
    let mut exempt_ips = proxy_exempt_endpoints
        .iter()
        .map(|(ip, _)| *ip)
        .collect::<Vec<_>>();
    exempt_ips.sort();
    exempt_ips.dedup();
    for ip in exempt_ips {
        let family_expr = match ip {
            IpAddr::V4(..) => "ip",
            IpAddr::V6(..) => "ip6",
        };
        let ip = ip.to_string();
        command(
            "nft",
            &[
                "add", "rule", "inet", NFT_TABLE, chain, family_expr, "daddr", &ip, "counter", "return",
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

fn add_output_loopback_dns_redirect_rule(proto: &'static str, port: u16) -> io::Result<()> {
    command(
        "nft",
        &[
            "add",
            "rule",
            "inet",
            NFT_TABLE,
            DNS_OUTPUT_CHAIN,
            "ip",
            "daddr",
            "127.0.0.0/8",
            proto,
            "dport",
            "53",
            "redirect",
            "to",
            &format!(":{port}"),
        ],
    )
}

fn add_output_loopback_return_rule(chain: &'static str) -> io::Result<()> {
    command("nft", &["add", "rule", "inet", NFT_TABLE, chain, "oifname", "lo", "return"])
}

fn add_fib_local_broadcast_return_rules(chain: &'static str) -> io::Result<()> {
    command(
        "nft",
        &[
            "add", "rule", "inet", NFT_TABLE, chain, "fib", "daddr", "type", "local", "return",
        ],
    )?;
    command(
        "nft",
        &[
            "add", "rule", "inet", NFT_TABLE, chain, "fib", "daddr", "type", "broadcast", "return",
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
    let set_name = match family_expr {
        "ip" => RESERVED4_SET,
        "ip6" => RESERVED6_SET,
        _ => return Ok(()),
    };
    let set_ref = format!("@{set_name}");
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
            &set_ref,
            proto,
            "dport",
            "!=",
            "53",
            "return",
        ],
    )?;
    add_fib_local_broadcast_return_rules(chain)
}

fn setup_nft_udp_tproxy(
    redir_port: u16,
    proxy_exempt_endpoints: &[(IpAddr, u16)],
    global_proxy: bool,
    client_ip_rules: &ClientIpRules,
    local_output_exempt_mark: Option<u32>,
    dns_ipv4_only: bool,
) -> io::Result<()> {
    setup_tproxy_policy_routing()?;
    add_nft_base_chain(TPROXY_PREROUTING_CHAIN, "filter", "prerouting", "mangle")?;
    add_nft_base_chain(TPROXY_OUTPUT_CHAIN, "route", "output", "mangle")?;
    if let Some(mark) = local_output_exempt_mark {
        let mark_arg = format!("{mark:#x}");
        command(
            "nft",
            &[
                "add",
                "rule",
                "inet",
                NFT_TABLE,
                TPROXY_PREROUTING_CHAIN,
                "meta",
                "mark",
                &mark_arg,
                "return",
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
    // SI-2: skip the IPv6 tproxy rule under dns_ipv4_only (see the TCP path).
    if !dns_ipv4_only {
        add_nft_udp_tproxy_prerouting_rule(
            "ip6",
            "@proxy6",
            "@direct6",
            "ip6",
            redir_port,
            global_proxy,
            client_ip_rules,
        )?;
    }
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
    // H-5: also exempt sslocal's own marked outbound UDP from the output
    // tproxy chain by identity, so the proxy transport can never self-loop.
    if let Some(mark) = local_output_exempt_mark {
        let mark_arg = format!("{mark:#x}");
        command(
            "nft",
            &["add", "rule", "inet", NFT_TABLE, TPROXY_OUTPUT_CHAIN, "meta", "mark", &mark_arg, "return"],
        )?;
    }
    add_output_loopback_return_rule(TPROXY_OUTPUT_CHAIN)?;
    add_proxy_endpoint_return_rules(TPROXY_OUTPUT_CHAIN, "udp", proxy_exempt_endpoints)?;
    add_nft_udp_tproxy_output_rule("ip", "@proxy4", "@direct4", global_proxy)?;
    if !dns_ipv4_only {
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
    command(
        "ip",
        &["rule", "add", "fwmark", TPROXY_MARK, "table", TPROXY_TABLE, "priority", "100"],
    )?;
    command(
        "ip",
        &["route", "add", "local", "0.0.0.0/0", "dev", "lo", "table", TPROXY_TABLE],
    )?;
    if let Err(err) = command(
        "ip",
        &["-6", "rule", "add", "fwmark", TPROXY_MARK, "table", TPROXY_TABLE, "priority", "100"],
    ) {
        warn!("failed to install IPv6 UDP tproxy policy rule: {}", err);
    }
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
    while command("ip", &["-6", "rule", "del", "fwmark", TPROXY_MARK, "table", TPROXY_TABLE]).is_ok() {}
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
    let _ = add_fixed_direct_set_elements();
    NFT_SETS_READY.store(true, Ordering::Relaxed);
    Ok(())
}

fn add_nft_sets() -> io::Result<()> {
    for (name, kind) in [
        (RESERVED4_SET, "ipv4_addr"),
        (RESERVED6_SET, "ipv6_addr"),
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
    write_add_literal_elements(&mut script, RESERVED4_SET, &FIXED_DIRECT4_RULES);
    write_add_literal_elements(&mut script, RESERVED6_SET, &FIXED_DIRECT6_RULES);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_nft_ip_nets_expands_ipv4_ranges() {
        let nets = parse_nft_ip_nets("elements = { 13.249.231.99-13.249.231.100 }");
        let first = "13.249.231.99".parse::<IpAddr>().unwrap();
        let second = "13.249.231.100".parse::<IpAddr>().unwrap();
        let outside = "13.249.231.101".parse::<IpAddr>().unwrap();

        assert!(nets.iter().any(|net| net.contains(&first)));
        assert!(nets.iter().any(|net| net.contains(&second)));
        assert!(!nets.iter().any(|net| net.contains(&outside)));
    }

    #[test]
    fn parse_nft_ip_nets_expands_ipv6_ranges() {
        let nets = parse_nft_ip_nets("elements = { 2001:db8::1-2001:db8::2 }");
        let first = "2001:db8::1".parse::<IpAddr>().unwrap();
        let second = "2001:db8::2".parse::<IpAddr>().unwrap();
        let outside = "2001:db8::3".parse::<IpAddr>().unwrap();

        assert!(nets.iter().any(|net| net.contains(&first)));
        assert!(nets.iter().any(|net| net.contains(&second)));
        assert!(!nets.iter().any(|net| net.contains(&outside)));
    }
}
