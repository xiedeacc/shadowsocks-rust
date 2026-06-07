//! Runtime routing state for the embedded web admin.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    fs,
    io::{self, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
    process::Command,
    sync::{
        Arc, RwLock as StdRwLock,
        atomic::{AtomicU64, Ordering as AtomicOrdering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use hickory_resolver::proto::op::Message;
use ipnet::IpNet;
use log::warn;
use serde::{Deserialize, Serialize};
use shadowsocks::relay::socks5::Address;
use tokio::{sync::RwLock as TokioRwLock, time};

// =====================================================================
// Hot-path instrumentation counters.
//
// Why these are global atomics rather than living on `RoutingState`:
// the diagnostic logger we ship in this build needs to be cheap enough
// to run in production (counters bumped on every DNS query), and it
// needs to keep working even if every call site holds the routing lock
// at once. `AtomicU64::fetch_add(_, Relaxed)` compiles to a single
// inlined LOCK XADD on x86 / LDADD on aarch64 — practically free vs.
// the wall-clock cost of the operations they instrument (subprocess
// fork, file write, full-table prune).
//
// All `*_NS` counters are cumulative wall-clock nanoseconds since
// process start. The 60s diagnostic logger emits the deltas, so we get
// per-minute "% time spent in this hot section" without keeping a
// histogram in memory. `Relaxed` is intentional — we don't need
// happens-before ordering across counters; each is independent.
// =====================================================================
static PRUNE_DNS_CACHE_CALLS: AtomicU64 = AtomicU64::new(0);
static PRUNE_DNS_CACHE_TOTAL_NS: AtomicU64 = AtomicU64::new(0);
static NFT_INVOCATIONS: AtomicU64 = AtomicU64::new(0);
static NFT_TOTAL_NS: AtomicU64 = AtomicU64::new(0);
static APPEND_LINES_CALLS: AtomicU64 = AtomicU64::new(0);
static APPEND_LINES_TOTAL_NS: AtomicU64 = AtomicU64::new(0);
static ADD_DNS_RESULTS_CALLS: AtomicU64 = AtomicU64::new(0);
static ADD_DNS_RESULTS_TOTAL_NS: AtomicU64 = AtomicU64::new(0);

// Threshold above which a single hot-path operation is logged at
// `warn!` level. Picked low enough to flag pathological cases without
// drowning the log on a healthy system: the 99p we expect on this
// hardware is well under 10ms per `nft add element`, and `prune` should
// be sub-millisecond at modest cache sizes.
const SLOW_HOT_PATH_MS: u128 = 100;

use crate::config::RouteRulesConfig;

const DIRECT_IP_FILE: &str = "direct_ip.txt";
const DIRECT_DOMAIN_FILE: &str = "direct_domain.txt";
const BYPASS_IP_FILE: &str = "bypass_ip.txt";
const BYPASS_DOMAIN_FILE: &str = "bypass_domain.txt";
const TEMP_DIRECT_IP_FILE: &str = "direct_ip.temp";
const TEMP_DIRECT_DOMAIN_FILE: &str = "direct_domain.temp";
const TEMP_BYPASS_IP_FILE: &str = "bypass_ip.temp";
const TEMP_BYPASS_DOMAIN_FILE: &str = "bypass_domain.temp";
const RECORD_FILE: &str = "record.txt";
const SOURCE_DIR: &str = "source";
const SOURCE_TEMP_DIR: &str = "temp";
const GENERATED_RULE_FILES: [&str; 4] = [DIRECT_IP_FILE, DIRECT_DOMAIN_FILE, BYPASS_IP_FILE, BYPASS_DOMAIN_FILE];
const MAX_EVENTS: usize = 4096;
const DEFAULT_WINDOW: Duration = Duration::from_secs(300);
const BYPASS_IP_PERSIST_DELAY: Duration = Duration::from_secs(30);
const DNS_CACHE_REFRESH_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
const SOURCE_REFRESH_INTERVAL: Duration = Duration::from_secs(7 * 24 * 60 * 60);
/// How long an authoritative per-flow decision (Redir/Tun/Proxy/etc.)
/// is retained so the kernel-snapshot scraper can re-label a long-lived
/// flow even after its `ConnectionEvent` aged out of `DEFAULT_WINDOW`.
/// Long enough to cover persistent TLS/HLS/WebSocket connections but
/// bounded so stale tuples don't leak forever.
const FLOW_DECISION_TTL: Duration = Duration::from_secs(3600);
const PRIVATE_DIRECT_IP_RULES: [&str; 13] = [
    "0.0.0.0/8",
    "127.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "::/128",
    "::1/128",
    "fc00::/7",
    "fe80::/10",
    "ff00::/8",
];

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteDecision {
    Direct,
    Proxy,
}

impl RouteDecision {
    pub fn is_bypassed(self) -> bool {
        matches!(self, Self::Direct)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RoutingSources {
    pub geoip_sources: Vec<String>,
    pub bypass_domain_sources: Vec<String>,
    #[serde(default = "default_dns_cache_capacity")]
    pub dns_cache_capacity: usize,
    #[serde(default = "default_dns_cache_ttl_seconds")]
    pub dns_cache_ttl_seconds: u64,
    #[serde(default = "default_dns_cache_refresh_enabled")]
    pub dns_cache_refresh_enabled: bool,
    #[serde(default = "default_dns_cache_refresh_batch_size")]
    pub dns_cache_refresh_batch_size: usize,
    #[serde(default = "default_dns_intercept_mode")]
    pub dns_intercept_mode: String,
    #[serde(default = "default_dns_ipv4_only")]
    pub dns_ipv4_only: bool,
}

/// Runtime DNS service endpoints derived from the *first* DNS listener in
/// `locals[]` at startup. Single source of truth for "which upstream DNS
/// server should the routing layer ask?" — kept as a dedicated runtime
/// state slot (rather than in [`RoutingSources`] / `route_rules`) so the
/// JSON config does not have to repeat what `locals[].dns` already
/// declares.
///
/// Empty when no DNS listener is configured (e.g. server-mode binaries
/// or local-mode without `protocol: "dns"`).
#[derive(Clone, Debug, Default, Serialize)]
pub struct DnsRuntimeState {
    pub domestic_dns: Vec<String>,
    pub foreign_dns: Vec<String>,
    /// Address+port the local DNS service is bound on. Used by the
    /// firewall / TUN interceptor to know where to redirect captured
    /// DNS traffic.
    pub listen: Option<SocketAddr>,
}

fn default_dns_cache_capacity() -> usize {
    10_000
}

fn default_dns_cache_ttl_seconds() -> u64 {
    7 * 24 * 60 * 60
}

fn default_dns_cache_refresh_enabled() -> bool {
    true
}

fn default_dns_cache_refresh_batch_size() -> usize {
    500
}

fn default_dns_intercept_mode() -> String {
    "off".to_owned()
}

fn default_dns_ipv4_only() -> bool {
    true
}

impl From<&RouteRulesConfig> for RoutingSources {
    fn from(config: &RouteRulesConfig) -> Self {
        sanitize_sources(Self {
            geoip_sources: config.geoip_sources.clone(),
            bypass_domain_sources: config.bypass_domain_sources.clone(),
            dns_cache_capacity: config.dns_cache_capacity,
            dns_cache_ttl_seconds: config.dns_cache_ttl_seconds,
            dns_cache_refresh_enabled: config.dns_cache_refresh_enabled,
            dns_cache_refresh_batch_size: config.dns_cache_refresh_batch_size,
            dns_intercept_mode: config.dns_intercept_mode.clone(),
            dns_ipv4_only: config.dns_ipv4_only,
        })
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RuleLists {
    pub direct_ip: Vec<String>,
    pub direct_domain: Vec<String>,
    pub bypass_ip: Vec<String>,
    pub bypass_domain: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ConflictEvent {
    pub timestamp: u64,
    pub kind: ConflictKind,
    pub value: String,
    pub regions: Vec<String>,
    pub sources: Vec<String>,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConflictKind {
    Ip,
    Domain,
}

#[derive(Clone, Debug, Serialize)]
pub struct ConnectionEvent {
    pub timestamp: u64,
    pub source_ip: IpAddr,
    pub source_port: u16,
    pub destination_ip: Option<IpAddr>,
    pub destination_domain: Option<String>,
    pub domain: Option<String>,
    pub destination_port: u16,
    pub protocol: String,
    pub decision: ConnectionDecision,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionDecision {
    Direct,
    Proxy,
    HttpProxy,
    Socks5Proxy,
    Redir,
    Tun,
    /// Flow observed in the kernel (conntrack / /proc/net/{tcp,udp}) but not
    /// matched to an in-memory sslocal decision.
    Observed,
}

/// Five-tuple identifying a kernel-visible flow, used as the key of
/// the `flow_decisions` map so scraper rows can be re-labeled from the
/// authoritative `record_connection` decision.
type FlowKey = (IpAddr, u16, IpAddr, u16, &'static str);

#[derive(Clone, Debug, Serialize)]
pub struct DnsEvent {
    pub timestamp: u64,
    pub domain: String,
    pub query_type: String,
    pub results: Vec<IpAddr>,
    pub resolver: RouteDecision,
    pub cache_hit: bool,
}

#[derive(Clone, Debug, Hash, Eq, PartialEq)]
struct DnsCacheKey {
    domain: String,
    query_type: String,
    resolver: RouteDecision,
}

#[derive(Clone, Debug)]
struct DnsCacheEntry {
    message: Message,
    results: Vec<IpAddr>,
    expires_at: u64,
    inserted_at: u64,
    refreshed_at: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct DnsCacheStats {
    pub size: usize,
    pub capacity: usize,
    pub ttl_seconds: u64,
    pub refresh_enabled: bool,
    pub refresh_batch_size: usize,
}

/// Lightweight snapshot of the routing state's most leak-prone collections.
/// Designed to be cheap to gather (read lock, no pruning) so it can be
/// emitted from a 60s background logger without adding to lock contention.
#[derive(Clone, Debug)]
pub struct RuntimeDiagnostics {
    pub dns_cache_size: usize,
    /// Length of the FIFO order queue used to enforce capacity. A growing
    /// gap between this and `dns_cache_size` indicates duplicate-key leaks.
    pub dns_cache_order_len: usize,
    pub dns_cache_capacity: usize,
    pub dns_cache_ttl_seconds: u64,
    pub dns_events: usize,
    pub connections: usize,
    /// Size of the authoritative per-flow decision map. Bounded by
    /// `MAX_EVENTS` and `FLOW_DECISION_TTL`; surfaced here so the
    /// periodic logger flags unexpected growth.
    pub flow_decisions: usize,
    /// Reverse-DNS map. Never pruned today — included here so the
    /// periodic logger flags growth.
    pub reverse_domains: usize,
    pub persistent_direct_ip: usize,
    pub persistent_bypass_ip: usize,
    pub temporary_direct_ip: usize,
    pub temporary_bypass_ip: usize,
    /// Cumulative hot-path counters (since process start). The diagnostic
    /// task computes per-tick deltas so we can compute "% of wall clock
    /// spent in this section" or "rate of nft fork+exec / sec".
    pub prune_dns_cache_calls: u64,
    pub prune_dns_cache_total_ns: u64,
    pub nft_invocations: u64,
    pub nft_total_ns: u64,
    pub append_lines_calls: u64,
    pub append_lines_total_ns: u64,
    pub add_dns_results_calls: u64,
    pub add_dns_results_total_ns: u64,
}

/// Snapshot the cumulative hot-path counters. Cheap (8 relaxed atomic
/// loads); intended to be called from the periodic logger once per
/// minute, and from any future SIGUSR1 dump path.
pub fn hot_path_counters() -> (u64, u64, u64, u64, u64, u64, u64, u64) {
    (
        PRUNE_DNS_CACHE_CALLS.load(AtomicOrdering::Relaxed),
        PRUNE_DNS_CACHE_TOTAL_NS.load(AtomicOrdering::Relaxed),
        NFT_INVOCATIONS.load(AtomicOrdering::Relaxed),
        NFT_TOTAL_NS.load(AtomicOrdering::Relaxed),
        APPEND_LINES_CALLS.load(AtomicOrdering::Relaxed),
        APPEND_LINES_TOTAL_NS.load(AtomicOrdering::Relaxed),
        ADD_DNS_RESULTS_CALLS.load(AtomicOrdering::Relaxed),
        ADD_DNS_RESULTS_TOTAL_NS.load(AtomicOrdering::Relaxed),
    )
}

#[derive(Clone, Debug, Serialize)]
pub struct DnsCacheView {
    pub domain: String,
    pub query_type: String,
    pub resolver: RouteDecision,
    pub results: Vec<IpAddr>,
    pub expires_at: u64,
    pub inserted_at: u64,
    pub refreshed_at: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct DnsCacheIpView {
    pub ip: IpAddr,
    pub domain: String,
    pub query_type: String,
    pub resolver: RouteDecision,
    pub expires_at: u64,
}

#[derive(Clone, Debug)]
pub struct DnsCacheRefreshCandidate {
    pub domain: String,
    pub query_type: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct IpMembershipDebug {
    pub query: String,
    pub valid: bool,
    pub error: Option<String>,
    pub bypass_file: bool,
    pub bypass_file_matches: Vec<String>,
    pub nft_checked: bool,
    pub nft_bypass: bool,
    pub nft_matches: Vec<String>,
    pub nft_error: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct RoutingSnapshot {
    pub rules_dir: PathBuf,
    pub sources: RoutingSources,
    pub temporary: RuleLists,
    pub persistent: RuleLists,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleUpdateStatus {
    Idle,
    Running,
    Completed,
    Failed,
}

#[derive(Clone, Debug, Serialize)]
pub struct RuleUpdateProgress {
    pub status: RuleUpdateStatus,
    pub current_source: Option<String>,
    pub completed_files: usize,
    pub total_files: usize,
    pub remaining_files: usize,
    pub percent: u8,
    pub message: Option<String>,
    pub completed_messages: Vec<String>,
}

impl Default for RuleUpdateProgress {
    fn default() -> Self {
        Self {
            status: RuleUpdateStatus::Idle,
            current_source: None,
            completed_files: 0,
            total_files: 0,
            remaining_files: 0,
            percent: 0,
            message: None,
            completed_messages: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Default)]
struct CompiledRules {
    direct_ip: Vec<IpNet>,
    direct_ip_exact: HashSet<IpAddr>,
    direct_domain: HashSet<String>,
    bypass_ip: Vec<IpNet>,
    bypass_ip_exact: HashSet<IpAddr>,
    bypass_domain: HashSet<String>,
}

#[derive(Debug)]
struct RoutingInner {
    rules_dir: PathBuf,
    sources: RoutingSources,
    temporary_raw: RuleLists,
    persistent_raw: RuleLists,
    temporary: CompiledRules,
    persistent: CompiledRules,
    geoip_cn: Vec<IpNet>,
    geoip_modified: Option<SystemTime>,
    direct_ip_modified: Option<SystemTime>,
    bypass_ip_modified: Option<SystemTime>,
    direct_domain_modified: Option<SystemTime>,
    bypass_domain_modified: Option<SystemTime>,
    ip_conflicts: VecDeque<ConflictEvent>,
    domain_conflicts: VecDeque<ConflictEvent>,
    connections: VecDeque<ConnectionEvent>,
    /// Flow-keyed authoritative decision map. Survives independently of
    /// `connections` (which is bounded by `DEFAULT_WINDOW`) so the
    /// kernel-snapshot scraper in `recent_connections` can re-label
    /// long-lived flows whose original `Redir`/`Tun` event has already
    /// been trimmed. Pruned by `FLOW_DECISION_TTL` and `MAX_EVENTS`.
    flow_decisions: HashMap<FlowKey, (ConnectionDecision, u64)>,
    dns: VecDeque<DnsEvent>,
    reverse_domains: HashMap<IpAddr, String>,
    dns_cache: HashMap<DnsCacheKey, DnsCacheEntry>,
    dns_cache_order: VecDeque<DnsCacheKey>,
    bypass_ip_dirty: bool,
    bypass_ip_persist_scheduled: bool,
}

#[derive(Clone, Debug)]
pub struct RoutingState {
    inner: Arc<TokioRwLock<RoutingInner>>,
    progress: Arc<StdRwLock<RuleUpdateProgress>>,
    /// Mirror of `sources.dns_ipv4_only` so hot DNS hooks can check it
    /// without taking the async lock on `inner`.
    dns_ipv4_only_flag: Arc<std::sync::atomic::AtomicBool>,
    /// Runtime DNS endpoints derived from `locals[]`'s DNS listener.
    /// Populated at startup from the first DNS listener; mutable via
    /// `/api/dns` so the web admin can hot-reload upstreams without
    /// editing the config file.
    dns_runtime: Arc<TokioRwLock<DnsRuntimeState>>,
}

impl RoutingState {
    pub async fn load(config: RouteRulesConfig) -> io::Result<Self> {
        fs::create_dir_all(&config.rules_dir)?;
        ensure_file(config.rules_dir.join(DIRECT_IP_FILE))?;
        ensure_file(config.rules_dir.join(DIRECT_DOMAIN_FILE))?;
        ensure_file(config.rules_dir.join(BYPASS_IP_FILE))?;
        ensure_file(config.rules_dir.join(BYPASS_DOMAIN_FILE))?;
        ensure_file(config.rules_dir.join(TEMP_DIRECT_IP_FILE))?;
        ensure_file(config.rules_dir.join(TEMP_DIRECT_DOMAIN_FILE))?;
        ensure_file(config.rules_dir.join(TEMP_BYPASS_IP_FILE))?;
        ensure_file(config.rules_dir.join(TEMP_BYPASS_DOMAIN_FILE))?;

        let persistent_raw = read_rule_lists(&config.rules_dir)?;
        let persistent = compile_rules(&persistent_raw);
        let geoip_path = config.rules_dir.join(SOURCE_DIR).join("geoip.dat");
        let geoip_cn = read_geoip_cn_nets(&geoip_path)?;
        let geoip_modified = file_modified(&geoip_path)?;
        let direct_ip_modified = file_modified(&config.rules_dir.join(DIRECT_IP_FILE))?;
        let bypass_ip_modified = file_modified(&config.rules_dir.join(BYPASS_IP_FILE))?;
        let direct_domain_modified = file_modified(&config.rules_dir.join(DIRECT_DOMAIN_FILE))?;
        let bypass_domain_modified = file_modified(&config.rules_dir.join(BYPASS_DOMAIN_FILE))?;
        let temporary_raw = with_private_direct_rules(read_temporary_rule_lists(&config.rules_dir)?);
        let temporary = compile_rules(&temporary_raw);
        let mut inner = RoutingInner {
            sources: RoutingSources::from(&config),
            rules_dir: config.rules_dir,
            temporary_raw,
            persistent_raw,
            temporary,
            persistent,
            geoip_cn,
            geoip_modified,
            direct_ip_modified,
            bypass_ip_modified,
            direct_domain_modified,
            bypass_domain_modified,
            ip_conflicts: VecDeque::new(),
            domain_conflicts: VecDeque::new(),
            connections: VecDeque::new(),
            flow_decisions: HashMap::new(),
            dns: VecDeque::new(),
            reverse_domains: HashMap::new(),
            dns_cache: HashMap::new(),
            dns_cache_order: VecDeque::new(),
            bypass_ip_dirty: false,
            bypass_ip_persist_scheduled: false,
        };
        rebuild_conflicts(&mut inner);
        let v4_only = inner.sources.dns_ipv4_only;
        let state = Self {
            inner: Arc::new(TokioRwLock::new(inner)),
            progress: Arc::new(StdRwLock::new(RuleUpdateProgress::default())),
            dns_ipv4_only_flag: Arc::new(std::sync::atomic::AtomicBool::new(v4_only)),
            dns_runtime: Arc::new(TokioRwLock::new(DnsRuntimeState::default())),
        };
        state.spawn_periodic_source_update();
        Ok(state)
    }

    /// Install runtime DNS endpoints (domestic / foreign upstreams + bound
    /// listen address) derived from the first DNS listener parsed from
    /// `locals[]`. Called once at startup before the DNS server task is
    /// spawned. Subsequent calls overwrite, which the web admin uses for
    /// hot-reload.
    pub async fn set_dns_runtime(&self, state: DnsRuntimeState) {
        *self.dns_runtime.write().await = state;
    }

    pub async fn snapshot(&self) -> RoutingSnapshot {
        let inner = self.inner.read().await;
        RoutingSnapshot {
            rules_dir: inner.rules_dir.clone(),
            sources: inner.sources.clone(),
            temporary: inner.temporary_raw.clone(),
            persistent: RuleLists::default(),
        }
    }

    pub async fn set_sources(&self, sources: RoutingSources) {
        let mut inner = self.inner.write().await;
        inner.sources = sanitize_sources(sources);
        // Keep the lock-free mirror in sync so the DNS hot path
        // immediately picks up runtime UI toggles (e.g. IPv4-only).
        self.dns_ipv4_only_flag
            .store(inner.sources.dns_ipv4_only, std::sync::atomic::Ordering::Relaxed);
    }

    pub async fn set_temporary_rules(&self, rules: RuleLists) -> io::Result<()> {
        let rules = with_private_direct_rules(normalize_rule_lists(rules));
        validate_temporary_rules(&rules)?;
        #[cfg(all(target_os = "linux", feature = "local-dns"))]
        let (rules_dir, bypass_nets) = {
            let inner = self.inner.read().await;
            (inner.rules_dir.clone(), temporary_nft_bypass_nets(&inner, &rules))
        };
        let mut inner = self.inner.write().await;
        write_temporary_rule_lists(&inner.rules_dir, &rules)?;
        inner.temporary_raw = rules;
        inner.temporary = compile_rules(&inner.temporary_raw);
        rebuild_conflicts(&mut inner);
        drop(inner);
        #[cfg(all(target_os = "linux", feature = "local-dns"))]
        {
            if let Err(err) = crate::local::dns::intercept_linux::replace_route_nets(&rules_dir, &[], &bypass_nets) {
                warn!("failed to refresh nft bypass set after temporary rule change: {}", err);
            }
        }
        Ok(())
    }

    pub async fn route_ip(&self, ip: &IpAddr) -> Option<RouteDecision> {
        let mut inner = self.inner.write().await;
        route_ip_inner(&mut inner, ip)
    }

    pub async fn route_domain(&self, domain: &str) -> Option<RouteDecision> {
        let mut inner = self.inner.write().await;
        route_domain_inner(&mut inner, domain)
    }

    pub async fn route_address(&self, addr: &Address) -> Option<RouteDecision> {
        match addr {
            Address::SocketAddress(saddr) => self.route_ip(&saddr.ip()).await,
            Address::DomainNameAddress(domain, ..) => self.route_domain(domain).await,
        }
    }

    pub async fn add_dns_results(&self, decision: RouteDecision, domain: &str, results: &[IpAddr]) -> io::Result<()> {
        // Whole-function timing — we suspect this path of holding the
        // routing write lock too long because it does (a) sync file
        // append on the Direct branch and (b) sync `nft` fork+exec on
        // the Proxy branch, both inside / right next to the lock. The
        // counter is read by the periodic diagnostic logger.
        let total_start = Instant::now();
        ADD_DNS_RESULTS_CALLS.fetch_add(1, AtomicOrdering::Relaxed);

        let mut schedule_bypass_persist = false;
        let additions = {
            let mut inner = self.inner.write().await;
            let mut additions = Vec::new();
            for ip in results {
                let target_exists = match decision {
                    RouteDecision::Direct => {
                        compiled_rules_match_ip(&inner.persistent.direct_ip_exact, &inner.persistent.direct_ip, ip)
                    }
                    RouteDecision::Proxy => {
                        compiled_rules_match_ip(&inner.persistent.bypass_ip_exact, &inner.persistent.bypass_ip, ip)
                    }
                };
                if target_exists {
                    continue;
                }

                additions.push(*ip);
            }

            if additions.is_empty() {
                let elapsed = total_start.elapsed();
                ADD_DNS_RESULTS_TOTAL_NS.fetch_add(elapsed.as_nanos() as u64, AtomicOrdering::Relaxed);
                return Ok(());
            }

            let lines = additions.iter().map(ToString::to_string).collect::<Vec<_>>();
            match decision {
                RouteDecision::Direct => {
                    // append_lines is a *blocking* file write done while
                    // holding the routing write lock. We time it
                    // explicitly so we can answer "is the lock being held
                    // for tens of ms because of disk?" from log alone.
                    let started = Instant::now();
                    let result = append_lines(&inner.rules_dir.join(DIRECT_IP_FILE), &lines);
                    let elapsed = started.elapsed();
                    APPEND_LINES_CALLS.fetch_add(1, AtomicOrdering::Relaxed);
                    APPEND_LINES_TOTAL_NS.fetch_add(elapsed.as_nanos() as u64, AtomicOrdering::Relaxed);
                    if elapsed.as_millis() >= SLOW_HOT_PATH_MS {
                        warn!(
                            "append_lines slow: {}ms ({} lines, file={}, domain={})",
                            elapsed.as_millis(),
                            lines.len(),
                            DIRECT_IP_FILE,
                            domain
                        );
                    }
                    result?;
                    inner.persistent_raw.direct_ip.extend(lines);
                    inner.persistent.direct_ip_exact.extend(additions.iter().copied());
                    inner
                        .persistent
                        .direct_ip
                        .extend(additions.iter().copied().map(IpNet::from));
                }
                RouteDecision::Proxy => {
                    inner.persistent_raw.bypass_ip.extend(lines);
                    inner.persistent.bypass_ip_exact.extend(additions.iter().copied());
                    inner
                        .persistent
                        .bypass_ip
                        .extend(additions.iter().copied().map(IpNet::from));
                    inner.bypass_ip_dirty = true;
                    if !inner.bypass_ip_persist_scheduled {
                        inner.bypass_ip_persist_scheduled = true;
                        schedule_bypass_persist = true;
                    }
                }
            }
            rebuild_conflicts(&mut inner);
            additions
        };
        warn!(
            "dns added {} {:?} IPs for {} to runtime rules",
            additions.len(),
            decision,
            domain
        );
        #[cfg(all(target_os = "linux", feature = "local-dns"))]
        {
            // Move the nft fork+exec onto a blocking-pool thread so the
            // tokio worker that's running the DNS handler isn't stalled
            // for the duration of the syscall. The helpers
            // `add_route_ips` / `remove_route_ips` were also reworked
            // to issue a single `nft -f -` per call instead of N
            // per-IP invocations, so this is now one fork+exec total
            // for the whole resolution batch.
            let nft_start = Instant::now();
            let additions_for_nft = additions.clone();
            let result = tokio::task::spawn_blocking(move || -> Result<(), io::Error> {
                match decision {
                    RouteDecision::Direct => {
                        crate::local::dns::intercept_linux::remove_route_ips(RouteDecision::Proxy, &additions_for_nft)
                    }
                    RouteDecision::Proxy => {
                        crate::local::dns::intercept_linux::add_route_ips(decision, &additions_for_nft)
                    }
                }
            })
            .await
            .unwrap_or_else(|join_err| Err(io::Error::other(format!("nft join error: {join_err}"))));
            let nft_elapsed = nft_start.elapsed();
            // One invocation per call now (batched), regardless of
            // additions.len(). The per-IP cost has effectively
            // collapsed into a single fork+exec.
            NFT_INVOCATIONS.fetch_add(1, AtomicOrdering::Relaxed);
            NFT_TOTAL_NS.fetch_add(nft_elapsed.as_nanos() as u64, AtomicOrdering::Relaxed);
            if nft_elapsed.as_millis() >= SLOW_HOT_PATH_MS {
                warn!(
                    "nft sync slow: {}ms ({} IPs, decision={:?}, domain={})",
                    nft_elapsed.as_millis(),
                    additions.len(),
                    decision,
                    domain
                );
            }
            if let Err(err) = result {
                match decision {
                    RouteDecision::Direct => {
                        warn!("failed to remove direct DNS result IPs from nft bypass set: {}", err)
                    }
                    RouteDecision::Proxy => {
                        warn!("failed to sync DNS result IPs to nft set: {}", err)
                    }
                }
            }
        }
        if schedule_bypass_persist {
            self.schedule_bypass_ip_persist();
        }

        let elapsed = total_start.elapsed();
        ADD_DNS_RESULTS_TOTAL_NS.fetch_add(elapsed.as_nanos() as u64, AtomicOrdering::Relaxed);
        if elapsed.as_millis() >= SLOW_HOT_PATH_MS {
            warn!(
                "add_dns_results slow: {}ms (decision={:?}, domain={}, additions={})",
                elapsed.as_millis(),
                decision,
                domain,
                additions.len(),
            );
        }
        Ok(())
    }

    fn schedule_bypass_ip_persist(&self) {
        let state = self.clone();
        tokio::spawn(async move {
            time::sleep(BYPASS_IP_PERSIST_DELAY).await;
            state.persist_bypass_ip_if_dirty().await;
        });
    }

    async fn persist_bypass_ip_if_dirty(&self) {
        let (path, lines) = {
            let mut inner = self.inner.write().await;
            if !inner.bypass_ip_dirty {
                inner.bypass_ip_persist_scheduled = false;
                return;
            }
            inner.bypass_ip_dirty = false;
            (
                inner.rules_dir.join(BYPASS_IP_FILE),
                normalize_lines(inner.persistent_raw.bypass_ip.clone()),
            )
        };

        let result = tokio::task::spawn_blocking(move || write_lines_atomic(path, &lines)).await;
        let failed = match result {
            Ok(Ok(())) => false,
            Ok(Err(err)) => {
                warn!("failed to persist DNS bypass IPs: {}", err);
                true
            }
            Err(err) => {
                warn!("failed to join DNS bypass IP persist task: {}", err);
                true
            }
        };

        let reschedule = {
            let mut inner = self.inner.write().await;
            if failed {
                inner.bypass_ip_dirty = true;
            }
            inner.bypass_ip_persist_scheduled = false;
            inner.bypass_ip_dirty
        };
        if reschedule {
            self.schedule_bypass_ip_persist();
        }
    }

    fn spawn_periodic_source_update(&self) {
        let state = self.clone();
        tokio::spawn(async move {
            let mut interval = time::interval(SOURCE_REFRESH_INTERVAL);
            interval.tick().await;
            loop {
                interval.tick().await;
                if !state.try_begin_update().await {
                    continue;
                }
                if let Err(err) = state.update_from_sources().await {
                    warn!("weekly route source update failed: {}", err);
                }
            }
        });
    }

    pub async fn update_from_sources(&self) -> io::Result<()> {
        let (sources, rules_dir) = {
            let inner = self.inner.read().await;
            (inner.sources.clone(), inner.rules_dir.clone())
        };
        let source_dir = rules_dir.join(SOURCE_DIR);
        let total_files = total_update_steps(&sources);
        if self.update_progress().await.status != RuleUpdateStatus::Running {
            self.begin_update_progress(total_files).await;
        }

        let learned_bypass_ip = read_lines(rules_dir.join(BYPASS_IP_FILE))?
            .into_iter()
            .filter(|rule| parse_ip_net(rule).is_some())
            .collect::<Vec<_>>();
        let mut direct_ip = Vec::new();
        let mut bypass_domain_candidates = Vec::new();
        let mut geoip_cn = Vec::new();
        let mut completed_files = 0usize;

        for source in &sources.geoip_sources {
            let source_name = source_progress_name(source);
            self.mark_source_started(&source_name, completed_files, total_files)
                .await;
            let downloaded = match download_source(source, &source_dir).await {
                Ok(downloaded) => downloaded,
                Err(err) => {
                    self.mark_update_failed(&source_name, completed_files, total_files, &err)
                        .await;
                    return Err(err);
                }
            };
            completed_files += 1;
            self.mark_source_completed(
                &downloaded.display_name,
                downloaded.from_cache,
                &source_dir,
                completed_files,
                total_files,
            )
            .await;
            self.mark_source_processing(&downloaded.display_name, completed_files, total_files, "parsing rules")
                .await;
            match parse_geoip_cn_nets(&downloaded.bytes) {
                Ok(nets) => {
                    direct_ip.extend(nets.iter().map(ToString::to_string));
                    geoip_cn = nets;
                }
                Err(_) => {
                    let text = String::from_utf8_lossy(&downloaded.bytes);
                    direct_ip.extend(parse_text_rules(&text));
                }
            }
        }

        for source in &sources.bypass_domain_sources {
            let source_name = source_progress_name(source);
            self.mark_source_started(&source_name, completed_files, total_files)
                .await;
            let downloaded = match download_source(source, &source_dir).await {
                Ok(downloaded) => downloaded,
                Err(err) => {
                    self.mark_update_failed(&source_name, completed_files, total_files, &err)
                        .await;
                    return Err(err);
                }
            };
            completed_files += 1;
            self.mark_source_completed(
                &downloaded.display_name,
                downloaded.from_cache,
                &source_dir,
                completed_files,
                total_files,
            )
            .await;
            let rules = parse_text_rules(&String::from_utf8_lossy(&downloaded.bytes));
            bypass_domain_candidates.extend(rules);
        }

        let direct_domain = read_lines(rules_dir.join(DIRECT_DOMAIN_FILE))?;
        let bypass_domain = bypass_domain_candidates;

        self.mark_generating_files(completed_files, total_files).await;
        let lists = normalize_rule_lists(RuleLists {
            direct_ip,
            direct_domain,
            bypass_ip: learned_bypass_ip,
            bypass_domain,
        });
        let persistent = compile_rules(&lists);
        completed_files = match self
            .write_rule_lists_with_progress(&rules_dir, &lists, completed_files, total_files)
            .await
        {
            Ok(completed_files) => completed_files,
            Err(err) => {
                self.mark_update_failed("generated route files", completed_files, total_files, &err)
                    .await;
                return Err(err);
            }
        };

        let completed_messages = self.completed_messages();
        let mut inner = self.inner.write().await;
        inner.persistent_raw = lists;
        inner.persistent = persistent;
        inner.geoip_cn = geoip_cn;
        inner.geoip_modified = file_modified(&inner.rules_dir.join(SOURCE_DIR).join("geoip.dat"))?;
        inner.direct_ip_modified = file_modified(&inner.rules_dir.join(DIRECT_IP_FILE))?;
        inner.bypass_ip_modified = file_modified(&inner.rules_dir.join(BYPASS_IP_FILE))?;
        inner.direct_domain_modified = file_modified(&inner.rules_dir.join(DIRECT_DOMAIN_FILE))?;
        inner.bypass_domain_modified = file_modified(&inner.rules_dir.join(BYPASS_DOMAIN_FILE))?;
        rebuild_conflicts(&mut inner);
        drop(inner);
        self.set_update_progress(RuleUpdateProgress {
            status: RuleUpdateStatus::Completed,
            current_source: None,
            completed_files,
            total_files,
            remaining_files: 0,
            percent: 100,
            message: Some("completed".to_owned()),
            completed_messages,
        })
        .await;
        Ok(())
    }

    pub async fn update_progress(&self) -> RuleUpdateProgress {
        self.progress
            .read()
            .map(|progress| progress.clone())
            .unwrap_or_default()
    }

    pub async fn download_sources(&self) -> io::Result<()> {
        let (sources, source_dir) = {
            let inner = self.inner.read().await;
            (inner.sources.clone(), inner.rules_dir.join(SOURCE_DIR))
        };
        let total_files = total_download_steps(&sources);
        if self.update_progress().await.status != RuleUpdateStatus::Running {
            self.begin_update_progress(total_files).await;
        }

        let mut completed_files = 0usize;
        for source in sources.geoip_sources.iter().chain(sources.bypass_domain_sources.iter()) {
            let source_name = source_progress_name(source);
            self.mark_source_started(&source_name, completed_files, total_files)
                .await;
            let downloaded = match download_source(source, &source_dir).await {
                Ok(downloaded) => downloaded,
                Err(err) => {
                    self.mark_update_failed(&source_name, completed_files, total_files, &err)
                        .await;
                    return Err(err);
                }
            };
            completed_files += 1;
            self.mark_source_completed(
                &downloaded.display_name,
                downloaded.from_cache,
                &source_dir,
                completed_files,
                total_files,
            )
            .await;
        }

        self.set_update_progress(RuleUpdateProgress {
            status: RuleUpdateStatus::Completed,
            current_source: None,
            completed_files,
            total_files,
            remaining_files: 0,
            percent: 100,
            message: Some("download completed".to_owned()),
            completed_messages: self.completed_messages(),
        })
        .await;
        Ok(())
    }

    pub async fn try_begin_download(&self) -> bool {
        let total_files = {
            let inner = self.inner.read().await;
            total_download_steps(&inner.sources)
        };
        self.try_begin_update_progress(total_files)
    }

    pub async fn try_begin_update(&self) -> bool {
        let total_files = {
            let inner = self.inner.read().await;
            total_update_steps(&inner.sources)
        };
        self.try_begin_update_progress(total_files)
    }

    async fn begin_update_progress(&self, total_files: usize) {
        self.set_update_progress(RuleUpdateProgress {
            status: RuleUpdateStatus::Running,
            current_source: None,
            completed_files: 0,
            total_files,
            remaining_files: total_files,
            percent: 0,
            message: Some("starting".to_owned()),
            completed_messages: Vec::new(),
        })
        .await;
    }

    fn try_begin_update_progress(&self, total_files: usize) -> bool {
        let Ok(mut progress) = self.progress.write() else {
            return false;
        };
        if progress.status == RuleUpdateStatus::Running {
            return false;
        }
        *progress = RuleUpdateProgress {
            status: RuleUpdateStatus::Running,
            current_source: None,
            completed_files: 0,
            total_files,
            remaining_files: total_files,
            percent: 0,
            message: Some("starting".to_owned()),
            completed_messages: Vec::new(),
        };
        true
    }

    async fn set_update_progress(&self, progress: RuleUpdateProgress) {
        if let Ok(mut current) = self.progress.write() {
            *current = progress;
        }
    }

    fn completed_messages(&self) -> Vec<String> {
        self.progress
            .read()
            .map(|progress| progress.completed_messages.clone())
            .unwrap_or_default()
    }

    async fn mark_source_started(&self, source: &str, completed_files: usize, total_files: usize) {
        let percent = progress_percent(completed_files, total_files);
        self.set_update_progress(RuleUpdateProgress {
            status: RuleUpdateStatus::Running,
            current_source: Some(source.to_owned()),
            completed_files,
            total_files,
            remaining_files: total_files.saturating_sub(completed_files),
            percent,
            message: Some("downloading".to_owned()),
            completed_messages: self.completed_messages(),
        })
        .await;
    }

    async fn mark_source_completed(
        &self,
        source: &str,
        from_cache: bool,
        cache_dir: &Path,
        completed_files: usize,
        total_files: usize,
    ) {
        let percent = progress_percent(completed_files, total_files);
        let message = if from_cache {
            format!("{source} already exists in {}, using cached file", cache_dir.display())
        } else {
            format!("{source} downloaded successfully")
        };
        let mut completed_messages = self.completed_messages();
        completed_messages.push(message.clone());
        self.set_update_progress(RuleUpdateProgress {
            status: RuleUpdateStatus::Running,
            current_source: Some(source.to_owned()),
            completed_files,
            total_files,
            remaining_files: total_files.saturating_sub(completed_files),
            percent,
            message: Some(message),
            completed_messages,
        })
        .await;
    }

    async fn mark_source_processing(&self, source: &str, completed_files: usize, total_files: usize, message: &str) {
        self.set_update_progress(RuleUpdateProgress {
            status: RuleUpdateStatus::Running,
            current_source: Some(source.to_owned()),
            completed_files,
            total_files,
            remaining_files: total_files.saturating_sub(completed_files),
            percent: progress_percent(completed_files, total_files),
            message: Some(message.to_owned()),
            completed_messages: self.completed_messages(),
        })
        .await;
    }

    async fn mark_generating_files(&self, completed_files: usize, total_files: usize) {
        let completed_messages = self.completed_messages();
        self.set_update_progress(RuleUpdateProgress {
            status: RuleUpdateStatus::Running,
            current_source: None,
            completed_files,
            total_files,
            remaining_files: total_files.saturating_sub(completed_files),
            percent: progress_percent(completed_files, total_files),
            message: Some("generating persistent files".to_owned()),
            completed_messages,
        })
        .await;
    }

    async fn write_rule_lists_with_progress(
        &self,
        dir: &Path,
        lists: &RuleLists,
        mut completed_files: usize,
        total_files: usize,
    ) -> io::Result<usize> {
        for (file_name, lines) in [
            (DIRECT_IP_FILE, &lists.direct_ip),
            (DIRECT_DOMAIN_FILE, &lists.direct_domain),
            (BYPASS_IP_FILE, &lists.bypass_ip),
            (BYPASS_DOMAIN_FILE, &lists.bypass_domain),
        ] {
            self.mark_generated_file_started(file_name, completed_files, total_files)
                .await;
            write_lines_atomic(dir.join(file_name), lines)?;
            completed_files += 1;
            self.mark_generated_file_completed(file_name, completed_files, total_files)
                .await;
        }
        Ok(completed_files)
    }

    async fn mark_generated_file_started(&self, file_name: &str, completed_files: usize, total_files: usize) {
        self.set_update_progress(RuleUpdateProgress {
            status: RuleUpdateStatus::Running,
            current_source: Some(file_name.to_owned()),
            completed_files,
            total_files,
            remaining_files: total_files.saturating_sub(completed_files),
            percent: progress_percent(completed_files, total_files),
            message: Some(format!("generating {file_name}")),
            completed_messages: self.completed_messages(),
        })
        .await;
    }

    async fn mark_generated_file_completed(&self, file_name: &str, completed_files: usize, total_files: usize) {
        let message = format!("{file_name} generated successfully");
        let mut completed_messages = self.completed_messages();
        completed_messages.push(message.clone());
        self.set_update_progress(RuleUpdateProgress {
            status: RuleUpdateStatus::Running,
            current_source: Some(file_name.to_owned()),
            completed_files,
            total_files,
            remaining_files: total_files.saturating_sub(completed_files),
            percent: progress_percent(completed_files, total_files),
            message: Some(message),
            completed_messages,
        })
        .await;
    }

    async fn mark_update_failed(&self, source: &str, completed_files: usize, total_files: usize, err: &io::Error) {
        let percent = progress_percent(completed_files, total_files);
        self.set_update_progress(RuleUpdateProgress {
            status: RuleUpdateStatus::Failed,
            current_source: Some(source.to_owned()),
            completed_files,
            total_files,
            remaining_files: total_files.saturating_sub(completed_files),
            percent,
            message: Some(err.to_string()),
            completed_messages: self.completed_messages(),
        })
        .await;
    }

    pub async fn domestic_dns(&self) -> Vec<String> {
        self.dns_runtime.read().await.domestic_dns.clone()
    }

    pub async fn foreign_dns(&self) -> Vec<String> {
        self.dns_runtime.read().await.foreign_dns.clone()
    }

    pub async fn dns_runtime_snapshot(&self) -> DnsRuntimeState {
        self.dns_runtime.read().await.clone()
    }

    /// Returns true when the user configured / defaulted to v4-only DNS
    /// (strips AAAA from responses to avoid happy-eyeballs delay on
    /// hosts without working public IPv6).
    pub async fn dns_ipv4_only(&self) -> bool {
        self.inner.read().await.sources.dns_ipv4_only
    }

    /// Sync version of [`Self::dns_ipv4_only`] for hot paths (DNS
    /// answer post-processing) that cannot take the async lock.
    pub fn dns_ipv4_only_sync(&self) -> bool {
        self.dns_ipv4_only_flag.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub async fn dns_tun_intercept_target(&self) -> Option<SocketAddr> {
        let mode = self.inner.read().await.sources.dns_intercept_mode.clone();
        if !matches!(mode.as_str(), "tun" | "both") {
            return None;
        }
        let listen = self.dns_runtime.read().await.listen?;
        let ip = match listen.ip() {
            IpAddr::V4(v4) if v4.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(v6) if v6.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
            ip => ip,
        };
        Some(SocketAddr::new(ip, listen.port()))
    }

    #[cfg(all(target_os = "linux", feature = "local-dns"))]
    pub async fn sync_persistent_ip_rules_to_firewall(&self) -> io::Result<()> {
        let (rules_dir, bypass) = {
            let inner = self.inner.read().await;
            (inner.rules_dir.clone(), persistent_nft_bypass_nets(&inner))
        };
        crate::local::dns::intercept_linux::replace_route_nets(&rules_dir, &[], &bypass)
    }

    pub async fn record_connection(
        &self,
        source: SocketAddr,
        target: &Address,
        protocol: &str,
        decision: ConnectionDecision,
    ) {
        let (destination_ip, destination_domain, destination_port) = match target {
            Address::SocketAddress(saddr) => (Some(saddr.ip()), None, saddr.port()),
            Address::DomainNameAddress(domain, port) => (None, Some(domain.clone()), *port),
        };
        let mut inner = self.inner.write().await;
        if destination_ip.is_some_and(|ip| is_private_connection_ip(&ip)) {
            return;
        }
        let domain = destination_domain.clone().or_else(|| {
            destination_ip
                .as_ref()
                .and_then(|ip| inner.reverse_domains.get(ip).cloned())
        });
        let ts = now();
        // Record an authoritative flow->decision entry so the kernel
        // snapshot scraper in `recent_connections` can re-label this
        // 5-tuple even after the ConnectionEvent ages out of
        // DEFAULT_WINDOW. Domain-only targets (no resolved IP) can't be
        // matched against /proc/net/* rows, so we skip those.
        let proto_static = match protocol {
            "tcp" => Some("tcp"),
            "udp" => Some("udp"),
            _ => None,
        };
        if let (Some(dst_ip), Some(p)) = (destination_ip, proto_static) {
            let key: FlowKey = (source.ip(), source.port(), dst_ip, destination_port, p);
            inner.flow_decisions.insert(key, (decision, ts));
            if inner.flow_decisions.len() > MAX_EVENTS {
                // Evict the oldest entry to keep the map bounded
                // (record_connection is on the hot accept path).
                if let Some(oldest_key) = inner
                    .flow_decisions
                    .iter()
                    .min_by_key(|(_, (_, ts))| *ts)
                    .map(|(k, _)| *k)
                {
                    inner.flow_decisions.remove(&oldest_key);
                }
            }
        }
        push_event(
            &mut inner.connections,
            ConnectionEvent {
                timestamp: ts,
                source_ip: source.ip(),
                source_port: source.port(),
                destination_ip,
                destination_domain,
                domain,
                destination_port,
                protocol: protocol.to_owned(),
                decision,
            },
        );
        trim_old(&mut inner.connections, DEFAULT_WINDOW);
    }

    pub async fn record_dns(
        &self,
        domain: String,
        query_type: String,
        results: Vec<IpAddr>,
        resolver: RouteDecision,
        cache_hit: bool,
    ) {
        let mut inner = self.inner.write().await;
        let normalized_domain = normalize_dns_domain(&domain);
        for ip in &results {
            inner.reverse_domains.insert(*ip, normalized_domain.clone());
        }
        push_event(
            &mut inner.dns,
            DnsEvent {
                timestamp: now(),
                domain: normalized_domain,
                query_type,
                results,
                resolver,
                cache_hit,
            },
        );
        trim_old(&mut inner.dns, DEFAULT_WINDOW);
    }

    pub async fn dns_cache_lookup(&self, domain: &str, query_type: &str, resolver: RouteDecision) -> Option<Message> {
        let mut inner = self.inner.write().await;
        prune_dns_cache(&mut inner);
        let key = dns_cache_key(domain, query_type, resolver);
        inner.dns_cache.get(&key).map(|entry| entry.message.clone())
    }

    pub async fn dns_cache_lookup_any(&self, domain: &str, query_type: &str) -> Option<(Message, RouteDecision)> {
        let mut inner = self.inner.write().await;
        prune_dns_cache(&mut inner);
        for resolver in [RouteDecision::Proxy, RouteDecision::Direct] {
            let key = dns_cache_key(domain, query_type, resolver);
            if let Some(entry) = inner.dns_cache.get(&key) {
                return Some((entry.message.clone(), resolver));
            }
        }
        None
    }

    pub async fn dns_cache_insert(
        &self,
        domain: &str,
        query_type: &str,
        resolver: RouteDecision,
        message: Message,
        results: Vec<IpAddr>,
    ) {
        let mut inner = self.inner.write().await;
        prune_dns_cache(&mut inner);
        let key = dns_cache_key(domain, query_type, resolver);
        let now = now();
        let ttl = inner.sources.dns_cache_ttl_seconds.max(1);
        inner.dns_cache.insert(
            key.clone(),
            DnsCacheEntry {
                message,
                results,
                expires_at: now.saturating_add(ttl),
                inserted_at: now,
                refreshed_at: now,
            },
        );
        inner.dns_cache_order.push_back(key);
        enforce_dns_cache_capacity(&mut inner);
    }

    pub async fn dns_cache_proxy_refresh_candidates(&self) -> Vec<DnsCacheRefreshCandidate> {
        let mut inner = self.inner.write().await;
        prune_dns_cache(&mut inner);
        if !inner.sources.dns_cache_refresh_enabled {
            return Vec::new();
        }
        let cutoff = now().saturating_sub(DNS_CACHE_REFRESH_INTERVAL.as_secs());
        let batch_size = inner.sources.dns_cache_refresh_batch_size.max(1);
        inner
            .dns_cache
            .iter()
            .filter(|(key, entry)| key.resolver == RouteDecision::Proxy && entry.refreshed_at <= cutoff)
            .take(batch_size)
            .map(|(key, _)| DnsCacheRefreshCandidate {
                domain: key.domain.clone(),
                query_type: key.query_type.clone(),
            })
            .collect()
    }

    pub async fn dns_cache_refresh_preserve_ttl(
        &self,
        domain: &str,
        query_type: &str,
        resolver: RouteDecision,
        message: Message,
        results: Vec<IpAddr>,
    ) -> bool {
        let mut inner = self.inner.write().await;
        prune_dns_cache(&mut inner);
        let key = dns_cache_key(domain, query_type, resolver);
        if let Some(entry) = inner.dns_cache.get_mut(&key) {
            entry.message = message;
            entry.results = results;
            entry.refreshed_at = now();
            true
        } else {
            false
        }
    }

    pub async fn dns_cache_stats(&self) -> DnsCacheStats {
        let mut inner = self.inner.write().await;
        prune_dns_cache(&mut inner);
        DnsCacheStats {
            size: inner.dns_cache.len(),
            capacity: inner.sources.dns_cache_capacity,
            ttl_seconds: inner.sources.dns_cache_ttl_seconds,
            refresh_enabled: inner.sources.dns_cache_refresh_enabled,
            refresh_batch_size: inner.sources.dns_cache_refresh_batch_size,
        }
    }

    /// Cheap, lock-light snapshot used by the periodic in-process diagnostic
    /// logger. Takes a *read* lock and intentionally skips `prune_dns_cache`
    /// so it does not add to the write-lock contention that already shows up
    /// on hot DNS paths when the cache grows large. Reports raw container
    /// sizes only — including `dns_cache_order` so a runaway append (a known
    /// failure mode if duplicate keys ever leak in) is visible directly in
    /// the log.
    pub async fn runtime_diagnostics(&self) -> RuntimeDiagnostics {
        let inner = self.inner.read().await;
        let (prune_calls, prune_ns, nft_calls, nft_ns, append_calls, append_ns, add_calls, add_ns) =
            hot_path_counters();
        RuntimeDiagnostics {
            dns_cache_size: inner.dns_cache.len(),
            dns_cache_order_len: inner.dns_cache_order.len(),
            dns_cache_capacity: inner.sources.dns_cache_capacity,
            dns_cache_ttl_seconds: inner.sources.dns_cache_ttl_seconds,
            dns_events: inner.dns.len(),
            connections: inner.connections.len(),
            flow_decisions: inner.flow_decisions.len(),
            reverse_domains: inner.reverse_domains.len(),
            persistent_direct_ip: inner.persistent.direct_ip.len(),
            persistent_bypass_ip: inner.persistent.bypass_ip.len(),
            temporary_direct_ip: inner.temporary.direct_ip.len(),
            temporary_bypass_ip: inner.temporary.bypass_ip.len(),
            prune_dns_cache_calls: prune_calls,
            prune_dns_cache_total_ns: prune_ns,
            nft_invocations: nft_calls,
            nft_total_ns: nft_ns,
            append_lines_calls: append_calls,
            append_lines_total_ns: append_ns,
            add_dns_results_calls: add_calls,
            add_dns_results_total_ns: add_ns,
        }
    }

    pub async fn dns_cache_query(&self, domain: &str) -> Vec<DnsCacheView> {
        let mut inner = self.inner.write().await;
        prune_dns_cache(&mut inner);
        let domain = normalize_dns_domain(domain);
        let mut rows = inner
            .dns_cache
            .iter()
            .filter(|(key, _)| key.domain == domain)
            .map(|(key, entry)| DnsCacheView {
                domain: key.domain.clone(),
                query_type: key.query_type.clone(),
                resolver: key.resolver,
                results: entry.results.clone(),
                expires_at: entry.expires_at,
                inserted_at: entry.inserted_at,
                refreshed_at: entry.refreshed_at,
            })
            .collect::<Vec<_>>();
        rows.sort_by(|a, b| {
            a.query_type
                .cmp(&b.query_type)
                .then_with(|| a.inserted_at.cmp(&b.inserted_at))
        });
        rows
    }

    pub async fn dns_cache_query_ip(&self, ip: &str) -> Vec<DnsCacheIpView> {
        let Ok(ip) = ip.trim().parse::<IpAddr>() else {
            return Vec::new();
        };
        let mut inner = self.inner.write().await;
        prune_dns_cache(&mut inner);
        let mut rows = inner
            .dns_cache
            .iter()
            .filter(|(_, entry)| entry.results.iter().any(|result| *result == ip))
            .map(|(key, entry)| DnsCacheIpView {
                ip,
                domain: key.domain.clone(),
                query_type: key.query_type.clone(),
                resolver: key.resolver,
                expires_at: entry.expires_at,
            })
            .collect::<Vec<_>>();
        rows.sort_by(|a, b| a.domain.cmp(&b.domain).then_with(|| a.query_type.cmp(&b.query_type)));
        rows
    }

    pub async fn dns_cache_clear(&self, domain: Option<&str>) -> usize {
        let mut inner = self.inner.write().await;
        let before = inner.dns_cache.len();
        if let Some(domain) = domain {
            let domain = normalize_dns_domain(domain);
            inner.dns_cache.retain(|key, _| key.domain != domain);
            inner.dns_cache_order.retain(|key| key.domain != domain);
        } else {
            inner.dns_cache.clear();
            inner.dns_cache_order.clear();
        }
        before.saturating_sub(inner.dns_cache.len())
    }

    pub async fn ip_conflicts(&self) -> Vec<ConflictEvent> {
        if let Err(err) = self.refresh_rule_files_from_disk().await {
            warn!("failed to refresh rule files for IP conflicts: {}", err);
        }
        self.inner.read().await.ip_conflicts.iter().cloned().collect()
    }

    pub async fn domain_conflicts(&self) -> Vec<ConflictEvent> {
        if let Err(err) = self.refresh_rule_files_from_disk().await {
            warn!("failed to refresh rule files for domain conflicts: {}", err);
        }
        self.inner.read().await.domain_conflicts.iter().cloned().collect()
    }

    async fn refresh_rule_files_from_disk(&self) -> io::Result<()> {
        let mut inner = self.inner.write().await;
        refresh_rule_files_from_disk_inner(&mut inner)?;

        Ok(())
    }

    pub async fn recent_connections(&self, excluded_remotes: &[IpAddr]) -> Vec<ConnectionEvent> {
        let mut inner = self.inner.write().await;
        trim_old(&mut inner.connections, DEFAULT_WINDOW);
        // Prune stale flow decisions so the relabel map stays bounded
        // even on a router with high TCP/UDP churn.
        let ttl_cutoff = now().saturating_sub(FLOW_DECISION_TTL.as_secs());
        inner.flow_decisions.retain(|_, (_, ts)| *ts >= ttl_cutoff);
        let reverse_domains = inner.reverse_domains.clone();
        let flow_decisions = inner.flow_decisions.clone();
        let mut rows = inner
            .connections
            .iter()
            .rev()
            .filter(|event| !is_excluded_remote(event, excluded_remotes))
            .cloned()
            .collect::<Vec<_>>();
        let mut seen = rows.iter().map(connection_key).collect::<HashSet<_>>();
        for mut event in collect_system_connections(&reverse_domains) {
            if is_excluded_remote(&event, excluded_remotes) {
                continue;
            }
            // Re-label scraper rows from the authoritative in-memory
            // decision map when the 5-tuple matches.
            if let Some(dst_ip) = event.destination_ip {
                let proto_static = match event.protocol.as_str() {
                    "tcp" => Some("tcp"),
                    "udp" => Some("udp"),
                    _ => None,
                };
                if let Some(p) = proto_static {
                    let key: FlowKey = (event.source_ip, event.source_port, dst_ip, event.destination_port, p);
                    if let Some((decision, _)) = flow_decisions.get(&key) {
                        event.decision = *decision;
                    }
                }
            }
            if seen.insert(connection_key(&event)) {
                rows.push(event);
            }
        }
        rows.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        rows
    }

    pub async fn truncate_record_file(&self) -> io::Result<()> {
        let path = self.inner.read().await.rules_dir.join(RECORD_FILE);
        write_lines_atomic(path, &[])
    }

    pub async fn append_record_connections(&self, rows: &[ConnectionEvent]) -> io::Result<()> {
        let path = self.inner.read().await.rules_dir.join(RECORD_FILE);
        let lines = rows
            .iter()
            .filter_map(|row| serde_json::to_string(row).ok())
            .collect::<Vec<_>>();
        append_lines(&path, &lines)
    }

    pub async fn recent_dns(&self) -> Vec<DnsEvent> {
        let mut inner = self.inner.write().await;
        trim_old(&mut inner.dns, DEFAULT_WINDOW);
        inner.dns.iter().rev().cloned().collect()
    }

    pub async fn direct_bypass_file_conflicts(&self) -> (Vec<String>, Vec<String>) {
        let inner = self.inner.read().await;
        let direct_ip = inner
            .persistent_raw
            .direct_ip
            .iter()
            .filter_map(|rule| parse_ip_net(rule))
            .collect::<Vec<_>>();
        let bypass_ip = inner
            .persistent_raw
            .bypass_ip
            .iter()
            .filter_map(|rule| parse_ip_net(rule))
            .collect::<Vec<_>>();
        let ip_conflicts = ip_net_conflicts(&direct_ip, &bypass_ip);

        let direct_domain = inner
            .persistent_raw
            .direct_domain
            .iter()
            .map(|domain| normalize_domain(domain))
            .filter(|domain| !domain.is_empty())
            .collect::<HashSet<_>>();
        let bypass_domain = inner
            .persistent_raw
            .bypass_domain
            .iter()
            .map(|domain| normalize_domain(domain))
            .filter(|domain| !domain.is_empty())
            .collect::<HashSet<_>>();
        let domain_conflicts = domain_rule_conflicts(&direct_domain, &bypass_domain);

        (ip_conflicts, domain_conflicts)
    }

    pub async fn debug_ip_membership(&self, input: &str) -> IpMembershipDebug {
        let query = input.trim().to_owned();
        let parsed = parse_debug_ip_query(&query);
        let mut result = IpMembershipDebug {
            query,
            valid: parsed.is_ok(),
            error: parsed.as_ref().err().map(ToString::to_string),
            bypass_file: false,
            bypass_file_matches: Vec::new(),
            nft_checked: false,
            nft_bypass: false,
            nft_matches: Vec::new(),
            nft_error: None,
        };
        let Ok(parsed) = parsed else {
            return result;
        };

        let inner = self.inner.read().await;
        result.bypass_file_matches = inner
            .persistent_raw
            .bypass_ip
            .iter()
            .filter_map(|rule| parse_ip_net(rule))
            .filter(|net| debug_ip_query_matches(&parsed, net))
            .map(|net| net.to_string())
            .collect();
        result.bypass_file = !result.bypass_file_matches.is_empty();
        drop(inner);

        #[cfg(all(target_os = "linux", feature = "local-dns"))]
        {
            result.nft_checked = true;
            match crate::local::dns::intercept_linux::bypass_set_matches(&parsed.to_string()) {
                Ok(matches) => {
                    result.nft_bypass = !matches.is_empty();
                    result.nft_matches = matches;
                }
                Err(err) => result.nft_error = Some(err.to_string()),
            }
        }

        result
    }
}

fn route_ip_inner(inner: &mut RoutingInner, ip: &IpAddr) -> Option<RouteDecision> {
    let temp_direct = compiled_rules_match_ip(&inner.temporary.direct_ip_exact, &inner.temporary.direct_ip, ip);
    let temp_proxy = compiled_rules_match_ip(&inner.temporary.bypass_ip_exact, &inner.temporary.bypass_ip, ip);
    if temp_direct && temp_proxy {
        return Some(RouteDecision::Direct);
    }
    if temp_direct {
        return Some(RouteDecision::Direct);
    }
    if temp_proxy {
        return Some(RouteDecision::Proxy);
    }

    let direct = compiled_rules_match_ip(&inner.persistent.direct_ip_exact, &inner.persistent.direct_ip, ip);
    let proxy = compiled_rules_match_ip(&inner.persistent.bypass_ip_exact, &inner.persistent.bypass_ip, ip);
    if direct && proxy {
        return Some(RouteDecision::Direct);
    }
    if direct {
        Some(RouteDecision::Direct)
    } else if proxy {
        Some(RouteDecision::Proxy)
    } else {
        None
    }
}

fn route_domain_inner(inner: &mut RoutingInner, domain: &str) -> Option<RouteDecision> {
    let domain = normalize_domain(domain);
    let temp_direct = rules_match_domain(&inner.temporary.direct_domain, &domain);
    let temp_proxy = rules_match_domain(&inner.temporary.bypass_domain, &domain);
    if temp_direct && temp_proxy {
        return Some(RouteDecision::Direct);
    }
    if temp_direct {
        return Some(RouteDecision::Direct);
    }
    if temp_proxy {
        return Some(RouteDecision::Proxy);
    }

    let direct = rules_match_domain(&inner.persistent.direct_domain, &domain);
    let proxy = rules_match_domain(&inner.persistent.bypass_domain, &domain);
    if direct && proxy {
        return Some(RouteDecision::Direct);
    }
    if direct {
        Some(RouteDecision::Direct)
    } else if proxy {
        Some(RouteDecision::Proxy)
    } else {
        None
    }
}

fn refresh_rule_files_from_disk_inner(inner: &mut RoutingInner) -> io::Result<()> {
    let direct_ip_modified = file_modified(&inner.rules_dir.join(DIRECT_IP_FILE))?;
    let bypass_ip_modified = file_modified(&inner.rules_dir.join(BYPASS_IP_FILE))?;
    let direct_domain_modified = file_modified(&inner.rules_dir.join(DIRECT_DOMAIN_FILE))?;
    let bypass_domain_modified = file_modified(&inner.rules_dir.join(BYPASS_DOMAIN_FILE))?;
    let geoip_path = inner.rules_dir.join(SOURCE_DIR).join("geoip.dat");
    let geoip_modified = file_modified(&geoip_path)?;

    if direct_ip_modified == inner.direct_ip_modified
        && bypass_ip_modified == inner.bypass_ip_modified
        && direct_domain_modified == inner.direct_domain_modified
        && bypass_domain_modified == inner.bypass_domain_modified
        && geoip_modified == inner.geoip_modified
    {
        return Ok(());
    }

    inner.persistent_raw = read_rule_lists(&inner.rules_dir)?;
    inner.persistent = compile_rules(&inner.persistent_raw);
    if geoip_modified != inner.geoip_modified {
        inner.geoip_cn = read_geoip_cn_nets(&geoip_path)?;
    }
    inner.direct_ip_modified = direct_ip_modified;
    inner.bypass_ip_modified = bypass_ip_modified;
    inner.direct_domain_modified = direct_domain_modified;
    inner.bypass_domain_modified = bypass_domain_modified;
    inner.geoip_modified = geoip_modified;
    rebuild_conflicts(inner);
    Ok(())
}

fn rebuild_conflicts(inner: &mut RoutingInner) {
    inner.ip_conflicts.clear();
    inner.domain_conflicts.clear();

    for rule in ip_net_conflicts(&inner.persistent.direct_ip, &inner.persistent.bypass_ip) {
        push_event(
            &mut inner.ip_conflicts,
            new_conflict_event_with_metadata(
                ConflictKind::Ip,
                rule,
                vec!["direct".to_owned(), "bypass".to_owned()],
                vec![DIRECT_IP_FILE.to_owned(), BYPASS_IP_FILE.to_owned()],
            ),
        );
    }

    for rule in ip_net_conflicts(&inner.geoip_cn, &inner.persistent.bypass_ip) {
        push_event(
            &mut inner.ip_conflicts,
            new_conflict_event_with_metadata(
                ConflictKind::Ip,
                rule,
                vec!["cn".to_owned(), "bypass".to_owned()],
                vec!["geoip.dat".to_owned(), BYPASS_IP_FILE.to_owned()],
            ),
        );
    }

    for rule in domain_rule_conflicts(&inner.persistent.direct_domain, &inner.persistent.bypass_domain) {
        push_event(
            &mut inner.domain_conflicts,
            new_conflict_event_with_metadata(
                ConflictKind::Domain,
                rule,
                vec!["direct".to_owned(), "bypass".to_owned()],
                vec![DIRECT_DOMAIN_FILE.to_owned(), BYPASS_DOMAIN_FILE.to_owned()],
            ),
        );
    }
}

fn new_conflict_event_with_metadata(
    kind: ConflictKind,
    value: String,
    regions: Vec<String>,
    sources: Vec<String>,
) -> ConflictEvent {
    warn!("routing rule conflict {:?}: {}", kind, value);
    ConflictEvent {
        timestamp: now(),
        kind,
        value,
        regions,
        sources,
    }
}

fn rules_match_ip(rules: &[IpNet], ip: &IpAddr) -> bool {
    rules.iter().any(|net| net.contains(ip))
}

fn ip_nets_overlap(left: &IpNet, right: &IpNet) -> bool {
    match (left, right) {
        (IpNet::V4(left), IpNet::V4(right)) => left.contains(&right.network()) || right.contains(&left.network()),
        (IpNet::V6(left), IpNet::V6(right)) => left.contains(&right.network()) || right.contains(&left.network()),
        _ => false,
    }
}

fn ip_net_conflicts(direct: &[IpNet], bypass: &[IpNet]) -> Vec<String> {
    let mut conflicts = Vec::new();
    for direct in direct {
        for bypass in bypass {
            if ip_nets_overlap(direct, bypass) {
                let direct = display_ip_net(direct);
                let bypass = display_ip_net(bypass);
                conflicts.push(if direct == bypass {
                    direct
                } else {
                    format!("{direct} <-> {bypass}")
                });
            }
        }
    }
    conflicts.sort_unstable();
    conflicts.dedup();
    conflicts
}

fn display_ip_net(net: &IpNet) -> String {
    match net {
        IpNet::V4(net) if net.prefix_len() == 32 => net.addr().to_string(),
        IpNet::V6(net) if net.prefix_len() == 128 => net.addr().to_string(),
        _ => net.to_string(),
    }
}

fn compiled_rules_match_ip(exact: &HashSet<IpAddr>, nets: &[IpNet], ip: &IpAddr) -> bool {
    exact.contains(ip) || rules_match_ip(nets, ip)
}

fn rules_match_domain(rules: &HashSet<String>, domain: &str) -> bool {
    rules.contains(domain) || rules.iter().any(|rule| domain_matches_rule(rule, domain))
}

fn domain_rule_conflicts(direct: &HashSet<String>, bypass: &HashSet<String>) -> Vec<String> {
    let mut conflicts = Vec::new();
    let direct_wildcards = direct.iter().filter(|rule| rule.contains('*')).collect::<Vec<_>>();
    let bypass_wildcards = bypass.iter().filter(|rule| rule.contains('*')).collect::<Vec<_>>();

    for direct in direct {
        if direct.contains('*') {
            continue;
        }
        for bypass_candidate in domain_match_candidates(direct) {
            if bypass.contains(&bypass_candidate) {
                conflicts.push(format_domain_conflict(direct, &bypass_candidate));
            }
        }
    }

    for bypass in bypass {
        if bypass.contains('*') {
            continue;
        }
        for direct_candidate in domain_match_candidates(bypass) {
            if direct.contains(&direct_candidate) {
                conflicts.push(format_domain_conflict(&direct_candidate, bypass));
            }
        }
    }

    for direct in &direct_wildcards {
        for bypass in bypass {
            if domain_rules_overlap(direct, bypass) {
                conflicts.push(format_domain_conflict(direct, bypass));
            }
        }
    }

    for bypass in &bypass_wildcards {
        for direct in direct {
            if direct.contains('*') {
                continue;
            }
            if domain_rules_overlap(direct, bypass) {
                conflicts.push(format_domain_conflict(direct, bypass));
            }
        }
    }

    conflicts.sort_unstable();
    conflicts.dedup();
    conflicts
}

fn domain_match_candidates(domain: &str) -> Vec<String> {
    let mut candidates = vec![domain.to_owned()];
    for (idx, _) in domain.match_indices('.') {
        let suffix = &domain[idx + 1..];
        if suffix.contains('.') {
            candidates.push(suffix.to_owned());
        }
    }
    candidates
}

fn format_domain_conflict(direct: &str, bypass: &str) -> String {
    if direct == bypass {
        direct.to_owned()
    } else {
        format!("{direct} <-> {bypass}")
    }
}

fn domain_rules_overlap(left: &str, right: &str) -> bool {
    if domain_matches_rule(left, right) || domain_matches_rule(right, left) {
        return true;
    }
    if !left.contains('*') && !right.contains('*') {
        return false;
    }
    wildcard_overlap_candidates(left, right)
        .into_iter()
        .any(|candidate| domain_matches_rule(left, &candidate) && domain_matches_rule(right, &candidate))
}

fn wildcard_overlap_candidates(left: &str, right: &str) -> Vec<String> {
    let left_prefix = left.split('*').next().unwrap_or_default();
    let left_suffix = left.rsplit('*').next().unwrap_or_default();
    let right_prefix = right.split('*').next().unwrap_or_default();
    let right_suffix = right.rsplit('*').next().unwrap_or_default();
    [
        left.replace('*', "example"),
        right.replace('*', "example"),
        join_wildcard_candidate(right_prefix, left_suffix),
        join_wildcard_candidate(left_prefix, right_suffix),
    ]
    .into_iter()
    .map(|candidate| normalize_domain(&candidate))
    .filter(|candidate| !candidate.is_empty())
    .collect()
}

fn join_wildcard_candidate(prefix: &str, suffix: &str) -> String {
    match (prefix.strip_suffix('.'), suffix.strip_prefix('.')) {
        (Some(prefix), Some(suffix)) => format!("{prefix}.{suffix}"),
        _ => format!("{prefix}{suffix}"),
    }
}

fn domain_matches_rule(rule: &str, domain: &str) -> bool {
    if rule.contains('*') {
        wildcard_domain_matches(rule, domain)
    } else if !rule.contains('.') {
        domain == rule
    } else {
        domain == rule
            || (domain.len() > rule.len()
                && domain.ends_with(rule)
                && domain.as_bytes()[domain.len() - rule.len() - 1] == b'.')
    }
}

fn wildcard_domain_matches(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    let mut remaining = value;
    let mut parts = pattern.split('*').peekable();
    let mut first = true;
    while let Some(part) = parts.next() {
        if part.is_empty() {
            first = false;
            continue;
        }
        if first && !pattern.starts_with('*') {
            let Some(stripped) = remaining.strip_prefix(part) else {
                return false;
            };
            remaining = stripped;
        } else if parts.peek().is_none() && !pattern.ends_with('*') {
            return remaining.ends_with(part);
        } else if let Some(idx) = remaining.find(part) {
            remaining = &remaining[idx + part.len()..];
        } else {
            return false;
        }
        first = false;
    }
    pattern.ends_with('*') || remaining.is_empty()
}

fn compile_rules(raw: &RuleLists) -> CompiledRules {
    CompiledRules {
        direct_ip: raw.direct_ip.iter().filter_map(|s| parse_ip_net(s)).collect(),
        direct_ip_exact: raw.direct_ip.iter().filter_map(|s| s.parse::<IpAddr>().ok()).collect(),
        direct_domain: raw
            .direct_domain
            .iter()
            .map(|s| normalize_domain(s))
            .filter(|s| !s.is_empty())
            .collect(),
        bypass_ip: raw.bypass_ip.iter().filter_map(|s| parse_ip_net(s)).collect(),
        bypass_ip_exact: raw.bypass_ip.iter().filter_map(|s| s.parse::<IpAddr>().ok()).collect(),
        bypass_domain: raw
            .bypass_domain
            .iter()
            .map(|s| normalize_domain(s))
            .filter(|s| !s.is_empty())
            .collect(),
    }
}

fn parse_ip_net(value: &str) -> Option<IpNet> {
    if let Ok(net) = value.parse::<IpNet>() {
        return Some(net);
    }
    value.parse::<IpAddr>().ok().map(IpNet::from)
}

#[derive(Clone, Debug)]
enum DebugIpQuery {
    Ip(IpAddr),
    Net(IpNet),
}

impl std::fmt::Display for DebugIpQuery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DebugIpQuery::Ip(ip) => write!(f, "{ip}"),
            DebugIpQuery::Net(net) => write!(f, "{net}"),
        }
    }
}

fn parse_debug_ip_query(value: &str) -> io::Result<DebugIpQuery> {
    let value = value.trim();
    if value.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "ip or cidr is required"));
    }
    if value.contains('/') {
        value
            .parse::<IpNet>()
            .map(DebugIpQuery::Net)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, format!("invalid cidr: {err}")))
    } else {
        value
            .parse::<IpAddr>()
            .map(DebugIpQuery::Ip)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, format!("invalid ip: {err}")))
    }
}

fn debug_ip_query_matches(query: &DebugIpQuery, net: &IpNet) -> bool {
    match query {
        DebugIpQuery::Ip(ip) => net.contains(ip),
        DebugIpQuery::Net(query_net) => ip_nets_overlap(query_net, net),
    }
}

fn is_private_connection_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            ip.is_loopback()
                || ip.octets()[0] == 10
                || (ip.octets()[0] == 172 && (16..=31).contains(&ip.octets()[1]))
                || (ip.octets()[0] == 192 && ip.octets()[1] == 168)
        }
        IpAddr::V6(ip) => {
            ip.is_loopback()
                || ip
                    .to_ipv4_mapped()
                    .is_some_and(|ip| is_private_connection_ip(&IpAddr::V4(ip)))
                || (ip.segments()[0] & 0xfe00) == 0xfc00
                || (ip.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

fn connection_key(event: &ConnectionEvent) -> (IpAddr, u16, Option<IpAddr>, Option<String>, u16, String) {
    (
        event.source_ip,
        event.source_port,
        event.destination_ip,
        event.destination_domain.clone(),
        event.destination_port,
        event.protocol.clone(),
    )
}

fn is_excluded_remote(event: &ConnectionEvent, excluded_remotes: &[IpAddr]) -> bool {
    let Some(destination_ip) = event.destination_ip else {
        return false;
    };
    excluded_remotes.iter().any(|ip| *ip == destination_ip)
}

fn collect_system_connections(reverse_domains: &HashMap<IpAddr, String>) -> Vec<ConnectionEvent> {
    let mut rows = Vec::new();
    let mut seen = HashSet::new();
    for event in collect_conntrack_connections(reverse_domains)
        .into_iter()
        .chain(collect_proc_net_connections(reverse_domains))
    {
        if seen.insert(connection_key(&event)) {
            rows.push(event);
        }
    }
    rows
}

fn collect_conntrack_connections(reverse_domains: &HashMap<IpAddr, String>) -> Vec<ConnectionEvent> {
    ["/proc/net/nf_conntrack", "/proc/net/ip_conntrack"]
        .into_iter()
        .find_map(|path| fs::read_to_string(path).ok())
        .map(|content| {
            content
                .lines()
                .filter_map(|line| parse_conntrack_line(line, reverse_domains))
                .collect()
        })
        .unwrap_or_default()
}

fn parse_conntrack_line(line: &str, reverse_domains: &HashMap<IpAddr, String>) -> Option<ConnectionEvent> {
    let mut protocol = None;
    for token in line.split_whitespace().take(4) {
        if matches!(token, "tcp" | "udp") {
            protocol = Some(token.to_owned());
            break;
        }
    }
    let protocol = protocol?;
    let mut source_ip = None;
    let mut destination_ip = None;
    let mut source_port = None;
    let mut destination_port = None;
    for token in line.split_whitespace() {
        let Some((key, value)) = token.split_once('=') else {
            continue;
        };
        match key {
            "src" if source_ip.is_none() => source_ip = value.parse::<IpAddr>().ok(),
            "dst" if destination_ip.is_none() => destination_ip = value.parse::<IpAddr>().ok(),
            "sport" if source_port.is_none() => source_port = value.parse::<u16>().ok(),
            "dport" if destination_port.is_none() => destination_port = value.parse::<u16>().ok(),
            _ => {}
        }
        if source_ip.is_some() && destination_ip.is_some() && source_port.is_some() && destination_port.is_some() {
            break;
        }
    }
    let destination_ip = destination_ip?;
    if is_private_connection_ip(&destination_ip) {
        return None;
    }
    Some(ConnectionEvent {
        timestamp: now(),
        source_ip: source_ip?,
        source_port: source_port?,
        destination_ip: Some(destination_ip),
        destination_domain: None,
        domain: reverse_domains.get(&destination_ip).cloned(),
        destination_port: destination_port?,
        protocol,
        decision: ConnectionDecision::Observed,
    })
}

fn collect_proc_net_connections(reverse_domains: &HashMap<IpAddr, String>) -> Vec<ConnectionEvent> {
    [
        ("/proc/net/tcp", "tcp", false),
        ("/proc/net/udp", "udp", false),
        ("/proc/net/tcp6", "tcp", true),
        ("/proc/net/udp6", "udp", true),
    ]
    .into_iter()
    .flat_map(|(path, protocol, ipv6)| {
        fs::read_to_string(path).ok().into_iter().flat_map(move |content| {
            content
                .lines()
                .skip(1)
                .filter_map(move |line| parse_proc_net_line(line, protocol, ipv6, reverse_domains))
                .collect::<Vec<_>>()
        })
    })
    .collect()
}

fn parse_proc_net_line(
    line: &str,
    protocol: &str,
    ipv6: bool,
    reverse_domains: &HashMap<IpAddr, String>,
) -> Option<ConnectionEvent> {
    let fields = line.split_whitespace().collect::<Vec<_>>();
    let local = fields.get(1)?;
    let remote = fields.get(2)?;
    let state = fields.get(3).copied().unwrap_or_default();
    if state == "0A" {
        return None;
    }
    let (source_ip, source_port) = parse_proc_net_addr(local, ipv6)?;
    let (destination_ip, destination_port) = parse_proc_net_addr(remote, ipv6)?;
    if destination_port == 0 || is_unspecified_ip(&destination_ip) || is_private_connection_ip(&destination_ip) {
        return None;
    }
    Some(ConnectionEvent {
        timestamp: now(),
        source_ip,
        source_port,
        destination_ip: Some(destination_ip),
        destination_domain: None,
        domain: reverse_domains.get(&destination_ip).cloned(),
        destination_port,
        protocol: protocol.to_owned(),
        decision: ConnectionDecision::Observed,
    })
}

fn parse_proc_net_addr(value: &str, ipv6: bool) -> Option<(IpAddr, u16)> {
    let (addr, port) = value.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    if ipv6 {
        let bytes = (0..16)
            .map(|idx| u8::from_str_radix(&addr[idx * 2..idx * 2 + 2], 16).ok())
            .collect::<Option<Vec<_>>>()?;
        let mut octets = [0u8; 16];
        for (chunk_idx, chunk) in bytes.chunks(4).enumerate() {
            for (idx, byte) in chunk.iter().rev().enumerate() {
                octets[chunk_idx * 4 + idx] = *byte;
            }
        }
        Some((IpAddr::V6(Ipv6Addr::from(octets)), port))
    } else {
        let raw = u32::from_str_radix(addr, 16).ok()?;
        Some((IpAddr::V4(Ipv4Addr::from(raw.to_le_bytes())), port))
    }
}

fn is_unspecified_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_unspecified(),
        IpAddr::V6(ip) => ip.is_unspecified(),
    }
}

fn progress_percent(completed_files: usize, total_files: usize) -> u8 {
    if total_files == 0 {
        100
    } else {
        ((completed_files.saturating_mul(100)) / total_files).min(100) as u8
    }
}

fn total_update_steps(sources: &RoutingSources) -> usize {
    total_download_steps(sources) + GENERATED_RULE_FILES.len()
}

fn total_download_steps(sources: &RoutingSources) -> usize {
    sources.geoip_sources.len() + sources.bypass_domain_sources.len()
}

fn normalize_rule_lists(lists: RuleLists) -> RuleLists {
    RuleLists {
        direct_ip: normalize_lines(lists.direct_ip),
        direct_domain: normalize_domains(lists.direct_domain),
        bypass_ip: normalize_lines(lists.bypass_ip),
        bypass_domain: normalize_domains(lists.bypass_domain),
    }
}

fn with_private_direct_rules(mut lists: RuleLists) -> RuleLists {
    lists
        .direct_ip
        .extend(PRIVATE_DIRECT_IP_RULES.iter().map(|rule| (*rule).to_owned()));
    normalize_rule_lists(lists)
}

fn validate_temporary_rules(lists: &RuleLists) -> io::Result<()> {
    let _ = lists;
    Ok(())
}

#[cfg(all(target_os = "linux", feature = "local-dns"))]
fn persistent_nft_bypass_nets(inner: &RoutingInner) -> Vec<IpNet> {
    let direct = &inner.persistent.direct_ip;
    let mut bypass = inner.persistent.bypass_ip.clone();
    bypass.retain(|net| !direct.iter().any(|direct| ip_nets_overlap(direct, net)));
    bypass
}

#[cfg(all(target_os = "linux", feature = "local-dns"))]
fn temporary_nft_bypass_nets(inner: &RoutingInner, rules: &RuleLists) -> Vec<IpNet> {
    let temporary_direct = rules
        .direct_ip
        .iter()
        .filter_map(|rule| parse_ip_net(rule))
        .collect::<Vec<_>>();

    let mut direct = inner.persistent.direct_ip.clone();
    direct.extend(temporary_direct);
    let mut bypass = inner.persistent.bypass_ip.clone();
    bypass.extend(rules.bypass_ip.iter().filter_map(|rule| parse_ip_net(rule)));
    bypass.retain(|net| !direct.iter().any(|direct| ip_nets_overlap(direct, net)));

    bypass
}

fn normalize_lines(lines: Vec<String>) -> Vec<String> {
    let mut set = HashSet::new();
    for line in lines {
        let line = line.trim();
        if !line.is_empty() {
            set.insert(line.to_owned());
        }
    }
    let mut lines: Vec<_> = set.into_iter().collect();
    lines.sort_unstable();
    lines
}

fn normalize_domains(lines: Vec<String>) -> Vec<String> {
    let mut lines: Vec<_> = lines
        .into_iter()
        .map(|s| normalize_domain(&s))
        .filter(|s| !s.is_empty())
        .collect();
    lines.sort_unstable();
    lines.dedup();
    lines
}

fn normalize_domain(value: &str) -> String {
    let value = value
        .trim()
        .trim_end_matches('.')
        .trim_start_matches("domain:")
        .trim_start_matches("full:")
        .trim_start_matches("regexp:")
        .trim_start_matches("keyword:");
    value.to_ascii_lowercase()
}

fn normalize_dns_domain(value: &str) -> String {
    normalize_domain(value)
}

fn dns_cache_key(domain: &str, query_type: &str, resolver: RouteDecision) -> DnsCacheKey {
    DnsCacheKey {
        domain: normalize_dns_domain(domain),
        query_type: query_type.to_ascii_uppercase(),
        resolver,
    }
}

fn parse_text_rules(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| {
            let line = line.split('#').next().unwrap_or_default().trim();
            if line.is_empty() { None } else { Some(line.to_owned()) }
        })
        .collect()
}

fn read_rule_lists(dir: &Path) -> io::Result<RuleLists> {
    Ok(RuleLists {
        direct_ip: read_lines(dir.join(DIRECT_IP_FILE))?,
        direct_domain: read_lines(dir.join(DIRECT_DOMAIN_FILE))?,
        bypass_ip: read_lines(dir.join(BYPASS_IP_FILE))?,
        bypass_domain: read_lines(dir.join(BYPASS_DOMAIN_FILE))?,
    })
}

fn read_temporary_rule_lists(dir: &Path) -> io::Result<RuleLists> {
    Ok(RuleLists {
        direct_ip: read_lines(dir.join(TEMP_DIRECT_IP_FILE))?,
        direct_domain: read_lines(dir.join(TEMP_DIRECT_DOMAIN_FILE))?,
        bypass_ip: read_lines(dir.join(TEMP_BYPASS_IP_FILE))?,
        bypass_domain: read_lines(dir.join(TEMP_BYPASS_DOMAIN_FILE))?,
    })
}

fn write_temporary_rule_lists(dir: &Path, lists: &RuleLists) -> io::Result<()> {
    write_lines_atomic(dir.join(TEMP_DIRECT_IP_FILE), &lists.direct_ip)?;
    write_lines_atomic(dir.join(TEMP_DIRECT_DOMAIN_FILE), &lists.direct_domain)?;
    write_lines_atomic(dir.join(TEMP_BYPASS_IP_FILE), &lists.bypass_ip)?;
    write_lines_atomic(dir.join(TEMP_BYPASS_DOMAIN_FILE), &lists.bypass_domain)?;
    Ok(())
}

fn sanitize_sources(sources: RoutingSources) -> RoutingSources {
    sources
}

fn read_lines(path: impl AsRef<Path>) -> io::Result<Vec<String>> {
    let path = path.as_ref();
    if !path.exists() {
        return Ok(Vec::new());
    }
    Ok(parse_text_rules(&fs::read_to_string(path)?))
}

fn append_lines(path: &Path, lines: &[String]) -> io::Result<()> {
    if lines.is_empty() {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = fs::OpenOptions::new().create(true).append(true).open(path)?;
    for line in lines {
        writeln!(file, "{line}")?;
    }
    Ok(())
}

fn write_lines_atomic(path: impl AsRef<Path>, lines: &[String]) -> io::Result<()> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("tmp");
    {
        let mut file = fs::File::create(&tmp)?;
        for line in lines {
            writeln!(file, "{line}")?;
        }
    }
    fs::rename(tmp, path)
}

fn ensure_file(path: impl AsRef<Path>) -> io::Result<()> {
    let path = path.as_ref();
    if !path.exists() {
        write_lines_atomic(path, &[])?;
    }
    Ok(())
}

fn file_modified(path: &Path) -> io::Result<Option<SystemTime>> {
    match fs::metadata(path) {
        Ok(metadata) => metadata.modified().map(Some),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err),
    }
}

struct DownloadedSource {
    bytes: Vec<u8>,
    display_name: String,
    from_cache: bool,
}

async fn download_source(source: &str, cache_dir: &Path) -> io::Result<DownloadedSource> {
    if source.starts_with("http://") || source.starts_with("https://") {
        let source = source.to_owned();
        let cache_dir = cache_dir.to_owned();
        tokio::task::spawn_blocking(move || {
            let display_name = source_cache_name(&source);
            let cache_path = cached_source_path(&source, &cache_dir);
            if !source_needs_refresh(&cache_path, SOURCE_REFRESH_INTERVAL)?
                && let Some(bytes) = read_non_empty_file(&cache_path)?
            {
                return Ok(DownloadedSource {
                    bytes,
                    display_name,
                    from_cache: true,
                });
            }

            fs::create_dir_all(&cache_dir)?;
            let temp_dir = cache_dir.join(SOURCE_TEMP_DIR);
            fs::create_dir_all(&temp_dir)?;
            for (cmd, args) in [
                ("uclient-fetch", vec!["-q", "-O", "-", &source]),
                ("wget", vec!["-qO-", &source]),
                ("curl", vec!["-fsSL", &source]),
            ] {
                match Command::new(cmd).args(args).output() {
                    Ok(out) if out.status.success() && !out.stdout.is_empty() => {
                        write_downloaded_source_atomic(&cache_path, &temp_dir, &out.stdout)?;
                        return Ok(DownloadedSource {
                            bytes: out.stdout,
                            display_name,
                            from_cache: false,
                        });
                    }
                    _ => continue,
                }
            }
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                "no working downloader found; install uclient-fetch, wget, or curl",
            ))
        })
        .await
        .map_err(|err| io::Error::other(err.to_string()))?
    } else {
        Ok(DownloadedSource {
            bytes: fs::read(source)?,
            display_name: source_progress_name(source),
            from_cache: true,
        })
    }
}

fn cached_source_path(source: &str, cache_dir: &Path) -> PathBuf {
    cache_dir.join(source_cache_name(source))
}

fn write_downloaded_source_atomic(path: &Path, temp_dir: &Path, bytes: &[u8]) -> io::Result<()> {
    fs::create_dir_all(temp_dir)?;
    let file_name = path.file_name().unwrap_or_else(|| std::ffi::OsStr::new("source.dat"));
    let tmp = temp_dir.join(file_name);
    fs::write(&tmp, bytes)?;
    fs::rename(tmp, path)
}

fn source_progress_name(source: &str) -> String {
    if source.starts_with("http://") || source.starts_with("https://") {
        source_cache_name(source)
    } else {
        Path::new(source)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(source)
            .to_owned()
    }
}

fn source_cache_name(source: &str) -> String {
    let source = source
        .split('#')
        .next()
        .unwrap_or(source)
        .split('?')
        .next()
        .unwrap_or(source)
        .trim_end_matches('/');
    let name = source
        .rsplit('/')
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or("source.dat");
    let name = name
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_') {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>();
    if name.is_empty() { "source.dat".to_owned() } else { name }
}

fn read_non_empty_file(path: &Path) -> io::Result<Option<Vec<u8>>> {
    match fs::metadata(path) {
        Ok(metadata) if metadata.len() > 0 => fs::read(path).map(Some),
        Ok(_) => Ok(None),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err),
    }
}

fn source_needs_refresh(path: &Path, interval: Duration) -> io::Result<bool> {
    let metadata = match fs::metadata(path) {
        Ok(metadata) if metadata.len() > 0 => metadata,
        Ok(_) => return Ok(true),
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(true),
        Err(err) => return Err(err),
    };
    let modified = metadata.modified()?;
    Ok(modified.elapsed().unwrap_or(interval) >= interval)
}

fn read_geoip_cn_nets(path: &Path) -> io::Result<Vec<IpNet>> {
    match fs::read(path) {
        Ok(bytes) => parse_geoip_cn_nets(&bytes),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(err) => Err(err),
    }
}

fn parse_geoip_cn_nets(bytes: &[u8]) -> io::Result<Vec<IpNet>> {
    let entries = read_len_fields(bytes, 1)?;
    if entries.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "empty geoip.dat"));
    }
    let mut nets = Vec::new();
    for entry in entries {
        let country = read_string_fields(entry, 1)
            .into_iter()
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase();
        if country != "cn" {
            continue;
        }
        for cidr in read_len_fields(entry, 2)? {
            let ip = read_bytes_fields(cidr, 1).into_iter().next().unwrap_or_default();
            let prefix = read_varint_fields(cidr, 2).into_iter().next().unwrap_or(0);
            let ip = match ip.len() {
                4 => IpAddr::from([ip[0], ip[1], ip[2], ip[3]]),
                16 => {
                    let mut b = [0u8; 16];
                    b.copy_from_slice(&ip);
                    IpAddr::from(b)
                }
                _ => continue,
            };
            if let Some(net) = parse_ip_net(&format!("{ip}/{prefix}")) {
                nets.push(net);
            }
        }
    }
    nets.sort_unstable_by_key(ToString::to_string);
    nets.dedup();
    Ok(nets)
}

fn read_len_fields(mut bytes: &[u8], field: u64) -> io::Result<Vec<&[u8]>> {
    let mut out = Vec::new();
    while !bytes.is_empty() {
        let key = read_varint(&mut bytes)?;
        let number = key >> 3;
        let wire = key & 0x07;
        match wire {
            0 => {
                let _ = read_varint(&mut bytes)?;
            }
            2 => {
                let len = read_varint(&mut bytes)? as usize;
                if bytes.len() < len {
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "protobuf field length"));
                }
                let (value, rest) = bytes.split_at(len);
                if number == field {
                    out.push(value);
                }
                bytes = rest;
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unsupported protobuf wire type",
                ));
            }
        }
    }
    Ok(out)
}

fn read_bytes_fields(bytes: &[u8], field: u64) -> Vec<Vec<u8>> {
    read_len_fields(bytes, field)
        .unwrap_or_default()
        .into_iter()
        .map(ToOwned::to_owned)
        .collect()
}

fn read_string_fields(bytes: &[u8], field: u64) -> Vec<String> {
    read_bytes_fields(bytes, field)
        .into_iter()
        .filter_map(|v| String::from_utf8(v).ok())
        .collect()
}

fn read_varint_fields(mut bytes: &[u8], field: u64) -> Vec<u64> {
    let mut out = Vec::new();
    while !bytes.is_empty() {
        let Ok(key) = read_varint(&mut bytes) else {
            break;
        };
        let number = key >> 3;
        let wire = key & 0x07;
        match wire {
            0 => {
                if let Ok(value) = read_varint(&mut bytes)
                    && number == field
                {
                    out.push(value);
                }
            }
            2 => {
                let Ok(len) = read_varint(&mut bytes) else {
                    break;
                };
                let len = len as usize;
                if bytes.len() < len {
                    break;
                }
                bytes = &bytes[len..];
            }
            _ => break,
        }
    }
    out
}

fn read_varint(bytes: &mut &[u8]) -> io::Result<u64> {
    let mut value = 0u64;
    for shift in (0..64).step_by(7) {
        let Some((&byte, rest)) = bytes.split_first() else {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "protobuf varint"));
        };
        *bytes = rest;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(io::Error::new(io::ErrorKind::InvalidData, "protobuf varint too long"))
}

fn push_event<T>(events: &mut VecDeque<T>, event: T) {
    events.push_back(event);
    while events.len() > MAX_EVENTS {
        events.pop_front();
    }
}

fn trim_old<T: Timestamped>(events: &mut VecDeque<T>, window: Duration) {
    let cutoff = now().saturating_sub(window.as_secs());
    while events.front().is_some_and(|event| event.timestamp() < cutoff) {
        events.pop_front();
    }
}

fn prune_dns_cache(inner: &mut RoutingInner) {
    // Instrumentation rationale: this function is called on every
    // DNS lookup *under the routing write lock*. If it's the actual
    // hot-path bottleneck we suspect, the cumulative time spent here
    // — divided by elapsed wall clock — gives the duty cycle of the
    // routing lock spent on pruning alone. The periodic logger reports
    // both call count and total ns, so we can divide and read off
    // average duration too.
    let started = Instant::now();
    let cache_before = inner.dns_cache.len();
    let order_before = inner.dns_cache_order.len();

    let now = now();
    let expired = inner
        .dns_cache
        .iter()
        .filter_map(|(key, entry)| (entry.expires_at <= now).then_some(key.clone()))
        .collect::<Vec<_>>();
    for key in expired {
        inner.dns_cache.remove(&key);
    }
    inner.dns_cache_order.retain(|key| inner.dns_cache.contains_key(key));

    let elapsed = started.elapsed();
    PRUNE_DNS_CACHE_CALLS.fetch_add(1, AtomicOrdering::Relaxed);
    PRUNE_DNS_CACHE_TOTAL_NS.fetch_add(elapsed.as_nanos() as u64, AtomicOrdering::Relaxed);
    if elapsed.as_millis() >= SLOW_HOT_PATH_MS {
        warn!(
            "prune_dns_cache slow: {}ms (cache {} -> {}, order {} -> {})",
            elapsed.as_millis(),
            cache_before,
            inner.dns_cache.len(),
            order_before,
            inner.dns_cache_order.len(),
        );
    }
}

fn enforce_dns_cache_capacity(inner: &mut RoutingInner) {
    let capacity = inner.sources.dns_cache_capacity.max(1);
    while inner.dns_cache.len() > capacity {
        if let Some(key) = inner.dns_cache_order.pop_front() {
            inner.dns_cache.remove(&key);
        } else {
            break;
        }
    }
}

trait Timestamped {
    fn timestamp(&self) -> u64;
}

impl Timestamped for ConnectionEvent {
    fn timestamp(&self) -> u64 {
        self.timestamp
    }
}

impl Timestamped for DnsEvent {
    fn timestamp(&self) -> u64 {
        self.timestamp
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_rules_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ss-rust-routing-{name}-{}", now()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[tokio::test]
    async fn temporary_rules_override_persistent_rules() {
        let dir = temp_rules_dir("override");
        write_lines_atomic(dir.join(DIRECT_IP_FILE), &["1.1.1.1".to_owned()]).unwrap();
        write_lines_atomic(dir.join(DIRECT_DOMAIN_FILE), &["example.com".to_owned()]).unwrap();
        write_lines_atomic(dir.join(BYPASS_IP_FILE), &[]).unwrap();
        write_lines_atomic(dir.join(BYPASS_DOMAIN_FILE), &[]).unwrap();

        let mut config = RouteRulesConfig::default();
        config.rules_dir = dir;
        let state = RoutingState::load(config).await.unwrap();
        assert_eq!(
            state.route_ip(&"1.1.1.1".parse().unwrap()).await,
            Some(RouteDecision::Direct)
        );
        assert_eq!(state.route_domain("example.com").await, Some(RouteDecision::Direct));

        state
            .set_temporary_rules(RuleLists {
                bypass_ip: vec!["1.1.1.1".to_owned()],
                bypass_domain: vec!["example.com".to_owned()],
                ..RuleLists::default()
            })
            .await
            .unwrap();

        assert_eq!(
            state.route_ip(&"1.1.1.1".parse().unwrap()).await,
            Some(RouteDecision::Proxy)
        );
        assert_eq!(state.route_domain("example.com").await, Some(RouteDecision::Proxy));
    }

    #[tokio::test]
    async fn source_update_writes_four_rule_files() {
        let dir = temp_rules_dir("sources");
        let bypass_source = dir.join("bypass.txt");
        fs::write(
            dir.join(DIRECT_DOMAIN_FILE),
            "direct.example\n# comment\nchina.example\n",
        )
        .unwrap();
        fs::write(&bypass_source, "proxy.example\ngfw.example\n").unwrap();

        let mut config = RouteRulesConfig::default();
        config.rules_dir = dir.clone();
        config.geoip_sources.clear();
        config.bypass_domain_sources = vec![bypass_source.display().to_string()];

        let state = RoutingState::load(config).await.unwrap();
        state.update_from_sources().await.unwrap();

        let direct_domain = read_lines(dir.join(DIRECT_DOMAIN_FILE)).unwrap();
        let bypass_domain = read_lines(dir.join(BYPASS_DOMAIN_FILE)).unwrap();
        assert!(direct_domain.contains(&"direct.example".to_owned()));
        assert!(direct_domain.contains(&"china.example".to_owned()));
        assert!(bypass_domain.contains(&"proxy.example".to_owned()));
        assert!(bypass_domain.contains(&"gfw.example".to_owned()));
        assert!(dir.join(DIRECT_IP_FILE).exists());
        assert!(dir.join(BYPASS_IP_FILE).exists());
    }

    #[tokio::test]
    async fn wildcard_domain_rules_route_and_conflict() {
        let dir = temp_rules_dir("wildcard-domain");
        write_lines_atomic(dir.join(DIRECT_IP_FILE), &[]).unwrap();
        write_lines_atomic(dir.join(BYPASS_IP_FILE), &[]).unwrap();
        write_lines_atomic(dir.join(DIRECT_DOMAIN_FILE), &["*.example.com".to_owned()]).unwrap();
        write_lines_atomic(dir.join(BYPASS_DOMAIN_FILE), &["api.*".to_owned()]).unwrap();

        let mut config = RouteRulesConfig::default();
        config.rules_dir = dir;
        config.geoip_sources.clear();
        config.bypass_domain_sources.clear();
        let state = RoutingState::load(config).await.unwrap();

        assert_eq!(state.route_domain("www.example.com").await, Some(RouteDecision::Direct));
        assert_eq!(state.route_domain("api.example.com").await, Some(RouteDecision::Direct));
        let conflicts = state.domain_conflicts().await;
        assert!(conflicts.iter().any(|conflict| {
            matches!(
                conflict.value.as_str(),
                "*.example.com <-> api.*" | "api.* <-> *.example.com"
            ) && conflict.sources == [DIRECT_DOMAIN_FILE.to_owned(), BYPASS_DOMAIN_FILE.to_owned()]
        }));
    }

    #[tokio::test]
    async fn single_label_domain_rules_do_not_match_tlds() {
        let dir = temp_rules_dir("single-label-domain");
        write_lines_atomic(dir.join(DIRECT_IP_FILE), &[]).unwrap();
        write_lines_atomic(dir.join(BYPASS_IP_FILE), &[]).unwrap();
        write_lines_atomic(dir.join(DIRECT_DOMAIN_FILE), &["cn".to_owned()]).unwrap();
        write_lines_atomic(dir.join(BYPASS_DOMAIN_FILE), &["google.cn".to_owned()]).unwrap();

        let mut config = RouteRulesConfig::default();
        config.rules_dir = dir;
        config.geoip_sources.clear();
        config.bypass_domain_sources.clear();
        let state = RoutingState::load(config).await.unwrap();

        assert_eq!(state.route_domain("cn").await, Some(RouteDecision::Direct));
        assert_eq!(state.route_domain("google.cn").await, Some(RouteDecision::Proxy));
        assert!(state.domain_conflicts().await.is_empty());
    }

    #[tokio::test]
    async fn multi_label_domain_rules_match_subdomains() {
        let dir = temp_rules_dir("suffix-domain");
        write_lines_atomic(dir.join(DIRECT_IP_FILE), &[]).unwrap();
        write_lines_atomic(dir.join(BYPASS_IP_FILE), &[]).unwrap();
        write_lines_atomic(dir.join(DIRECT_DOMAIN_FILE), &["c.pki.goog".to_owned()]).unwrap();
        write_lines_atomic(dir.join(BYPASS_DOMAIN_FILE), &["pki.goog".to_owned()]).unwrap();

        let mut config = RouteRulesConfig::default();
        config.rules_dir = dir;
        config.geoip_sources.clear();
        config.bypass_domain_sources.clear();
        let state = RoutingState::load(config).await.unwrap();

        assert_eq!(state.route_domain("pki.goog").await, Some(RouteDecision::Proxy));
        assert_eq!(state.route_domain("c.pki.goog").await, Some(RouteDecision::Direct));
        assert!(!state.domain_conflicts().await.is_empty());
    }

    #[tokio::test]
    async fn dns_learned_bypass_ip_keeps_direct_priority_and_indexes_conflict() {
        let dir = temp_rules_dir("dns-learned-conflict");
        write_lines_atomic(dir.join(DIRECT_IP_FILE), &["203.0.113.10".to_owned()]).unwrap();
        write_lines_atomic(dir.join(BYPASS_IP_FILE), &[]).unwrap();
        write_lines_atomic(dir.join(DIRECT_DOMAIN_FILE), &[]).unwrap();
        write_lines_atomic(dir.join(BYPASS_DOMAIN_FILE), &["example.com".to_owned()]).unwrap();

        let mut config = RouteRulesConfig::default();
        config.rules_dir = dir.clone();
        config.geoip_sources.clear();
        config.bypass_domain_sources.clear();
        let state = RoutingState::load(config).await.unwrap();

        state
            .add_dns_results(
                RouteDecision::Proxy,
                "www.example.com",
                &["203.0.113.10".parse().unwrap()],
            )
            .await
            .unwrap();

        state.persist_bypass_ip_if_dirty().await;

        assert!(
            read_lines(dir.join(BYPASS_IP_FILE))
                .unwrap()
                .contains(&"203.0.113.10".to_owned())
        );
        assert_eq!(
            state.route_ip(&"203.0.113.10".parse().unwrap()).await,
            Some(RouteDecision::Direct)
        );
        let conflicts = state.ip_conflicts().await;
        assert!(conflicts.iter().any(|conflict| {
            conflict.value == "203.0.113.10"
                && conflict.regions == ["direct".to_owned(), "bypass".to_owned()]
                && conflict.sources == [DIRECT_IP_FILE.to_owned(), BYPASS_IP_FILE.to_owned()]
        }));
    }

    #[tokio::test]
    async fn temporary_rules_persist_to_temp_files() {
        let dir = temp_rules_dir("temporary-persist");
        let mut config = RouteRulesConfig::default();
        config.rules_dir = dir.clone();
        config.geoip_sources.clear();
        config.bypass_domain_sources.clear();

        let state = RoutingState::load(config.clone()).await.unwrap();
        state
            .set_temporary_rules(RuleLists {
                direct_ip: vec!["203.0.113.0/24".to_owned()],
                direct_domain: vec!["direct.temp.example".to_owned()],
                bypass_ip: vec!["198.51.100.10".to_owned()],
                bypass_domain: vec!["*.temp.example".to_owned()],
            })
            .await
            .unwrap();

        assert!(
            read_lines(dir.join(TEMP_DIRECT_IP_FILE))
                .unwrap()
                .contains(&"203.0.113.0/24".to_owned())
        );
        assert!(
            read_lines(dir.join(TEMP_BYPASS_DOMAIN_FILE))
                .unwrap()
                .contains(&"*.temp.example".to_owned())
        );

        let reloaded = RoutingState::load(config).await.unwrap();
        assert_eq!(
            reloaded.route_ip(&"198.51.100.10".parse().unwrap()).await,
            Some(RouteDecision::Proxy)
        );
        assert_eq!(
            reloaded.route_domain("direct.temp.example").await,
            Some(RouteDecision::Direct)
        );
    }

    #[tokio::test]
    async fn dns_cache_insert_query_and_clear() {
        let dir = temp_rules_dir("dns-cache");
        let mut config = RouteRulesConfig::default();
        config.rules_dir = dir;
        config.dns_cache_capacity = 1;
        config.dns_cache_ttl_seconds = 60;

        let state = RoutingState::load(config).await.unwrap();
        state
            .dns_cache_insert(
                "Example.COM.",
                "A",
                RouteDecision::Direct,
                Message::query(),
                vec!["1.2.3.4".parse().unwrap()],
            )
            .await;

        assert_eq!(state.dns_cache_stats().await.size, 1);
        assert!(
            state
                .dns_cache_lookup("example.com", "a", RouteDecision::Direct)
                .await
                .is_some()
        );
        assert_eq!(
            state.dns_cache_query("example.com").await[0].results[0].to_string(),
            "1.2.3.4"
        );

        let cleared = state.dns_cache_clear(Some("example.com")).await;
        assert_eq!(cleared, 1);
        assert_eq!(state.dns_cache_stats().await.size, 0);
    }

    #[tokio::test]
    async fn dns_cache_enforces_capacity() {
        let dir = temp_rules_dir("dns-cache-capacity");
        let mut config = RouteRulesConfig::default();
        config.rules_dir = dir;
        config.dns_cache_capacity = 1;

        let state = RoutingState::load(config).await.unwrap();
        state
            .dns_cache_insert(
                "first.example",
                "A",
                RouteDecision::Direct,
                Message::query(),
                vec!["1.1.1.1".parse().unwrap()],
            )
            .await;
        state
            .dns_cache_insert(
                "second.example",
                "A",
                RouteDecision::Direct,
                Message::query(),
                vec!["2.2.2.2".parse().unwrap()],
            )
            .await;

        assert_eq!(state.dns_cache_stats().await.size, 1);
        assert!(state.dns_cache_query("first.example").await.is_empty());
        assert_eq!(
            state.dns_cache_query("second.example").await[0].results[0].to_string(),
            "2.2.2.2"
        );
    }
}
