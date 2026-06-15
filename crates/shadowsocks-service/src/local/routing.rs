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
        atomic::{AtomicBool, AtomicU64, Ordering as AtomicOrdering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use hickory_resolver::proto::op::Message;
use ipnet::IpNet;
use log::warn;
use serde::{Deserialize, Serialize};
use shadowsocks::relay::socks5::Address;
use tokio::{
    sync::{Notify, RwLock as TokioRwLock, mpsc, oneshot},
    time,
};

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
use crate::local::utils::is_fixed_direct_ip;

const DIRECT_IP_FILE: &str = "direct_ip.txt";
const DIRECT_DOMAIN_FILE: &str = "direct_domain.txt";
const PROXY_IP_FILE: &str = "proxy_ip.txt";
const PROXY_DOMAIN_FILE: &str = "proxy_domain.txt";
const TEMP_DIRECT_IP_FILE: &str = "direct_ip.temp";
const TEMP_DIRECT_DOMAIN_FILE: &str = "direct_domain.temp";
const TEMP_PROXY_IP_FILE: &str = "proxy_ip.temp";
const TEMP_PROXY_DOMAIN_FILE: &str = "proxy_domain.temp";
const TEMP_DIR: &str = "temp";
const TEMP_IP_CONFLICTS_FILE: &str = "ip_conflicts.jsonl";
const TEMP_DOMAIN_CONFLICTS_FILE: &str = "domain_conflicts.jsonl";
const RECORD_FILE: &str = "record.txt";
const SOURCE_DIR: &str = "source";
const SOURCE_TEMP_DIR: &str = "temp";
const GENERATED_RULE_FILES: [&str; 4] = [DIRECT_IP_FILE, DIRECT_DOMAIN_FILE, PROXY_IP_FILE, PROXY_DOMAIN_FILE];
const MAX_EVENTS: usize = 4096;
const RECORD_MAX_DURATION: Duration = Duration::from_secs(300);
const RECORD_QUEUE_CAPACITY: usize = 8192;
const PROXY_IP_PERSIST_DELAY: Duration = Duration::from_secs(30);
const DNS_CACHE_REFRESH_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
const SOURCE_REFRESH_INTERVAL: Duration = Duration::from_secs(7 * 24 * 60 * 60);
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RoutingSources {
    pub geoip_sources: Vec<String>,
    pub proxy_domain_sources: Vec<String>,
    #[serde(default)]
    pub global_proxy: bool,
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
            proxy_domain_sources: config.proxy_domain_sources.clone(),
            global_proxy: config.global_proxy,
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
    pub proxy_ip: Vec<String>,
    pub proxy_domain: Vec<String>,
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
    HttpProxy,
    Socks5Proxy,
    Redir,
    Tun,
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
    pub error: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ActivityRecordStatus {
    pub recording: bool,
    pub expires_at: Option<u64>,
    pub remaining_seconds: u64,
    pub dropped_events: u64,
}

#[derive(Clone, Debug)]
struct RecordControl {
    recording: Arc<AtomicBool>,
    session_id: Arc<AtomicU64>,
    expires_at: Arc<AtomicU64>,
    dropped_events: Arc<AtomicU64>,
}

#[derive(Debug)]
enum RecordCommand {
    Start {
        ack: oneshot::Sender<io::Result<()>>,
    },
    Stop {
        session_id: u64,
        ack: oneshot::Sender<io::Result<()>>,
    },
    Flush {
        ack: oneshot::Sender<io::Result<()>>,
    },
    Connection(RecordConnectionEvent),
    Dns(RecordDnsEvent),
}

#[derive(Debug)]
struct RecordConnectionEvent {
    session_id: u64,
    source: SocketAddr,
    destination_ip: Option<IpAddr>,
    destination_domain: Option<String>,
    destination_port: u16,
    protocol: String,
    decision: ConnectionDecision,
}

#[derive(Debug)]
struct RecordDnsEvent {
    session_id: u64,
    domain: String,
    query_type: String,
    results: Vec<IpAddr>,
    resolver: RouteDecision,
    cache_hit: bool,
    error: Option<String>,
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
    /// Size of the authoritative per-flow decision map for the current
    /// Record session. Bounded by `MAX_EVENTS`; surfaced here so the
    /// periodic logger flags unexpected growth.
    pub flow_decisions: usize,
    /// Reverse-DNS map. Never pruned today — included here so the
    /// periodic logger flags growth.
    pub reverse_domains: usize,
    pub persistent_direct_ip: usize,
    pub persistent_proxy_ip: usize,
    pub temporary_direct_ip: usize,
    pub temporary_proxy_ip: usize,
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
    pub proxy_file: bool,
    pub proxy_file_matches: Vec<String>,
    pub nft_checked: bool,
    pub nft_proxy: bool,
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
    direct_domain: CompiledDomainRules,
    proxy_ip: Vec<IpNet>,
    proxy_ip_exact: HashSet<IpAddr>,
    proxy_domain: CompiledDomainRules,
}

#[derive(Clone, Debug, Default)]
struct CompiledDomainRules {
    raw: HashSet<String>,
    exact: HashSet<String>,
    suffix: HashSet<String>,
    match_all: bool,
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
    temporary_fingerprint: Vec<Option<u64>>,
    direct_ip_modified: Option<SystemTime>,
    proxy_ip_modified: Option<SystemTime>,
    direct_domain_modified: Option<SystemTime>,
    proxy_domain_modified: Option<SystemTime>,
    ip_conflicts: VecDeque<ConflictEvent>,
    domain_conflicts: VecDeque<ConflictEvent>,
    connections: VecDeque<ConnectionEvent>,
    /// Flow-keyed authoritative decision map for the current Record session.
    /// Cleared on Record start/stop/expire, so it does not need per-entry TTL.
    flow_decisions: HashMap<FlowKey, ConnectionDecision>,
    /// Kernel-visible flows that were already open when the current Record
    /// session started. These are not "recent" activity for this session and
    /// should not be reintroduced as default-Direct scraper rows.
    system_connection_baseline: HashSet<FlowKey>,
    /// First time a non-baseline kernel-visible flow was observed during the
    /// current Record session. Kernel snapshots do not carry creation time, so
    /// keep this stable instead of refreshing rows to "now" every poll.
    system_connection_first_seen: HashMap<FlowKey, u64>,
    dns: VecDeque<DnsEvent>,
    reverse_domains: HashMap<IpAddr, String>,
    dns_cache: HashMap<DnsCacheKey, DnsCacheEntry>,
    dns_cache_order: VecDeque<DnsCacheKey>,
    proxy_ip_dirty: bool,
    proxy_ip_persist_scheduled: bool,
}

#[derive(Clone, Debug)]
pub struct RoutingState {
    inner: Arc<TokioRwLock<RoutingInner>>,
    progress: Arc<StdRwLock<RuleUpdateProgress>>,
    record_control: RecordControl,
    record_tx: mpsc::Sender<RecordCommand>,
    /// Mirror of `sources.dns_ipv4_only` so hot DNS hooks can check it
    /// without taking the async lock on `inner`.
    dns_ipv4_only_flag: Arc<std::sync::atomic::AtomicBool>,
    /// Runtime DNS endpoints derived from `locals[]`'s DNS listener.
    /// Populated at startup from the first DNS listener; mutable via
    /// `/api/dns` so the web admin can hot-reload upstreams without
    /// editing the config file.
    dns_runtime: Arc<TokioRwLock<DnsRuntimeState>>,
    /// Notified whenever the temporary proxy domain list changes so the DNS
    /// server can (re-)resolve those domains and pre-seed the nft proxy set,
    /// instead of waiting for a client to query them through us. See
    /// [`RoutingState::proxy_warmup_notify`].
    proxy_warmup_notify: Arc<Notify>,
}

fn spawn_record_worker(
    inner: Arc<TokioRwLock<RoutingInner>>,
    control: RecordControl,
    mut rx: mpsc::Receiver<RecordCommand>,
) {
    tokio::spawn(async move {
        let mut recorded_connections = HashSet::new();
        while let Some(command) = rx.recv().await {
            match command {
                RecordCommand::Start { ack } => {
                    let system_connection_baseline = collect_system_connection_keys();
                    let path = {
                        let mut inner = inner.write().await;
                        clear_activity_state(&mut inner);
                        inner.system_connection_baseline = system_connection_baseline;
                        inner.rules_dir.join(RECORD_FILE)
                    };
                    recorded_connections.clear();
                    control.dropped_events.store(0, AtomicOrdering::Relaxed);
                    let result = write_lines_atomic(path, &[]);
                    let _ = ack.send(result);
                }
                RecordCommand::Stop { session_id, ack } => {
                    if control.session_id.load(AtomicOrdering::Relaxed) == session_id {
                        let mut inner = inner.write().await;
                        clear_activity_state(&mut inner);
                        recorded_connections.clear();
                    }
                    let _ = ack.send(Ok(()));
                }
                RecordCommand::Flush { ack } => {
                    let _ = ack.send(Ok(()));
                }
                RecordCommand::Connection(event) => {
                    if !is_record_session_active(&control, event.session_id) {
                        continue;
                    }
                    let mut row = None;
                    let mut path = None;
                    {
                        let mut inner = inner.write().await;
                        if !is_record_session_active(&control, event.session_id) {
                            continue;
                        }
                        let domain = event.destination_domain.clone().or_else(|| {
                            event
                                .destination_ip
                                .as_ref()
                                .and_then(|ip| connection_domain_for_ip(&inner, ip))
                        });
                        if let (Some(dst_ip), Some(proto)) = (
                            event.destination_ip,
                            protocol_static(event.protocol.as_str()),
                        ) {
                            let key: FlowKey = (
                                event.source.ip(),
                                event.source.port(),
                                dst_ip,
                                event.destination_port,
                                proto,
                            );
                            inner.flow_decisions.insert(key, event.decision);
                        }
                        let connection = ConnectionEvent {
                            timestamp: now(),
                            source_ip: event.source.ip(),
                            source_port: event.source.port(),
                            destination_ip: event.destination_ip,
                            destination_domain: event.destination_domain,
                            domain,
                            destination_port: event.destination_port,
                            protocol: event.protocol,
                            decision: event.decision,
                        };
                        push_event(&mut inner.connections, connection.clone());
                        if recorded_connections.insert(connection_record_key(&connection)) {
                            path = Some(inner.rules_dir.join(RECORD_FILE));
                            row = Some(connection);
                        }
                    }
                    if let (Some(path), Some(row)) = (path, row) {
                        if let Ok(line) = serde_json::to_string(&row) {
                            let _ = append_lines(&path, &[line]);
                        }
                    }
                }
                RecordCommand::Dns(event) => {
                    if !is_record_session_active(&control, event.session_id) {
                        continue;
                    }
                    let mut inner = inner.write().await;
                    if !is_record_session_active(&control, event.session_id) {
                        continue;
                    }
                    let normalized_domain = normalize_dns_domain(&event.domain);
                    if event.error.is_none() {
                        for ip in &event.results {
                            inner.reverse_domains.insert(*ip, normalized_domain.clone());
                        }
                    }
                    push_event(
                        &mut inner.dns,
                        DnsEvent {
                            timestamp: now(),
                            domain: normalized_domain,
                            query_type: event.query_type,
                            results: event.results,
                            resolver: event.resolver,
                            cache_hit: event.cache_hit,
                            error: event.error,
                        },
                    );
                }
            }
        }
    });
}

fn clear_activity_state(inner: &mut RoutingInner) {
    inner.connections.clear();
    inner.dns.clear();
    inner.flow_decisions.clear();
    inner.system_connection_baseline.clear();
    inner.system_connection_first_seen.clear();
    inner.reverse_domains.clear();
}

fn is_record_session_active(control: &RecordControl, session_id: u64) -> bool {
    control.recording.load(AtomicOrdering::Relaxed)
        && control.session_id.load(AtomicOrdering::Relaxed) == session_id
        && now() < control.expires_at.load(AtomicOrdering::Relaxed)
}

fn protocol_static(protocol: &str) -> Option<&'static str> {
    match protocol {
        "tcp" => Some("tcp"),
        "udp" => Some("udp"),
        _ => None,
    }
}

impl RoutingState {
    pub async fn load(config: RouteRulesConfig) -> io::Result<Self> {
        fs::create_dir_all(&config.rules_dir)?;
        fs::create_dir_all(config.rules_dir.join(TEMP_DIR))?;
        ensure_file(config.rules_dir.join(DIRECT_IP_FILE))?;
        ensure_file(config.rules_dir.join(DIRECT_DOMAIN_FILE))?;
        ensure_file(config.rules_dir.join(PROXY_IP_FILE))?;
        ensure_file(config.rules_dir.join(PROXY_DOMAIN_FILE))?;
        ensure_file(temp_file_path(&config.rules_dir, TEMP_DIRECT_IP_FILE))?;
        ensure_file(temp_file_path(&config.rules_dir, TEMP_DIRECT_DOMAIN_FILE))?;
        ensure_file(temp_file_path(&config.rules_dir, TEMP_PROXY_IP_FILE))?;
        ensure_file(temp_file_path(&config.rules_dir, TEMP_PROXY_DOMAIN_FILE))?;

        let persistent_raw = read_rule_lists(&config.rules_dir)?;
        let persistent = compile_rules(&persistent_raw)?;
        let geoip_path = config.rules_dir.join(SOURCE_DIR).join("geoip.dat");
        let geoip_cn = read_geoip_cn_nets(&geoip_path)?;
        let geoip_modified = file_modified(&geoip_path)?;
        let direct_ip_modified = file_modified(&config.rules_dir.join(DIRECT_IP_FILE))?;
        let proxy_ip_modified = file_modified(&config.rules_dir.join(PROXY_IP_FILE))?;
        let direct_domain_modified = file_modified(&config.rules_dir.join(DIRECT_DOMAIN_FILE))?;
        let proxy_domain_modified = file_modified(&config.rules_dir.join(PROXY_DOMAIN_FILE))?;
        let temporary_raw = with_private_direct_rules(read_temporary_rule_lists(&config.rules_dir)?);
        let temporary_fingerprint = temporary_files_fingerprint(&config.rules_dir)?;
        let temporary = compile_rules(&temporary_raw)?;
        let mut inner = RoutingInner {
            sources: RoutingSources::from(&config),
            rules_dir: config.rules_dir,
            temporary_raw,
            persistent_raw,
            temporary,
            persistent,
            geoip_cn,
            geoip_modified,
            temporary_fingerprint,
            direct_ip_modified,
            proxy_ip_modified,
            direct_domain_modified,
            proxy_domain_modified,
            ip_conflicts: VecDeque::new(),
            domain_conflicts: VecDeque::new(),
            connections: VecDeque::new(),
            flow_decisions: HashMap::new(),
            system_connection_baseline: HashSet::new(),
            system_connection_first_seen: HashMap::new(),
            dns: VecDeque::new(),
            reverse_domains: HashMap::new(),
            dns_cache: HashMap::new(),
            dns_cache_order: VecDeque::new(),
            proxy_ip_dirty: false,
            proxy_ip_persist_scheduled: false,
        };
        rebuild_conflicts(&mut inner);
        let v4_only = inner.sources.dns_ipv4_only;
        let inner = Arc::new(TokioRwLock::new(inner));
        let record_control = RecordControl {
            recording: Arc::new(AtomicBool::new(false)),
            session_id: Arc::new(AtomicU64::new(0)),
            expires_at: Arc::new(AtomicU64::new(0)),
            dropped_events: Arc::new(AtomicU64::new(0)),
        };
        let (record_tx, record_rx) = mpsc::channel(RECORD_QUEUE_CAPACITY);
        spawn_record_worker(inner.clone(), record_control.clone(), record_rx);
        let state = Self {
            inner,
            progress: Arc::new(StdRwLock::new(RuleUpdateProgress::default())),
            record_control,
            record_tx,
            dns_ipv4_only_flag: Arc::new(std::sync::atomic::AtomicBool::new(v4_only)),
            dns_runtime: Arc::new(TokioRwLock::new(DnsRuntimeState::default())),
            proxy_warmup_notify: Arc::new(Notify::new()),
        };
        state.spawn_periodic_source_update();
        state.spawn_periodic_temporary_reload();
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

    pub async fn start_activity_recording(&self) -> io::Result<ActivityRecordStatus> {
        self.record_control
            .session_id
            .fetch_add(1, AtomicOrdering::Relaxed);
        let expires_at = now().saturating_add(RECORD_MAX_DURATION.as_secs());
        self.record_control.recording.store(false, AtomicOrdering::Relaxed);
        self.record_control.expires_at.store(expires_at, AtomicOrdering::Relaxed);
        let (ack_tx, ack_rx) = oneshot::channel();
        if self
            .record_tx
            .send(RecordCommand::Start { ack: ack_tx })
            .await
            .is_err()
        {
            self.record_control.recording.store(false, AtomicOrdering::Relaxed);
            return Err(io::Error::other("record worker is not running"));
        }
        match ack_rx.await {
            Ok(result) => result?,
            Err(err) => {
                return Err(io::Error::other(format!("record worker dropped start ack: {err}")));
            }
        }
        self.record_control.recording.store(true, AtomicOrdering::Relaxed);
        Ok(self.activity_record_status().await)
    }

    pub async fn stop_activity_recording(&self) -> io::Result<ActivityRecordStatus> {
        self.stop_activity_recording_inner().await?;
        Ok(self.activity_record_status_no_expire())
    }

    pub async fn flush_activity_recording(&self) -> io::Result<()> {
        let (ack_tx, ack_rx) = oneshot::channel();
        if self
            .record_tx
            .send(RecordCommand::Flush { ack: ack_tx })
            .await
            .is_err()
        {
            return Err(io::Error::other("record worker is not running"));
        }
        ack_rx
            .await
            .map_err(|err| io::Error::other(format!("record worker dropped flush ack: {err}")))?
    }

    pub async fn activity_record_status(&self) -> ActivityRecordStatus {
        self.stop_expired_activity_recording().await;
        self.activity_record_status_no_expire()
    }

    fn activity_record_status_no_expire(&self) -> ActivityRecordStatus {
        let recording = self.record_control.recording.load(AtomicOrdering::Relaxed);
        let expires_at = self.record_control.expires_at.load(AtomicOrdering::Relaxed);
        let now = now();
        ActivityRecordStatus {
            recording,
            expires_at: (recording && expires_at > 0).then_some(expires_at),
            remaining_seconds: if recording { expires_at.saturating_sub(now) } else { 0 },
            dropped_events: self.record_control.dropped_events.load(AtomicOrdering::Relaxed),
        }
    }

    async fn stop_expired_activity_recording(&self) {
        let recording = self.record_control.recording.load(AtomicOrdering::Relaxed);
        let expires_at = self.record_control.expires_at.load(AtomicOrdering::Relaxed);
        if recording && now() >= expires_at {
            let _ = self.stop_activity_recording_inner().await;
        }
    }

    async fn stop_activity_recording_inner(&self) -> io::Result<()> {
        let session_id = self.record_control.session_id.load(AtomicOrdering::Relaxed);
        self.record_control.recording.store(false, AtomicOrdering::Relaxed);
        self.record_control.expires_at.store(0, AtomicOrdering::Relaxed);
        let (ack_tx, ack_rx) = oneshot::channel();
        if self
            .record_tx
            .send(RecordCommand::Stop {
                session_id,
                ack: ack_tx,
            })
            .await
            .is_err()
        {
            return Err(io::Error::other("record worker is not running"));
        }
        ack_rx
            .await
            .map_err(|err| io::Error::other(format!("record worker dropped stop ack: {err}")))?
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

    /// Handle for the DNS server to wait on temporary-proxy-domain changes.
    /// Each `notified()` wake means the temporary proxy domain list may have
    /// changed and should be (re-)resolved to warm the nft proxy set.
    pub fn proxy_warmup_notify(&self) -> Arc<Notify> {
        self.proxy_warmup_notify.clone()
    }

    /// Snapshot of the current temporary proxy *domain* rules. These cannot be
    /// pre-loaded into nft directly (the set holds IPs, not names), so the DNS
    /// server resolves them and injects the answers via `add_dns_results`.
    pub async fn temporary_proxy_domains(&self) -> Vec<String> {
        self.inner.read().await.temporary_raw.proxy_domain.clone()
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
        let (rules_dir, direct_nets, proxy_nets) = {
            let inner = self.inner.read().await;
            temporary_nft_route_nets(&inner, &rules)
        };
        let mut inner = self.inner.write().await;
        write_temporary_rule_lists(&inner.rules_dir, &rules)?;
        inner.temporary_fingerprint = temporary_files_fingerprint(&inner.rules_dir)?;
        inner.temporary_raw = rules;
        inner.temporary = compile_rules(&inner.temporary_raw)?;
        rebuild_conflicts(&mut inner);
        drop(inner);
        #[cfg(all(target_os = "linux", feature = "local-dns"))]
        {
            if let Err(err) = crate::local::dns::intercept_linux::replace_route_nets(&rules_dir, &direct_nets, &proxy_nets) {
                warn!("failed to refresh nft proxy set after temporary rule change: {}", err);
            }
        }
        // Newly added proxy domains have no IP in nft yet — ask the DNS server
        // to resolve them and pre-seed the proxy set proactively.
        self.proxy_warmup_notify.notify_one();
        Ok(())
    }

    pub async fn save_temporary_rules_to_files(&self, rules: RuleLists) -> io::Result<()> {
        let rules = with_private_direct_rules(normalize_rule_lists(rules));
        validate_temporary_rules(&rules)?;
        let rules_dir = self.inner.read().await.rules_dir.clone();
        write_temporary_rule_lists(&rules_dir, &rules)
    }

    pub async fn reload_temporary_rules_from_files(&self) -> io::Result<RuleLists> {
        let rules_dir = self.inner.read().await.rules_dir.clone();
        let rules = with_private_direct_rules(read_temporary_rule_lists(&rules_dir)?);
        validate_temporary_rules(&rules)?;
        let temporary_fingerprint = temporary_files_fingerprint(&rules_dir)?;
        #[cfg(all(target_os = "linux", feature = "local-dns"))]
        let (direct_nets, proxy_nets) = {
            let inner = self.inner.read().await;
            let (_, direct_nets, proxy_nets) = temporary_nft_route_nets(&inner, &rules);
            (direct_nets, proxy_nets)
        };
        let mut inner = self.inner.write().await;
        inner.temporary_fingerprint = temporary_fingerprint;
        inner.temporary_raw = rules;
        inner.temporary = compile_rules(&inner.temporary_raw)?;
        rebuild_conflicts(&mut inner);
        let temporary = inner.temporary_raw.clone();
        drop(inner);
        #[cfg(all(target_os = "linux", feature = "local-dns"))]
        {
            if let Err(err) = crate::local::dns::intercept_linux::replace_route_nets(&rules_dir, &direct_nets, &proxy_nets) {
                warn!("failed to refresh nft proxy set after temporary rule reload: {}", err);
            }
        }
        self.proxy_warmup_notify.notify_one();
        Ok(temporary)
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

        let mut schedule_proxy_persist = false;
        let (nft_ips, global_proxy) = {
            let mut inner = self.inner.write().await;
            let global_proxy = inner.sources.global_proxy;
            if global_proxy && matches!(decision, RouteDecision::Proxy) {
                let elapsed = total_start.elapsed();
                ADD_DNS_RESULTS_TOTAL_NS.fetch_add(elapsed.as_nanos() as u64, AtomicOrdering::Relaxed);
                return Ok(());
            }
            let mut nft_ips = Vec::new();
            let mut lines = Vec::new();
            let mut proxy_changed = false;
            for ip in results {
                match decision {
                    RouteDecision::Direct => {
                        if !global_proxy || is_fixed_direct_ip(ip) {
                            nft_ips.push(*ip);
                        }
                    }
                    RouteDecision::Proxy => {
                        let target_exists =
                            compiled_rules_match_ip(&inner.persistent.proxy_ip_exact, &inner.persistent.proxy_ip, ip);
                        let direct_exists =
                            dns_proxy_ip_blocked_from_nft_by_direct_rule(&inner, ip);
                        let line = format_proxy_ip_domain_line(ip, domain);
                        match inner
                            .persistent_raw
                            .proxy_ip
                            .iter()
                            .position(|rule| proxy_ip_line_matches_ip(rule, ip))
                        {
                            Some(idx) => {
                                if proxy_ip_line_domain(&inner.persistent_raw.proxy_ip[idx]).is_none() {
                                    inner.persistent_raw.proxy_ip[idx] = line;
                                    proxy_changed = true;
                                    inner.proxy_ip_dirty = true;
                                    if !inner.proxy_ip_persist_scheduled {
                                        inner.proxy_ip_persist_scheduled = true;
                                        schedule_proxy_persist = true;
                                    }
                                }
                            }
                            None => {
                                lines.push(line);
                                proxy_changed = true;
                            }
                        }
                        if !target_exists {
                            inner.persistent.proxy_ip_exact.insert(*ip);
                            inner.persistent.proxy_ip.push(IpNet::from(*ip));
                        }
                        if !direct_exists {
                            nft_ips.push(*ip);
                        }
                    }
                }
            }
            nft_ips.sort_unstable();
            nft_ips.dedup();

            if !proxy_changed && nft_ips.is_empty() {
                let elapsed = total_start.elapsed();
                ADD_DNS_RESULTS_TOTAL_NS.fetch_add(elapsed.as_nanos() as u64, AtomicOrdering::Relaxed);
                return Ok(());
            }

            match decision {
                RouteDecision::Direct => {}
                RouteDecision::Proxy => {
                    if proxy_changed {
                        inner.persistent_raw.proxy_ip.extend(lines);
                        inner.proxy_ip_dirty = true;
                        if !inner.proxy_ip_persist_scheduled {
                            inner.proxy_ip_persist_scheduled = true;
                            schedule_proxy_persist = true;
                        }
                    }
                }
            }
            rebuild_ip_conflicts(&mut inner);
            (nft_ips, global_proxy)
        };
        if !nft_ips.is_empty() {
            warn!(
                "dns processed {} {:?} nft candidate IPs for {}",
                nft_ips.len(),
                decision,
                domain
            );
        }
        #[cfg(all(target_os = "linux", feature = "local-dns"))]
        if !nft_ips.is_empty()
        {
            // Move the nft fork+exec onto a blocking-pool thread so the
            // tokio worker that's running the DNS handler isn't stalled
            // for the duration of the syscall. The helpers
            // `add_route_ips` / `remove_route_ips` were also reworked
            // to issue a single `nft -f -` per call instead of N
            // per-IP invocations, so this is now one fork+exec total
            // for the whole resolution batch.
            let nft_start = Instant::now();
            let additions_for_nft = nft_ips.clone();
            let result = tokio::task::spawn_blocking(move || -> Result<(), io::Error> {
                let res = match decision {
                    RouteDecision::Direct if global_proxy => {
                        crate::local::dns::intercept_linux::add_route_ips(RouteDecision::Direct, &additions_for_nft)
                    }
                    RouteDecision::Direct => {
                        crate::local::dns::intercept_linux::remove_route_ips(RouteDecision::Proxy, &additions_for_nft)
                    }
                    RouteDecision::Proxy => {
                        crate::local::dns::intercept_linux::add_route_ips(decision, &additions_for_nft)
                    }
                };
                // The nft set membership for these IPs just changed. Any flow
                // already pinned in conntrack (established before the change)
                // keeps its old prerouting verdict, so a connection that went
                // direct before the IP entered proxy4 would stay direct. Drop
                // those conntrack entries so the next packet is re-evaluated
                // against the updated sets.
                crate::local::dns::intercept_linux::flush_conntrack_dst(&additions_for_nft);
                res
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
                    nft_ips.len(),
                    decision,
                    domain
                );
            }
            if let Err(err) = result {
                match decision {
                    RouteDecision::Direct if global_proxy => {
                        warn!("failed to sync direct DNS result IPs to nft direct set: {}", err)
                    }
                    RouteDecision::Direct => {
                        warn!("failed to remove direct DNS result IPs from nft proxy set: {}", err)
                    }
                    RouteDecision::Proxy => {
                        warn!("failed to sync DNS result IPs to nft set: {}", err)
                    }
                }
            }
        }
        if schedule_proxy_persist {
            self.schedule_proxy_ip_persist();
        }

        let elapsed = total_start.elapsed();
        ADD_DNS_RESULTS_TOTAL_NS.fetch_add(elapsed.as_nanos() as u64, AtomicOrdering::Relaxed);
        if elapsed.as_millis() >= SLOW_HOT_PATH_MS {
            warn!(
                "add_dns_results slow: {}ms (decision={:?}, domain={}, additions={})",
                elapsed.as_millis(),
                decision,
                domain,
                nft_ips.len(),
            );
        }
        Ok(())
    }

    fn schedule_proxy_ip_persist(&self) {
        let state = self.clone();
        tokio::spawn(async move {
            time::sleep(PROXY_IP_PERSIST_DELAY).await;
            state.persist_proxy_ip_if_dirty().await;
        });
    }

    async fn persist_proxy_ip_if_dirty(&self) {
        let (path, lines) = {
            let mut inner = self.inner.write().await;
            if !inner.proxy_ip_dirty {
                inner.proxy_ip_persist_scheduled = false;
                return;
            }
            inner.proxy_ip_dirty = false;
            (
                inner.rules_dir.join(PROXY_IP_FILE),
                normalize_proxy_ip_lines(inner.persistent_raw.proxy_ip.clone()),
            )
        };

        let result = tokio::task::spawn_blocking(move || write_lines_atomic(path, &lines)).await;
        let failed = match result {
            Ok(Ok(())) => false,
            Ok(Err(err)) => {
                warn!("failed to persist DNS proxy IPs: {}", err);
                true
            }
            Err(err) => {
                warn!("failed to join DNS proxy IP persist task: {}", err);
                true
            }
        };

        let reschedule = {
            let mut inner = self.inner.write().await;
            if failed {
                inner.proxy_ip_dirty = true;
            }
            inner.proxy_ip_persist_scheduled = false;
            inner.proxy_ip_dirty
        };
        if reschedule {
            self.schedule_proxy_ip_persist();
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

    fn spawn_periodic_temporary_reload(&self) {
        let state = self.clone();
        tokio::spawn(async move {
            let mut interval = time::interval(Duration::from_secs(2));
            interval.tick().await;
            loop {
                interval.tick().await;
                let (rules_dir, known_fingerprint) = {
                    let inner = state.inner.read().await;
                    (inner.rules_dir.clone(), inner.temporary_fingerprint.clone())
                };
                match temporary_files_fingerprint(&rules_dir) {
                    Ok(fingerprint) if fingerprint != known_fingerprint => {
                        if let Err(err) = state.reload_temporary_rules_from_files().await {
                            warn!("failed to reload temporary rules after temp file change: {}", err);
                        }
                    }
                    Ok(_) => {}
                    Err(err) => warn!("failed to stat temporary rule files: {}", err),
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

        let learned_proxy_ip = read_lines(rules_dir.join(PROXY_IP_FILE))?
            .into_iter()
            .filter(|rule| parse_ip_net(rule).is_some())
            .collect::<Vec<_>>();
        let direct_ip = read_lines(rules_dir.join(DIRECT_IP_FILE))?;
        let mut proxy_domain_candidates = Vec::new();
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
                downloaded.status,
                &source_dir,
                completed_files,
                total_files,
            )
            .await;
            self.mark_source_processing(
                &downloaded.display_name,
                completed_files,
                total_files,
                "parsing geoip conflicts",
            )
            .await;
            match parse_geoip_cn_nets(&downloaded.bytes) {
                Ok(nets) => {
                    geoip_cn.extend(nets);
                }
                Err(_) => {
                    let text = String::from_utf8_lossy(&downloaded.bytes);
                    geoip_cn.extend(
                        parse_text_rules(&text)
                            .into_iter()
                            .filter_map(|rule| parse_ip_net(&rule)),
                    );
                }
            }
        }

        for source in &sources.proxy_domain_sources {
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
                downloaded.status,
                &source_dir,
                completed_files,
                total_files,
            )
            .await;
            let rules = parse_text_rules(&String::from_utf8_lossy(&downloaded.bytes));
            proxy_domain_candidates.extend(rules);
        }

        let direct_domain = read_lines(rules_dir.join(DIRECT_DOMAIN_FILE))?;
        let proxy_domain = proxy_domain_candidates;

        self.mark_generating_files(completed_files, total_files).await;
        let lists = normalize_rule_lists(RuleLists {
            direct_ip,
            direct_domain,
            proxy_ip: learned_proxy_ip,
            proxy_domain,
        });
        let persistent = compile_rules(&lists)?;
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
        inner.proxy_ip_modified = file_modified(&inner.rules_dir.join(PROXY_IP_FILE))?;
        inner.direct_domain_modified = file_modified(&inner.rules_dir.join(DIRECT_DOMAIN_FILE))?;
        inner.proxy_domain_modified = file_modified(&inner.rules_dir.join(PROXY_DOMAIN_FILE))?;
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

    pub fn mark_rule_job_failed_sync(&self, message: String) {
        if let Ok(mut progress) = self.progress.write() {
            let total_files = progress.total_files;
            let completed_files = progress.completed_files;
            let remaining_files = progress.remaining_files;
            let percent = progress.percent;
            let current_source = progress.current_source.clone();
            let mut completed_messages = progress.completed_messages.clone();
            completed_messages.push(message.clone());
            *progress = RuleUpdateProgress {
                status: RuleUpdateStatus::Failed,
                current_source,
                completed_files,
                total_files,
                remaining_files,
                percent,
                message: Some(message),
                completed_messages,
            };
        }
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
        for source in sources.geoip_sources.iter().chain(sources.proxy_domain_sources.iter()) {
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
                downloaded.status,
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
        status: DownloadedSourceStatus,
        cache_dir: &Path,
        completed_files: usize,
        total_files: usize,
    ) {
        let percent = progress_percent(completed_files, total_files);
        let message = match status {
            DownloadedSourceStatus::Downloaded => format!("{source} downloaded successfully"),
            DownloadedSourceStatus::FallbackCache => {
                format!(
                    "{source} download failed or was empty; kept existing file in {}",
                    cache_dir.display()
                )
            }
            DownloadedSourceStatus::LocalFile => format!("{source} loaded from local file"),
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
            (PROXY_IP_FILE, &lists.proxy_ip),
            (PROXY_DOMAIN_FILE, &lists.proxy_domain),
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
        let (rules_dir, direct, proxy) = {
            let inner = self.inner.read().await;
            persistent_nft_route_nets(&inner)
        };
        crate::local::dns::intercept_linux::replace_route_nets(&rules_dir, &direct, &proxy)
    }

    pub async fn record_connection(
        &self,
        source: SocketAddr,
        target: &Address,
        protocol: &str,
        decision: ConnectionDecision,
    ) {
        if !self.record_control.recording.load(AtomicOrdering::Relaxed) {
            return;
        }
        let session_id = self.record_control.session_id.load(AtomicOrdering::Relaxed);
        if !is_record_session_active(&self.record_control, session_id) {
            return;
        }
        let (destination_ip, destination_domain, destination_port) = match target {
            Address::SocketAddress(saddr) => (Some(saddr.ip()), None, saddr.port()),
            Address::DomainNameAddress(domain, port) => (None, Some(domain.clone()), *port),
        };
        if self
            .record_tx
            .try_send(RecordCommand::Connection(RecordConnectionEvent {
                session_id,
                source,
                destination_ip,
                destination_domain,
                destination_port,
                protocol: protocol.to_owned(),
                decision,
            }))
            .is_err()
        {
            self.record_control
                .dropped_events
                .fetch_add(1, AtomicOrdering::Relaxed);
        }
    }

    pub async fn record_dns(
        &self,
        domain: String,
        query_type: String,
        results: Vec<IpAddr>,
        resolver: RouteDecision,
        cache_hit: bool,
    ) {
        if !self.record_control.recording.load(AtomicOrdering::Relaxed) {
            return;
        }
        let session_id = self.record_control.session_id.load(AtomicOrdering::Relaxed);
        if !is_record_session_active(&self.record_control, session_id) {
            return;
        }
        if self
            .record_tx
            .try_send(RecordCommand::Dns(RecordDnsEvent {
                session_id,
                domain,
                query_type,
                results,
                resolver,
                cache_hit,
                error: None,
            }))
            .is_err()
        {
            self.record_control
                .dropped_events
                .fetch_add(1, AtomicOrdering::Relaxed);
        }
    }

    pub async fn record_dns_error(
        &self,
        domain: String,
        query_type: String,
        resolver: RouteDecision,
        cache_hit: bool,
        error: String,
    ) {
        if !self.record_control.recording.load(AtomicOrdering::Relaxed) {
            return;
        }
        let session_id = self.record_control.session_id.load(AtomicOrdering::Relaxed);
        if !is_record_session_active(&self.record_control, session_id) {
            return;
        }
        if self
            .record_tx
            .try_send(RecordCommand::Dns(RecordDnsEvent {
                session_id,
                domain,
                query_type,
                results: Vec::new(),
                resolver,
                cache_hit,
                error: Some(error),
            }))
            .is_err()
        {
            self.record_control
                .dropped_events
                .fetch_add(1, AtomicOrdering::Relaxed);
        }
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
        if !key.domain.is_empty() {
            for ip in &results {
                inner.reverse_domains.insert(*ip, key.domain.clone());
            }
        }
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
            persistent_proxy_ip: inner.persistent.proxy_ip.len(),
            temporary_direct_ip: inner.temporary.direct_ip.len(),
            temporary_proxy_ip: inner.temporary.proxy_ip.len(),
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
        rebuild_reverse_domains_from_dns_cache(&mut inner);
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

    pub async fn recent_connections(&self, excluded_remotes: &HashSet<IpAddr>) -> Vec<ConnectionEvent> {
        self.stop_expired_activity_recording().await;
        if !self.record_control.recording.load(AtomicOrdering::Relaxed) {
            return Vec::new();
        }
        let inner = self.inner.read().await;
        let reverse_domains = build_reverse_domain_map(&inner);
        let flow_decisions = inner.flow_decisions.clone();
        let system_connection_baseline = inner.system_connection_baseline.clone();
        let mut rows = inner
            .connections
            .iter()
            .rev()
            .filter(|event| !is_excluded_remote(event, excluded_remotes))
            .cloned()
            .map(|mut event| {
                fill_connection_domain(&mut event, &reverse_domains);
                event
            })
            .collect::<Vec<_>>();
        drop(inner);
        let mut dedupped_recent_connections = rows.iter().map(connection_key).collect::<HashSet<_>>();
        let mut system_connections = collect_system_connections(&reverse_domains);
        let observed_at = now();
        let system_connection_first_seen = {
            let mut inner = self.inner.write().await;
            let mut first_seen = HashMap::new();
            for event in &system_connections {
                if is_excluded_remote(event, excluded_remotes) {
                    continue;
                }
                let Some(key) = flow_key_for_event(event) else {
                    continue;
                };
                if system_connection_baseline.contains(&key) {
                    continue;
                }
                let timestamp = remember_system_connection_first_seen(
                    &mut inner.system_connection_first_seen,
                    key,
                    observed_at,
                );
                first_seen.insert(key, timestamp);
            }
            first_seen
        };
        for mut event in system_connections.drain(..) {
            if is_excluded_remote(&event, excluded_remotes) {
                continue;
            }
            // Re-label scraper rows from the authoritative in-memory
            // decision map when the 5-tuple matches.
            if let Some(key) = flow_key_for_event(&event) {
                if system_connection_baseline.contains(&key) {
                    continue;
                }
                if let Some(timestamp) = system_connection_first_seen.get(&key) {
                    event.timestamp = *timestamp;
                }
                if let Some(decision) = flow_decisions.get(&key) {
                    event.decision = *decision;
                }
            }
            if dedupped_recent_connections.insert(connection_key(&event)) {
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
        self.stop_expired_activity_recording().await;
        if !self.record_control.recording.load(AtomicOrdering::Relaxed) {
            return Vec::new();
        }
        let inner = self.inner.read().await;
        inner.dns.iter().rev().cloned().collect()
    }

    pub async fn direct_proxy_file_conflicts(&self) -> (Vec<String>, Vec<String>) {
        let inner = self.inner.read().await;
        let direct_ip = inner
            .persistent_raw
            .direct_ip
            .iter()
            .filter_map(|rule| parse_ip_net(rule))
            .collect::<Vec<_>>();
        let proxy_ip = inner
            .persistent_raw
            .proxy_ip
            .iter()
            .filter_map(|rule| parse_ip_net(rule))
            .collect::<Vec<_>>();
        let ip_conflicts = ip_net_conflicts(&direct_ip, &proxy_ip);

        let direct_domain = inner
            .persistent_raw
            .direct_domain
            .iter()
            .map(|domain| normalize_domain(domain))
            .filter(|domain| !domain.is_empty())
            .collect::<HashSet<_>>();
        let proxy_domain = inner
            .persistent_raw
            .proxy_domain
            .iter()
            .map(|domain| normalize_domain(domain))
            .filter(|domain| !domain.is_empty())
            .collect::<HashSet<_>>();
        let domain_conflicts = domain_rule_conflicts(&direct_domain, &proxy_domain);

        (ip_conflicts, domain_conflicts)
    }

    pub async fn debug_ip_membership(&self, input: &str) -> IpMembershipDebug {
        let query = input.trim().to_owned();
        let parsed = parse_debug_ip_query(&query);
        let mut result = IpMembershipDebug {
            query,
            valid: parsed.is_ok(),
            error: parsed.as_ref().err().map(ToString::to_string),
            proxy_file: false,
            proxy_file_matches: Vec::new(),
            nft_checked: false,
            nft_proxy: false,
            nft_matches: Vec::new(),
            nft_error: None,
        };
        let Ok(parsed) = parsed else {
            return result;
        };

        let inner = self.inner.read().await;
        result.proxy_file_matches = inner
            .persistent_raw
            .proxy_ip
            .iter()
            .filter_map(|rule| parse_ip_net(rule))
            .filter(|net| debug_ip_query_matches(&parsed, net))
            .map(|net| net.to_string())
            .collect();
        result.proxy_file = !result.proxy_file_matches.is_empty();
        drop(inner);

        #[cfg(all(target_os = "linux", feature = "local-dns"))]
        {
            result.nft_checked = true;
            match crate::local::dns::intercept_linux::proxy_set_matches(&parsed.to_string()) {
                Ok(matches) => {
                    result.nft_proxy = !matches.is_empty();
                    result.nft_matches = matches;
                }
                Err(err) => result.nft_error = Some(err.to_string()),
            }
        }

        result
    }
}

fn route_ip_inner(inner: &mut RoutingInner, ip: &IpAddr) -> Option<RouteDecision> {
    if inner.sources.global_proxy {
        return Some(if is_fixed_direct_ip(ip) {
            RouteDecision::Direct
        } else {
            RouteDecision::Proxy
        });
    }

    let temp_direct = compiled_rules_match_ip(&inner.temporary.direct_ip_exact, &inner.temporary.direct_ip, ip);
    let temp_proxy = compiled_rules_match_ip(&inner.temporary.proxy_ip_exact, &inner.temporary.proxy_ip, ip);
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
    let proxy = compiled_rules_match_ip(&inner.persistent.proxy_ip_exact, &inner.persistent.proxy_ip, ip);
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
    if inner.sources.global_proxy {
        return Some(RouteDecision::Proxy);
    }

    let temp_direct = rules_match_domain(&inner.temporary.direct_domain, &domain);
    let temp_proxy = rules_match_domain(&inner.temporary.proxy_domain, &domain);
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
    let proxy = rules_match_domain(&inner.persistent.proxy_domain, &domain);
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
    let proxy_ip_modified = file_modified(&inner.rules_dir.join(PROXY_IP_FILE))?;
    let direct_domain_modified = file_modified(&inner.rules_dir.join(DIRECT_DOMAIN_FILE))?;
    let proxy_domain_modified = file_modified(&inner.rules_dir.join(PROXY_DOMAIN_FILE))?;
    let geoip_path = inner.rules_dir.join(SOURCE_DIR).join("geoip.dat");
    let geoip_modified = file_modified(&geoip_path)?;

    if direct_ip_modified == inner.direct_ip_modified
        && proxy_ip_modified == inner.proxy_ip_modified
        && direct_domain_modified == inner.direct_domain_modified
        && proxy_domain_modified == inner.proxy_domain_modified
        && geoip_modified == inner.geoip_modified
    {
        return Ok(());
    }

    inner.persistent_raw = read_rule_lists(&inner.rules_dir)?;
    inner.persistent = compile_rules(&inner.persistent_raw)?;
    if geoip_modified != inner.geoip_modified {
        inner.geoip_cn = read_geoip_cn_nets(&geoip_path)?;
    }
    inner.direct_ip_modified = direct_ip_modified;
    inner.proxy_ip_modified = proxy_ip_modified;
    inner.direct_domain_modified = direct_domain_modified;
    inner.proxy_domain_modified = proxy_domain_modified;
    inner.geoip_modified = geoip_modified;
    rebuild_conflicts(inner);
    Ok(())
}

fn rebuild_conflicts(inner: &mut RoutingInner) {
    rebuild_ip_conflicts(inner);
    rebuild_domain_conflicts(inner);
}

fn rebuild_ip_conflicts(inner: &mut RoutingInner) {
    inner.ip_conflicts.clear();
    for rule in ip_net_conflicts(&inner.persistent.direct_ip, &inner.persistent.proxy_ip) {
        push_event(
            &mut inner.ip_conflicts,
            new_conflict_event_with_metadata(
                ConflictKind::Ip,
                rule,
                vec!["direct".to_owned(), "proxy".to_owned()],
                vec![DIRECT_IP_FILE.to_owned(), PROXY_IP_FILE.to_owned()],
            ),
        );
    }

    for rule in ip_net_conflicts(&inner.geoip_cn, &inner.persistent.proxy_ip) {
        push_event(
            &mut inner.ip_conflicts,
            new_conflict_event_with_metadata(
                ConflictKind::Ip,
                rule,
                vec!["cn".to_owned(), "proxy".to_owned()],
                vec!["geoip.dat".to_owned(), PROXY_IP_FILE.to_owned()],
            ),
        );
    }
    persist_conflict_events(&inner.rules_dir, TEMP_IP_CONFLICTS_FILE, &inner.ip_conflicts);
}

fn rebuild_domain_conflicts(inner: &mut RoutingInner) {
    inner.domain_conflicts.clear();
    for rule in domain_rule_conflicts(&inner.persistent.direct_domain.raw, &inner.persistent.proxy_domain.raw) {
        push_event(
            &mut inner.domain_conflicts,
            new_conflict_event_with_metadata(
                ConflictKind::Domain,
                rule,
                vec!["direct".to_owned(), "proxy".to_owned()],
                vec![DIRECT_DOMAIN_FILE.to_owned(), PROXY_DOMAIN_FILE.to_owned()],
            ),
        );
    }
    persist_conflict_events(&inner.rules_dir, TEMP_DOMAIN_CONFLICTS_FILE, &inner.domain_conflicts);
}

fn persist_conflict_events(dir: &Path, file_name: &str, conflicts: &VecDeque<ConflictEvent>) {
    let lines = conflicts
        .iter()
        .filter_map(|conflict| serde_json::to_string(conflict).ok())
        .collect::<Vec<_>>();
    if let Err(err) =
        fs::create_dir_all(dir.join(TEMP_DIR)).and_then(|()| write_lines_atomic(temp_file_path(dir, file_name), &lines))
    {
        warn!("failed to persist {}: {}", file_name, err);
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

fn ip_net_conflicts(direct: &[IpNet], proxy: &[IpNet]) -> Vec<String> {
    let mut direct_v4 = Vec::new();
    let mut direct_v6 = Vec::new();
    let mut proxy_v4 = Vec::new();
    let mut proxy_v6 = Vec::new();
    for net in direct {
        let range = ip_net_range(net);
        if range.is_v4 {
            direct_v4.push(range);
        } else {
            direct_v6.push(range);
        }
    }
    for net in proxy {
        let range = ip_net_range(net);
        if range.is_v4 {
            proxy_v4.push(range);
        } else {
            proxy_v6.push(range);
        }
    }

    let mut conflicts = ip_range_conflicts(direct_v4, proxy_v4);
    conflicts.extend(ip_range_conflicts(direct_v6, proxy_v6));
    conflicts.sort_unstable();
    conflicts.dedup();
    conflicts
}

#[derive(Clone, Debug)]
struct IpRange {
    start: u128,
    end: u128,
    label: String,
    is_v4: bool,
}

fn ip_net_range(net: &IpNet) -> IpRange {
    match net {
        IpNet::V4(net) => {
            let start = u32::from(net.network()) as u128;
            IpRange {
                start,
                end: ip_range_end(start, 32, net.prefix_len()),
                label: display_ip_net(&IpNet::V4(*net)),
                is_v4: true,
            }
        }
        IpNet::V6(net) => {
            let start = u128::from(net.network());
            IpRange {
                start,
                end: ip_range_end(start, 128, net.prefix_len()),
                label: display_ip_net(&IpNet::V6(*net)),
                is_v4: false,
            }
        }
    }
}

fn ip_range_end(start: u128, bits: u8, prefix_len: u8) -> u128 {
    let host_bits = bits.saturating_sub(prefix_len);
    if host_bits == 0 {
        start
    } else if host_bits >= 128 {
        u128::MAX
    } else {
        start | ((1u128 << host_bits) - 1)
    }
}

fn ip_range_conflicts(mut direct: Vec<IpRange>, mut proxy: Vec<IpRange>) -> Vec<String> {
    direct.sort_unstable_by_key(|range| (range.start, range.end));
    proxy.sort_unstable_by_key(|range| (range.start, range.end));

    let mut conflicts = Vec::new();
    let mut first_possible = 0usize;
    for direct in &direct {
        while first_possible < proxy.len() && proxy[first_possible].end < direct.start {
            first_possible += 1;
        }
        let mut idx = first_possible;
        while idx < proxy.len() && proxy[idx].start <= direct.end {
            if proxy[idx].end >= direct.start {
                conflicts.push(format_ip_conflict(&direct.label, &proxy[idx].label));
            }
            idx += 1;
        }
    }
    conflicts
}

fn format_ip_conflict(direct: &str, proxy: &str) -> String {
    if direct == proxy {
        direct.to_owned()
    } else {
        format!("{direct} <-> {proxy}")
    }
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

fn rules_match_domain(rules: &CompiledDomainRules, domain: &str) -> bool {
    if rules.match_all || rules.exact.contains(domain) {
        return true;
    }
    for candidate in domain_match_candidates(domain) {
        if rules.suffix.contains(&candidate) {
            return true;
        }
    }
    false
}

fn domain_rule_conflicts(direct: &HashSet<String>, proxy: &HashSet<String>) -> Vec<String> {
    let mut conflicts = Vec::new();
    let direct_wildcards = direct.iter().filter(|rule| rule.contains('*')).collect::<Vec<_>>();
    let proxy_wildcards = proxy.iter().filter(|rule| rule.contains('*')).collect::<Vec<_>>();

    for direct in direct {
        if direct.contains('*') {
            continue;
        }
        for proxy_candidate in domain_match_candidates(direct) {
            if proxy.contains(&proxy_candidate) {
                conflicts.push(format_domain_conflict(direct, &proxy_candidate));
            }
        }
    }

    for proxy in proxy {
        if proxy.contains('*') {
            continue;
        }
        for direct_candidate in domain_match_candidates(proxy) {
            if direct.contains(&direct_candidate) {
                conflicts.push(format_domain_conflict(&direct_candidate, proxy));
            }
        }
    }

    for direct in &direct_wildcards {
        for proxy in proxy {
            if domain_rules_overlap(direct, proxy) {
                conflicts.push(format_domain_conflict(direct, proxy));
            }
        }
    }

    for proxy in &proxy_wildcards {
        for direct in direct {
            if direct.contains('*') {
                continue;
            }
            if domain_rules_overlap(direct, proxy) {
                conflicts.push(format_domain_conflict(direct, proxy));
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

fn format_domain_conflict(direct: &str, proxy: &str) -> String {
    if direct == proxy {
        direct.to_owned()
    } else {
        format!("{direct} <-> {proxy}")
    }
}

fn domain_rules_overlap(left: &str, right: &str) -> bool {
    domain_matches_rule(left, right) || domain_matches_rule(right, left)
}

fn domain_matches_rule(rule: &str, domain: &str) -> bool {
    if let Some(suffix_rule) = rule.strip_prefix("*.") {
        domain_matches_rule(suffix_rule, domain)
    } else if rule.contains('*') {
        false
    } else if !rule.contains('.') {
        domain == rule
    } else {
        domain == rule
            || (domain.len() > rule.len()
                && domain.ends_with(rule)
                && domain.as_bytes()[domain.len() - rule.len() - 1] == b'.')
    }
}

fn compile_rules(raw: &RuleLists) -> io::Result<CompiledRules> {
    Ok(CompiledRules {
        direct_ip: raw.direct_ip.iter().filter_map(|s| parse_ip_net(s)).collect(),
        direct_ip_exact: raw.direct_ip.iter().filter_map(|s| parse_ip_addr(s)).collect(),
        direct_domain: compile_domain_rules(&raw.direct_domain)?,
        proxy_ip: raw.proxy_ip.iter().filter_map(|s| parse_ip_net(s)).collect(),
        proxy_ip_exact: raw.proxy_ip.iter().filter_map(|s| parse_ip_addr(s)).collect(),
        proxy_domain: compile_domain_rules(&raw.proxy_domain)?,
    })
}

fn compile_domain_rules(lines: &[String]) -> io::Result<CompiledDomainRules> {
    let mut compiled = CompiledDomainRules::default();
    for line in lines {
        let rule = normalize_domain(line);
        if rule.is_empty() {
            continue;
        }
        compiled.raw.insert(rule.clone());
        if rule == "*" {
            compiled.match_all = true;
        } else if let Some(suffix) = rule.strip_prefix("*.") {
            if suffix.is_empty() || suffix.contains('*') || !suffix.contains('.') {
                return Err(invalid_domain_wildcard(&rule));
            }
            compiled.suffix.insert(suffix.to_owned());
        } else if rule.contains('*') {
            return Err(invalid_domain_wildcard(&rule));
        } else if rule.contains('.') {
            compiled.suffix.insert(rule);
        } else {
            compiled.exact.insert(rule);
        }
    }
    Ok(compiled)
}

fn invalid_domain_wildcard(rule: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("unsupported domain wildcard rule '{rule}'; only '*.domain.tld' wildcard form is supported"),
    )
}

fn parse_ip_net(value: &str) -> Option<IpNet> {
    let value = ip_rule_value(value)?;
    if let Ok(net) = value.parse::<IpNet>() {
        return Some(net);
    }
    value.parse::<IpAddr>().ok().map(IpNet::from)
}

fn parse_ip_addr(value: &str) -> Option<IpAddr> {
    ip_rule_value(value)?.parse::<IpAddr>().ok()
}

fn ip_rule_value(value: &str) -> Option<&str> {
    value.split_whitespace().next().filter(|value| !value.is_empty())
}

fn format_proxy_ip_domain_line(ip: &IpAddr, domain: &str) -> String {
    let domain = normalize_dns_domain(domain);
    if domain.is_empty() {
        ip.to_string()
    } else {
        format!("{ip} {domain}")
    }
}

fn proxy_ip_line_matches_ip(rule: &str, ip: &IpAddr) -> bool {
    let Some(rule_net) = parse_ip_net(rule) else {
        return false;
    };
    rule_net.contains(ip)
}

fn proxy_ip_line_domain(rule: &str) -> Option<String> {
    let domain = rule.split_whitespace().nth(1).map(normalize_dns_domain)?;
    (!domain.is_empty()).then_some(domain)
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

fn is_filtered_system_connection_ip(ip: &IpAddr) -> bool {
    is_fixed_direct_ip(ip)
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

fn flow_key_for_event(event: &ConnectionEvent) -> Option<FlowKey> {
    Some((
        event.source_ip,
        event.source_port,
        event.destination_ip?,
        event.destination_port,
        protocol_static(event.protocol.as_str())?,
    ))
}

fn remember_system_connection_first_seen(first_seen: &mut HashMap<FlowKey, u64>, key: FlowKey, observed_at: u64) -> u64 {
    *first_seen.entry(key).or_insert(observed_at)
}

fn connection_record_key(row: &ConnectionEvent) -> String {
    format!(
        "{}|{}|{:?}|{:?}|{}|{}|{:?}",
        row.source_ip,
        row.source_port,
        row.destination_ip,
        row.destination_domain,
        row.destination_port,
        row.protocol,
        row.decision
    )
}

fn build_reverse_domain_map(inner: &RoutingInner) -> HashMap<IpAddr, String> {
    let mut domains = inner.reverse_domains.clone();
    for (ip, domain) in latest_dns_cache_domain_map(inner) {
        domains.entry(ip).or_insert(domain);
    }
    domains
}

fn rebuild_reverse_domains_from_dns_cache(inner: &mut RoutingInner) {
    inner.reverse_domains = latest_dns_cache_domain_map(inner);
}

fn latest_dns_cache_domain_map(inner: &RoutingInner) -> HashMap<IpAddr, String> {
    let mut cache_domains = HashMap::<IpAddr, (u64, String)>::new();
    let now = now();
    for (key, entry) in &inner.dns_cache {
        if key.domain.is_empty() || entry.expires_at <= now {
            continue;
        }
        let freshness = entry.refreshed_at.max(entry.inserted_at);
        for ip in &entry.results {
            cache_domains
                .entry(*ip)
                .and_modify(|(current, domain)| {
                    if freshness > *current {
                        *current = freshness;
                        *domain = key.domain.clone();
                    }
                })
                .or_insert_with(|| (freshness, key.domain.clone()));
        }
    }
    cache_domains
        .into_iter()
        .map(|(ip, (_, domain))| (ip, domain))
        .collect()
}

fn connection_domain_for_ip(inner: &RoutingInner, ip: &IpAddr) -> Option<String> {
    inner.reverse_domains.get(ip).cloned().or_else(|| {
        let now = now();
        inner
            .dns_cache
            .iter()
            .filter(|(key, entry)| {
                !key.domain.is_empty()
                    && entry.expires_at > now
                    && entry.results.iter().any(|result| result == ip)
            })
            .max_by_key(|(_, entry)| entry.refreshed_at.max(entry.inserted_at))
            .map(|(key, _)| key.domain.clone())
    })
}

fn fill_connection_domain(event: &mut ConnectionEvent, reverse_domains: &HashMap<IpAddr, String>) {
    if event.domain.is_some() {
        return;
    }
    event.domain = event.destination_domain.clone().or_else(|| {
        event
            .destination_ip
            .as_ref()
            .and_then(|ip| reverse_domains.get(ip).cloned())
    });
}

fn is_excluded_remote(event: &ConnectionEvent, excluded_remotes: &HashSet<IpAddr>) -> bool {
    let Some(destination_ip) = event.destination_ip else {
        return false;
    };
    excluded_remotes.contains(&destination_ip)
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

fn collect_system_connection_keys() -> HashSet<FlowKey> {
    collect_system_connections(&HashMap::new())
        .iter()
        .filter_map(flow_key_for_event)
        .collect()
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
    if is_filtered_system_connection_ip(&destination_ip) {
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
        decision: ConnectionDecision::Direct,
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
    if destination_port == 0
        || is_unspecified_ip(&destination_ip)
        || is_filtered_system_connection_ip(&destination_ip)
    {
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
        decision: ConnectionDecision::Direct,
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
    sources.geoip_sources.len() + sources.proxy_domain_sources.len()
}

fn normalize_rule_lists(lists: RuleLists) -> RuleLists {
    RuleLists {
        direct_ip: normalize_lines(lists.direct_ip),
        direct_domain: normalize_domains(lists.direct_domain),
        proxy_ip: normalize_proxy_ip_lines(lists.proxy_ip),
        proxy_domain: normalize_domains(lists.proxy_domain),
    }
}

fn normalize_proxy_ip_lines(lines: Vec<String>) -> Vec<String> {
    let mut by_ip = HashMap::new();
    for line in lines {
        let Some(line) = normalize_proxy_ip_line(&line) else {
            continue;
        };
        let Some(ip) = ip_rule_value(&line).map(ToOwned::to_owned) else {
            continue;
        };
        let replace = by_ip.get(&ip).is_none_or(|current: &String| {
            proxy_ip_line_domain(current).is_none() && proxy_ip_line_domain(&line).is_some()
        });
        if replace {
            by_ip.insert(ip, line);
        }
    }
    let mut lines = by_ip.into_values().collect::<Vec<_>>();
    lines.sort_unstable();
    lines
}

fn normalize_proxy_ip_line(line: &str) -> Option<String> {
    let mut parts = line.split_whitespace();
    let ip = parts.next()?;
    parse_ip_net(ip)?;
    let domain = parts.next().map(normalize_dns_domain).unwrap_or_default();
    Some(if domain.is_empty() {
        ip.to_owned()
    } else {
        format!("{ip} {domain}")
    })
}

fn with_private_direct_rules(mut lists: RuleLists) -> RuleLists {
    lists
        .direct_ip
        .extend(PRIVATE_DIRECT_IP_RULES.iter().map(|rule| (*rule).to_owned()));
    normalize_rule_lists(lists)
}

fn validate_temporary_rules(lists: &RuleLists) -> io::Result<()> {
    compile_rules(lists).map(|_| ())
}

#[cfg(all(target_os = "linux", feature = "local-dns"))]
fn persistent_nft_route_nets(inner: &RoutingInner) -> (PathBuf, Vec<IpNet>, Vec<IpNet>) {
    let mut direct = if inner.sources.global_proxy {
        fixed_direct_nets()
    } else {
        inner.persistent.direct_ip.clone()
    };
    if !inner.sources.global_proxy {
        direct.extend(inner.temporary.direct_ip.iter().copied());
    }
    let mut proxy = inner.persistent.proxy_ip.clone();
    proxy.extend(inner.temporary.proxy_ip.iter().copied());
    proxy.retain(|net| !direct.iter().any(|direct| ip_nets_overlap(direct, net)));
    (inner.rules_dir.clone(), direct, proxy)
}

fn dns_proxy_ip_blocked_from_nft_by_direct_rule(inner: &RoutingInner, ip: &IpAddr) -> bool {
    compiled_rules_match_ip(&inner.persistent.direct_ip_exact, &inner.persistent.direct_ip, ip)
        || compiled_rules_match_ip(&inner.temporary.direct_ip_exact, &inner.temporary.direct_ip, ip)
}

#[cfg(all(target_os = "linux", feature = "local-dns"))]
fn temporary_nft_route_nets(inner: &RoutingInner, rules: &RuleLists) -> (PathBuf, Vec<IpNet>, Vec<IpNet>) {
    let mut direct = if inner.sources.global_proxy {
        fixed_direct_nets()
    } else {
        inner.persistent.direct_ip.clone()
    };
    if !inner.sources.global_proxy {
        direct.extend(rules.direct_ip.iter().filter_map(|rule| parse_ip_net(rule)));
    }
    let mut proxy = inner.persistent.proxy_ip.clone();
    proxy.extend(rules.proxy_ip.iter().filter_map(|rule| parse_ip_net(rule)));
    proxy.retain(|net| !direct.iter().any(|direct| ip_nets_overlap(direct, net)));

    (inner.rules_dir.clone(), direct, proxy)
}

#[cfg(all(target_os = "linux", feature = "local-dns"))]
fn fixed_direct_nets() -> Vec<IpNet> {
    PRIVATE_DIRECT_IP_RULES
        .iter()
        .filter_map(|rule| parse_ip_net(rule))
        .collect()
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
        proxy_ip: read_lines(dir.join(PROXY_IP_FILE))?,
        proxy_domain: read_lines(dir.join(PROXY_DOMAIN_FILE))?,
    })
}

fn read_temporary_rule_lists(dir: &Path) -> io::Result<RuleLists> {
    Ok(RuleLists {
        direct_ip: read_temp_lines(dir, TEMP_DIRECT_IP_FILE)?,
        direct_domain: read_temp_lines(dir, TEMP_DIRECT_DOMAIN_FILE)?,
        proxy_ip: read_temp_lines(dir, TEMP_PROXY_IP_FILE)?,
        proxy_domain: read_temp_lines(dir, TEMP_PROXY_DOMAIN_FILE)?,
    })
}

fn write_temporary_rule_lists(dir: &Path, lists: &RuleLists) -> io::Result<()> {
    fs::create_dir_all(dir.join(TEMP_DIR))?;
    write_lines_atomic(temp_file_path(dir, TEMP_DIRECT_IP_FILE), &lists.direct_ip)?;
    write_lines_atomic(temp_file_path(dir, TEMP_DIRECT_DOMAIN_FILE), &lists.direct_domain)?;
    write_lines_atomic(temp_file_path(dir, TEMP_PROXY_IP_FILE), &lists.proxy_ip)?;
    write_lines_atomic(temp_file_path(dir, TEMP_PROXY_DOMAIN_FILE), &lists.proxy_domain)?;
    Ok(())
}

fn temporary_files_fingerprint(dir: &Path) -> io::Result<Vec<Option<u64>>> {
    [
        TEMP_DIRECT_IP_FILE,
        TEMP_DIRECT_DOMAIN_FILE,
        TEMP_PROXY_IP_FILE,
        TEMP_PROXY_DOMAIN_FILE,
    ]
    .into_iter()
    .map(|file_name| file_fingerprint(&temp_file_path(dir, file_name)))
    .collect()
}

fn file_fingerprint(path: &Path) -> io::Result<Option<u64>> {
    if !path.exists() {
        return Ok(None);
    }
    let bytes = fs::read(path)?;
    let mut hash = 0xcbf29ce484222325u64;
    for byte in bytes {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    Ok(Some(hash))
}

fn read_temp_lines(dir: &Path, file_name: &str) -> io::Result<Vec<String>> {
    read_lines(temp_file_path(dir, file_name))
}

fn temp_file_path(dir: &Path, file_name: &str) -> PathBuf {
    dir.join(TEMP_DIR).join(file_name)
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
    status: DownloadedSourceStatus,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DownloadedSourceStatus {
    Downloaded,
    FallbackCache,
    LocalFile,
}

async fn download_source(source: &str, cache_dir: &Path) -> io::Result<DownloadedSource> {
    if source.starts_with("http://") || source.starts_with("https://") {
        let source = source.to_owned();
        let cache_dir = cache_dir.to_owned();
        tokio::task::spawn_blocking(move || {
            let display_name = source_cache_name(&source);
            let cache_path = cached_source_path(&source, &cache_dir);
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
                            status: DownloadedSourceStatus::Downloaded,
                        });
                    }
                    _ => continue,
                }
            }
            if let Some(bytes) = read_non_empty_file(&cache_path)? {
                return Ok(DownloadedSource {
                    bytes,
                    display_name,
                    status: DownloadedSourceStatus::FallbackCache,
                });
            }
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                "download failed or returned empty output, and no existing source file is available",
            ))
        })
        .await
        .map_err(|err| io::Error::other(err.to_string()))?
    } else {
        Ok(DownloadedSource {
            bytes: fs::read(source)?,
            display_name: source_progress_name(source),
            status: DownloadedSourceStatus::LocalFile,
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

    async fn wait_for_recorded_connection(
        state: &RoutingState,
        source: SocketAddr,
        destination: IpAddr,
        port: u16,
    ) -> ConnectionEvent {
        for _ in 0..50 {
            if let Some(row) = state.recent_connections(&HashSet::new()).await.into_iter().find(|row| {
                row.source_ip == source.ip()
                    && row.source_port == source.port()
                    && row.destination_ip == Some(destination)
                    && row.destination_port == port
            }) {
                return row;
            }
            time::sleep(Duration::from_millis(10)).await;
        }
        panic!("recorded connection was not observed");
    }

    #[test]
    fn flow_key_for_system_rows_ignores_display_domain() {
        let mut event = ConnectionEvent {
            timestamp: now(),
            source_ip: "192.168.2.246".parse().unwrap(),
            source_port: 54000,
            destination_ip: Some("172.64.155.209".parse().unwrap()),
            destination_domain: None,
            domain: None,
            destination_port: 443,
            protocol: "tcp".to_owned(),
            decision: ConnectionDecision::Direct,
        };
        let baseline_key = flow_key_for_event(&event).unwrap();

        event.domain = Some("chatgpt.com".to_owned());
        event.decision = ConnectionDecision::Redir;

        assert_eq!(flow_key_for_event(&event), Some(baseline_key));
    }

    #[test]
    fn system_connection_first_seen_timestamp_is_stable() {
        let key: FlowKey = (
            "192.168.2.246".parse().unwrap(),
            54000,
            "172.64.155.209".parse().unwrap(),
            443,
            "tcp",
        );
        let mut first_seen = HashMap::new();

        assert_eq!(remember_system_connection_first_seen(&mut first_seen, key, 100), 100);
        assert_eq!(remember_system_connection_first_seen(&mut first_seen, key, 200), 100);
    }

    #[test]
    fn fixed_direct_ip_matches_documented_ranges() {
        for ip in [
            "0.1.2.3",
            "10.1.2.3",
            "100.64.0.1",
            "100.127.255.255",
            "127.0.0.1",
            "169.254.1.1",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "198.18.0.1",
            "198.19.255.255",
            "::",
            "::1",
            "fc00::1",
            "fdff::1",
            "fe80::1",
            "ff02::1",
        ] {
            assert!(is_fixed_direct_ip(&ip.parse().unwrap()), "{ip}");
        }

        for ip in ["1.1.1.1", "100.128.0.1", "172.32.0.1", "198.20.0.1", "2001:db8::1"] {
            assert!(!is_fixed_direct_ip(&ip.parse().unwrap()), "{ip}");
        }
    }

    #[tokio::test]
    async fn activity_recording_keeps_fixed_direct_application_events() {
        let dir = temp_rules_dir("record-fixed-direct");
        let mut config = RouteRulesConfig::default();
        config.rules_dir = dir;
        config.geoip_sources.clear();
        config.proxy_domain_sources.clear();
        let state = RoutingState::load(config).await.unwrap();

        assert!(state.recent_connections(&HashSet::new()).await.is_empty());
        state.start_activity_recording().await.unwrap();

        let source = "127.0.0.1:40000".parse::<SocketAddr>().unwrap();
        let destination = "10.1.2.3".parse::<IpAddr>().unwrap();
        let target = Address::SocketAddress(SocketAddr::new(destination, 443));
        state
            .record_connection(source, &target, "tcp", ConnectionDecision::Direct)
            .await;

        let row = wait_for_recorded_connection(&state, source, destination, 443).await;
        assert_eq!(row.decision, ConnectionDecision::Direct);

        state.stop_activity_recording().await.unwrap();
        assert!(state.recent_connections(&HashSet::new()).await.is_empty());
    }

    #[tokio::test]
    async fn activity_recording_records_socks5_proxy_decision() {
        let dir = temp_rules_dir("record-socks5-proxy");
        let mut config = RouteRulesConfig::default();
        config.rules_dir = dir;
        config.geoip_sources.clear();
        config.proxy_domain_sources.clear();
        let state = RoutingState::load(config).await.unwrap();
        state.start_activity_recording().await.unwrap();

        let source = "127.0.0.1:40001".parse::<SocketAddr>().unwrap();
        let destination = "203.0.113.10".parse::<IpAddr>().unwrap();
        let target = Address::SocketAddress(SocketAddr::new(destination, 443));
        state
            .record_connection(source, &target, "tcp", ConnectionDecision::Socks5Proxy)
            .await;

        let row = wait_for_recorded_connection(&state, source, destination, 443).await;
        assert_eq!(row.decision, ConnectionDecision::Socks5Proxy);
    }

    #[tokio::test]
    async fn recent_connections_backfills_domain_from_dns_cache() {
        let dir = temp_rules_dir("record-domain-backfill");
        let mut config = RouteRulesConfig::default();
        config.rules_dir = dir;
        config.geoip_sources.clear();
        config.proxy_domain_sources.clear();
        config.dns_cache_ttl_seconds = 60;
        let state = RoutingState::load(config).await.unwrap();
        state.start_activity_recording().await.unwrap();

        let source = "127.0.0.1:40002".parse::<SocketAddr>().unwrap();
        let destination = "203.0.113.20".parse::<IpAddr>().unwrap();
        let target = Address::SocketAddress(SocketAddr::new(destination, 443));
        state
            .record_connection(source, &target, "tcp", ConnectionDecision::Direct)
            .await;

        let row = wait_for_recorded_connection(&state, source, destination, 443).await;
        assert_eq!(row.domain, None);

        state
            .dns_cache_insert(
                "api.example.",
                "A",
                RouteDecision::Direct,
                Message::query(),
                vec![destination],
            )
            .await;

        let row = wait_for_recorded_connection(&state, source, destination, 443).await;
        assert_eq!(row.domain.as_deref(), Some("api.example"));
    }

    #[tokio::test]
    async fn temporary_rules_override_persistent_rules() {
        let dir = temp_rules_dir("override");
        write_lines_atomic(dir.join(DIRECT_IP_FILE), &["1.1.1.1".to_owned()]).unwrap();
        write_lines_atomic(dir.join(DIRECT_DOMAIN_FILE), &["example.com".to_owned()]).unwrap();
        write_lines_atomic(dir.join(PROXY_IP_FILE), &[]).unwrap();
        write_lines_atomic(dir.join(PROXY_DOMAIN_FILE), &[]).unwrap();

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
                proxy_ip: vec!["1.1.1.1".to_owned()],
                proxy_domain: vec!["example.com".to_owned()],
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
    async fn global_proxy_routes_unknown_public_targets_through_proxy() {
        let dir = temp_rules_dir("global-proxy");
        write_lines_atomic(dir.join(DIRECT_IP_FILE), &["1.1.1.1".to_owned()]).unwrap();
        write_lines_atomic(dir.join(DIRECT_DOMAIN_FILE), &["direct.example".to_owned()]).unwrap();
        write_lines_atomic(dir.join(PROXY_IP_FILE), &[]).unwrap();
        write_lines_atomic(dir.join(PROXY_DOMAIN_FILE), &[]).unwrap();

        let mut config = RouteRulesConfig::default();
        config.rules_dir = dir;
        config.global_proxy = true;
        let state = RoutingState::load(config).await.unwrap();

        assert_eq!(
            state.route_ip(&"8.8.8.8".parse().unwrap()).await,
            Some(RouteDecision::Proxy)
        );
        assert_eq!(state.route_domain("unknown.example").await, Some(RouteDecision::Proxy));
        assert_eq!(
            state.route_ip(&"1.1.1.1".parse().unwrap()).await,
            Some(RouteDecision::Proxy)
        );
        assert_eq!(
            state.route_ip(&"192.168.1.1".parse().unwrap()).await,
            Some(RouteDecision::Direct)
        );
        assert_eq!(
            state.route_domain("direct.example").await,
            Some(RouteDecision::Proxy)
        );
    }

    #[tokio::test]
    async fn global_proxy_does_not_learn_proxy_dns_result_ips() {
        let dir = temp_rules_dir("global-proxy-no-proxy-ip-learning");
        write_lines_atomic(dir.join(DIRECT_IP_FILE), &[]).unwrap();
        write_lines_atomic(dir.join(PROXY_IP_FILE), &[]).unwrap();
        write_lines_atomic(dir.join(DIRECT_DOMAIN_FILE), &[]).unwrap();
        write_lines_atomic(dir.join(PROXY_DOMAIN_FILE), &[]).unwrap();

        let mut config = RouteRulesConfig::default();
        config.rules_dir = dir.clone();
        config.geoip_sources.clear();
        config.proxy_domain_sources.clear();
        config.global_proxy = true;
        let state = RoutingState::load(config).await.unwrap();
        let ip = "203.0.113.10".parse().unwrap();

        state
            .add_dns_results(RouteDecision::Proxy, "www.example.com", &[ip])
            .await
            .unwrap();
        state.persist_proxy_ip_if_dirty().await;

        assert!(read_lines(dir.join(PROXY_IP_FILE)).unwrap().is_empty());
        let inner = state.inner.read().await;
        assert!(inner.persistent_raw.proxy_ip.is_empty());
        assert!(!inner.proxy_ip_dirty);
        assert!(!inner.proxy_ip_persist_scheduled);
    }

    #[tokio::test]
    async fn temporary_proxy_domain_matches_aws_console_subdomain_immediately() {
        let dir = temp_rules_dir("temporary-aws-domain");
        let mut config = RouteRulesConfig::default();
        config.rules_dir = dir;
        config.geoip_sources.clear();
        config.proxy_domain_sources.clear();
        let state = RoutingState::load(config).await.unwrap();

        state
            .set_temporary_rules(RuleLists {
                proxy_domain: vec!["aws.amazon.com".to_owned()],
                ..RuleLists::default()
            })
            .await
            .unwrap();

        assert_eq!(state.route_domain("aws.amazon.com").await, Some(RouteDecision::Proxy));
        assert_eq!(
            state.route_domain("ap-southeast-1.console.aws.amazon.com")
                .await,
            Some(RouteDecision::Proxy)
        );
    }

    #[tokio::test]
    async fn source_update_writes_four_rule_files() {
        let dir = temp_rules_dir("sources");
        let geoip_source = dir.join("geoip.txt");
        let proxy_source = dir.join("proxy.txt");
        fs::write(dir.join(DIRECT_IP_FILE), "192.0.2.0/24\n").unwrap();
        write_temporary_rule_lists(
            &dir,
            &RuleLists {
                direct_ip: vec!["203.0.113.0/24".to_owned()],
                direct_domain: vec!["temp-direct.example".to_owned()],
                proxy_ip: vec!["203.0.113.10".to_owned()],
                proxy_domain: vec!["temp-proxy.example".to_owned()],
            },
        )
        .unwrap();
        fs::write(
            dir.join(DIRECT_DOMAIN_FILE),
            "direct.example\n# comment\nchina.example\n",
        )
        .unwrap();
        fs::write(&geoip_source, "198.51.100.0/24\n").unwrap();
        fs::write(&proxy_source, "proxy.example\ngfw.example\n").unwrap();

        let mut config = RouteRulesConfig::default();
        config.rules_dir = dir.clone();
        config.geoip_sources = vec![geoip_source.display().to_string()];
        config.proxy_domain_sources = vec![proxy_source.display().to_string()];

        let state = RoutingState::load(config).await.unwrap();
        state.update_from_sources().await.unwrap();

        let direct_domain = read_lines(dir.join(DIRECT_DOMAIN_FILE)).unwrap();
        let direct_ip = read_lines(dir.join(DIRECT_IP_FILE)).unwrap();
        let proxy_ip = read_lines(dir.join(PROXY_IP_FILE)).unwrap();
        let proxy_domain = read_lines(dir.join(PROXY_DOMAIN_FILE)).unwrap();
        assert!(direct_ip.contains(&"192.0.2.0/24".to_owned()));
        assert!(!direct_ip.contains(&"203.0.113.0/24".to_owned()));
        assert!(!direct_ip.contains(&"198.51.100.0/24".to_owned()));
        assert!(direct_domain.contains(&"direct.example".to_owned()));
        assert!(direct_domain.contains(&"china.example".to_owned()));
        assert!(!direct_domain.contains(&"temp-direct.example".to_owned()));
        assert!(!proxy_ip.contains(&"203.0.113.10".to_owned()));
        assert!(proxy_domain.contains(&"proxy.example".to_owned()));
        assert!(proxy_domain.contains(&"gfw.example".to_owned()));
        assert!(!proxy_domain.contains(&"temp-proxy.example".to_owned()));
        assert!(dir.join(DIRECT_IP_FILE).exists());
        assert!(dir.join(PROXY_IP_FILE).exists());
    }

    #[tokio::test]
    async fn http_source_download_failure_keeps_existing_cache() {
        let dir = temp_rules_dir("source-fallback");
        let source = "http://127.0.0.1:9/gfw.txt";
        let cache_dir = dir.join(SOURCE_DIR);
        fs::create_dir_all(&cache_dir).unwrap();
        let cache_path = cached_source_path(source, &cache_dir);
        fs::write(&cache_path, "cached.example\n").unwrap();

        let downloaded = download_source(source, &cache_dir).await.unwrap();

        assert_eq!(downloaded.bytes, b"cached.example\n");
        assert_eq!(downloaded.status, DownloadedSourceStatus::FallbackCache);
        assert_eq!(fs::read(&cache_path).unwrap(), b"cached.example\n");
    }

    #[tokio::test]
    async fn source_update_and_download_jobs_are_mutually_exclusive() {
        let dir = temp_rules_dir("source-job-lock");
        let mut config = RouteRulesConfig::default();
        config.rules_dir = dir;
        config.geoip_sources.clear();
        config.proxy_domain_sources.clear();

        let state = RoutingState::load(config).await.unwrap();

        assert!(state.try_begin_update().await);
        assert!(!state.try_begin_update().await);
        assert!(!state.try_begin_download().await);

        state.mark_rule_job_failed_sync("release update lock".to_owned());

        assert!(state.try_begin_download().await);
        assert!(!state.try_begin_update().await);
        assert!(!state.try_begin_download().await);
    }

    #[tokio::test]
    async fn wildcard_suffix_domain_rules_route_and_conflict() {
        let dir = temp_rules_dir("wildcard-domain");
        write_lines_atomic(dir.join(DIRECT_IP_FILE), &[]).unwrap();
        write_lines_atomic(dir.join(PROXY_IP_FILE), &[]).unwrap();
        write_lines_atomic(dir.join(DIRECT_DOMAIN_FILE), &["*.example.com".to_owned()]).unwrap();
        write_lines_atomic(dir.join(PROXY_DOMAIN_FILE), &["example.com".to_owned()]).unwrap();

        let mut config = RouteRulesConfig::default();
        config.rules_dir = dir;
        config.geoip_sources.clear();
        config.proxy_domain_sources.clear();
        let state = RoutingState::load(config).await.unwrap();

        assert_eq!(state.route_domain("www.example.com").await, Some(RouteDecision::Direct));
        assert_eq!(state.route_domain("example.com").await, Some(RouteDecision::Direct));
        assert_eq!(state.route_domain("api.example.com").await, Some(RouteDecision::Direct));
        let conflicts = state.domain_conflicts().await;
        assert!(conflicts.iter().any(|conflict| {
            conflict.value == "*.example.com <-> example.com"
                && conflict.sources == [DIRECT_DOMAIN_FILE.to_owned(), PROXY_DOMAIN_FILE.to_owned()]
        }));
    }

    #[tokio::test]
    async fn complex_domain_wildcards_are_rejected() {
        let dir = temp_rules_dir("complex-wildcard-domain");
        write_lines_atomic(dir.join(DIRECT_IP_FILE), &[]).unwrap();
        write_lines_atomic(dir.join(PROXY_IP_FILE), &[]).unwrap();
        write_lines_atomic(dir.join(DIRECT_DOMAIN_FILE), &[]).unwrap();
        write_lines_atomic(dir.join(PROXY_DOMAIN_FILE), &["api.*".to_owned()]).unwrap();

        let mut config = RouteRulesConfig::default();
        config.rules_dir = dir;
        config.geoip_sources.clear();
        config.proxy_domain_sources.clear();
        let err = match RoutingState::load(config).await {
            Ok(_) => panic!("complex wildcard should be rejected"),
            Err(err) => err,
        };

        assert!(
            err.to_string()
                .contains("only '*.domain.tld' wildcard form is supported")
        );
    }

    #[tokio::test]
    async fn direct_domain_overrides_proxy_suffix_after_reload() {
        let dir = temp_rules_dir("domain-priority-reload");
        write_lines_atomic(dir.join(DIRECT_IP_FILE), &[]).unwrap();
        write_lines_atomic(dir.join(PROXY_IP_FILE), &[]).unwrap();
        write_lines_atomic(dir.join(DIRECT_DOMAIN_FILE), &["a.baidu.com".to_owned()]).unwrap();
        write_lines_atomic(dir.join(PROXY_DOMAIN_FILE), &["baidu.com".to_owned()]).unwrap();
        write_temporary_rule_lists(
            &dir,
            &RuleLists {
                direct_ip: Vec::new(),
                direct_domain: vec!["b.baidu.com".to_owned()],
                proxy_ip: Vec::new(),
                proxy_domain: vec!["temp.baidu.com".to_owned()],
            },
        )
        .unwrap();

        let mut config = RouteRulesConfig::default();
        config.rules_dir = dir;
        config.geoip_sources.clear();
        config.proxy_domain_sources.clear();
        let state = RoutingState::load(config).await.unwrap();

        assert_eq!(state.route_domain("baidu.com").await, Some(RouteDecision::Proxy));
        assert_eq!(state.route_domain("c.baidu.com").await, Some(RouteDecision::Proxy));
        assert_eq!(state.route_domain("a.baidu.com").await, Some(RouteDecision::Direct));
        assert_eq!(state.route_domain("b.baidu.com").await, Some(RouteDecision::Direct));
        assert_eq!(state.route_domain("temp.baidu.com").await, Some(RouteDecision::Proxy));
    }

    #[tokio::test]
    async fn apex_and_wildcard_domain_rules_are_suffix_equivalent() {
        let dir = temp_rules_dir("domain-suffix-equivalence");
        write_lines_atomic(dir.join(DIRECT_IP_FILE), &[]).unwrap();
        write_lines_atomic(dir.join(PROXY_IP_FILE), &[]).unwrap();
        write_lines_atomic(dir.join(DIRECT_DOMAIN_FILE), &["*.direct.baidu.com".to_owned()]).unwrap();
        write_lines_atomic(dir.join(PROXY_DOMAIN_FILE), &["baidu.com".to_owned()]).unwrap();

        let mut config = RouteRulesConfig::default();
        config.rules_dir = dir;
        config.geoip_sources.clear();
        config.proxy_domain_sources.clear();
        let state = RoutingState::load(config).await.unwrap();

        assert_eq!(state.route_domain("baidu.com").await, Some(RouteDecision::Proxy));
        assert_eq!(state.route_domain("a.baidu.com").await, Some(RouteDecision::Proxy));
        assert_eq!(
            state.route_domain("direct.baidu.com").await,
            Some(RouteDecision::Direct)
        );
        assert_eq!(
            state.route_domain("a.direct.baidu.com").await,
            Some(RouteDecision::Direct)
        );
    }

    #[tokio::test]
    async fn single_label_domain_rules_do_not_match_tlds() {
        let dir = temp_rules_dir("single-label-domain");
        write_lines_atomic(dir.join(DIRECT_IP_FILE), &[]).unwrap();
        write_lines_atomic(dir.join(PROXY_IP_FILE), &[]).unwrap();
        write_lines_atomic(dir.join(DIRECT_DOMAIN_FILE), &["cn".to_owned()]).unwrap();
        write_lines_atomic(dir.join(PROXY_DOMAIN_FILE), &["google.cn".to_owned()]).unwrap();

        let mut config = RouteRulesConfig::default();
        config.rules_dir = dir;
        config.geoip_sources.clear();
        config.proxy_domain_sources.clear();
        let state = RoutingState::load(config).await.unwrap();

        assert_eq!(state.route_domain("cn").await, Some(RouteDecision::Direct));
        assert_eq!(state.route_domain("google.cn").await, Some(RouteDecision::Proxy));
        assert!(state.domain_conflicts().await.is_empty());
    }

    #[tokio::test]
    async fn multi_label_domain_rules_match_subdomains() {
        let dir = temp_rules_dir("suffix-domain");
        write_lines_atomic(dir.join(DIRECT_IP_FILE), &[]).unwrap();
        write_lines_atomic(dir.join(PROXY_IP_FILE), &[]).unwrap();
        write_lines_atomic(dir.join(DIRECT_DOMAIN_FILE), &["c.pki.goog".to_owned()]).unwrap();
        write_lines_atomic(dir.join(PROXY_DOMAIN_FILE), &["pki.goog".to_owned()]).unwrap();

        let mut config = RouteRulesConfig::default();
        config.rules_dir = dir;
        config.geoip_sources.clear();
        config.proxy_domain_sources.clear();
        let state = RoutingState::load(config).await.unwrap();

        assert_eq!(state.route_domain("pki.goog").await, Some(RouteDecision::Proxy));
        assert_eq!(state.route_domain("c.pki.goog").await, Some(RouteDecision::Direct));
        assert!(!state.domain_conflicts().await.is_empty());
    }

    #[tokio::test]
    async fn dns_learned_proxy_ip_keeps_direct_priority_and_indexes_conflict() {
        let dir = temp_rules_dir("dns-learned-conflict");
        write_lines_atomic(dir.join(DIRECT_IP_FILE), &["203.0.113.10".to_owned()]).unwrap();
        write_lines_atomic(dir.join(PROXY_IP_FILE), &[]).unwrap();
        write_lines_atomic(dir.join(DIRECT_DOMAIN_FILE), &[]).unwrap();
        write_lines_atomic(dir.join(PROXY_DOMAIN_FILE), &["example.com".to_owned()]).unwrap();

        let mut config = RouteRulesConfig::default();
        config.rules_dir = dir.clone();
        config.geoip_sources.clear();
        config.proxy_domain_sources.clear();
        let state = RoutingState::load(config).await.unwrap();

        state
            .add_dns_results(
                RouteDecision::Proxy,
                "www.example.com",
                &["203.0.113.10".parse().unwrap()],
            )
            .await
            .unwrap();

        state.persist_proxy_ip_if_dirty().await;

        assert!(
            read_lines(dir.join(PROXY_IP_FILE))
                .unwrap()
                .contains(&"203.0.113.10 www.example.com".to_owned())
        );
        assert_eq!(
            state.route_ip(&"203.0.113.10".parse().unwrap()).await,
            Some(RouteDecision::Direct)
        );
        let conflicts = state.ip_conflicts().await;
        assert!(conflicts.iter().any(|conflict| {
            conflict.value == "203.0.113.10"
                && conflict.regions == ["direct".to_owned(), "proxy".to_owned()]
                && conflict.sources == [DIRECT_IP_FILE.to_owned(), PROXY_IP_FILE.to_owned()]
        }));
    }

    #[tokio::test]
    async fn dns_learned_proxy_ip_keeps_temporary_direct_priority() {
        let dir = temp_rules_dir("dns-learned-temp-direct-conflict");
        write_lines_atomic(dir.join(DIRECT_IP_FILE), &[]).unwrap();
        write_lines_atomic(dir.join(PROXY_IP_FILE), &[]).unwrap();
        write_lines_atomic(dir.join(DIRECT_DOMAIN_FILE), &[]).unwrap();
        write_lines_atomic(dir.join(PROXY_DOMAIN_FILE), &["example.com".to_owned()]).unwrap();
        write_temporary_rule_lists(
            &dir,
            &RuleLists {
                direct_ip: vec!["203.0.113.10".to_owned()],
                direct_domain: Vec::new(),
                proxy_ip: Vec::new(),
                proxy_domain: Vec::new(),
            },
        )
        .unwrap();

        let mut config = RouteRulesConfig::default();
        config.rules_dir = dir.clone();
        config.geoip_sources.clear();
        config.proxy_domain_sources.clear();
        let state = RoutingState::load(config).await.unwrap();

        state
            .add_dns_results(
                RouteDecision::Proxy,
                "www.example.com",
                &["203.0.113.10".parse().unwrap()],
            )
            .await
            .unwrap();

        state.persist_proxy_ip_if_dirty().await;

        assert!(
            read_lines(dir.join(PROXY_IP_FILE))
                .unwrap()
                .contains(&"203.0.113.10 www.example.com".to_owned())
        );
        assert_eq!(
            state.route_ip(&"203.0.113.10".parse().unwrap()).await,
            Some(RouteDecision::Direct)
        );
    }

    #[tokio::test]
    async fn direct_dns_results_do_not_become_direct_ip_rules() {
        let dir = temp_rules_dir("dns-direct-not-persistent");
        write_lines_atomic(dir.join(DIRECT_IP_FILE), &[]).unwrap();
        write_lines_atomic(dir.join(PROXY_IP_FILE), &[]).unwrap();
        write_lines_atomic(dir.join(DIRECT_DOMAIN_FILE), &["direct.example".to_owned()]).unwrap();
        write_lines_atomic(dir.join(PROXY_DOMAIN_FILE), &[]).unwrap();

        let mut config = RouteRulesConfig::default();
        config.rules_dir = dir.clone();
        config.geoip_sources.clear();
        config.proxy_domain_sources.clear();
        let state = RoutingState::load(config).await.unwrap();
        let ip = "203.0.113.20".parse().unwrap();

        state
            .add_dns_results(RouteDecision::Direct, "direct.example", &[ip])
            .await
            .unwrap();

        assert!(read_lines(dir.join(DIRECT_IP_FILE)).unwrap().is_empty());
        assert_eq!(state.route_ip(&ip).await, None);
    }

    #[tokio::test]
    async fn dns_learned_proxy_ip_records_once_for_same_ip() {
        let dir = temp_rules_dir("dns-learned-domain-column");
        write_lines_atomic(dir.join(DIRECT_IP_FILE), &[]).unwrap();
        write_lines_atomic(dir.join(PROXY_IP_FILE), &[]).unwrap();
        write_lines_atomic(dir.join(DIRECT_DOMAIN_FILE), &[]).unwrap();
        write_lines_atomic(dir.join(PROXY_DOMAIN_FILE), &["example.com".to_owned()]).unwrap();

        let mut config = RouteRulesConfig::default();
        config.rules_dir = dir.clone();
        config.geoip_sources.clear();
        config.proxy_domain_sources.clear();
        let state = RoutingState::load(config).await.unwrap();
        let ip = "203.0.113.10".parse().unwrap();

        state
            .add_dns_results(RouteDecision::Proxy, "a.example.com.", &[ip])
            .await
            .unwrap();
        state
            .add_dns_results(RouteDecision::Proxy, "b.example.com.", &[ip])
            .await
            .unwrap();
        state.persist_proxy_ip_if_dirty().await;

        let lines = read_lines(dir.join(PROXY_IP_FILE)).unwrap();
        assert!(lines.contains(&"203.0.113.10 a.example.com".to_owned()));
        assert!(!lines.contains(&"203.0.113.10 b.example.com".to_owned()));
        assert_eq!(lines.iter().filter(|line| parse_ip_addr(line) == Some(ip)).count(), 1);
        assert_eq!(state.route_ip(&ip).await, Some(RouteDecision::Proxy));
    }

    #[tokio::test]
    async fn known_proxy_dns_result_does_not_dirty_proxy_file() {
        let dir = temp_rules_dir("dns-known-proxy-not-dirty");
        write_lines_atomic(dir.join(DIRECT_IP_FILE), &[]).unwrap();
        write_lines_atomic(dir.join(PROXY_IP_FILE), &["203.0.113.10 a.example.com".to_owned()]).unwrap();
        write_lines_atomic(dir.join(DIRECT_DOMAIN_FILE), &[]).unwrap();
        write_lines_atomic(dir.join(PROXY_DOMAIN_FILE), &["example.com".to_owned()]).unwrap();

        let mut config = RouteRulesConfig::default();
        config.rules_dir = dir.clone();
        config.geoip_sources.clear();
        config.proxy_domain_sources.clear();
        let state = RoutingState::load(config).await.unwrap();
        let ip = "203.0.113.10".parse().unwrap();

        state
            .add_dns_results(RouteDecision::Proxy, "b.example.com.", &[ip])
            .await
            .unwrap();

        let inner = state.inner.read().await;
        assert!(!inner.proxy_ip_dirty);
        assert!(!inner.proxy_ip_persist_scheduled);
        drop(inner);

        let lines = read_lines(dir.join(PROXY_IP_FILE)).unwrap();
        assert_eq!(lines, vec!["203.0.113.10 a.example.com".to_owned()]);
    }

    #[tokio::test]
    async fn known_proxy_ip_remains_eligible_for_nft_dns_sync() {
        let dir = temp_rules_dir("dns-known-proxy-nft-sync");
        write_lines_atomic(dir.join(DIRECT_IP_FILE), &[]).unwrap();
        write_lines_atomic(dir.join(PROXY_IP_FILE), &["203.0.113.10 a.example.com".to_owned()]).unwrap();
        write_lines_atomic(dir.join(DIRECT_DOMAIN_FILE), &[]).unwrap();
        write_lines_atomic(dir.join(PROXY_DOMAIN_FILE), &["example.com".to_owned()]).unwrap();

        let mut config = RouteRulesConfig::default();
        config.rules_dir = dir;
        config.geoip_sources.clear();
        config.proxy_domain_sources.clear();
        let state = RoutingState::load(config).await.unwrap();
        let ip = "203.0.113.10".parse().unwrap();
        let inner = state.inner.read().await;

        assert!(compiled_rules_match_ip(
            &inner.persistent.proxy_ip_exact,
            &inner.persistent.proxy_ip,
            &ip
        ));
        assert!(!dns_proxy_ip_blocked_from_nft_by_direct_rule(&inner, &ip));
    }

    #[tokio::test]
    async fn dns_learned_proxy_ip_upgrades_legacy_one_column_row() {
        let dir = temp_rules_dir("dns-learned-upgrade");
        write_lines_atomic(dir.join(DIRECT_IP_FILE), &[]).unwrap();
        write_lines_atomic(dir.join(PROXY_IP_FILE), &["203.0.113.10".to_owned()]).unwrap();
        write_lines_atomic(dir.join(DIRECT_DOMAIN_FILE), &[]).unwrap();
        write_lines_atomic(dir.join(PROXY_DOMAIN_FILE), &["example.com".to_owned()]).unwrap();

        let mut config = RouteRulesConfig::default();
        config.rules_dir = dir.clone();
        config.geoip_sources.clear();
        config.proxy_domain_sources.clear();
        let state = RoutingState::load(config).await.unwrap();
        let ip = "203.0.113.10".parse().unwrap();

        state
            .add_dns_results(RouteDecision::Proxy, "a.example.com.", &[ip])
            .await
            .unwrap();
        state.persist_proxy_ip_if_dirty().await;

        let lines = read_lines(dir.join(PROXY_IP_FILE)).unwrap();
        assert_eq!(lines, vec!["203.0.113.10 a.example.com".to_owned()]);
        assert_eq!(state.route_ip(&ip).await, Some(RouteDecision::Proxy));
    }

    #[test]
    fn ip_conflicts_handle_exact_and_cidr_overlaps() {
        let direct = vec![
            parse_ip_net("203.0.113.10").unwrap(),
            parse_ip_net("2001:db8:1::/48").unwrap(),
        ];
        let proxy = vec![
            parse_ip_net("203.0.113.0/24").unwrap(),
            parse_ip_net("2001:db8:1:1::1").unwrap(),
            parse_ip_net("198.51.100.0/24").unwrap(),
        ];

        let conflicts = ip_net_conflicts(&direct, &proxy);
        assert!(conflicts.contains(&"203.0.113.10 <-> 203.0.113.0/24".to_owned()));
        assert!(conflicts.contains(&"2001:db8:1::/48 <-> 2001:db8:1:1::1".to_owned()));
        assert_eq!(conflicts.len(), 2);
    }

    #[tokio::test]
    async fn temporary_rules_persist_to_temp_files() {
        let dir = temp_rules_dir("temporary-persist");
        let mut config = RouteRulesConfig::default();
        config.rules_dir = dir.clone();
        config.geoip_sources.clear();
        config.proxy_domain_sources.clear();

        let state = RoutingState::load(config.clone()).await.unwrap();
        state
            .set_temporary_rules(RuleLists {
                direct_ip: vec!["203.0.113.0/24".to_owned()],
                direct_domain: vec!["direct.temp.example".to_owned()],
                proxy_ip: vec!["198.51.100.10".to_owned()],
                proxy_domain: vec!["*.temp.example".to_owned()],
            })
            .await
            .unwrap();

        assert!(
            read_lines(temp_file_path(&dir, TEMP_DIRECT_IP_FILE))
                .unwrap()
                .contains(&"203.0.113.0/24".to_owned())
        );
        assert!(
            read_lines(temp_file_path(&dir, TEMP_PROXY_DOMAIN_FILE))
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
    async fn temporary_rules_reload_from_temp_files() {
        let dir = temp_rules_dir("temporary-reload");
        let mut config = RouteRulesConfig::default();
        config.rules_dir = dir.clone();
        config.geoip_sources.clear();
        config.proxy_domain_sources.clear();

        let state = RoutingState::load(config).await.unwrap();
        assert_eq!(state.route_domain("file.temp.example").await, None);

        write_lines_atomic(
            temp_file_path(&dir, TEMP_PROXY_DOMAIN_FILE),
            &["file.temp.example".to_owned()],
        )
        .unwrap();

        let reloaded = state.reload_temporary_rules_from_files().await.unwrap();
        assert!(reloaded.proxy_domain.contains(&"file.temp.example".to_owned()));
        assert_eq!(
            state.route_domain("file.temp.example").await,
            Some(RouteDecision::Proxy)
        );
    }

    #[tokio::test]
    async fn saved_temporary_rules_are_loaded_by_file_watcher() {
        let dir = temp_rules_dir("temporary-watch");
        let mut config = RouteRulesConfig::default();
        config.rules_dir = dir;
        config.geoip_sources.clear();
        config.proxy_domain_sources.clear();

        let state = RoutingState::load(config).await.unwrap();
        state
            .save_temporary_rules_to_files(RuleLists {
                proxy_domain: vec!["watched.temp.example".to_owned()],
                ..RuleLists::default()
            })
            .await
            .unwrap();

        assert_eq!(state.route_domain("watched.temp.example").await, None);
        tokio::time::sleep(Duration::from_secs(3)).await;
        assert_eq!(
            state.route_domain("watched.temp.example").await,
            Some(RouteDecision::Proxy)
        );
    }

    #[tokio::test]
    async fn conflict_results_persist_to_temp_dir() {
        let dir = temp_rules_dir("conflict-persist");
        write_lines_atomic(dir.join(DIRECT_IP_FILE), &["203.0.113.10".to_owned()]).unwrap();
        write_lines_atomic(dir.join(PROXY_IP_FILE), &["203.0.113.0/24 example.com".to_owned()]).unwrap();
        write_lines_atomic(dir.join(DIRECT_DOMAIN_FILE), &["direct.example.com".to_owned()]).unwrap();
        write_lines_atomic(dir.join(PROXY_DOMAIN_FILE), &["example.com".to_owned()]).unwrap();

        let mut config = RouteRulesConfig::default();
        config.rules_dir = dir.clone();
        config.geoip_sources.clear();
        config.proxy_domain_sources.clear();
        let state = RoutingState::load(config).await.unwrap();

        assert!(!state.ip_conflicts().await.is_empty());
        assert!(!state.domain_conflicts().await.is_empty());
        assert!(
            !read_lines(temp_file_path(&dir, TEMP_IP_CONFLICTS_FILE))
                .unwrap()
                .is_empty()
        );
        assert!(
            !read_lines(temp_file_path(&dir, TEMP_DOMAIN_CONFLICTS_FILE))
                .unwrap()
                .is_empty()
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

        let ip = "1.2.3.4".parse().unwrap();
        assert_eq!(state.dns_cache_stats().await.size, 1);
        assert_eq!(
            state.inner.read().await.reverse_domains.get(&ip).map(String::as_str),
            Some("example.com")
        );
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
        assert!(!state.inner.read().await.reverse_domains.contains_key(&ip));
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
