//! Runtime routing state for the embedded web admin.

use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    fs,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::{
        Arc, RwLock as StdRwLock,
        atomic::{AtomicBool, AtomicU64, Ordering as AtomicOrdering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use hickory_resolver::proto::{
    op::{Message, ResponseCode},
    rr::RData,
    serialize::binary::{BinDecodable, BinEncodable},
};
use ipnet::IpNet;
use log::{debug, warn};
use serde::{Deserialize, Serialize};
use shadowsocks::relay::socks5::Address;
use tokio::{
    sync::{Mutex as TokioMutex, Notify, RwLock as TokioRwLock, mpsc, oneshot},
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

// Pure helpers split into child modules; re-exported so existing call sites keep
// working unqualified. `fileio` = file IO / source download / geoip parsing;
// `rules` = rule compilation, IP/domain matching, conflict detection.
mod fileio;
mod rules;
#[allow(unused_imports)]
use fileio::*;
#[allow(unused_imports)]
use rules::*;

const DIRECT_IP_FILE: &str = "direct_ip.txt";
const DIRECT_DOMAIN_FILE: &str = "direct_domain.txt";
const PROXY_IP_FILE: &str = "proxy_ip.txt";
const PROXY_DOMAIN_FILE: &str = "proxy_domain.txt";
/// Durable accumulation of Futu-learned destination IPs/CIDRs (the special
/// record_proxy_ip SOCKS listener, e.g. port 1082). Kept in `data/` (not
/// `temp/`); periodically merged into `proxy_ip.temp` so the runtime temporary
/// proxy list catches up in batches.
const FUTU_IP_FILE: &str = "futu_ip.txt";
/// Durable accumulation of Futu-learned domain targets from the special
/// record_proxy_ip SOCKS listener. SOCKS exposes host:port rather than a full
/// URL with scheme, so entries are stored in memory and periodically flushed as
/// normalized `domain:port`.
const FUTU_URL_FILE: &str = "futu_url.txt";
const TEMP_DIRECT_IP_FILE: &str = "direct_ip.temp";
const TEMP_DIRECT_DOMAIN_FILE: &str = "direct_domain.temp";
const TEMP_PROXY_IP_FILE: &str = "proxy_ip.temp";
const TEMP_PROXY_DOMAIN_FILE: &str = "proxy_domain.temp";
const TEMP_DIR: &str = "temp";
const DNS_CACHE_FILE: &str = "dns_cache.jsonl";
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
const FUTU_RECORD_PERSIST_INTERVAL: Duration = Duration::from_secs(30);
const DNS_CACHE_REFRESH_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
const DNS_CACHE_PERSIST_CHECK_INTERVAL: Duration = Duration::from_secs(60 * 60);
const DNS_CACHE_PRUNE_INTERVAL_SECONDS: u64 = 30 * 24 * 60 * 60;
const SECONDS_PER_DAY: u64 = 24 * 60 * 60;
const SOURCE_REFRESH_INTERVAL: Duration = Duration::from_secs(7 * 24 * 60 * 60);
const NFT_INDEX_SYNC_INTERVAL: Duration = Duration::from_secs(5);
const PRIVATE_DIRECT_IP_RULES: [&str; 15] = [
    "0.0.0.0/8",
    "127.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "224.0.0.0/4",
    "240.0.0.0/4",
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceRouteDecision {
    pub decision: RouteDecision,
    pub update_route_sets: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RoutingSources {
    pub geoip_sources: Vec<String>,
    pub proxy_domain_sources: Vec<String>,
    #[serde(default)]
    pub global_proxy: bool,
    #[serde(default)]
    pub proxy_local_output: bool,
    #[serde(default)]
    pub client_global_proxy_ips: Vec<IpAddr>,
    #[serde(default)]
    pub client_direct_ips: Vec<IpAddr>,
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
            proxy_local_output: config.proxy_local_output,
            client_global_proxy_ips: config.client_global_proxy_ips.clone(),
            client_direct_ips: config.client_direct_ips.clone(),
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
    pub source_ip: Option<IpAddr>,
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
    source_ip: Option<IpAddr>,
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
    order: u64,
}

#[derive(Clone, Debug)]
struct DnsCachePersistItem {
    key: DnsCacheKey,
    entry: DnsCacheEntry,
}

#[derive(Debug, Deserialize, Serialize)]
struct PersistedDnsCacheEntry {
    domain: String,
    query_type: String,
    resolver: RouteDecision,
    results: Vec<IpAddr>,
    expires_at: u64,
    inserted_at: u64,
    refreshed_at: u64,
    order: u64,
    message: String,
}

#[derive(Debug, Default)]
struct LoadedDnsCache {
    cache: HashMap<DnsCacheKey, DnsCacheEntry>,
    expirations: BTreeMap<u64, HashSet<DnsCacheKey>>,
    next_order: u64,
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
    /// Number of keys indexed in the expiration buckets used for capacity
    /// eviction. A gap versus `dns_cache_size` would indicate index drift.
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
    direct_ip_ranges: CidrRanges,
    direct_domain: CompiledDomainRules,
    proxy_ip: Vec<IpNet>,
    proxy_ip_exact: HashSet<IpAddr>,
    proxy_ip_domainless_exact: HashSet<IpAddr>,
    proxy_ip_ranges: CidrRanges,
    proxy_domain: CompiledDomainRules,
}

#[derive(Clone, Debug, Default)]
struct CompiledDomainRules {
    raw: HashSet<String>,
    exact: HashSet<String>,
    suffix: HashSet<String>,
    match_all: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct NftRouteIndex {
    direct_ip: Vec<IpNet>,
    direct_ip_exact: HashSet<IpAddr>,
    direct_ip_ranges: CidrRanges,
    proxy_ip: Vec<IpNet>,
    proxy_ip_exact: HashSet<IpAddr>,
    proxy_ip_ranges: CidrRanges,
}

#[derive(Debug)]
struct RoutingInner {
    rules_dir: PathBuf,
    sources: RoutingSources,
    temporary_raw: RuleLists,
    persistent_raw: RuleLists,
    temporary: CompiledRules,
    persistent: CompiledRules,
    nft_route_index: NftRouteIndex,
    /// Bumped every time `nft_route_index` is authoritatively reset (the 5s
    /// firewall sync, or a temporary-rule rebuild). The DNS hot path captures
    /// this before it drops the routing lock for the (off-lock) `nft` add and
    /// re-checks it before extending the index, so a reset that raced the add
    /// discards the stale extend instead of resurrecting a phantom entry — an
    /// index IP that the live `proxy4` set no longer contains. A phantom would
    /// make `dns_results_need_sync` skip re-adding the IP forever, silently
    /// breaking redir for that destination until a manual flush.
    nft_route_index_epoch: u64,
    geoip_cn: Vec<IpNet>,
    // LPM index over `geoip_cn` for O(log n) membership on the learning hot path
    // (audit #6). Kept in sync wherever `geoip_cn` is assigned.
    geoip_cn_ranges: CidrRanges,
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
    dns_cache_expirations: BTreeMap<u64, HashSet<DnsCacheKey>>,
    dns_cache_next_order: u64,
    last_dns_cache_prune_at: u64,
    last_dns_cache_persist_at: u64,
    dns_cache_generation: u64,
    dns_cache_dirty: bool,
    proxy_ip_dirty: bool,
    proxy_ip_persist_scheduled: bool,
    futu_ip_entries: HashSet<String>,
    futu_ip_dirty: bool,
    futu_proxy_sync_dirty: bool,
    futu_ip_generation: u64,
    futu_url_entries: HashSet<String>,
    futu_url_dirty: bool,
    futu_url_generation: u64,
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
    dns_cache_persist_lock: Arc<TokioMutex<()>>,
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
                            source_ip: event.source_ip,
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
        ensure_file(config.rules_dir.join(FUTU_IP_FILE))?;
        ensure_file(config.rules_dir.join(FUTU_URL_FILE))?;
        ensure_file(temp_file_path(&config.rules_dir, TEMP_DIRECT_IP_FILE))?;
        ensure_file(temp_file_path(&config.rules_dir, TEMP_DIRECT_DOMAIN_FILE))?;
        ensure_file(temp_file_path(&config.rules_dir, TEMP_PROXY_IP_FILE))?;
        ensure_file(temp_file_path(&config.rules_dir, TEMP_PROXY_DOMAIN_FILE))?;
        let dns_cache_path = dns_cache_file_path(&config.rules_dir);
        ensure_file(&dns_cache_path)?;

        let sources = RoutingSources::from(&config);
        let loaded_dns_cache = read_dns_cache_file(&dns_cache_path, sources.dns_cache_capacity.max(1))?;
        let futu_ip_entries = read_futu_ip_entries(&config.rules_dir)?;
        let futu_url_entries = read_futu_url_entries(&config.rules_dir)?;
        let dns_cache_last_persist_at = file_modified(&dns_cache_path)?
            .and_then(system_time_unix_secs)
            .unwrap_or(0);
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
            sources,
            rules_dir: config.rules_dir,
            temporary_raw,
            persistent_raw,
            temporary,
            persistent,
            nft_route_index: NftRouteIndex::default(),
            nft_route_index_epoch: 0,
            geoip_cn_ranges: CidrRanges::build(&geoip_cn),
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
            dns_cache: loaded_dns_cache.cache,
            dns_cache_expirations: loaded_dns_cache.expirations,
            dns_cache_next_order: loaded_dns_cache.next_order,
            last_dns_cache_prune_at: 0,
            last_dns_cache_persist_at: dns_cache_last_persist_at,
            dns_cache_generation: 0,
            dns_cache_dirty: false,
            proxy_ip_dirty: false,
            proxy_ip_persist_scheduled: false,
            futu_proxy_sync_dirty: !futu_ip_entries.is_empty(),
            futu_ip_entries,
            futu_ip_dirty: false,
            futu_ip_generation: 0,
            futu_url_entries,
            futu_url_dirty: false,
            futu_url_generation: 0,
        };
        rebuild_reverse_domains_from_dns_cache(&mut inner);
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
            dns_cache_persist_lock: Arc::new(TokioMutex::new(())),
            proxy_warmup_notify: Arc::new(Notify::new()),
        };
        state.spawn_periodic_source_update();
        state.spawn_periodic_temporary_reload();
        state.spawn_periodic_dns_cache_persist();
        state.spawn_periodic_futu_record_persist();
        #[cfg(all(target_os = "linux", feature = "local-dns"))]
        state.spawn_periodic_nft_index_sync();
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
            } else {
                self.set_nft_route_index_from_nets(&direct_nets, &proxy_nets).await;
            }
        }
        // Newly added proxy domains have no IP in nft yet — ask the DNS server
        // to resolve them and pre-seed the proxy set proactively.
        self.proxy_warmup_notify.notify_one();
        Ok(())
    }

    pub async fn add_temporary_proxy_target(&self, target: &Address) -> io::Result<bool> {
        match target {
            Address::SocketAddress(socket_addr) => self.add_temporary_proxy_ip(socket_addr.ip()).await,
            Address::DomainNameAddress(domain, port) => self.add_futu_proxy_url(domain, *port).await,
        }
    }

    async fn add_futu_proxy_url(&self, domain: &str, port: u16) -> io::Result<bool> {
        let Some(entry) = format_futu_url_entry(domain, port) else {
            return Ok(false);
        };
        let mut inner = self.inner.write().await;
        if !inner.futu_url_entries.insert(entry) {
            return Ok(false);
        }
        inner.futu_url_dirty = true;
        inner.futu_url_generation = inner.futu_url_generation.wrapping_add(1);
        Ok(true)
    }

    pub async fn add_temporary_proxy_ip(&self, ip: IpAddr) -> io::Result<bool> {
        if is_fixed_direct_ip(&ip) {
            return Ok(false);
        }

        let Some(entry) = format_futu_ip_entry(ip) else {
            return Ok(false);
        };
        let mut inner = self.inner.write().await;
        if !inner.futu_ip_entries.insert(entry) {
            return Ok(false);
        }
        inner.futu_ip_dirty = true;
        inner.futu_proxy_sync_dirty = true;
        inner.futu_ip_generation = inner.futu_ip_generation.wrapping_add(1);
        Ok(true)
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
            } else {
                self.set_nft_route_index_from_nets(&direct_nets, &proxy_nets).await;
            }
        }
        self.proxy_warmup_notify.notify_one();
        Ok(temporary)
    }

    pub async fn route_ip(&self, ip: &IpAddr) -> Option<RouteDecision> {
        let inner = self.inner.read().await;
        route_ip_inner(&inner, ip)
    }

    pub async fn route_domain(&self, domain: &str) -> Option<RouteDecision> {
        let inner = self.inner.read().await;
        route_domain_inner(&inner, domain)
    }

    /// Resolver decision for a DNS query, honoring per-source overrides.
    ///
    /// A forced-direct source IP must ALWAYS resolve via the DOMESTIC resolver
    /// (`RouteDecision::Direct`), regardless of `proxy_domain` membership or
    /// `global_proxy`: its data-plane traffic is forced direct at the firewall
    /// (`saddr @client_direct … return`), so handing it foreign/proxy-only IPs
    /// — which it would then try to reach directly — is exactly the geo-split
    /// mismatch req 2.3 exists to prevent.
    ///
    /// A forced-proxy source IP must resolve via the FOREIGN resolver when the
    /// global proxy is not already enabled. Its data-plane traffic is forced
    /// into redir/tproxy by source IP, so DNS must make the same decision even
    /// when the domain is unknown or listed as direct.
    pub async fn route_domain_for_source(&self, domain: &str, source_ip: Option<IpAddr>) -> Option<RouteDecision> {
        self.route_domain_for_source_detail(domain, source_ip)
            .await
            .map(|route| route.decision)
    }

    pub async fn route_domain_for_source_detail(
        &self,
        domain: &str,
        source_ip: Option<IpAddr>,
    ) -> Option<SourceRouteDecision> {
        let inner = self.inner.read().await;
        Self::route_domain_for_source_inner(&inner, domain, source_ip)
    }

    fn route_domain_for_source_inner(
        inner: &RoutingInner,
        domain: &str,
        source_ip: Option<IpAddr>,
    ) -> Option<SourceRouteDecision> {
        let base_decision = route_domain_inner(inner, domain);
        if let Some(ip) = source_ip
            && inner.sources.client_direct_ips.contains(&ip)
        {
            return Some(SourceRouteDecision {
                decision: RouteDecision::Direct,
                update_route_sets: base_decision == Some(RouteDecision::Direct),
            });
        }
        if let Some(ip) = source_ip
            && !inner.sources.global_proxy
            && inner.sources.client_global_proxy_ips.contains(&ip)
        {
            return Some(SourceRouteDecision {
                decision: RouteDecision::Proxy,
                update_route_sets: base_decision == Some(RouteDecision::Proxy),
            });
        }
        base_decision.map(|decision| SourceRouteDecision {
            decision,
            update_route_sets: true,
        })
    }

    /// Whether `source_ip` is configured as a forced-direct client (req 2.3).
    /// Such a client's traffic must bypass the proxy even on the explicit
    /// SOCKS/HTTP entry points (the transparent redir/tproxy path already
    /// enforces this in the kernel via the `saddr @client_direct … return`
    /// rule). Tiny linear scan over the (usually 0–3 entry) list.
    pub async fn source_is_forced_direct(&self, source_ip: IpAddr) -> bool {
        self.inner.read().await.sources.client_direct_ips.contains(&source_ip)
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
        let (nft_ips, global_proxy, index_epoch) = {
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
            let mut new_proxy_ips = Vec::new();
            for ip in results {
                match decision {
                    RouteDecision::Direct => {
                        if direct_dns_result_needs_nft_sync(&inner, ip, global_proxy)
                            && !nft_route_index_matches(&inner.nft_route_index, RouteDecision::Direct, ip)
                        {
                            nft_ips.push(*ip);
                        }
                    }
                    RouteDecision::Proxy => {
                        let target_exists = compiled_rules_match_ip_indexed(
                            &inner.persistent.proxy_ip_exact,
                            &inner.persistent.proxy_ip_ranges,
                            ip,
                        );
                        if proxy_dns_result_needs_nft_sync(&inner, ip)
                            && !nft_route_index_matches(&inner.nft_route_index, RouteDecision::Proxy, ip)
                        {
                            nft_ips.push(*ip);
                        }
                        let line = format_proxy_ip_domain_line(ip, domain);
                        if target_exists {
                            if inner.persistent.proxy_ip_domainless_exact.contains(ip)
                                && let Some(idx) = inner
                                    .persistent_raw
                                    .proxy_ip
                                    .iter()
                                    .position(|rule| proxy_ip_line_exact_matches_ip(rule, ip))
                            {
                                if proxy_ip_line_domain(&inner.persistent_raw.proxy_ip[idx]).is_none() {
                                    inner.persistent_raw.proxy_ip[idx] = line;
                                    proxy_changed = true;
                                    inner.proxy_ip_dirty = true;
                                    inner.persistent.proxy_ip_domainless_exact.remove(ip);
                                    if !inner.proxy_ip_persist_scheduled {
                                        inner.proxy_ip_persist_scheduled = true;
                                        schedule_proxy_persist = true;
                                    }
                                }
                            }
                        } else {
                            lines.push(line);
                            proxy_changed = true;
                            inner.persistent.proxy_ip_exact.insert(*ip);
                            new_proxy_ips.push(*ip);
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
            // PERF: index conflicts only for the IPs newly learned in THIS call,
            // instead of re-running the full O(proxy_set × geoip) sweep that
            // rebuild_ip_conflicts performs. Pre-existing conflicts come from the
            // rule files (computed on load / file change); add_dns_results only
            // ever appends proxy IPs, so an incremental check stays correct and
            // keeps the routing write lock off the geoip-sized sweep + file write
            // on the DNS hot path (audit PERF-2 / H-4).
            index_new_proxy_ip_conflicts(&mut inner, &new_proxy_ips);
            // Capture the index epoch under the same lock that selected `nft_ips`.
            // If an authoritative reset bumps it before we re-acquire the lock to
            // record the index extend, that extend is discarded (see
            // `add_nft_route_index_ips`).
            let index_epoch = inner.nft_route_index_epoch;
            (nft_ips, global_proxy, index_epoch)
        };
        if !nft_ips.is_empty() {
            // Per-resolution diagnostic on the DNS hot path — debug, not warn,
            // so normal learning does not spam the log (audit low).
            debug!(
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
                match decision {
                    RouteDecision::Direct if global_proxy => {
                        crate::local::dns::intercept_linux::add_route_ips(RouteDecision::Direct, &additions_for_nft)
                    }
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
            } else {
                Self::schedule_conntrack_flush(nft_ips.clone());
                let index_decision = match decision {
                    RouteDecision::Direct if global_proxy => Some(RouteDecision::Direct),
                    RouteDecision::Proxy => Some(RouteDecision::Proxy),
                    RouteDecision::Direct => None,
                };
                if let Some(index_decision) = index_decision {
                    self.add_nft_route_index_ips(index_decision, &nft_ips, index_epoch).await;
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

    pub async fn dns_results_need_sync(&self, decision: RouteDecision, results: &[IpAddr]) -> bool {
        if results.is_empty() {
            return false;
        }
        let inner = self.inner.read().await;
        let global_proxy = inner.sources.global_proxy;
        if global_proxy && matches!(decision, RouteDecision::Proxy) {
            return false;
        }
        results.iter().any(|ip| match decision {
            RouteDecision::Direct => {
                direct_dns_result_needs_nft_sync(&inner, ip, global_proxy)
                    && !nft_route_index_matches(&inner.nft_route_index, RouteDecision::Direct, ip)
            }
            RouteDecision::Proxy => {
                if proxy_dns_result_needs_nft_sync(&inner, ip)
                    && !nft_route_index_matches(&inner.nft_route_index, RouteDecision::Proxy, ip)
                {
                    return true;
                }
                if !compiled_rules_match_ip_indexed(
                    &inner.persistent.proxy_ip_exact,
                    &inner.persistent.proxy_ip_ranges,
                    ip,
                ) {
                    return true;
                }
                inner.persistent.proxy_ip_domainless_exact.contains(ip)
            }
        })
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

    async fn persist_dns_cache_now(&self) -> io::Result<bool> {
        let _guard = self.dns_cache_persist_lock.lock().await;
        let now_ts = now();
        let (path, generation, rows) = {
            let inner = self.inner.read().await;
            (
                dns_cache_file_path(&inner.rules_dir),
                inner.dns_cache_generation,
                dns_cache_persist_items(&inner, now_ts),
            )
        };

        tokio::task::spawn_blocking(move || write_dns_cache_file(&path, rows))
            .await
            .map_err(|err| io::Error::other(format!("dns cache persist join error: {err}")))??;

        let mut inner = self.inner.write().await;
        inner.last_dns_cache_persist_at = now_ts;
        if inner.dns_cache_generation == generation {
            inner.dns_cache_dirty = false;
        }
        Ok(true)
    }

    async fn persist_dns_cache_if_due(&self) -> io::Result<bool> {
        let now_ts = now();
        {
            let inner = self.inner.read().await;
            if !inner.dns_cache_dirty || !dns_cache_persist_is_due(inner.last_dns_cache_persist_at, now_ts) {
                return Ok(false);
            }
        }
        self.persist_dns_cache_now().await
    }

    pub async fn materialize_proxy_dns_cache_to_proxy_ip(&self) -> io::Result<usize> {
        let (path, lines, added) = {
            let mut inner = self.inner.write().await;
            let now = now();

            let mut candidates = Vec::new();
            for (key, entry) in &inner.dns_cache {
                if key.resolver != RouteDecision::Proxy || key.domain.is_empty() || entry.expires_at <= now {
                    continue;
                }
                for ip in &entry.results {
                    candidates.push((*ip, key.domain.clone()));
                }
            }
            candidates.sort_unstable();
            candidates.dedup_by_key(|(ip, _)| *ip);

            let mut added = 0;
            for (ip, domain) in candidates {
                if is_fixed_direct_ip(&ip) || dns_proxy_ip_blocked_from_nft_by_direct_rule(&inner, &ip) {
                    continue;
                }

                let line = format_proxy_ip_domain_line(&ip, &domain);
                let mut changed = false;
                let target_exists = compiled_rules_match_ip_indexed(
                    &inner.persistent.proxy_ip_exact,
                    &inner.persistent.proxy_ip_ranges,
                    &ip,
                );
                if target_exists {
                    if inner.persistent.proxy_ip_domainless_exact.contains(&ip)
                        && let Some(idx) = inner
                            .persistent_raw
                            .proxy_ip
                            .iter()
                            .position(|rule| proxy_ip_line_exact_matches_ip(rule, &ip))
                    {
                        if proxy_ip_line_domain(&inner.persistent_raw.proxy_ip[idx]).is_none() {
                            inner.persistent_raw.proxy_ip[idx] = line;
                            inner.persistent.proxy_ip_domainless_exact.remove(&ip);
                            changed = true;
                        }
                    }
                } else {
                    inner.persistent_raw.proxy_ip.push(line);
                    inner.persistent.proxy_ip_exact.insert(ip);
                    added += 1;
                    changed = true;
                }

                if changed {
                    inner.proxy_ip_dirty = true;
                }
            }

            if !inner.proxy_ip_dirty {
                inner.proxy_ip_dirty = false;
                inner.proxy_ip_persist_scheduled = false;
                return Ok(0);
            }

            rebuild_ip_conflicts(&mut inner);
            inner.proxy_ip_dirty = false;
            inner.proxy_ip_persist_scheduled = false;
            (
                inner.rules_dir.join(PROXY_IP_FILE),
                normalize_proxy_ip_lines(inner.persistent_raw.proxy_ip.clone()),
                added,
            )
        };

        tokio::task::spawn_blocking(move || write_lines_atomic(path, &lines))
            .await
            .map_err(|err| io::Error::other(format!("proxy dns cache materialize join error: {err}")))??;
        Ok(added)
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

    fn spawn_periodic_dns_cache_persist(&self) {
        let state = self.clone();
        tokio::spawn(async move {
            let mut interval = time::interval(DNS_CACHE_PERSIST_CHECK_INTERVAL);
            interval.tick().await;
            loop {
                interval.tick().await;
                if let Err(err) = state.persist_dns_cache_if_due().await {
                    warn!("failed to persist DNS cache: {}", err);
                }
            }
        });
    }

    fn spawn_periodic_futu_record_persist(&self) {
        let state = self.clone();
        tokio::spawn(async move {
            let mut interval = time::interval(FUTU_RECORD_PERSIST_INTERVAL);
            interval.tick().await;
            loop {
                interval.tick().await;
                if let Err(err) = state.persist_futu_records_now().await {
                    warn!("failed to persist Futu record files: {}", err);
                }
            }
        });
    }

    async fn persist_futu_records_now(&self) -> io::Result<bool> {
        let (
            rules_dir,
            futu_ip_rows,
            futu_ip_dirty,
            futu_proxy_sync_dirty,
            futu_ip_generation,
            futu_url_rows,
            futu_url_generation,
        ) = {
            let inner = self.inner.read().await;
            if !inner.futu_ip_dirty && !inner.futu_proxy_sync_dirty && !inner.futu_url_dirty {
                return Ok(false);
            }
            let mut futu_ip_rows = inner.futu_ip_entries.iter().cloned().collect::<Vec<_>>();
            futu_ip_rows.sort_unstable();
            let futu_url_rows = if inner.futu_url_dirty {
                let mut rows = inner.futu_url_entries.iter().cloned().collect::<Vec<_>>();
                rows.sort_unstable();
                Some(rows)
            } else {
                None
            };
            (
                inner.rules_dir.clone(),
                futu_ip_rows,
                inner.futu_ip_dirty,
                inner.futu_proxy_sync_dirty,
                inner.futu_ip_generation,
                futu_url_rows,
                inner.futu_url_generation,
            )
        };

        let write_futu_url = futu_url_rows.is_some();
        tokio::task::spawn_blocking(move || -> io::Result<()> {
            if futu_ip_dirty {
                write_futu_ip_file(&rules_dir, &futu_ip_rows)?;
            }
            if futu_proxy_sync_dirty {
                merge_futu_ip_into_proxy_temp(&rules_dir, &futu_ip_rows)?;
            }
            if let Some(rows) = futu_url_rows {
                write_futu_url_file(&rules_dir, &rows)?;
            }
            Ok(())
        })
        .await
        .map_err(|err| io::Error::other(format!("futu record persist task failed: {err}")))??;

        let mut inner = self.inner.write().await;
        if futu_ip_dirty && inner.futu_ip_generation == futu_ip_generation {
            inner.futu_ip_dirty = false;
        }
        if futu_proxy_sync_dirty && inner.futu_ip_generation == futu_ip_generation {
            inner.futu_proxy_sync_dirty = false;
        }
        if write_futu_url && inner.futu_url_generation == futu_url_generation {
            inner.futu_url_dirty = false;
        }
        Ok(true)
    }

    #[cfg(all(target_os = "linux", feature = "local-dns"))]
    fn spawn_periodic_nft_index_sync(&self) {
        let state = self.clone();
        tokio::spawn(async move {
            let mut interval = time::interval(NFT_INDEX_SYNC_INTERVAL);
            // If a reconcile (full `nft list table` dump + parse) ever takes
            // longer than the 5s period, don't fire a burst of catch-up ticks —
            // just resume on the next interval (audit info).
            interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
            interval.tick().await;
            loop {
                interval.tick().await;
                if !state.nft_index_sync_enabled().await {
                    continue;
                }
                if let Err(err) = state.refresh_nft_route_index_from_firewall().await {
                    warn!("failed to refresh nft route index: {}", err);
                }
            }
        });
    }

    #[cfg(all(target_os = "linux", feature = "local-dns"))]
    async fn nft_index_sync_enabled(&self) -> bool {
        let mode = self.inner.read().await.sources.dns_intercept_mode.clone();
        matches!(mode.as_str(), "firewall" | "both")
    }

    #[cfg(all(target_os = "linux", feature = "local-dns"))]
    async fn refresh_nft_route_index_from_firewall(&self) -> io::Result<()> {
        let snapshot = tokio::task::spawn_blocking(crate::local::dns::intercept_linux::route_set_snapshot)
            .await
            .map_err(|err| io::Error::other(format!("nft index sync join error: {err}")))??;
        let index = nft_route_index_from_nets(&snapshot.direct, &snapshot.proxy);
        let mut inner = self.inner.write().await;
        if inner.nft_route_index != index {
            inner.nft_route_index = index;
            inner.nft_route_index_epoch = inner.nft_route_index_epoch.wrapping_add(1);
        }
        Ok(())
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
        inner.geoip_cn_ranges = CidrRanges::build(&inner.geoip_cn);
        inner.geoip_modified = file_modified(&inner.rules_dir.join(SOURCE_DIR).join("geoip.dat"))?;
        inner.direct_ip_modified = file_modified(&inner.rules_dir.join(DIRECT_IP_FILE))?;
        inner.proxy_ip_modified = file_modified(&inner.rules_dir.join(PROXY_IP_FILE))?;
        inner.direct_domain_modified = file_modified(&inner.rules_dir.join(DIRECT_DOMAIN_FILE))?;
        inner.proxy_domain_modified = file_modified(&inner.rules_dir.join(PROXY_DOMAIN_FILE))?;
        rebuild_conflicts(&mut inner);
        drop(inner);
        // Push the freshly-rebuilt persistent direct/proxy IP rules into the nft
        // sets. update_from_sources() runs on the weekly timer (and ad-hoc) with
        // NO service restart, so without this the kernel sets would keep serving
        // the baseline captured at the last startup/web-admin restart — silently
        // ignoring proxy_ip additions and direct_ip removals (req 1.2 / 1.7).
        #[cfg(all(target_os = "linux", feature = "local-dns"))]
        if let Err(err) = self.sync_persistent_ip_rules_to_firewall().await {
            warn!("failed to re-sync nft sets after route source update: {}", err);
        }
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
        let (rules_dir, direct, proxy, conntrack_flush_ips) = {
            let inner = self.inner.read().await;
            let (rules_dir, direct, proxy) = persistent_nft_route_nets(&inner);
            let conntrack_flush_ips = proxy_conntrack_flush_ips(&inner);
            (rules_dir, direct, proxy, conntrack_flush_ips)
        };
        crate::local::dns::intercept_linux::replace_route_nets(&rules_dir, &direct, &proxy)?;
        self.set_nft_route_index_from_nets(&direct, &proxy).await;
        if !conntrack_flush_ips.is_empty() {
            log::info!(
                "flushing conntrack for {} persisted proxy IPs after firewall sync",
                conntrack_flush_ips.len()
            );
            crate::local::dns::intercept_linux::flush_conntrack_dst(&conntrack_flush_ips);
        }
        Ok(())
    }

    #[cfg(all(target_os = "linux", feature = "local-dns"))]
    async fn set_nft_route_index_from_nets(&self, direct: &[IpNet], proxy: &[IpNet]) {
        let mut inner = self.inner.write().await;
        inner.nft_route_index = nft_route_index_from_nets(direct, proxy);
        inner.nft_route_index_epoch = inner.nft_route_index_epoch.wrapping_add(1);
    }

    /// Extend the in-memory index after a successful (off-lock) `nft` add.
    /// `expected_epoch` is the index epoch captured while the IPs were selected;
    /// if it no longer matches, an authoritative reset (5s sync or rule rebuild)
    /// ran while our `nft` add was in flight, so the extend is dropped — adding
    /// these IPs now could record an entry the live `proxy4` set no longer has.
    /// The next resolution (or the 5s sync) reconciles correctly.
    async fn add_nft_route_index_ips(&self, decision: RouteDecision, ips: &[IpAddr], expected_epoch: u64) {
        if ips.is_empty() {
            return;
        }
        let mut inner = self.inner.write().await;
        if inner.nft_route_index_epoch != expected_epoch {
            debug!(
                "dropping raced nft index extend ({:?}, {} ips): epoch {} -> {}",
                decision,
                ips.len(),
                expected_epoch,
                inner.nft_route_index_epoch
            );
            return;
        }
        match decision {
            RouteDecision::Direct => inner.nft_route_index.direct_ip_exact.extend(ips.iter().copied()),
            RouteDecision::Proxy => inner.nft_route_index.proxy_ip_exact.extend(ips.iter().copied()),
        }
    }

    #[cfg(all(target_os = "linux", feature = "local-dns"))]
    fn schedule_conntrack_flush(ips: Vec<IpAddr>) {
        if ips.is_empty() {
            return;
        }
        tokio::task::spawn_blocking(move || {
            crate::local::dns::intercept_linux::flush_conntrack_dst(&ips);
        });
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
        source_ip: Option<IpAddr>,
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
                source_ip,
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
        source_ip: Option<IpAddr>,
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
                source_ip,
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
        let inner = self.inner.read().await;
        let key = dns_cache_key(domain, query_type, resolver);
        let now = now();
        inner
            .dns_cache
            .get(&key)
            .filter(|entry| entry.expires_at > now)
            .map(|entry| entry.message.clone())
    }

    pub async fn dns_cache_lookup_any(&self, domain: &str, query_type: &str) -> Option<(Message, RouteDecision)> {
        let inner = self.inner.read().await;
        let now = now();
        for resolver in [RouteDecision::Proxy, RouteDecision::Direct] {
            let key = dns_cache_key(domain, query_type, resolver);
            if let Some(entry) = inner.dns_cache.get(&key)
                && entry.expires_at > now
            {
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
        if !dns_cache_message_is_cacheable(query_type, &message, &results) {
            return;
        }
        let mut inner = self.inner.write().await;
        let key = dns_cache_key(domain, query_type, resolver);
        let now = now();
        let ttl = inner.sources.dns_cache_ttl_seconds.max(1);
        if !key.domain.is_empty() {
            for ip in &results {
                inner.reverse_domains.insert(*ip, key.domain.clone());
            }
        }
        if let Some(expires_at) = inner.dns_cache.get(&key).map(|entry| entry.expires_at) {
            remove_dns_cache_expiration(&mut inner, &key, expires_at);
        }
        let order = inner
            .dns_cache
            .get(&key)
            .map(|entry| entry.order)
            .unwrap_or_else(|| {
                let order = inner.dns_cache_next_order;
                inner.dns_cache_next_order = inner.dns_cache_next_order.wrapping_add(1);
                order
            });
        let expires_at = now.saturating_add(ttl);
        inner.dns_cache.insert(
            key.clone(),
            DnsCacheEntry {
                message,
                results,
                expires_at,
                inserted_at: now,
                refreshed_at: now,
                order,
            },
        );
        insert_dns_cache_expiration(&mut inner, key, expires_at);
        maybe_prune_dns_cache_for_capacity(&mut inner);
        enforce_dns_cache_capacity(&mut inner);
        mark_dns_cache_dirty(&mut inner);
    }

    pub async fn dns_cache_refresh_candidates(&self, resolver: RouteDecision) -> Vec<DnsCacheRefreshCandidate> {
        let inner = self.inner.read().await;
        if !inner.sources.dns_cache_refresh_enabled {
            return Vec::new();
        }
        let now_ts = now();
        let cutoff = now_ts.saturating_sub(DNS_CACHE_REFRESH_INTERVAL.as_secs());
        let batch_size = inner.sources.dns_cache_refresh_batch_size.max(1);
        inner
            .dns_cache
            .iter()
            .filter(|(key, entry)| {
                key.resolver == resolver && entry.expires_at > now_ts && entry.refreshed_at <= cutoff
            })
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
        if !dns_cache_message_is_cacheable(query_type, &message, &results) {
            return false;
        }
        let mut inner = self.inner.write().await;
        let key = dns_cache_key(domain, query_type, resolver);
        if let Some(entry) = inner.dns_cache.get_mut(&key) {
            if entry.expires_at <= now() {
                return false;
            }
            entry.message = message;
            entry.results = results;
            entry.refreshed_at = now();
            mark_dns_cache_dirty(&mut inner);
            true
        } else {
            false
        }
    }

    pub async fn dns_cache_stats(&self) -> DnsCacheStats {
        let inner = self.inner.read().await;
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
    /// sizes only — including the expiration-bucket entry count so index drift
    /// is visible directly in the log.
    pub async fn runtime_diagnostics(&self) -> RuntimeDiagnostics {
        let inner = self.inner.read().await;
        let (prune_calls, prune_ns, nft_calls, nft_ns, append_calls, append_ns, add_calls, add_ns) =
            hot_path_counters();
        RuntimeDiagnostics {
            dns_cache_size: inner.dns_cache.len(),
            dns_cache_order_len: dns_cache_expiration_entries(&inner),
            dns_cache_capacity: inner.sources.dns_cache_capacity,
            dns_cache_ttl_seconds: inner.sources.dns_cache_ttl_seconds,
            dns_events: inner.dns.len(),
            connections: inner.connections.len(),
            flow_decisions: inner.flow_decisions.len(),
            reverse_domains: inner.reverse_domains.len(),
            persistent_direct_ip: compiled_rule_net_count(&inner.persistent.direct_ip_exact, &inner.persistent.direct_ip),
            persistent_proxy_ip: compiled_rule_net_count(&inner.persistent.proxy_ip_exact, &inner.persistent.proxy_ip),
            temporary_direct_ip: compiled_rule_net_count(&inner.temporary.direct_ip_exact, &inner.temporary.direct_ip),
            temporary_proxy_ip: compiled_rule_net_count(&inner.temporary.proxy_ip_exact, &inner.temporary.proxy_ip),
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
        let inner = self.inner.read().await;
        let domain = normalize_dns_domain(domain);
        let now = now();
        let mut rows = inner
            .dns_cache
            .iter()
            .filter(|(key, entry)| key.domain == domain && entry.expires_at > now)
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
        let inner = self.inner.read().await;
        let now = now();
        let mut rows = inner
            .dns_cache
            .iter()
            .filter(|(_, entry)| entry.expires_at > now && entry.results.iter().any(|result| *result == ip))
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
        let (cleared, should_persist) = {
            let mut inner = self.inner.write().await;
            let before = inner.dns_cache.len();
            if let Some(domain) = domain {
                let domain = normalize_dns_domain(domain);
                inner.dns_cache.retain(|key, _| key.domain != domain);
                rebuild_dns_cache_expirations(&mut inner);
            } else {
                inner.dns_cache.clear();
                inner.dns_cache_expirations.clear();
            }
            rebuild_reverse_domains_from_dns_cache(&mut inner);
            let cleared = before.saturating_sub(inner.dns_cache.len());
            let should_persist = domain.is_none() || cleared > 0;
            if should_persist {
                mark_dns_cache_dirty(&mut inner);
            }
            (cleared, should_persist)
        };
        if should_persist && let Err(err) = self.persist_dns_cache_now().await {
            warn!("failed to persist DNS cache after clear: {}", err);
        }
        cleared
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

    pub async fn recent_connections(
        &self,
        excluded_remotes: &HashSet<IpAddr>,
        source_filter: Option<IpAddr>,
    ) -> Vec<ConnectionEvent> {
        self.stop_expired_activity_recording().await;
        if !self.record_control.recording.load(AtomicOrdering::Relaxed) {
            return Vec::new();
        }
        let inner = self.inner.read().await;
        let reverse_domains = build_reverse_domain_map(&inner);
        let flow_decisions = inner.flow_decisions.clone();
        let system_connection_baseline = inner.system_connection_baseline.clone();
        let global_proxy = inner.sources.global_proxy;
        let proxy_local_output = inner.sources.proxy_local_output;
        let client_global_proxy_ips = inner
            .sources
            .client_global_proxy_ips
            .iter()
            .copied()
            .collect::<HashSet<_>>();
        let client_direct_ips = inner
            .sources
            .client_direct_ips
            .iter()
            .copied()
            .collect::<HashSet<_>>();
        let mut rows = inner
            .connections
            .iter()
            .rev()
            .filter(|event| source_filter.is_none_or(|ip| event.source_ip == ip))
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
                if source_filter.is_some_and(|ip| event.source_ip != ip) {
                    continue;
                }
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
            if source_filter.is_some_and(|ip| event.source_ip != ip) {
                continue;
            }
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
                } else if client_direct_ips.contains(&event.source_ip) {
                    event.decision = ConnectionDecision::Direct;
                } else if proxy_local_output
                    && (global_proxy || client_global_proxy_ips.contains(&event.source_ip))
                    && system_connection_should_be_redir(&event)
                {
                    event.decision = ConnectionDecision::Redir;
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

    pub async fn recent_dns(&self, source_filter: Option<IpAddr>) -> Vec<DnsEvent> {
        self.stop_expired_activity_recording().await;
        if !self.record_control.recording.load(AtomicOrdering::Relaxed) {
            return Vec::new();
        }
        let inner = self.inner.read().await;
        inner
            .dns
            .iter()
            .rev()
            .filter(|event| source_filter.is_none_or(|ip| event.source_ip == Some(ip)))
            .cloned()
            .collect()
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

fn route_ip_inner(inner: &RoutingInner, ip: &IpAddr) -> Option<RouteDecision> {
    if inner.sources.global_proxy {
        return Some(if is_fixed_direct_ip(ip) {
            RouteDecision::Direct
        } else {
            RouteDecision::Proxy
        });
    }

    let temp_direct =
        compiled_rules_match_ip_indexed(&inner.temporary.direct_ip_exact, &inner.temporary.direct_ip_ranges, ip);
    let temp_proxy =
        compiled_rules_match_ip_indexed(&inner.temporary.proxy_ip_exact, &inner.temporary.proxy_ip_ranges, ip);
    if temp_direct && temp_proxy {
        return Some(RouteDecision::Direct);
    }
    if temp_direct {
        return Some(RouteDecision::Direct);
    }
    if temp_proxy {
        return Some(RouteDecision::Proxy);
    }

    let direct =
        compiled_rules_match_ip_indexed(&inner.persistent.direct_ip_exact, &inner.persistent.direct_ip_ranges, ip);
    let proxy =
        compiled_rules_match_ip_indexed(&inner.persistent.proxy_ip_exact, &inner.persistent.proxy_ip_ranges, ip);
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

fn route_domain_inner(inner: &RoutingInner, domain: &str) -> Option<RouteDecision> {
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
        inner.geoip_cn_ranges = CidrRanges::build(&inner.geoip_cn);
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
    let direct_ip = compiled_rule_nets_for_nft(&inner.persistent.direct_ip_exact, &inner.persistent.direct_ip);
    let proxy_ip = compiled_rule_nets_for_nft(&inner.persistent.proxy_ip_exact, &inner.persistent.proxy_ip);
    for rule in ip_net_conflicts(&direct_ip, &proxy_ip) {
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

    for rule in ip_net_conflicts(&inner.geoip_cn, &proxy_ip) {
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

/// Incremental counterpart to [`rebuild_ip_conflicts`] for the DNS learning hot
/// path: only tests the freshly learned proxy IPs against the direct and
/// geoip-CN sets and appends any conflicts, rather than clearing and re-sweeping
/// the entire proxy set (which on a populated gateway is thousands of CN CIDRs
/// re-sorted under the routing write lock per result — audit PERF-2). Does NOT
/// persist the conflict file here; it is rewritten on the next rule-file change.
fn index_new_proxy_ip_conflicts(inner: &mut RoutingInner, new_proxy_ips: &[IpAddr]) {
    for ip in new_proxy_ips {
        let value = ip.to_string();
        if compiled_rules_match_ip_indexed(&inner.persistent.direct_ip_exact, &inner.persistent.direct_ip_ranges, ip) {
            push_ip_conflict_if_absent(
                &mut inner.ip_conflicts,
                &value,
                vec!["direct".to_owned(), "proxy".to_owned()],
                vec![DIRECT_IP_FILE.to_owned(), PROXY_IP_FILE.to_owned()],
            );
        }
        // #6: O(log n) membership over the ~thousands of CN CIDRs instead of a
        // linear scan, on the per-learned-IP path. (Equivalent to
        // rules_match_ip(&inner.geoip_cn, ip); see CidrRanges property test.)
        if inner.geoip_cn_ranges.contains(ip) {
            push_ip_conflict_if_absent(
                &mut inner.ip_conflicts,
                &value,
                vec!["cn".to_owned(), "proxy".to_owned()],
                vec!["geoip.dat".to_owned(), PROXY_IP_FILE.to_owned()],
            );
        }
    }
}

fn push_ip_conflict_if_absent(
    events: &mut VecDeque<ConflictEvent>,
    value: &str,
    regions: Vec<String>,
    sources: Vec<String>,
) {
    if events.iter().any(|e| e.value == value && e.regions == regions) {
        return;
    }
    push_event(
        events,
        new_conflict_event_with_metadata(ConflictKind::Ip, value.to_owned(), regions, sources),
    );
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

fn system_connection_should_be_redir(event: &ConnectionEvent) -> bool {
    if event.destination_port == 53 {
        return false;
    }
    let Some(destination_ip) = event.destination_ip else {
        return false;
    };
    matches!(event.protocol.as_str(), "tcp" | "udp") && !is_fixed_direct_ip(&destination_ip)
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
        compiled_rule_nets_for_nft(&inner.persistent.direct_ip_exact, &inner.persistent.direct_ip)
    };
    if !inner.sources.global_proxy {
        direct.extend(compiled_rule_nets_for_nft(
            &inner.temporary.direct_ip_exact,
            &inner.temporary.direct_ip,
        ));
    }
    let mut proxy = compiled_rule_nets_for_nft(&inner.persistent.proxy_ip_exact, &inner.persistent.proxy_ip);
    proxy.extend(compiled_rule_nets_for_nft(
        &inner.temporary.proxy_ip_exact,
        &inner.temporary.proxy_ip,
    ));
    proxy.retain(|net| !direct.iter().any(|direct| ip_nets_overlap(direct, net)));
    (inner.rules_dir.clone(), direct, proxy)
}

#[cfg(all(target_os = "linux", feature = "local-dns"))]
fn proxy_conntrack_flush_ips(inner: &RoutingInner) -> Vec<IpAddr> {
    let mut ips: Vec<IpAddr> = inner
        .persistent
        .proxy_ip_exact
        .iter()
        .chain(inner.temporary.proxy_ip_exact.iter())
        .copied()
        .filter(|ip| !is_fixed_direct_ip(ip) && !dns_proxy_ip_blocked_from_nft_by_direct_rule(inner, ip))
        .collect();
    ips.sort_unstable();
    ips.dedup();
    ips
}

fn dns_proxy_ip_blocked_from_nft_by_direct_rule(inner: &RoutingInner, ip: &IpAddr) -> bool {
    compiled_rules_match_ip_indexed(&inner.persistent.direct_ip_exact, &inner.persistent.direct_ip_ranges, ip)
        || compiled_rules_match_ip_indexed(&inner.temporary.direct_ip_exact, &inner.temporary.direct_ip_ranges, ip)
}

fn proxy_dns_result_needs_nft_sync(inner: &RoutingInner, ip: &IpAddr) -> bool {
    !dns_proxy_ip_blocked_from_nft_by_direct_rule(inner, ip)
}

fn direct_dns_result_needs_nft_sync(_inner: &RoutingInner, _ip: &IpAddr, global_proxy: bool) -> bool {
    global_proxy
}

#[cfg(all(target_os = "linux", feature = "local-dns"))]
fn temporary_nft_route_nets(inner: &RoutingInner, rules: &RuleLists) -> (PathBuf, Vec<IpNet>, Vec<IpNet>) {
    let mut direct = if inner.sources.global_proxy {
        fixed_direct_nets()
    } else {
        compiled_rule_nets_for_nft(&inner.persistent.direct_ip_exact, &inner.persistent.direct_ip)
    };
    if !inner.sources.global_proxy {
        let (direct_cidrs, direct_exact, _) = compile_ip_rules(&rules.direct_ip, false);
        direct.extend(compiled_rule_nets_for_nft(&direct_exact, &direct_cidrs));
    }
    let mut proxy = compiled_rule_nets_for_nft(&inner.persistent.proxy_ip_exact, &inner.persistent.proxy_ip);
    let (proxy_cidrs, proxy_exact, _) = compile_ip_rules(&rules.proxy_ip, false);
    proxy.extend(compiled_rule_nets_for_nft(&proxy_exact, &proxy_cidrs));
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

fn dns_cache_file_path(dir: &Path) -> PathBuf {
    temp_file_path(dir, DNS_CACHE_FILE)
}

fn dns_cache_key(domain: &str, query_type: &str, resolver: RouteDecision) -> DnsCacheKey {
    DnsCacheKey {
        domain: normalize_dns_domain(domain),
        query_type: query_type.to_ascii_uppercase(),
        resolver,
    }
}

fn dns_cache_message_is_cacheable(query_type: &str, message: &Message, results: &[IpAddr]) -> bool {
    message.metadata.response_code == ResponseCode::NoError
        && (!results.is_empty() || dns_cache_message_has_service_binding_answers(query_type, message))
}

fn dns_cache_message_has_service_binding_answers(query_type: &str, message: &Message) -> bool {
    let query_type = query_type.to_ascii_uppercase();
    message.answers.iter().any(|record| {
        matches!(
            (&record.data, query_type.as_str()),
            (RData::HTTPS(_), "HTTPS") | (RData::SVCB(_), "SVCB")
        )
    })
}

fn mark_dns_cache_dirty(inner: &mut RoutingInner) {
    inner.dns_cache_dirty = true;
    inner.dns_cache_generation = inner.dns_cache_generation.wrapping_add(1);
}

fn dns_cache_persist_items(inner: &RoutingInner, now_ts: u64) -> Vec<DnsCachePersistItem> {
    let mut rows = inner
        .dns_cache
        .iter()
        .filter(|(key, entry)| {
            !key.domain.is_empty()
                && entry.expires_at > now_ts
                && dns_cache_message_is_cacheable(&key.query_type, &entry.message, &entry.results)
        })
        .map(|(key, entry)| DnsCachePersistItem {
            key: key.clone(),
            entry: entry.clone(),
        })
        .collect::<Vec<_>>();
    rows.sort_by(|a, b| {
        a.entry
            .order
            .cmp(&b.entry.order)
            .then_with(|| a.key.domain.cmp(&b.key.domain))
            .then_with(|| a.key.query_type.cmp(&b.key.query_type))
            .then_with(|| {
                route_decision_sort_key(a.key.resolver).cmp(&route_decision_sort_key(b.key.resolver))
            })
    });
    rows
}

fn write_dns_cache_file(path: &Path, rows: Vec<DnsCachePersistItem>) -> io::Result<()> {
    let mut lines = Vec::with_capacity(rows.len());
    for row in rows {
        let message = encode_dns_message(&row.entry.message)?;
        let persisted = PersistedDnsCacheEntry {
            domain: row.key.domain,
            query_type: row.key.query_type,
            resolver: row.key.resolver,
            results: row.entry.results,
            expires_at: row.entry.expires_at,
            inserted_at: row.entry.inserted_at,
            refreshed_at: row.entry.refreshed_at,
            order: row.entry.order,
            message,
        };
        lines.push(serde_json::to_string(&persisted).map_err(|err| {
            io::Error::new(io::ErrorKind::InvalidData, format!("serialize DNS cache row: {err}"))
        })?);
    }
    write_lines_atomic(path, &lines)
}

fn read_dns_cache_file(path: &Path, capacity: usize) -> io::Result<LoadedDnsCache> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(LoadedDnsCache::default()),
        Err(err) => return Err(err),
    };
    let now_ts = now();
    let mut cache = HashMap::<DnsCacheKey, DnsCacheEntry>::new();
    for (line_no, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let row = match serde_json::from_str::<PersistedDnsCacheEntry>(line) {
            Ok(row) => row,
            Err(err) => {
                warn!("skipping invalid DNS cache row {}: {}", line_no + 1, err);
                continue;
            }
        };
        let message = match decode_dns_message(&row.message) {
            Ok(message) => message,
            Err(err) => {
                warn!("skipping undecodable DNS cache row {}: {}", line_no + 1, err);
                continue;
            }
        };
        let key = dns_cache_key(&row.domain, &row.query_type, row.resolver);
        if key.domain.is_empty()
            || row.expires_at <= now_ts
            || !dns_cache_message_is_cacheable(&key.query_type, &message, &row.results)
        {
            continue;
        }
        let entry = DnsCacheEntry {
            message,
            results: row.results,
            expires_at: row.expires_at,
            inserted_at: row.inserted_at,
            refreshed_at: row.refreshed_at,
            order: row.order,
        };
        match cache.get(&key) {
            Some(existing)
                if (existing.expires_at, existing.refreshed_at, existing.order)
                    >= (entry.expires_at, entry.refreshed_at, entry.order) => {}
            _ => {
                cache.insert(key, entry);
            }
        }
    }

    let capacity = capacity.max(1);
    if cache.len() > capacity {
        let mut rows = cache.into_iter().collect::<Vec<_>>();
        rows.sort_by(|(left_key, left), (right_key, right)| {
            right
                .expires_at
                .cmp(&left.expires_at)
                .then_with(|| right.refreshed_at.cmp(&left.refreshed_at))
                .then_with(|| right.order.cmp(&left.order))
                .then_with(|| left_key.domain.cmp(&right_key.domain))
        });
        rows.truncate(capacity);
        cache = rows.into_iter().collect();
    }

    let next_order = cache
        .values()
        .map(|entry| entry.order)
        .max()
        .map(|order| order.wrapping_add(1))
        .unwrap_or(0);
    let mut expirations = BTreeMap::<u64, HashSet<DnsCacheKey>>::new();
    for (key, entry) in &cache {
        expirations.entry(entry.expires_at).or_default().insert(key.clone());
    }
    Ok(LoadedDnsCache {
        cache,
        expirations,
        next_order,
    })
}

fn encode_dns_message(message: &Message) -> io::Result<String> {
    let bytes = message.to_bytes().map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("encode DNS message: {err}"),
        )
    })?;
    Ok(BASE64_STANDARD.encode(bytes))
}

fn decode_dns_message(encoded: &str) -> io::Result<Message> {
    let bytes = BASE64_STANDARD.decode(encoded).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("decode DNS message base64: {err}"),
        )
    })?;
    Message::from_bytes(&bytes).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("decode DNS message: {err}"),
        )
    })
}

fn route_decision_sort_key(decision: RouteDecision) -> u8 {
    match decision {
        RouteDecision::Direct => 0,
        RouteDecision::Proxy => 1,
    }
}

fn push_event<T>(events: &mut VecDeque<T>, event: T) {
    events.push_back(event);
    while events.len() > MAX_EVENTS {
        events.pop_front();
    }
}

fn insert_dns_cache_expiration(inner: &mut RoutingInner, key: DnsCacheKey, expires_at: u64) {
    inner
        .dns_cache_expirations
        .entry(expires_at)
        .or_default()
        .insert(key);
}

fn remove_dns_cache_expiration(inner: &mut RoutingInner, key: &DnsCacheKey, expires_at: u64) {
    let remove_bucket = if let Some(keys) = inner.dns_cache_expirations.get_mut(&expires_at) {
        keys.remove(key);
        keys.is_empty()
    } else {
        false
    };
    if remove_bucket {
        inner.dns_cache_expirations.remove(&expires_at);
    }
}

fn rebuild_dns_cache_expirations(inner: &mut RoutingInner) {
    let mut expirations = BTreeMap::<u64, HashSet<DnsCacheKey>>::new();
    for (key, entry) in &inner.dns_cache {
        expirations.entry(entry.expires_at).or_default().insert(key.clone());
    }
    inner.dns_cache_expirations = expirations;
}

fn dns_cache_expiration_entries(inner: &RoutingInner) -> usize {
    inner.dns_cache_expirations.values().map(HashSet::len).sum()
}

fn maybe_prune_dns_cache_for_capacity(inner: &mut RoutingInner) {
    let capacity = inner.sources.dns_cache_capacity.max(1);
    if inner.dns_cache.len() < capacity {
        return;
    }
    let now = now();
    if !dns_cache_prune_is_due(inner.last_dns_cache_prune_at, now) {
        return;
    }
    prune_dns_cache(inner, now);
    inner.last_dns_cache_prune_at = now;
}

fn dns_cache_prune_is_due(last_prune_at: u64, now: u64) -> bool {
    is_saturday_utc(now) && now.saturating_sub(last_prune_at) >= DNS_CACHE_PRUNE_INTERVAL_SECONDS
}

fn dns_cache_persist_is_due(last_persist_at: u64, now: u64) -> bool {
    // Persist roughly hourly whenever the cache is dirty (the caller already
    // gates on the dirty flag), instead of only on Saturdays. The previous
    // Saturday-only cadence lost every DNS mapping learned since the last
    // Saturday on a reboot on any other day (audit DR-4). One small file write
    // per hour is negligible for flash wear.
    now.saturating_sub(last_persist_at) >= DNS_CACHE_PERSIST_CHECK_INTERVAL.as_secs()
}

fn is_saturday_utc(timestamp: u64) -> bool {
    // 1970-01-01 was Thursday. With Sunday=0, Saturday=6.
    (utc_day(timestamp) + 4) % 7 == 6
}

fn utc_day(timestamp: u64) -> u64 {
    timestamp / SECONDS_PER_DAY
}

fn prune_dns_cache(inner: &mut RoutingInner, now: u64) {
    let started = Instant::now();
    let cache_before = inner.dns_cache.len();
    let order_before = dns_cache_expiration_entries(inner);

    while let Some(expires_at) = inner.dns_cache_expirations.keys().next().copied() {
        if expires_at > now {
            break;
        }
        let Some(keys) = inner.dns_cache_expirations.remove(&expires_at) else {
            break;
        };
        for key in keys {
            if inner
                .dns_cache
                .get(&key)
                .is_some_and(|entry| entry.expires_at <= now)
            {
                inner.dns_cache.remove(&key);
            }
        }
    }

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
            dns_cache_expiration_entries(inner),
        );
    }
}

fn enforce_dns_cache_capacity(inner: &mut RoutingInner) {
    let capacity = inner.sources.dns_cache_capacity.max(1);
    while inner.dns_cache.len() > capacity {
        let Some(expires_at) = inner.dns_cache_expirations.keys().next().copied() else {
            break;
        };
        let Some(key) = oldest_dns_cache_key_in_bucket(inner, expires_at) else {
            inner.dns_cache_expirations.remove(&expires_at);
            continue;
        };
        remove_dns_cache_expiration(inner, &key, expires_at);
        if inner
            .dns_cache
            .get(&key)
            .is_some_and(|entry| entry.expires_at == expires_at)
        {
            inner.dns_cache.remove(&key);
        }
    }
}

fn oldest_dns_cache_key_in_bucket(inner: &RoutingInner, expires_at: u64) -> Option<DnsCacheKey> {
    inner
        .dns_cache_expirations
        .get(&expires_at)?
        .iter()
        .filter_map(|key| {
            inner
                .dns_cache
                .get(key)
                .filter(|entry| entry.expires_at == expires_at)
                .map(|entry| (key, entry.order))
        })
        .min_by(|(left_key, left_order), (right_key, right_order)| {
            left_order
                .cmp(right_order)
                .then_with(|| left_key.domain.cmp(&right_key.domain))
                .then_with(|| left_key.query_type.cmp(&right_key.query_type))
                .then_with(|| route_decision_rank(left_key.resolver).cmp(&route_decision_rank(right_key.resolver)))
        })
        .map(|(key, _)| key.clone())
}

fn route_decision_rank(decision: RouteDecision) -> u8 {
    match decision {
        RouteDecision::Direct => 0,
        RouteDecision::Proxy => 1,
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn system_time_unix_secs(time: SystemTime) -> Option<u64> {
    time.duration_since(UNIX_EPOCH).ok().map(|duration| duration.as_secs())
}

#[cfg(test)]
mod tests;
