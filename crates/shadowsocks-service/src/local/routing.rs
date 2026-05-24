//! Runtime routing state for the embedded web admin.

use std::{
    collections::{HashSet, VecDeque},
    fs,
    io::{self, Write},
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use ipnet::IpNet;
use log::warn;
use serde::{Deserialize, Serialize};
use shadowsocks::relay::socks5::Address;
use tokio::sync::RwLock;

use crate::config::RouteRulesConfig;

const DIRECT_IP_FILE: &str = "direct_ip.txt";
const DIRECT_DOMAIN_FILE: &str = "direct_domain.txt";
const BYPASS_IP_FILE: &str = "bypass_ip.txt";
const BYPASS_DOMAIN_FILE: &str = "bypass_domain.txt";
const MAX_EVENTS: usize = 4096;
const DEFAULT_WINDOW: Duration = Duration::from_secs(300);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleLayer {
    Temporary,
    Persistent,
    Dns,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RoutingSources {
    pub geoip_sources: Vec<String>,
    pub geosite_sources: Vec<String>,
    pub direct_domain_sources: Vec<String>,
    pub bypass_domain_sources: Vec<String>,
    pub domestic_dns: Vec<String>,
    pub foreign_dns: Vec<String>,
}

impl From<&RouteRulesConfig> for RoutingSources {
    fn from(config: &RouteRulesConfig) -> Self {
        Self {
            geoip_sources: config.geoip_sources.clone(),
            geosite_sources: config.geosite_sources.clone(),
            direct_domain_sources: config.direct_domain_sources.clone(),
            bypass_domain_sources: config.bypass_domain_sources.clone(),
            domestic_dns: config.domestic_dns.clone(),
            foreign_dns: config.foreign_dns.clone(),
        }
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
    pub layer: RuleLayer,
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
    pub destination_port: u16,
    pub protocol: String,
    pub decision: RouteDecision,
}

#[derive(Clone, Debug, Serialize)]
pub struct DnsEvent {
    pub timestamp: u64,
    pub domain: String,
    pub query_type: String,
    pub results: Vec<IpAddr>,
    pub resolver: RouteDecision,
}

#[derive(Clone, Debug, Serialize)]
pub struct RoutingSnapshot {
    pub rules_dir: PathBuf,
    pub sources: RoutingSources,
    pub temporary: RuleLists,
    pub persistent: RuleLists,
}

#[derive(Clone, Debug, Default)]
struct CompiledRules {
    direct_ip: Vec<IpNet>,
    direct_domain: HashSet<String>,
    bypass_ip: Vec<IpNet>,
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
    ip_conflicts: VecDeque<ConflictEvent>,
    domain_conflicts: VecDeque<ConflictEvent>,
    connections: VecDeque<ConnectionEvent>,
    dns: VecDeque<DnsEvent>,
}

#[derive(Clone, Debug)]
pub struct RoutingState {
    inner: Arc<RwLock<RoutingInner>>,
}

impl RoutingState {
    pub async fn load(config: RouteRulesConfig) -> io::Result<Self> {
        fs::create_dir_all(&config.rules_dir)?;
        ensure_file(config.rules_dir.join(DIRECT_IP_FILE))?;
        ensure_file(config.rules_dir.join(DIRECT_DOMAIN_FILE))?;
        ensure_file(config.rules_dir.join(BYPASS_IP_FILE))?;
        ensure_file(config.rules_dir.join(BYPASS_DOMAIN_FILE))?;

        let persistent_raw = read_rule_lists(&config.rules_dir)?;
        let persistent = compile_rules(&persistent_raw);
        let temporary_raw = RuleLists::default();
        let temporary = CompiledRules::default();
        let mut inner = RoutingInner {
            sources: RoutingSources::from(&config),
            rules_dir: config.rules_dir,
            temporary_raw,
            persistent_raw,
            temporary,
            persistent,
            ip_conflicts: VecDeque::new(),
            domain_conflicts: VecDeque::new(),
            connections: VecDeque::new(),
            dns: VecDeque::new(),
        };
        detect_conflicts(&mut inner, RuleLayer::Persistent);
        Ok(Self {
            inner: Arc::new(RwLock::new(inner)),
        })
    }

    pub async fn snapshot(&self) -> RoutingSnapshot {
        let inner = self.inner.read().await;
        RoutingSnapshot {
            rules_dir: inner.rules_dir.clone(),
            sources: inner.sources.clone(),
            temporary: inner.temporary_raw.clone(),
            persistent: inner.persistent_raw.clone(),
        }
    }

    pub async fn set_sources(&self, sources: RoutingSources) {
        let mut inner = self.inner.write().await;
        inner.sources = sources;
    }

    pub async fn set_temporary_rules(&self, rules: RuleLists) {
        let mut inner = self.inner.write().await;
        inner.temporary_raw = normalize_rule_lists(rules);
        inner.temporary = compile_rules(&inner.temporary_raw);
        detect_conflicts(&mut inner, RuleLayer::Temporary);
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
        let mut inner = self.inner.write().await;
        let path = match decision {
            RouteDecision::Direct => inner.rules_dir.join(DIRECT_IP_FILE),
            RouteDecision::Proxy => inner.rules_dir.join(BYPASS_IP_FILE),
        };
        append_unique_lines(&path, &results.iter().map(ToString::to_string).collect::<Vec<_>>())?;
        inner.persistent_raw = read_rule_lists(&inner.rules_dir)?;
        inner.persistent = compile_rules(&inner.persistent_raw);
        detect_conflicts(&mut inner, RuleLayer::Dns);
        warn_if_domain_conflict(&mut inner, domain, RuleLayer::Dns);
        Ok(())
    }

    pub async fn update_from_sources(&self) -> io::Result<()> {
        let sources = {
            let inner = self.inner.read().await;
            inner.sources.clone()
        };

        let mut direct_ip = Vec::new();
        let mut bypass_ip = Vec::new();
        let mut direct_domain = Vec::new();
        let mut bypass_domain = Vec::new();

        for source in &sources.geoip_sources {
            let bytes = download_source(source).await?;
            if parse_geoip_dat(&bytes, &mut direct_ip, &mut bypass_ip).is_err() {
                let text = String::from_utf8_lossy(&bytes);
                direct_ip.extend(parse_text_rules(&text));
            }
        }

        for source in &sources.geosite_sources {
            let bytes = download_source(source).await?;
            if parse_geosite_dat(&bytes, &mut direct_domain, &mut bypass_domain).is_err() {
                let text = String::from_utf8_lossy(&bytes);
                direct_domain.extend(parse_text_rules(&text));
            }
        }

        for source in &sources.direct_domain_sources {
            let bytes = download_source(source).await?;
            direct_domain.extend(parse_text_rules(&String::from_utf8_lossy(&bytes)));
        }

        for source in &sources.bypass_domain_sources {
            let bytes = download_source(source).await?;
            bypass_domain.extend(parse_text_rules(&String::from_utf8_lossy(&bytes)));
        }

        let lists = normalize_rule_lists(RuleLists {
            direct_ip,
            direct_domain,
            bypass_ip,
            bypass_domain,
        });

        let mut inner = self.inner.write().await;
        write_rule_lists(&inner.rules_dir, &lists)?;
        inner.persistent_raw = lists;
        inner.persistent = compile_rules(&inner.persistent_raw);
        detect_conflicts(&mut inner, RuleLayer::Persistent);
        Ok(())
    }

    pub async fn domestic_dns(&self) -> Vec<String> {
        self.inner.read().await.sources.domestic_dns.clone()
    }

    pub async fn foreign_dns(&self) -> Vec<String> {
        self.inner.read().await.sources.foreign_dns.clone()
    }

    pub async fn record_connection(
        &self,
        source: SocketAddr,
        target: &Address,
        protocol: &str,
        decision: RouteDecision,
    ) {
        let (destination_ip, destination_domain, destination_port) = match target {
            Address::SocketAddress(saddr) => (Some(saddr.ip()), None, saddr.port()),
            Address::DomainNameAddress(domain, port) => (None, Some(domain.clone()), *port),
        };
        let mut inner = self.inner.write().await;
        push_event(
            &mut inner.connections,
            ConnectionEvent {
                timestamp: now(),
                source_ip: source.ip(),
                source_port: source.port(),
                destination_ip,
                destination_domain,
                destination_port,
                protocol: protocol.to_owned(),
                decision,
            },
        );
        trim_old(&mut inner.connections, DEFAULT_WINDOW);
    }

    pub async fn record_dns(&self, domain: String, query_type: String, results: Vec<IpAddr>, resolver: RouteDecision) {
        let mut inner = self.inner.write().await;
        push_event(
            &mut inner.dns,
            DnsEvent {
                timestamp: now(),
                domain,
                query_type,
                results,
                resolver,
            },
        );
        trim_old(&mut inner.dns, DEFAULT_WINDOW);
    }

    pub async fn ip_conflicts(&self) -> Vec<ConflictEvent> {
        self.inner.read().await.ip_conflicts.iter().cloned().collect()
    }

    pub async fn domain_conflicts(&self) -> Vec<ConflictEvent> {
        self.inner.read().await.domain_conflicts.iter().cloned().collect()
    }

    pub async fn recent_connections(&self) -> Vec<ConnectionEvent> {
        let mut inner = self.inner.write().await;
        trim_old(&mut inner.connections, DEFAULT_WINDOW);
        inner.connections.iter().cloned().collect()
    }

    pub async fn recent_dns(&self) -> Vec<DnsEvent> {
        let mut inner = self.inner.write().await;
        trim_old(&mut inner.dns, DEFAULT_WINDOW);
        inner.dns.iter().cloned().collect()
    }
}

fn route_ip_inner(inner: &mut RoutingInner, ip: &IpAddr) -> Option<RouteDecision> {
    let temp_direct = rules_match_ip(&inner.temporary.direct_ip, ip);
    let temp_proxy = rules_match_ip(&inner.temporary.bypass_ip, ip);
    if temp_direct && temp_proxy {
        push_conflict(inner, ConflictKind::Ip, ip.to_string(), RuleLayer::Temporary);
        return Some(RouteDecision::Proxy);
    }
    if temp_proxy {
        return Some(RouteDecision::Proxy);
    }
    if temp_direct {
        return Some(RouteDecision::Direct);
    }

    let direct = rules_match_ip(&inner.persistent.direct_ip, ip);
    let proxy = rules_match_ip(&inner.persistent.bypass_ip, ip);
    if direct && proxy {
        push_conflict(inner, ConflictKind::Ip, ip.to_string(), RuleLayer::Persistent);
        return Some(RouteDecision::Proxy);
    }
    if proxy {
        Some(RouteDecision::Proxy)
    } else if direct {
        Some(RouteDecision::Direct)
    } else {
        None
    }
}

fn route_domain_inner(inner: &mut RoutingInner, domain: &str) -> Option<RouteDecision> {
    let domain = normalize_domain(domain);
    let temp_direct = rules_match_domain(&inner.temporary.direct_domain, &domain);
    let temp_proxy = rules_match_domain(&inner.temporary.bypass_domain, &domain);
    if temp_direct && temp_proxy {
        push_conflict(inner, ConflictKind::Domain, domain.clone(), RuleLayer::Temporary);
        return Some(RouteDecision::Proxy);
    }
    if temp_proxy {
        return Some(RouteDecision::Proxy);
    }
    if temp_direct {
        return Some(RouteDecision::Direct);
    }

    let direct = rules_match_domain(&inner.persistent.direct_domain, &domain);
    let proxy = rules_match_domain(&inner.persistent.bypass_domain, &domain);
    if direct && proxy {
        push_conflict(inner, ConflictKind::Domain, domain.clone(), RuleLayer::Persistent);
        return Some(RouteDecision::Proxy);
    }
    if proxy {
        Some(RouteDecision::Proxy)
    } else if direct {
        Some(RouteDecision::Direct)
    } else {
        None
    }
}

fn detect_conflicts(inner: &mut RoutingInner, layer: RuleLayer) {
    for rule in inner
        .persistent_raw
        .direct_ip
        .iter()
        .filter(|r| inner.persistent_raw.bypass_ip.contains(*r))
        .cloned()
        .collect::<Vec<_>>()
    {
        push_conflict(inner, ConflictKind::Ip, rule, layer);
    }
    for rule in inner
        .persistent_raw
        .direct_domain
        .iter()
        .filter(|r| inner.persistent_raw.bypass_domain.contains(*r))
        .cloned()
        .collect::<Vec<_>>()
    {
        push_conflict(inner, ConflictKind::Domain, rule, layer);
    }
}

fn warn_if_domain_conflict(inner: &mut RoutingInner, domain: &str, layer: RuleLayer) {
    let domain = normalize_domain(domain);
    if rules_match_domain(&inner.persistent.direct_domain, &domain)
        && rules_match_domain(&inner.persistent.bypass_domain, &domain)
    {
        push_conflict(inner, ConflictKind::Domain, domain, layer);
    }
}

fn push_conflict(inner: &mut RoutingInner, kind: ConflictKind, value: String, layer: RuleLayer) {
    warn!(
        "routing rule conflict {:?} {:?}: {}, preferring proxy",
        kind, layer, value
    );
    let event = ConflictEvent {
        timestamp: now(),
        kind,
        value,
        layer,
    };
    match kind {
        ConflictKind::Ip => push_event(&mut inner.ip_conflicts, event),
        ConflictKind::Domain => push_event(&mut inner.domain_conflicts, event),
    }
}

fn rules_match_ip(rules: &[IpNet], ip: &IpAddr) -> bool {
    rules.iter().any(|net| net.contains(ip))
}

fn rules_match_domain(rules: &HashSet<String>, domain: &str) -> bool {
    rules.contains(domain)
        || rules.iter().any(|rule| {
            domain.len() > rule.len()
                && domain.ends_with(rule)
                && domain.as_bytes()[domain.len() - rule.len() - 1] == b'.'
        })
}

fn compile_rules(raw: &RuleLists) -> CompiledRules {
    CompiledRules {
        direct_ip: raw.direct_ip.iter().filter_map(|s| parse_ip_net(s)).collect(),
        direct_domain: raw
            .direct_domain
            .iter()
            .map(|s| normalize_domain(s))
            .filter(|s| !s.is_empty())
            .collect(),
        bypass_ip: raw.bypass_ip.iter().filter_map(|s| parse_ip_net(s)).collect(),
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

fn normalize_rule_lists(lists: RuleLists) -> RuleLists {
    RuleLists {
        direct_ip: normalize_lines(lists.direct_ip),
        direct_domain: normalize_domains(lists.direct_domain),
        bypass_ip: normalize_lines(lists.bypass_ip),
        bypass_domain: normalize_domains(lists.bypass_domain),
    }
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

fn write_rule_lists(dir: &Path, lists: &RuleLists) -> io::Result<()> {
    write_lines_atomic(dir.join(DIRECT_IP_FILE), &lists.direct_ip)?;
    write_lines_atomic(dir.join(DIRECT_DOMAIN_FILE), &lists.direct_domain)?;
    write_lines_atomic(dir.join(BYPASS_IP_FILE), &lists.bypass_ip)?;
    write_lines_atomic(dir.join(BYPASS_DOMAIN_FILE), &lists.bypass_domain)?;
    Ok(())
}

fn read_lines(path: impl AsRef<Path>) -> io::Result<Vec<String>> {
    let path = path.as_ref();
    if !path.exists() {
        return Ok(Vec::new());
    }
    Ok(parse_text_rules(&fs::read_to_string(path)?))
}

fn append_unique_lines(path: &Path, lines: &[String]) -> io::Result<()> {
    let mut existing = read_lines(path)?;
    existing.extend(lines.iter().cloned());
    write_lines_atomic(path, &normalize_lines(existing))
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

async fn download_source(source: &str) -> io::Result<Vec<u8>> {
    if source.starts_with("http://") || source.starts_with("https://") {
        let source = source.to_owned();
        tokio::task::spawn_blocking(move || {
            for (cmd, args) in [
                ("uclient-fetch", vec!["-q", "-O", "-", &source]),
                ("wget", vec!["-qO-", &source]),
                ("curl", vec!["-fsSL", &source]),
            ] {
                match Command::new(cmd).args(args).output() {
                    Ok(out) if out.status.success() => return Ok(out.stdout),
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
        fs::read(source)
    }
}

fn parse_geoip_dat(bytes: &[u8], direct_ip: &mut Vec<String>, bypass_ip: &mut Vec<String>) -> io::Result<()> {
    let entries = read_len_fields(bytes, 1)?;
    if entries.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "empty geoip.dat"));
    }
    for entry in entries {
        let country = read_string_fields(entry, 1)
            .into_iter()
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase();
        let mut cidrs = Vec::new();
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
            cidrs.push(format!("{ip}/{prefix}"));
        }
        if country == "cn" {
            direct_ip.extend(cidrs);
        } else {
            bypass_ip.extend(cidrs);
        }
    }
    Ok(())
}

fn parse_geosite_dat(bytes: &[u8], direct_domain: &mut Vec<String>, bypass_domain: &mut Vec<String>) -> io::Result<()> {
    let entries = read_len_fields(bytes, 1)?;
    if entries.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "empty geosite.dat"));
    }
    for entry in entries {
        let country = read_string_fields(entry, 1)
            .into_iter()
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase();
        let target = if matches!(
            country.as_str(),
            "cn" | "direct" | "apple-cn" | "google-cn" | "category-games@cn"
        ) {
            &mut *direct_domain
        } else if country == "geolocation-!cn" || country == "gfw" || country == "proxy" {
            &mut *bypass_domain
        } else {
            continue;
        };
        for domain in read_len_fields(entry, 2)? {
            target.extend(read_string_fields(domain, 2));
        }
    }
    Ok(())
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
        assert_eq!(state.route_domain("www.example.com").await, Some(RouteDecision::Direct));

        state
            .set_temporary_rules(RuleLists {
                bypass_ip: vec!["1.1.1.1".to_owned()],
                bypass_domain: vec!["example.com".to_owned()],
                ..RuleLists::default()
            })
            .await;

        assert_eq!(
            state.route_ip(&"1.1.1.1".parse().unwrap()).await,
            Some(RouteDecision::Proxy)
        );
        assert_eq!(state.route_domain("www.example.com").await, Some(RouteDecision::Proxy));
    }

    #[tokio::test]
    async fn source_update_writes_four_rule_files() {
        let dir = temp_rules_dir("sources");
        let direct_source = dir.join("direct.txt");
        let bypass_source = dir.join("bypass.txt");
        fs::write(&direct_source, "direct.example\n# comment\nchina.example\n").unwrap();
        fs::write(&bypass_source, "proxy.example\ngfw.example\n").unwrap();

        let mut config = RouteRulesConfig::default();
        config.rules_dir = dir.clone();
        config.geoip_sources.clear();
        config.geosite_sources.clear();
        config.direct_domain_sources = vec![direct_source.display().to_string()];
        config.bypass_domain_sources = vec![bypass_source.display().to_string()];

        let state = RoutingState::load(config).await.unwrap();
        state.update_from_sources().await.unwrap();
        let snapshot = state.snapshot().await;

        assert!(snapshot.persistent.direct_domain.contains(&"direct.example".to_owned()));
        assert!(snapshot.persistent.direct_domain.contains(&"china.example".to_owned()));
        assert!(snapshot.persistent.bypass_domain.contains(&"proxy.example".to_owned()));
        assert!(snapshot.persistent.bypass_domain.contains(&"gfw.example".to_owned()));
        assert!(dir.join(DIRECT_IP_FILE).exists());
        assert!(dir.join(BYPASS_IP_FILE).exists());
    }
}
