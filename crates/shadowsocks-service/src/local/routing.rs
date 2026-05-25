//! Runtime routing state for the embedded web admin.

use std::{
    collections::{BTreeSet, HashMap, HashSet, VecDeque},
    fs,
    io::{self, Write},
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    process::Command,
    sync::{Arc, RwLock as StdRwLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use ipnet::IpNet;
use log::warn;
use serde::{Deserialize, Serialize};
use shadowsocks::relay::socks5::Address;
use tokio::sync::RwLock as TokioRwLock;

use crate::config::RouteRulesConfig;

const DIRECT_IP_FILE: &str = "direct_ip.txt";
const DIRECT_DOMAIN_FILE: &str = "direct_domain.txt";
const BYPASS_IP_FILE: &str = "bypass_ip.txt";
const BYPASS_DOMAIN_FILE: &str = "bypass_domain.txt";
const MANUAL_IP_FILE: &str = "manual_ip.txt";
const MANUAL_DOMAIN_FILE: &str = "manual_domain.txt";
const IP_METADATA_FILE: &str = "ip_metadata.txt";
const DOMAIN_METADATA_FILE: &str = "domain_metadata.txt";
const GEOIP_TEXT_FILE: &str = "geoip.txt";
const GENERATED_RULE_FILES: [&str; 4] = [DIRECT_IP_FILE, DIRECT_DOMAIN_FILE, BYPASS_IP_FILE, BYPASS_DOMAIN_FILE];
const REMOVED_SOURCE_FILES: [&str; 2] = ["direct-list.txt", "proxy-list.txt"];
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
        sanitize_sources(Self {
            geoip_sources: config.geoip_sources.clone(),
            geosite_sources: config.geosite_sources.clone(),
            direct_domain_sources: config.direct_domain_sources.clone(),
            bypass_domain_sources: config.bypass_domain_sources.clone(),
            domestic_dns: config.domestic_dns.clone(),
            foreign_dns: config.foreign_dns.clone(),
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
    pub layer: String,
    pub regions: Vec<String>,
    pub sources: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ManualIpRule {
    pub cidr: String,
    pub region: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ManualDomainRule {
    pub domain: String,
    pub region: String,
}

#[derive(Clone, Debug)]
struct CompiledManualIpRule {
    net: IpNet,
    region: String,
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
pub struct UnhitIpEvent {
    pub timestamp: u64,
    pub ip: IpAddr,
}

#[derive(Clone, Debug, Serialize)]
pub struct UnhitDomainEvent {
    pub timestamp: u64,
    pub domain: String,
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
    manual_ip_raw: Vec<ManualIpRule>,
    manual_domain_raw: Vec<ManualDomainRule>,
    temporary: CompiledRules,
    persistent: CompiledRules,
    manual_ip: Vec<CompiledManualIpRule>,
    manual_domain: Vec<ManualDomainRule>,
    ip_regions: HashMap<String, BTreeSet<String>>,
    ip_sources: HashMap<String, BTreeSet<String>>,
    domain_regions: HashMap<String, BTreeSet<String>>,
    domain_sources: HashMap<String, BTreeSet<String>>,
    ip_conflicts: VecDeque<ConflictEvent>,
    domain_conflicts: VecDeque<ConflictEvent>,
    connections: VecDeque<ConnectionEvent>,
    dns: VecDeque<DnsEvent>,
    unhit_ips: VecDeque<UnhitIpEvent>,
    unhit_domains: VecDeque<UnhitDomainEvent>,
}

#[derive(Clone, Debug)]
pub struct RoutingState {
    inner: Arc<TokioRwLock<RoutingInner>>,
    progress: Arc<StdRwLock<RuleUpdateProgress>>,
}

impl RoutingState {
    pub async fn load(config: RouteRulesConfig) -> io::Result<Self> {
        fs::create_dir_all(&config.rules_dir)?;
        ensure_file(config.rules_dir.join(DIRECT_IP_FILE))?;
        ensure_file(config.rules_dir.join(DIRECT_DOMAIN_FILE))?;
        ensure_file(config.rules_dir.join(BYPASS_IP_FILE))?;
        ensure_file(config.rules_dir.join(BYPASS_DOMAIN_FILE))?;
        ensure_file(config.rules_dir.join(MANUAL_IP_FILE))?;
        ensure_file(config.rules_dir.join(MANUAL_DOMAIN_FILE))?;
        ensure_file(config.rules_dir.join(IP_METADATA_FILE))?;
        ensure_file(config.rules_dir.join(DOMAIN_METADATA_FILE))?;

        let persistent_raw = read_rule_lists(&config.rules_dir)?;
        let persistent = compile_rules(&persistent_raw);
        let manual_ip_raw = read_manual_ip_rules(&config.rules_dir)?;
        let manual_ip = compile_manual_ip_rules(&manual_ip_raw);
        let manual_domain_raw = read_manual_domain_rules(&config.rules_dir)?;
        let (ip_regions, ip_sources) = read_rule_metadata(&config.rules_dir.join(IP_METADATA_FILE))?;
        let (domain_regions, domain_sources) = read_rule_metadata(&config.rules_dir.join(DOMAIN_METADATA_FILE))?;
        let temporary_raw = RuleLists::default();
        let temporary = CompiledRules::default();
        let mut inner = RoutingInner {
            sources: RoutingSources::from(&config),
            rules_dir: config.rules_dir,
            temporary_raw,
            persistent_raw,
            manual_ip_raw,
            manual_domain: manual_domain_raw.clone(),
            manual_domain_raw,
            temporary,
            persistent,
            manual_ip,
            ip_regions,
            ip_sources,
            domain_regions,
            domain_sources,
            ip_conflicts: VecDeque::new(),
            domain_conflicts: VecDeque::new(),
            connections: VecDeque::new(),
            dns: VecDeque::new(),
            unhit_ips: VecDeque::new(),
            unhit_domains: VecDeque::new(),
        };
        rebuild_conflicts(&mut inner);
        Ok(Self {
            inner: Arc::new(TokioRwLock::new(inner)),
            progress: Arc::new(StdRwLock::new(RuleUpdateProgress::default())),
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
        inner.sources = sanitize_sources(sources);
    }

    pub async fn set_temporary_rules(&self, rules: RuleLists) {
        let mut inner = self.inner.write().await;
        inner.temporary_raw = normalize_rule_lists(rules);
        inner.temporary = compile_rules(&inner.temporary_raw);
        rebuild_conflicts(&mut inner);
    }

    pub async fn route_ip(&self, ip: &IpAddr) -> Option<RouteDecision> {
        let mut inner = self.inner.write().await;
        route_ip_inner(&mut inner, ip)
    }

    pub async fn manual_ip_rules(&self) -> Vec<ManualIpRule> {
        self.inner.read().await.manual_ip_raw.clone()
    }

    pub async fn manual_domain_rules(&self) -> Vec<ManualDomainRule> {
        self.inner.read().await.manual_domain_raw.clone()
    }

    pub async fn set_manual_ip_rule(&self, rule: ManualIpRule) -> io::Result<()> {
        let rule = normalize_manual_ip_rule(rule)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid manual IP rule"))?;
        let mut inner = self.inner.write().await;
        set_manual_ip_rule_inner(&mut inner, rule)?;
        Ok(())
    }

    pub async fn remove_manual_ip_rule(&self, cidr: &str) -> io::Result<()> {
        let mut inner = self.inner.write().await;
        let cidr = cidr.trim();
        inner.manual_ip_raw.retain(|rule| rule.cidr != cidr);
        write_manual_ip_rules(&inner.rules_dir, &inner.manual_ip_raw)?;
        inner.manual_ip = compile_manual_ip_rules(&inner.manual_ip_raw);
        Ok(())
    }

    pub async fn set_manual_domain_rule(&self, rule: ManualDomainRule) -> io::Result<()> {
        let rule = normalize_manual_domain_rule(rule)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid manual domain rule"))?;
        let mut inner = self.inner.write().await;
        set_manual_domain_rule_inner(&mut inner, rule)?;
        Ok(())
    }

    pub async fn remove_manual_domain_rule(&self, domain: &str) -> io::Result<()> {
        let mut inner = self.inner.write().await;
        let domain = normalize_domain(domain);
        inner.manual_domain_raw.retain(|rule| rule.domain != domain);
        write_manual_domain_rules(&inner.rules_dir, &inner.manual_domain_raw)?;
        inner.manual_domain = inner.manual_domain_raw.clone();
        Ok(())
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
        rebuild_conflicts(&mut inner);
        warn_if_domain_conflict(&mut inner, domain, RuleLayer::Dns);
        Ok(())
    }

    pub async fn update_from_sources(&self) -> io::Result<()> {
        let (sources, rules_dir) = {
            let inner = self.inner.read().await;
            (inner.sources.clone(), inner.rules_dir.clone())
        };
        let total_files = total_update_steps(&sources);
        if self.update_progress().await.status != RuleUpdateStatus::Running {
            self.begin_update_progress(total_files).await;
        }

        let mut direct_ip = Vec::new();
        let mut bypass_ip = Vec::new();
        let mut direct_domain = Vec::new();
        let mut bypass_domain = Vec::new();
        let mut ip_regions = HashMap::new();
        let mut ip_sources = HashMap::new();
        let mut domain_regions = HashMap::new();
        let mut domain_sources = HashMap::new();
        let mut completed_files = 0usize;

        for source in &sources.geoip_sources {
            let source_name = source_progress_name(source);
            self.mark_source_started(&source_name, completed_files, total_files)
                .await;
            let downloaded = match download_source(source, &rules_dir).await {
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
                &rules_dir,
                completed_files,
                total_files,
            )
            .await;
            self.mark_source_processing(&downloaded.display_name, completed_files, total_files, "parsing rules")
                .await;
            if parse_geoip_dat(
                &downloaded.bytes,
                &downloaded.display_name,
                &mut direct_ip,
                &mut bypass_ip,
                &mut ip_regions,
                &mut ip_sources,
                Some(&rules_dir.join(GEOIP_TEXT_FILE)),
            )
            .is_err()
            {
                let text = String::from_utf8_lossy(&downloaded.bytes);
                let rules = parse_text_rules(&text);
                record_ip_sources(&rules, &downloaded.display_name, &mut ip_sources);
                direct_ip.extend(rules);
            }
        }

        for source in &sources.geosite_sources {
            let source_name = source_progress_name(source);
            self.mark_source_started(&source_name, completed_files, total_files)
                .await;
            let downloaded = match download_source(source, &rules_dir).await {
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
                &rules_dir,
                completed_files,
                total_files,
            )
            .await;
            self.mark_source_processing(&downloaded.display_name, completed_files, total_files, "parsing rules")
                .await;
            if parse_geosite_dat(
                &downloaded.bytes,
                &downloaded.display_name,
                &mut direct_domain,
                &mut bypass_domain,
                &mut domain_regions,
                &mut domain_sources,
            )
            .is_err()
            {
                let text = String::from_utf8_lossy(&downloaded.bytes);
                let rules = parse_text_rules(&text);
                record_domain_sources(&rules, &downloaded.display_name, &mut domain_sources);
                direct_domain.extend(rules);
            }
        }

        for source in &sources.direct_domain_sources {
            let source_name = source_progress_name(source);
            self.mark_source_started(&source_name, completed_files, total_files)
                .await;
            let downloaded = match download_source(source, &rules_dir).await {
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
                &rules_dir,
                completed_files,
                total_files,
            )
            .await;
            let rules = parse_text_rules(&String::from_utf8_lossy(&downloaded.bytes));
            record_domain_sources(&rules, &downloaded.display_name, &mut domain_sources);
            direct_domain.extend(rules);
        }

        for source in &sources.bypass_domain_sources {
            let source_name = source_progress_name(source);
            self.mark_source_started(&source_name, completed_files, total_files)
                .await;
            let downloaded = match download_source(source, &rules_dir).await {
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
                &rules_dir,
                completed_files,
                total_files,
            )
            .await;
            let rules = parse_text_rules(&String::from_utf8_lossy(&downloaded.bytes));
            record_domain_sources(&rules, &downloaded.display_name, &mut domain_sources);
            bypass_domain.extend(rules);
        }

        self.mark_generating_files(completed_files, total_files).await;
        let lists = normalize_rule_lists(RuleLists {
            direct_ip,
            direct_domain,
            bypass_ip,
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
        if let Err(err) = write_rule_metadata(&rules_dir.join(IP_METADATA_FILE), &ip_regions, &ip_sources) {
            self.mark_update_failed("ip metadata", completed_files, total_files, &err)
                .await;
            return Err(err);
        }
        if let Err(err) = write_rule_metadata(&rules_dir.join(DOMAIN_METADATA_FILE), &domain_regions, &domain_sources) {
            self.mark_update_failed("domain metadata", completed_files, total_files, &err)
                .await;
            return Err(err);
        }

        let completed_messages = self.completed_messages();
        let mut inner = self.inner.write().await;
        inner.persistent_raw = lists;
        inner.persistent = persistent;
        inner.ip_regions = ip_regions;
        inner.ip_sources = ip_sources;
        inner.domain_regions = domain_regions;
        inner.domain_sources = domain_sources;
        add_default_cn_manual_rules(&mut inner)?;
        add_default_cn_manual_domain_rules(&mut inner)?;
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
        inner.connections.iter().rev().cloned().collect()
    }

    pub async fn recent_dns(&self) -> Vec<DnsEvent> {
        let mut inner = self.inner.write().await;
        trim_old(&mut inner.dns, DEFAULT_WINDOW);
        inner.dns.iter().cloned().collect()
    }

    pub async fn recent_unhit_ips(&self) -> Vec<UnhitIpEvent> {
        let mut inner = self.inner.write().await;
        trim_old(&mut inner.unhit_ips, DEFAULT_WINDOW);
        inner.unhit_ips.iter().cloned().collect()
    }

    pub async fn recent_unhit_domains(&self) -> Vec<UnhitDomainEvent> {
        let mut inner = self.inner.write().await;
        trim_old(&mut inner.unhit_domains, DEFAULT_WINDOW);
        inner.unhit_domains.iter().cloned().collect()
    }
}

fn route_ip_inner(inner: &mut RoutingInner, ip: &IpAddr) -> Option<RouteDecision> {
    if let Some(rule) = inner.manual_ip.iter().find(|rule| rule.net.contains(ip)) {
        return Some(decision_for_region(&rule.region));
    }

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
        push_event(
            &mut inner.unhit_ips,
            UnhitIpEvent {
                timestamp: now(),
                ip: *ip,
            },
        );
        trim_old(&mut inner.unhit_ips, DEFAULT_WINDOW);
        None
    }
}

fn route_domain_inner(inner: &mut RoutingInner, domain: &str) -> Option<RouteDecision> {
    let domain = normalize_domain(domain);
    if let Some(rule) = inner
        .manual_domain
        .iter()
        .find(|rule| domain_matches_rule(&rule.domain, &domain))
    {
        return Some(decision_for_region(&rule.region));
    }

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
        push_event(
            &mut inner.unhit_domains,
            UnhitDomainEvent {
                timestamp: now(),
                domain,
            },
        );
        trim_old(&mut inner.unhit_domains, DEFAULT_WINDOW);
        None
    }
}

fn rebuild_conflicts(inner: &mut RoutingInner) {
    inner.ip_conflicts.clear();
    inner.domain_conflicts.clear();

    for (rule, layer) in combined_conflict_layers(
        &inner.temporary_raw.direct_ip,
        &inner.temporary_raw.bypass_ip,
        &inner.persistent_raw.direct_ip,
        &inner.persistent_raw.bypass_ip,
    ) {
        let regions = inner
            .ip_regions
            .get(&rule)
            .map(|regions| regions.iter().cloned().collect())
            .unwrap_or_default();
        let sources = inner
            .ip_sources
            .get(&rule)
            .map(|sources| sources.iter().cloned().collect())
            .unwrap_or_default();
        push_event(
            &mut inner.ip_conflicts,
            new_conflict_event_with_metadata(ConflictKind::Ip, rule, layer, regions, sources),
        );
    }

    for (rule, layer) in combined_conflict_layers(
        &inner.temporary_raw.direct_domain,
        &inner.temporary_raw.bypass_domain,
        &inner.persistent_raw.direct_domain,
        &inner.persistent_raw.bypass_domain,
    ) {
        let regions = inner
            .domain_regions
            .get(&rule)
            .map(|regions| regions.iter().cloned().collect())
            .unwrap_or_default();
        let sources = inner
            .domain_sources
            .get(&rule)
            .map(|sources| sources.iter().cloned().collect())
            .unwrap_or_default();
        push_event(
            &mut inner.domain_conflicts,
            new_conflict_event_with_metadata(ConflictKind::Domain, rule, layer, regions, sources),
        );
    }
}

fn combined_conflict_layers(
    temp_direct: &[String],
    temp_bypass: &[String],
    persistent_direct: &[String],
    persistent_bypass: &[String],
) -> Vec<(String, String)> {
    let temp_bypass = temp_bypass.iter().collect::<HashSet<_>>();
    let persistent_bypass = persistent_bypass.iter().collect::<HashSet<_>>();
    let mut layers_by_rule = HashMap::<String, Vec<&'static str>>::new();

    for rule in temp_direct.iter().filter(|rule| temp_bypass.contains(*rule)) {
        layers_by_rule.entry(rule.clone()).or_default().push("temporary");
    }
    for rule in persistent_direct
        .iter()
        .filter(|rule| persistent_bypass.contains(*rule))
    {
        layers_by_rule.entry(rule.clone()).or_default().push("persistent");
    }

    let mut conflicts = layers_by_rule
        .into_iter()
        .map(|(rule, mut layers)| {
            layers.dedup();
            (rule, layers.join(", "))
        })
        .collect::<Vec<_>>();
    conflicts.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    conflicts
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
    let event = new_conflict_event(kind, value, layer_label(layer).to_owned());
    match kind {
        ConflictKind::Ip => push_event(&mut inner.ip_conflicts, event),
        ConflictKind::Domain => push_event(&mut inner.domain_conflicts, event),
    }
}

fn new_conflict_event(kind: ConflictKind, value: String, layer: String) -> ConflictEvent {
    new_conflict_event_with_metadata(kind, value, layer, Vec::new(), Vec::new())
}

fn new_conflict_event_with_metadata(
    kind: ConflictKind,
    value: String,
    layer: String,
    regions: Vec<String>,
    sources: Vec<String>,
) -> ConflictEvent {
    warn!(
        "routing rule conflict {:?} {:?}: {}, preferring proxy",
        kind, layer, value
    );
    ConflictEvent {
        timestamp: now(),
        kind,
        value,
        layer,
        regions,
        sources,
    }
}

fn layer_label(layer: RuleLayer) -> &'static str {
    match layer {
        RuleLayer::Temporary => "temporary",
        RuleLayer::Persistent => "persistent",
        RuleLayer::Dns => "dns",
    }
}

fn rules_match_ip(rules: &[IpNet], ip: &IpAddr) -> bool {
    rules.iter().any(|net| net.contains(ip))
}

fn decision_for_region(region: &str) -> RouteDecision {
    if region.eq_ignore_ascii_case("cn") {
        RouteDecision::Direct
    } else {
        RouteDecision::Proxy
    }
}

fn rules_match_domain(rules: &HashSet<String>, domain: &str) -> bool {
    rules.contains(domain) || rules.iter().any(|rule| domain_matches_rule(rule, domain))
}

fn domain_matches_rule(rule: &str, domain: &str) -> bool {
    domain == rule
        || (domain.len() > rule.len()
            && domain.ends_with(rule)
            && domain.as_bytes()[domain.len() - rule.len() - 1] == b'.')
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

fn progress_percent(completed_files: usize, total_files: usize) -> u8 {
    if total_files == 0 {
        100
    } else {
        ((completed_files.saturating_mul(100)) / total_files).min(100) as u8
    }
}

fn total_update_steps(sources: &RoutingSources) -> usize {
    sources.geoip_sources.len()
        + sources.geosite_sources.len()
        + sources.direct_domain_sources.len()
        + sources.bypass_domain_sources.len()
        + GENERATED_RULE_FILES.len()
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

type MetadataMap = HashMap<String, BTreeSet<String>>;

fn read_rule_metadata(path: &Path) -> io::Result<(MetadataMap, MetadataMap)> {
    if !path.exists() {
        return Ok((HashMap::new(), HashMap::new()));
    }
    let mut regions = HashMap::<String, BTreeSet<String>>::new();
    let mut sources = HashMap::<String, BTreeSet<String>>::new();
    for line in fs::read_to_string(path)?.lines() {
        let line = line.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split('\t');
        let Some(value) = parts.next().map(str::trim).filter(|value| !value.is_empty()) else {
            continue;
        };
        if let Some(values) = parts.next() {
            insert_csv_metadata(&mut regions, value, values);
        }
        if let Some(values) = parts.next() {
            insert_csv_metadata(&mut sources, value, values);
        }
    }
    Ok((regions, sources))
}

fn insert_csv_metadata(target: &mut MetadataMap, key: &str, values: &str) {
    for value in values.split(',').map(str::trim).filter(|value| !value.is_empty()) {
        target.entry(key.to_owned()).or_default().insert(value.to_owned());
    }
}

fn write_rule_metadata(path: &Path, regions: &MetadataMap, sources: &MetadataMap) -> io::Result<()> {
    let mut keys = regions.keys().chain(sources.keys()).cloned().collect::<Vec<_>>();
    keys.sort_unstable();
    keys.dedup();
    let lines = keys
        .into_iter()
        .map(|key| {
            format!(
                "{}\t{}\t{}",
                key,
                metadata_values(regions.get(&key)),
                metadata_values(sources.get(&key))
            )
        })
        .collect::<Vec<_>>();
    write_lines_atomic(path, &lines)
}

fn metadata_values(values: Option<&BTreeSet<String>>) -> String {
    values
        .map(|values| values.iter().cloned().collect::<Vec<_>>().join(","))
        .unwrap_or_default()
}

fn sanitize_sources(mut sources: RoutingSources) -> RoutingSources {
    sources
        .direct_domain_sources
        .retain(|source| !is_removed_source(source));
    sources
        .bypass_domain_sources
        .retain(|source| !is_removed_source(source));
    sources
}

fn is_removed_source(source: &str) -> bool {
    let name = source_cache_name(source);
    REMOVED_SOURCE_FILES.contains(&name.as_str())
}

fn read_manual_ip_rules(dir: &Path) -> io::Result<Vec<ManualIpRule>> {
    let path = dir.join(MANUAL_IP_FILE);
    if !path.exists() {
        return Ok(Vec::new());
    }
    Ok(fs::read_to_string(path)?
        .lines()
        .filter_map(parse_manual_ip_line)
        .collect())
}

fn read_manual_domain_rules(dir: &Path) -> io::Result<Vec<ManualDomainRule>> {
    let path = dir.join(MANUAL_DOMAIN_FILE);
    if !path.exists() {
        return Ok(Vec::new());
    }
    Ok(fs::read_to_string(path)?
        .lines()
        .filter_map(parse_manual_domain_line)
        .collect())
}

fn parse_manual_ip_line(line: &str) -> Option<ManualIpRule> {
    let line = line.split('#').next().unwrap_or_default().trim();
    if line.is_empty() {
        return None;
    }
    let mut parts = line.split_whitespace();
    normalize_manual_ip_rule(ManualIpRule {
        cidr: parts.next()?.to_owned(),
        region: parts.next()?.to_owned(),
    })
}

fn parse_manual_domain_line(line: &str) -> Option<ManualDomainRule> {
    let line = line.split('#').next().unwrap_or_default().trim();
    if line.is_empty() {
        return None;
    }
    let mut parts = line.split_whitespace();
    normalize_manual_domain_rule(ManualDomainRule {
        domain: parts.next()?.to_owned(),
        region: parts.next()?.to_owned(),
    })
}

fn write_manual_ip_rules(dir: &Path, rules: &[ManualIpRule]) -> io::Result<()> {
    let lines = rules
        .iter()
        .filter_map(|rule| normalize_manual_ip_rule(rule.clone()))
        .map(|rule| format!("{} {}", rule.cidr, rule.region))
        .collect::<Vec<_>>();
    write_lines_atomic(dir.join(MANUAL_IP_FILE), &lines)
}

fn write_manual_domain_rules(dir: &Path, rules: &[ManualDomainRule]) -> io::Result<()> {
    let lines = rules
        .iter()
        .filter_map(|rule| normalize_manual_domain_rule(rule.clone()))
        .map(|rule| format!("{} {}", rule.domain, rule.region))
        .collect::<Vec<_>>();
    write_lines_atomic(dir.join(MANUAL_DOMAIN_FILE), &lines)
}

fn normalize_manual_ip_rule(rule: ManualIpRule) -> Option<ManualIpRule> {
    let cidr = rule.cidr.trim();
    parse_ip_net(cidr)?;
    let region = rule.region.trim().to_ascii_lowercase();
    if region.is_empty() {
        return None;
    }
    Some(ManualIpRule {
        cidr: cidr.to_owned(),
        region,
    })
}

fn normalize_manual_domain_rule(rule: ManualDomainRule) -> Option<ManualDomainRule> {
    let domain = normalize_domain(&rule.domain);
    if domain.is_empty() {
        return None;
    }
    let region = rule.region.trim().to_ascii_lowercase();
    if region.is_empty() {
        return None;
    }
    Some(ManualDomainRule { domain, region })
}

fn compile_manual_ip_rules(rules: &[ManualIpRule]) -> Vec<CompiledManualIpRule> {
    rules
        .iter()
        .filter_map(|rule| {
            Some(CompiledManualIpRule {
                net: parse_ip_net(&rule.cidr)?,
                region: rule.region.clone(),
            })
        })
        .collect()
}

fn set_manual_ip_rule_inner(inner: &mut RoutingInner, rule: ManualIpRule) -> io::Result<()> {
    inner.manual_ip_raw.retain(|existing| existing.cidr != rule.cidr);
    inner.manual_ip_raw.push(rule);
    inner.manual_ip_raw.sort_unstable_by(|a, b| a.cidr.cmp(&b.cidr));
    write_manual_ip_rules(&inner.rules_dir, &inner.manual_ip_raw)?;
    inner.manual_ip = compile_manual_ip_rules(&inner.manual_ip_raw);
    Ok(())
}

fn set_manual_domain_rule_inner(inner: &mut RoutingInner, rule: ManualDomainRule) -> io::Result<()> {
    inner
        .manual_domain_raw
        .retain(|existing| existing.domain != rule.domain);
    inner.manual_domain_raw.push(rule);
    inner.manual_domain_raw.sort_unstable_by(|a, b| a.domain.cmp(&b.domain));
    write_manual_domain_rules(&inner.rules_dir, &inner.manual_domain_raw)?;
    inner.manual_domain = inner.manual_domain_raw.clone();
    Ok(())
}

fn add_default_cn_manual_rules(inner: &mut RoutingInner) -> io::Result<()> {
    let existing = inner
        .manual_ip_raw
        .iter()
        .map(|rule| rule.cidr.clone())
        .collect::<HashSet<_>>();
    let mut changed = false;
    for (cidr, regions) in &inner.ip_regions {
        if existing.contains(cidr) || !regions.contains("cn") || regions.len() < 2 {
            continue;
        }
        if !rules_match_exact(&inner.persistent_raw.direct_ip, cidr)
            || !rules_match_exact(&inner.persistent_raw.bypass_ip, cidr)
        {
            continue;
        }
        inner.manual_ip_raw.push(ManualIpRule {
            cidr: cidr.clone(),
            region: "cn".to_owned(),
        });
        changed = true;
    }
    if changed {
        inner.manual_ip_raw.sort_unstable_by(|a, b| a.cidr.cmp(&b.cidr));
        write_manual_ip_rules(&inner.rules_dir, &inner.manual_ip_raw)?;
        inner.manual_ip = compile_manual_ip_rules(&inner.manual_ip_raw);
    }
    Ok(())
}

fn add_default_cn_manual_domain_rules(inner: &mut RoutingInner) -> io::Result<()> {
    let existing = inner
        .manual_domain_raw
        .iter()
        .map(|rule| rule.domain.clone())
        .collect::<HashSet<_>>();
    let mut changed = false;
    for (domain, regions) in &inner.domain_regions {
        if existing.contains(domain) || !regions.contains("cn") || regions.len() < 2 {
            continue;
        }
        if !rules_match_exact(&inner.persistent_raw.direct_domain, domain)
            || !rules_match_exact(&inner.persistent_raw.bypass_domain, domain)
        {
            continue;
        }
        inner.manual_domain_raw.push(ManualDomainRule {
            domain: domain.clone(),
            region: "cn".to_owned(),
        });
        changed = true;
    }
    if changed {
        inner.manual_domain_raw.sort_unstable_by(|a, b| a.domain.cmp(&b.domain));
        write_manual_domain_rules(&inner.rules_dir, &inner.manual_domain_raw)?;
        inner.manual_domain = inner.manual_domain_raw.clone();
    }
    Ok(())
}

fn rules_match_exact(rules: &[String], value: &str) -> bool {
    rules.iter().any(|rule| rule == value)
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
            if let Some(bytes) = read_non_empty_file(&cache_path)? {
                return Ok(DownloadedSource {
                    bytes,
                    display_name,
                    from_cache: true,
                });
            }

            fs::create_dir_all(&cache_dir)?;
            for (cmd, args) in [
                ("uclient-fetch", vec!["-q", "-O", "-", &source]),
                ("wget", vec!["-qO-", &source]),
                ("curl", vec!["-fsSL", &source]),
            ] {
                match Command::new(cmd).args(args).output() {
                    Ok(out) if out.status.success() && !out.stdout.is_empty() => {
                        write_bytes_atomic(&cache_path, &out.stdout)?;
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

fn write_bytes_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, bytes)?;
    fs::rename(tmp, path)
}

fn parse_geoip_dat(
    bytes: &[u8],
    source_name: &str,
    direct_ip: &mut Vec<String>,
    bypass_ip: &mut Vec<String>,
    ip_regions: &mut HashMap<String, BTreeSet<String>>,
    ip_sources: &mut HashMap<String, BTreeSet<String>>,
    text_output: Option<&Path>,
) -> io::Result<()> {
    let entries = read_len_fields(bytes, 1)?;
    if entries.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "empty geoip.dat"));
    }
    let mut text_lines = Vec::new();
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
            let cidr = format!("{ip}/{prefix}");
            ip_regions.entry(cidr.clone()).or_default().insert(country.clone());
            ip_sources
                .entry(cidr.clone())
                .or_default()
                .insert(source_name.to_owned());
            cidrs.push(cidr);
        }
        text_lines.push(format!("[{country}]"));
        text_lines.extend(cidrs.iter().cloned());
        text_lines.push(String::new());
        if country == "cn" {
            direct_ip.extend(cidrs);
        } else {
            bypass_ip.extend(cidrs);
        }
    }
    if let Some(path) = text_output {
        write_lines_atomic(path, &text_lines)?;
    }
    Ok(())
}

fn record_ip_sources(rules: &[String], source_name: &str, ip_sources: &mut HashMap<String, BTreeSet<String>>) {
    for rule in rules {
        if parse_ip_net(rule).is_some() {
            ip_sources
                .entry(rule.clone())
                .or_default()
                .insert(source_name.to_owned());
        }
    }
}

fn parse_geosite_dat(
    bytes: &[u8],
    source_name: &str,
    direct_domain: &mut Vec<String>,
    bypass_domain: &mut Vec<String>,
    domain_regions: &mut HashMap<String, BTreeSet<String>>,
    domain_sources: &mut HashMap<String, BTreeSet<String>>,
) -> io::Result<()> {
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
            for domain in read_string_fields(domain, 2) {
                let domain = normalize_domain(&domain);
                if domain.is_empty() {
                    continue;
                }
                domain_regions
                    .entry(domain.clone())
                    .or_default()
                    .insert(country.clone());
                domain_sources
                    .entry(domain.clone())
                    .or_default()
                    .insert(source_name.to_owned());
                target.push(domain);
            }
        }
    }
    Ok(())
}

fn record_domain_sources(rules: &[String], source_name: &str, domain_sources: &mut HashMap<String, BTreeSet<String>>) {
    for rule in rules {
        let domain = normalize_domain(rule);
        if !domain.is_empty() {
            domain_sources.entry(domain).or_default().insert(source_name.to_owned());
        }
    }
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

impl Timestamped for UnhitIpEvent {
    fn timestamp(&self) -> u64 {
        self.timestamp
    }
}

impl Timestamped for UnhitDomainEvent {
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
