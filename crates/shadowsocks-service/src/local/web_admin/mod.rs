//! Embedded web admin for routing rules and DNS split.

use std::{
    collections::{HashMap, HashSet},
    convert::Infallible,
    fs, io,
    net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs},
    path::{Path, PathBuf},
    pin::Pin,
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request, Response, StatusCode, body::Incoming, server::conn::http1, service::service_fn};
use log::{error, info, trace};
use pin_project::pin_project;
use tokio::{net::TcpListener, sync::Mutex, time};

use crate::{
    config::{DEFAULT_DEPLOY_DIR, WebAdminConfig},
    local::routing::{ConnectionDecision, ConnectionEvent, RouteDecision, RoutingState, RuleLists},
};

type ResponseBody = Full<Bytes>;
const DEBUG_RANDOM_PARAM: &str = "deubg_random";
static DEBUG_RANDOM_COUNTER: AtomicU64 = AtomicU64::new(1);

pub struct WebAdminBuilder {
    config: WebAdminConfig,
    routing_state: RoutingState,
}

impl WebAdminBuilder {
    pub fn new(config: WebAdminConfig, routing_state: RoutingState) -> Self {
        Self { config, routing_state }
    }

    pub async fn build(self) -> io::Result<WebAdmin> {
        let listener = TcpListener::bind(self.config.listen).await?;
        Ok(WebAdmin {
            listener,
            token: self.config.token,
            config_path: PathBuf::from(DEFAULT_DEPLOY_DIR).join("conf/shadowsocks-client.json"),
            routing_state: self.routing_state,
            process_started_at: unix_now(),
        })
    }
}

pub struct WebAdmin {
    listener: TcpListener,
    token: Option<String>,
    config_path: PathBuf,
    routing_state: RoutingState,
    process_started_at: u64,
}

impl WebAdmin {
    pub async fn run(self) -> io::Result<()> {
        info!("shadowsocks web admin listening on {}", self.listener.local_addr()?);
        let server_filters = Arc::new(server_filters_from_config_path(&self.config_path));
        let handler = Arc::new(WebAdminHandler {
            token: self.token,
            config_path: self.config_path,
            routing_state: self.routing_state,
            server_filters,
            debug_lock: Mutex::new(()),
            process_started_at: self.process_started_at,
            nft_ruleset_cache: Mutex::new(None),
        });

        loop {
            let (stream, peer_addr) = match self.listener.accept().await {
                Ok(s) => s,
                Err(err) => {
                    error!("failed to accept web admin clients, err: {}", err);
                    time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
            };

            trace!("web admin accepted client from {}", peer_addr);
            let handler = handler.clone();
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                if let Err(err) = http1::Builder::new()
                    .serve_connection(io, service_fn(move |req| handler.clone().serve(req, peer_addr)))
                    .await
                {
                    error!("web admin connection {} failed with error: {}", peer_addr, err);
                }
            });
        }
    }
}

struct WebAdminHandler {
    token: Option<String>,
    config_path: PathBuf,
    routing_state: RoutingState,
    server_filters: Arc<HashSet<IpAddr>>,
    debug_lock: Mutex<()>,
    process_started_at: u64,
    /// Memoized `nft list ruleset` output `(text, generated_at_unix)`. The
    /// command is run lazily on the first request and only re-run when the
    /// admin clicks Refresh; every other reader serves this cache.
    nft_ruleset_cache: Mutex<Option<(String, u64)>>,
}

impl WebAdminHandler {
    async fn serve(
        self: Arc<Self>,
        req: Request<Incoming>,
        peer_addr: SocketAddr,
    ) -> Result<Response<ResponseBody>, Infallible> {
        Ok(match self.handle(req, peer_addr).await {
            Ok(resp) => resp,
            Err(err) => json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &serde_json::json!({ "error": err.to_string() }),
            ),
        })
    }

    async fn handle(&self, req: Request<Incoming>, peer_addr: SocketAddr) -> io::Result<Response<ResponseBody>> {
        if !is_lan_admin_peer(peer_addr.ip()) {
            return Ok(json_response(
                StatusCode::FORBIDDEN,
                &serde_json::json!({ "error": "web admin is only available from LAN clients" }),
            ));
        }
        if !self.authorized(&req) {
            return Ok(json_response(
                StatusCode::UNAUTHORIZED,
                &serde_json::json!({ "error": "unauthorized" }),
            ));
        }

        let method = req.method().clone();
        let path = req.uri().path().to_owned();
        match (method, path.as_str()) {
            (Method::GET, "/") | (Method::GET, "/index.html") => Ok(html_response(INDEX_HTML)),
            (Method::POST, "/api/restart") => {
                restart_service_after_response();
                Ok(json_response(
                    StatusCode::ACCEPTED,
                    &serde_json::json!({ "ok": true, "restart": true }),
                ))
            }
            (Method::GET, "/api/client-config") => {
                let content = match fs::read_to_string(&self.config_path) {
                    Ok(content) => content,
                    Err(err) if err.kind() == io::ErrorKind::NotFound => String::new(),
                    Err(err) => return Err(err),
                };
                let parsed = if content.trim().is_empty() {
                    None
                } else {
                    json5::from_str::<serde_json::Value>(&content).ok()
                };
                Ok(json_response(
                    StatusCode::OK,
                    &serde_json::json!({
                        "path": self.config_path,
                        "content": content,
                        "parsed": parsed,
                    }),
                ))
            }
            (Method::PUT, "/api/client-config") => {
                let payload: ClientConfigPayload = read_json(req).await?;
                let existing = match fs::read_to_string(&self.config_path) {
                    Ok(content) => content,
                    Err(err) if err.kind() == io::ErrorKind::NotFound => String::new(),
                    Err(err) => return Err(err),
                };
                if existing == payload.content {
                    return Ok(json_response(
                        StatusCode::OK,
                        &serde_json::json!({ "ok": true, "restart": false, "unchanged": true }),
                    ));
                }
                if let Some(parent) = self.config_path.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::write(&self.config_path, payload.content)?;
                restart_service_after_response();
                Ok(json_response(
                    StatusCode::OK,
                    &serde_json::json!({ "ok": true, "restart": true }),
                ))
            }
            (Method::GET, "/api/config/rules") => {
                Ok(json_response(StatusCode::OK, &self.routing_state.snapshot().await))
            }
            (Method::POST, "/api/rules/update") => {
                let routing_state = self.routing_state.clone();
                if !routing_state.try_begin_update().await {
                    return Ok(json_response(
                        StatusCode::ACCEPTED,
                        &serde_json::json!({ "ok": true, "started": false, "message": "rule update already running" }),
                    ));
                }
                thread::spawn(move || {
                    let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
                        Ok(runtime) => runtime,
                        Err(err) => {
                            log::warn!("failed to create route rule update runtime: {}", err);
                            routing_state.mark_rule_job_failed_sync(format!(
                                "failed to create route rule update runtime: {err}"
                            ));
                            return;
                        }
                    };
                    match runtime.block_on(routing_state.update_from_sources()) {
                        Ok(()) => restart_service_after_response(),
                        Err(err) => log::warn!("failed to update route rules from sources: {}", err),
                    }
                });
                Ok(json_response(StatusCode::ACCEPTED, &serde_json::json!({ "ok": true })))
            }
            (Method::POST, "/api/rules/download") => {
                let routing_state = self.routing_state.clone();
                if !routing_state.try_begin_download().await {
                    return Ok(json_response(
                        StatusCode::ACCEPTED,
                        &serde_json::json!({ "ok": true, "started": false, "message": "rule update already running" }),
                    ));
                }
                thread::spawn(move || {
                    let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
                        Ok(runtime) => runtime,
                        Err(err) => {
                            log::warn!("failed to create route rule download runtime: {}", err);
                            routing_state.mark_rule_job_failed_sync(format!(
                                "failed to create route rule download runtime: {err}"
                            ));
                            return;
                        }
                    };
                    if let Err(err) = runtime.block_on(routing_state.download_sources()) {
                        log::warn!("failed to download route rule sources: {}", err);
                    }
                });
                Ok(json_response(StatusCode::ACCEPTED, &serde_json::json!({ "ok": true })))
            }
            (Method::GET, "/api/rules/update-progress") => Ok(json_response(
                StatusCode::OK,
                &self.routing_state.update_progress().await,
            )),
            (Method::GET, "/api/dns") => Ok(json_response(
                StatusCode::OK,
                &serde_json::json!({
                    "domestic_dns": self.routing_state.domestic_dns().await,
                    "foreign_dns": self.routing_state.foreign_dns().await,
                }),
            )),
            (Method::GET, "/api/dns/cache/stats") => Ok(json_response(
                StatusCode::OK,
                &self.routing_state.dns_cache_stats().await,
            )),
            (Method::GET, "/api/dns/cache/query") => {
                let domain = query_param(req.uri().query(), "domain").unwrap_or_default();
                Ok(json_response(
                    StatusCode::OK,
                    &self.routing_state.dns_cache_query(&domain).await,
                ))
            }
            (Method::GET, "/api/dns/cache/query-ip") => {
                let ip = query_param(req.uri().query(), "ip").unwrap_or_default();
                Ok(json_response(
                    StatusCode::OK,
                    &self.routing_state.dns_cache_query_ip(&ip).await,
                ))
            }
            (Method::POST, "/api/dns/cache/clear") => {
                let payload: DnsCacheClearPayload = read_json(req).await?;
                let cleared = self.routing_state.dns_cache_clear(payload.domain.as_deref()).await;
                Ok(json_response(
                    StatusCode::OK,
                    &serde_json::json!({ "ok": true, "cleared": cleared }),
                ))
            }
            (Method::PUT, "/api/dns") => {
                // Hot-reload upstream resolvers chosen by the routing
                // layer. Persists into the per-listener config slot
                // ([`DnsRuntimeState`]) so it stays consistent with the
                // `locals[].dns` source of truth — no `route_rules`
                // duplication anymore.
                let dns: DnsPayload = read_json(req).await?;
                let mut state = self.routing_state.dns_runtime_snapshot().await;
                state.domestic_dns = dns.domestic_dns;
                state.foreign_dns = dns.foreign_dns;
                self.routing_state.set_dns_runtime(state).await;
                Ok(json_response(StatusCode::OK, &serde_json::json!({ "ok": true })))
            }
            (Method::GET, "/api/temp-rules") => {
                let temporary = self.routing_state.reload_temporary_rules_from_files().await?;
                Ok(json_response(StatusCode::OK, &temporary))
            }
            (Method::PUT, "/api/temp-rules") => {
                let rules: RuleLists = read_json(req).await?;
                self.routing_state.set_temporary_rules(rules).await?;
                Ok(json_response(StatusCode::OK, &serde_json::json!({ "ok": true })))
            }
            (Method::GET, "/api/conflicts/ip") => {
                Ok(json_response(StatusCode::OK, &self.routing_state.ip_conflicts().await))
            }
            (Method::GET, "/api/conflicts/domain") => Ok(json_response(
                StatusCode::OK,
                &self.routing_state.domain_conflicts().await,
            )),
            (Method::GET, "/api/lan/addresses") => Ok(json_response(StatusCode::OK, &lan_addresses())),
            (Method::GET, "/api/lan/dhcp-clients") => Ok(json_response(StatusCode::OK, &dhcp_clients())),
            (Method::GET, "/api/activity/connections") => Ok(json_response(
                StatusCode::OK,
                &self
                    .routing_state
                    .recent_connections(&self.server_filters, source_ip_query(req.uri().query()))
                    .await,
            )),
            (Method::POST, "/api/activity/record/start") => {
                let status = self.routing_state.start_activity_recording().await?;
                Ok(json_response(StatusCode::OK, &serde_json::json!({ "ok": true, "status": status })))
            }
            (Method::POST, "/api/activity/record/stop") => {
                let status = self.routing_state.stop_activity_recording().await?;
                Ok(json_response(StatusCode::OK, &serde_json::json!({ "ok": true, "status": status })))
            }
            (Method::GET, "/api/activity/record/status") => {
                Ok(json_response(StatusCode::OK, &self.routing_state.activity_record_status().await))
            }
            (Method::GET, "/api/activity/dns") => {
                Ok(json_response(
                    StatusCode::OK,
                    &self.routing_state.recent_dns(source_ip_query(req.uri().query())).await,
                ))
            }
            (Method::GET, "/api/sys/status") => Ok(json_response(StatusCode::OK, &self.sys_status().await)),
            (Method::GET, "/api/sys/uptime") => Ok(json_response(StatusCode::OK, &self.process_uptime())),
            (Method::GET, "/api/sys/platform") => Ok(json_response(StatusCode::OK, &platform_info())),
            (Method::GET, "/api/nft/ruleset") => {
                let refresh = req.uri().query().is_some_and(query_has_refresh);
                Ok(json_response(StatusCode::OK, &self.nft_ruleset(refresh).await))
            }
            (Method::POST, "/api/sys/debug-url") => {
                let payload: DebugUrlPayload = read_json(req).await?;
                Ok(json_response(
                    StatusCode::OK,
                    &self.debug_url(payload.url, payload.mode.as_deref()).await?,
                ))
            }
            (Method::POST, "/api/sys/debug-ip") => {
                let payload: DebugIpPayload = read_json(req).await?;
                Ok(json_response(
                    StatusCode::OK,
                    &self.routing_state.debug_ip_membership(&payload.query).await,
                ))
            }
            (Method::GET, "/api/log/status") => Ok(json_response(StatusCode::OK, &self.sys_status().await)),
            _ => Ok(json_response(
                StatusCode::NOT_FOUND,
                &serde_json::json!({ "error": "not found" }),
            )),
        }
    }

    fn authorized(&self, req: &Request<Incoming>) -> bool {
        let Some(expected) = self.token.as_deref() else {
            return true;
        };

        if let Some(value) = req.headers().get("x-admin-token").and_then(|v| v.to_str().ok()) {
            return value == expected;
        }
        if let Some(value) = req.headers().get("authorization").and_then(|v| v.to_str().ok())
            && value.strip_prefix("Bearer ").is_some_and(|token| token == expected)
        {
            return true;
        }
        req.uri()
            .query()
            .and_then(|q| q.split('&').find_map(|pair| pair.strip_prefix("token=")))
            .is_some_and(|token| token == expected)
    }

    async fn sys_status(&self) -> serde_json::Value {
        let (ip_conflicts, domain_conflicts) = self.routing_state.direct_proxy_file_conflicts().await;
        let mut status = system_status();
        if let Some(object) = status.as_object_mut() {
            object.insert("ip_conflicts".to_owned(), serde_json::json!(ip_conflicts));
            object.insert("domain_conflicts".to_owned(), serde_json::json!(domain_conflicts));
            object.insert(
                "process_started_at".to_owned(),
                serde_json::json!(self.process_started_at),
            );
            object.insert(
                "process_uptime_seconds".to_owned(),
                serde_json::json!(self.process_uptime_seconds()),
            );
        }
        status
    }

    fn process_uptime_seconds(&self) -> u64 {
        unix_now().saturating_sub(self.process_started_at)
    }

    fn process_uptime(&self) -> serde_json::Value {
        serde_json::json!({
            "process_started_at": self.process_started_at,
            "process_uptime_seconds": self.process_uptime_seconds(),
            "now": unix_now(),
        })
    }

    /// Serve the cached `nft list ruleset`. The command runs only on the first
    /// request or when `refresh` is set (the admin's Refresh button); all other
    /// reads return the in-memory snapshot.
    async fn nft_ruleset(&self, refresh: bool) -> serde_json::Value {
        if !refresh {
            let guard = self.nft_ruleset_cache.lock().await;
            if let Some((text, generated_at)) = guard.as_ref() {
                return serde_json::json!({
                    "ruleset": text,
                    "generated_at": generated_at,
                    "cached": true,
                });
            }
        }
        let text = match tokio::task::spawn_blocking(nft_list_ruleset).await {
            Ok(Ok(text)) => text,
            Ok(Err(err)) => {
                // On failure keep serving the last good snapshot (if any) so a
                // transient nft hiccup doesn't blank the panel.
                let guard = self.nft_ruleset_cache.lock().await;
                return serde_json::json!({
                    "error": err.to_string(),
                    "ruleset": guard.as_ref().map(|(text, _)| text.clone()).unwrap_or_default(),
                    "generated_at": guard.as_ref().map(|(_, generated_at)| *generated_at),
                    "cached": guard.is_some(),
                });
            }
            Err(join_err) => {
                return serde_json::json!({ "error": format!("nft task failed: {join_err}") });
            }
        };
        let generated_at = unix_now();
        *self.nft_ruleset_cache.lock().await = Some((text.clone(), generated_at));
        serde_json::json!({
            "ruleset": text,
            "generated_at": generated_at,
            "cached": false,
        })
    }

    async fn debug_url(&self, url: String, mode: Option<&str>) -> io::Result<serde_json::Value> {
        let url = normalize_debug_url(&url)?;
        let host = debug_url_host(&url)?;
        let mode = DebugUrlMode::parse(mode)?;
        let _debug_guard = self.debug_lock.lock().await;
        let debug_random = debug_random_string();
        let debug_url = append_debug_random_param(&url, &debug_random);
        let redir_port = local_port_from_config_path(&self.config_path, DebugUrlMode::Redir.protocol());
        let http_port = local_port_from_config_path(&self.config_path, DebugUrlMode::Http.protocol());
        let socks_port = local_port_from_config_path(&self.config_path, DebugUrlMode::Socks.protocol());
        let redir_port_running = redir_port.is_some_and(local_port_running);
        let http_port_running = http_port.is_some_and(local_port_running);
        let socks_port_running = socks_port.is_some_and(local_port_running);
        let (local_port, port_running) = match mode {
            DebugUrlMode::Redir => (redir_port, redir_port_running),
            DebugUrlMode::Http => (http_port, http_port_running),
            DebugUrlMode::Socks => (socks_port, socks_port_running),
        };
        let dns_relevant = mode == DebugUrlMode::Redir;
        let record_started_by_debug = {
            let status = self.routing_state.activity_record_status().await;
            if status.recording {
                false
            } else {
                self.routing_state.start_activity_recording().await?;
                true
            }
        };
        let started_at = unix_now();
        let decision = self.routing_state.route_domain(&host).await;
        let cached_before_entries = if dns_relevant {
            self.routing_state.dns_cache_query(&host).await
        } else {
            Vec::new()
        };
        let cached_before = cached_before_entries
            .iter()
            .any(|entry| entry.query_type.eq_ignore_ascii_case("A") && decision.map_or(true, |d| entry.resolver == d));
        let curl_command = intended_debug_curl_command(&debug_url, mode, local_port);

        let curl_result = if port_running {
            tokio::task::spawn_blocking({
                let debug_url = debug_url.clone();
                move || run_debug_curl(&debug_url, mode, local_port)
            })
            .await
            .map_err(io::Error::other)??
        } else {
            DebugCurlResult::not_running(curl_command, format!("{} port not running", mode.as_str()))
        };
        self.routing_state.flush_activity_recording().await?;

        let dns_events = if dns_relevant {
            self.routing_state.recent_dns(None).await
        } else {
            Vec::new()
        };
        let matching_dns = dns_events
            .iter()
            .filter(|event| event.timestamp >= started_at && domain_matches_debug_host(&event.domain, &host))
            .cloned()
            .collect::<Vec<_>>();
        let resolved_ips = matching_dns
            .iter()
            .flat_map(|event| event.results.iter().copied())
            .collect::<Vec<_>>();
        let cache_entries = if dns_relevant {
            self.routing_state.dns_cache_query(&host).await
        } else {
            Vec::new()
        };
        let mut resolved_ips = resolved_ips;
        resolved_ips.extend(
            cache_entries
                .iter()
                .filter(|entry| entry.query_type.eq_ignore_ascii_case("A"))
                .filter(|entry| decision.map_or(true, |d| entry.resolver == d))
                .flat_map(|entry| entry.results.iter().copied()),
        );
        let mut seen_ips = HashSet::new();
        resolved_ips.retain(|ip| seen_ips.insert(*ip));

        let mut nft_proxy = false;
        let mut nft_matches: Vec<String> = Vec::new();
        let mut nft_error: Option<String> = None;
        let nft_checked = cfg!(all(target_os = "linux", feature = "local-dns")) && dns_relevant;
        #[cfg(all(target_os = "linux", feature = "local-dns"))]
        {
            if nft_checked {
                for ip in &resolved_ips {
                    match crate::local::dns::intercept_linux::proxy_set_matches(&ip.to_string()) {
                        Ok(matches) => {
                            nft_proxy |= !matches.is_empty();
                            nft_matches.extend(matches);
                        }
                        Err(err) => nft_error = Some(err.to_string()),
                    }
                }
                nft_matches.sort();
                nft_matches.dedup();
            }
        }

        let debug_connection = self.wait_debug_connection(mode, &host, &resolved_ips, started_at).await;
        let port_received = debug_connection.is_some();
        let route_decision = debug_route_decision(mode, decision, debug_connection.as_ref());
        if record_started_by_debug {
            let _ = self.routing_state.stop_activity_recording().await;
        }

        Ok(serde_json::json!({
            "url": url,
            "debug_url": debug_url,
            "debug_random_param": DEBUG_RANDOM_PARAM,
            "debug_random": debug_random,
            "debug_mode": mode.as_str(),
            "host": host,
            "proxy_domain": matches!(decision, Some(RouteDecision::Proxy)),
            "rule_route_decision": decision,
            "route_decision": route_decision,
            "dns_intercepted": dns_relevant.then_some(!matching_dns.is_empty()),
            "dns_cache_hit": dns_relevant.then_some(cached_before),
            "resolved_ips": resolved_ips,
            "nft_checked": nft_checked,
            "nft_proxy": nft_checked.then_some(nft_proxy),
            "nft_matches": nft_matches,
            "nft_error": nft_error,
            "connection_recorded": port_received,
            "transparent_connection_recorded": mode == DebugUrlMode::Redir && port_received,
            "local_port": local_port,
            "port_running": port_running,
            "port_received": port_received,
            "port_status": debug_port_status(port_running, port_received),
            "transparent_port_running": redir_port_running,
            "transparent_port_received": mode == DebugUrlMode::Redir && port_received,
            "http_port_running": http_port_running,
            "http_port_received": mode == DebugUrlMode::Http && port_received,
            "socks_port_running": socks_port_running,
            "socks_port_received": mode == DebugUrlMode::Socks && port_received,
            "response_received": curl_result.response_received,
            "http_code": curl_result.http_code,
            "time_namelookup": curl_result.time_namelookup,
            "time_connect": curl_result.time_connect,
            "time_appconnect": curl_result.time_appconnect,
            "time_starttransfer": curl_result.time_starttransfer,
            "time_total": curl_result.time_total,
            "curl_command": curl_result.command,
            "curl_exit_code": curl_result.exit_code,
            "curl_error": curl_result.error,
        }))
    }

    async fn wait_debug_connection(
        &self,
        mode: DebugUrlMode,
        host: &str,
        resolved_ips: &[IpAddr],
        started_at: u64,
    ) -> Option<ConnectionEvent> {
        for attempt in 0..10 {
            let connections = self
                .routing_state
                .recent_connections(&self.server_filters, None)
                .await;
            if let Some(event) = connections
                .into_iter()
                .find(|event| debug_connection_matches(event, mode, host, resolved_ips, started_at))
            {
                return Some(event);
            }
            if attempt < 9 {
                time::sleep(Duration::from_millis(50)).await;
            }
        }
        None
    }
}

#[derive(serde::Deserialize)]
struct DnsPayload {
    domestic_dns: Vec<String>,
    foreign_dns: Vec<String>,
}

#[derive(serde::Deserialize)]
struct DnsCacheClearPayload {
    domain: Option<String>,
}

#[derive(serde::Deserialize)]
struct DebugUrlPayload {
    url: String,
    mode: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DebugUrlMode {
    Redir,
    Http,
    Socks,
}

impl DebugUrlMode {
    fn parse(mode: Option<&str>) -> io::Result<Self> {
        match mode.unwrap_or("redir").trim().to_ascii_lowercase().as_str() {
            "" | "redir" | "transparent" => Ok(Self::Redir),
            "http" => Ok(Self::Http),
            "socks" | "socks5" => Ok(Self::Socks),
            mode => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unsupported debug mode: {mode}"),
            )),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Redir => "redir",
            Self::Http => "http",
            Self::Socks => "socks",
        }
    }

    fn protocol(self) -> &'static str {
        match self {
            Self::Redir => "redir",
            Self::Http => "http",
            Self::Socks => "socks",
        }
    }
}

#[derive(serde::Deserialize)]
struct DebugIpPayload {
    query: String,
}

#[derive(serde::Deserialize)]
struct ClientConfigPayload {
    content: String,
}

#[derive(serde::Serialize)]
struct DhcpClient {
    ip: IpAddr,
    ips: Vec<IpAddr>,
    mac: String,
    hostname: String,
    expires_at: Option<u64>,
    source: &'static str,
}

#[derive(serde::Serialize)]
struct LanAddress {
    address: IpAddr,
    source: &'static str,
}

struct DebugCurlResult {
    command: String,
    response_received: bool,
    http_code: String,
    time_namelookup: String,
    time_connect: String,
    time_appconnect: String,
    time_starttransfer: String,
    time_total: String,
    exit_code: Option<i32>,
    error: Option<String>,
}

impl DebugCurlResult {
    fn not_running(command: String, error: String) -> Self {
        Self {
            command,
            response_received: false,
            http_code: "000".to_owned(),
            time_namelookup: String::new(),
            time_connect: String::new(),
            time_appconnect: String::new(),
            time_starttransfer: String::new(),
            time_total: String::new(),
            exit_code: None,
            error: Some(error),
        }
    }
}

fn restart_service_after_response() {
    thread::spawn(|| {
        std::thread::sleep(Duration::from_millis(300));
        #[cfg(windows)]
        if let Err(err) = Command::new("powershell")
            .args([
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                "Restart-Service -Name ssservice -ErrorAction Stop",
            ])
            .status()
        {
            log::warn!("failed to restart ssservice after config save: {}", err);
        }
        #[cfg(not(windows))]
        {
            cleanup_redir_firewall_before_restart();
            let openwrt_init = Path::new("/etc/init.d/shadowsocks");
            let restart = if openwrt_init.exists() {
                Command::new(openwrt_init).arg("restart").status()
            } else {
                Command::new("systemctl")
                    .args(["restart", "shadowsocks-client.service"])
                    .status()
            };

            if let Err(err) = restart {
                log::warn!("failed to restart shadowsocks service after config save: {}", err);
            }
        }
    });
}

#[cfg(not(windows))]
fn cleanup_redir_firewall_before_restart() {
    let _ = Command::new("nft")
        .args(["delete", "table", "inet", "ssrust_redir"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    while Command::new("ip")
        .args(["rule", "del", "fwmark", "0x1", "table", "100"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
    {}
    let _ = Command::new("ip")
        .args(["route", "del", "local", "0.0.0.0/0", "dev", "lo", "table", "100"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    let _ = Command::new("ip")
        .args(["-6", "route", "del", "local", "::/0", "dev", "lo", "table", "100"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

fn platform_info() -> serde_json::Value {
    serde_json::json!({
        "target_os": std::env::consts::OS,
        "transparent_backend": transparent_backend(),
        "service_name": service_name(),
        "git_commit": git_commit(),
        "git_commit_time_bj": git_commit_time_bj(),
    })
}

/// Short git commit the binary was built from (embedded by build.rs).
fn git_commit() -> &'static str {
    match option_env!("SSRUST_GIT_COMMIT") {
        Some(commit) if !commit.is_empty() => commit,
        _ => "unknown",
    }
}

/// Commit time for the embedded git commit.
fn git_commit_time_bj() -> &'static str {
    match option_env!("SSRUST_GIT_COMMIT_TIME_BJ") {
        Some(time) if !time.is_empty() => time,
        _ => "unknown",
    }
}

fn query_has_refresh(query: &str) -> bool {
    query
        .split('&')
        .any(|pair| matches!(pair, "refresh=1" | "refresh=true" | "refresh"))
}

#[cfg(target_os = "linux")]
fn nft_list_ruleset() -> io::Result<String> {
    let output = Command::new("nft")
        .args(["list", "ruleset"])
        .stdin(Stdio::null())
        .output()?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(io::Error::other(format!(
            "nft list ruleset exited with {}: {}",
            output.status,
            stderr.trim()
        )))
    }
}

#[cfg(not(target_os = "linux"))]
fn nft_list_ruleset() -> io::Result<String> {
    Err(io::Error::other("nft list ruleset is only available on Linux"))
}

fn service_name() -> &'static str {
    if cfg!(windows) {
        "ssservice"
    } else {
        "shadowsocks-client.service"
    }
}

fn transparent_backend() -> &'static str {
    if cfg!(windows) { "tun" } else { "redir" }
}

#[cfg(target_os = "linux")]
fn system_status() -> serde_json::Value {
    let install_command = "sudo apt update && sudo apt install -y nftables";
    match Command::new("nft").arg("--version").output() {
        Ok(output) if output.status.success() => {
            let version = String::from_utf8_lossy(&output.stdout).trim().to_owned();
            let table_ok = Command::new("nft")
                .args(["list", "table", "inet", "ssrust_redir"])
                .status()
                .is_ok_and(|status| status.success());
            serde_json::json!({
                "nft_installed": true,
                "nft_version": version,
                "dns_table_installed": table_ok,
                "nft_set_counts": nft_set_counts_status(),
                "install_command": install_command,
            })
        }
        Ok(output) => serde_json::json!({
            "nft_installed": false,
            "nft_version": "",
            "dns_table_installed": false,
            "nft_set_counts": nft_set_counts_unavailable(),
            "install_command": install_command,
            "error": String::from_utf8_lossy(&output.stderr).trim(),
        }),
        Err(err) => serde_json::json!({
            "nft_installed": false,
            "nft_version": "",
            "dns_table_installed": false,
            "nft_set_counts": nft_set_counts_unavailable(),
            "install_command": install_command,
            "error": err.to_string(),
        }),
    }
}

#[cfg(all(target_os = "linux", feature = "local-dns"))]
fn nft_set_counts_status() -> serde_json::Value {
    match crate::local::dns::intercept_linux::route_set_counts() {
        Ok(counts) => serde_json::json!({
            "checked": true,
            "direct4": counts.direct4,
            "direct6": counts.direct6,
            "proxy4": counts.proxy4,
            "proxy6": counts.proxy6,
            "direct_total": counts.direct_total(),
            "proxy_total": counts.proxy_total(),
            "total": counts.total(),
        }),
        Err(err) => serde_json::json!({
            "checked": true,
            "error": err.to_string(),
        }),
    }
}

#[cfg(not(all(target_os = "linux", feature = "local-dns")))]
fn nft_set_counts_status() -> serde_json::Value {
    nft_set_counts_unavailable()
}

fn nft_set_counts_unavailable() -> serde_json::Value {
    serde_json::json!({
        "checked": false,
    })
}

#[cfg(windows)]
fn system_status() -> serde_json::Value {
    let service_installed = Command::new("sc")
        .args(["query", service_name()])
        .status()
        .is_ok_and(|status| status.success());
    let adapter_output = Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            "Get-NetAdapter -Name shadowsocks-tun -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Status",
        ])
        .output();
    let tun_adapter_status = adapter_output
        .ok()
        .and_then(|output| {
            output
                .status
                .success()
                .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        })
        .filter(|status| !status.is_empty());
    serde_json::json!({
        "platform": "windows",
        "transparent_backend": "tun",
        "tun_supported": true,
        "service_installed": service_installed,
        "service_name": service_name(),
        "tun_adapter": "shadowsocks-tun",
        "tun_adapter_status": tun_adapter_status,
        "install_command": r#".\deploy\scripts\deploy_windows.ps1 -InstallDir D:\software\shadowsocks"#,
    })
}

#[cfg(not(any(target_os = "linux", windows)))]
fn system_status() -> serde_json::Value {
    serde_json::json!({
        "platform": std::env::consts::OS,
        "transparent_backend": transparent_backend(),
        "tun_supported": cfg!(any(target_os = "ios", target_os = "macos", target_os = "android", target_os = "freebsd")),
        "install_command": "",
    })
}

fn is_lan_admin_peer(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            ip.is_loopback()
                || ip.octets()[0] == 10
                || (ip.octets()[0] == 172 && (16..=31).contains(&ip.octets()[1]))
                || (ip.octets()[0] == 192 && ip.octets()[1] == 168)
        }
        IpAddr::V6(ip) => {
            ip.is_loopback()
                || ip.to_ipv4_mapped().is_some_and(|ip| is_lan_admin_peer(IpAddr::V4(ip)))
                || (ip.segments()[0] & 0xfe00) == 0xfc00
                || (ip.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

fn dhcp_clients() -> Vec<DhcpClient> {
    let mut clients = read_dhcp_leases(Path::new("/tmp/dhcp.leases")).unwrap_or_default();
    add_ipv6_neighbors_to_clients(&mut clients);
    for client in &mut clients {
        sort_dedup_ips(&mut client.ips);
    }
    clients.sort_by(|a, b| {
        a.hostname
            .cmp(&b.hostname)
            .then_with(|| a.ip.cmp(&b.ip))
            .then_with(|| a.mac.cmp(&b.mac))
    });
    clients
}

fn lan_addresses() -> Vec<LanAddress> {
    let mut seen = HashSet::new();
    let mut addresses = Vec::new();
    collect_openwrt_lan_addresses(&mut seen, &mut addresses);
    if addresses.is_empty() {
        collect_linux_lan_device_addresses(&mut seen, &mut addresses);
    }
    addresses.sort_by_key(|addr| addr.address);
    addresses
}

fn collect_openwrt_lan_addresses(seen: &mut HashSet<IpAddr>, addresses: &mut Vec<LanAddress>) {
    let Ok(output) = Command::new("ubus")
        .args(["-S", "call", "network.interface.lan", "status"])
        .output()
    else {
        return;
    };
    if !output.status.success() {
        return;
    }
    let Ok(status) = serde_json::from_slice::<serde_json::Value>(&output.stdout) else {
        return;
    };
    for key in ["ipv4-address", "ipv6-address"] {
        if let Some(values) = status.get(key).and_then(|value| value.as_array()) {
            for value in values {
                if let Some(ip) = value.get("address").and_then(|value| value.as_str()).and_then(parse_lan_bind_ip) {
                    push_lan_address(seen, addresses, ip, "lan");
                }
            }
        }
    }
    if let Some(values) = status.get("ipv6-prefix-assignment").and_then(|value| value.as_array()) {
        for value in values {
            if let Some(ip) = value
                .get("local-address")
                .and_then(|value| value.get("address"))
                .and_then(|value| value.as_str())
                .and_then(parse_lan_bind_ip)
            {
                push_lan_address(seen, addresses, ip, "lan");
            }
        }
    }
}

fn collect_linux_lan_device_addresses(seen: &mut HashSet<IpAddr>, addresses: &mut Vec<LanAddress>) {
    for dev in ["br-lan", "lan"] {
        let Ok(output) = Command::new("ip").args(["-j", "addr", "show", "dev", dev]).output() else {
            continue;
        };
        if !output.status.success() {
            continue;
        }
        let Ok(ifaces) = serde_json::from_slice::<serde_json::Value>(&output.stdout) else {
            continue;
        };
        let Some(ifaces) = ifaces.as_array() else {
            continue;
        };
        for iface in ifaces {
            let Some(values) = iface.get("addr_info").and_then(|value| value.as_array()) else {
                continue;
            };
            for value in values {
                if value.get("scope").and_then(|value| value.as_str()) == Some("link") {
                    continue;
                }
                if let Some(ip) = value.get("local").and_then(|value| value.as_str()).and_then(parse_lan_bind_ip) {
                    push_lan_address(seen, addresses, ip, "lan");
                }
            }
        }
        if !addresses.is_empty() {
            break;
        }
    }
}

fn parse_lan_bind_ip(value: &str) -> Option<IpAddr> {
    let ip = value.parse::<IpAddr>().ok()?;
    match ip {
        IpAddr::V4(ip) if ip.is_loopback() || ip.is_unspecified() => None,
        IpAddr::V6(ip) if ip.is_loopback() || ip.is_unspecified() || (ip.segments()[0] & 0xffc0) == 0xfe80 => None,
        _ => Some(ip),
    }
}

fn push_lan_address(seen: &mut HashSet<IpAddr>, addresses: &mut Vec<LanAddress>, address: IpAddr, source: &'static str) {
    if seen.insert(address) {
        addresses.push(LanAddress { address, source });
    }
}

fn read_dhcp_leases(path: &Path) -> io::Result<Vec<DhcpClient>> {
    let content = fs::read_to_string(path)?;
    let mut seen = HashSet::new();
    let mut clients = Vec::new();
    for line in content.lines() {
        let mut parts = line.split_whitespace();
        let expires_at = parts
            .next()
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|value| *value > 0);
        let Some(mac) = parts.next() else {
            continue;
        };
        let Some(ip) = parts.next().and_then(|value| value.parse::<IpAddr>().ok()) else {
            continue;
        };
        let hostname = parts
            .next()
            .filter(|value| *value != "*")
            .unwrap_or("")
            .to_owned();
        if seen.insert(ip) {
            clients.push(DhcpClient {
                ip,
                ips: vec![ip],
                mac: mac.to_owned(),
                hostname,
                expires_at,
                source: "dhcp",
            });
        }
    }
    clients.sort_by_key(|client| client.ip);
    Ok(clients)
}

fn add_ipv6_neighbors_to_clients(clients: &mut [DhcpClient]) {
    let by_mac = clients
        .iter()
        .enumerate()
        .map(|(idx, client)| (normalize_mac(&client.mac), idx))
        .collect::<HashMap<_, _>>();
    if by_mac.is_empty() {
        return;
    }
    for neighbor in collect_lan_ipv6_neighbors() {
        let Some(idx) = by_mac.get(&normalize_mac(&neighbor.mac)).copied() else {
            continue;
        };
        clients[idx].ips.push(IpAddr::V6(neighbor.ip));
    }
}

struct Ipv6Neighbor {
    ip: std::net::Ipv6Addr,
    mac: String,
}

fn collect_lan_ipv6_neighbors() -> Vec<Ipv6Neighbor> {
    let mut seen = HashSet::new();
    let mut neighbors = Vec::new();
    for dev in ["br-lan", "lan"] {
        collect_ipv6_neighbors_for_dev(Some(dev), &mut seen, &mut neighbors);
    }
    if neighbors.is_empty() {
        collect_ipv6_neighbors_for_dev(None, &mut seen, &mut neighbors);
    }
    neighbors
}

fn collect_ipv6_neighbors_for_dev(
    dev: Option<&str>,
    seen: &mut HashSet<(std::net::Ipv6Addr, String)>,
    neighbors: &mut Vec<Ipv6Neighbor>,
) {
    let mut args = vec!["-j", "-6", "neigh", "show"];
    if let Some(dev) = dev {
        args.extend(["dev", dev]);
    }
    let Ok(output) = Command::new("ip").args(args).output() else {
        return;
    };
    if !output.status.success() {
        return;
    }
    let Ok(rows) = serde_json::from_slice::<serde_json::Value>(&output.stdout) else {
        return;
    };
    let Some(rows) = rows.as_array() else {
        return;
    };
    append_ipv6_neighbors_from_rows(rows, seen, neighbors);
}

fn append_ipv6_neighbors_from_rows(
    rows: &[serde_json::Value],
    seen: &mut HashSet<(std::net::Ipv6Addr, String)>,
    neighbors: &mut Vec<Ipv6Neighbor>,
) {
    for row in rows {
        if !ipv6_neighbor_state_is_usable(row) {
            continue;
        }
        let Some(mac) = row.get("lladdr").and_then(|value| value.as_str()).map(normalize_mac) else {
            continue;
        };
        let Some(ip) = row
            .get("dst")
            .and_then(|value| value.as_str())
            .and_then(|value| value.parse::<std::net::Ipv6Addr>().ok())
            .filter(|ip| is_client_ipv6_candidate(*ip))
        else {
            continue;
        };
        if seen.insert((ip, mac.clone())) {
            neighbors.push(Ipv6Neighbor { ip, mac });
        }
    }
}

fn ipv6_neighbor_state_is_usable(row: &serde_json::Value) -> bool {
    let states = row
        .get("state")
        .and_then(|value| value.as_array())
        .into_iter()
        .flatten()
        .filter_map(|value| value.as_str())
        .collect::<Vec<_>>();
    !states.iter().any(|state| matches!(*state, "FAILED" | "INCOMPLETE"))
}

fn is_client_ipv6_candidate(ip: std::net::Ipv6Addr) -> bool {
    !ip.is_loopback() && !ip.is_unspecified() && !ip.is_multicast() && (ip.segments()[0] & 0xffc0) != 0xfe80
}

fn normalize_mac(mac: &str) -> String {
    mac.to_ascii_lowercase()
}

fn sort_dedup_ips(ips: &mut Vec<IpAddr>) {
    ips.sort();
    ips.dedup();
}

fn normalize_debug_url(url: &str) -> io::Result<String> {
    let url = url.trim();
    if url.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "url is required"));
    }
    if url.contains("://") {
        Ok(url.to_owned())
    } else {
        Ok(format!("http://{url}"))
    }
}

fn debug_random_string() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let counter = DEBUG_RANDOM_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{:x}{:x}{:x}", nanos, std::process::id(), counter)
}

fn append_debug_random_param(url: &str, value: &str) -> String {
    let (base, fragment) = url.split_once('#').map_or((url, None), |(base, fragment)| (base, Some(fragment)));
    let separator = if base.contains('?') {
        if base.ends_with('?') || base.ends_with('&') { "" } else { "&" }
    } else {
        "?"
    };
    let mut out = format!("{base}{separator}{DEBUG_RANDOM_PARAM}={value}");
    if let Some(fragment) = fragment {
        out.push('#');
        out.push_str(fragment);
    }
    out
}

fn debug_url_host(url: &str) -> io::Result<String> {
    let uri = url
        .parse::<hyper::Uri>()
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, format!("invalid url: {err}")))?;
    uri.host()
        .map(|host| host.trim_matches(['[', ']']).to_ascii_lowercase())
        .filter(|host| !host.is_empty())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "url host is required"))
}

fn domain_matches_debug_host(domain: &str, host: &str) -> bool {
    domain
        .trim_end_matches('.')
        .eq_ignore_ascii_case(host.trim_end_matches('.'))
}

fn server_filters_from_config_path(config_path: &PathBuf) -> HashSet<IpAddr> {
    let Ok(content) = fs::read_to_string(config_path) else {
        return HashSet::new();
    };
    let Ok(config) = json5::from_str::<serde_json::Value>(&content) else {
        return HashSet::new();
    };
    config
        .get("servers")
        .and_then(|servers| servers.as_array())
        .into_iter()
        .flatten()
        .flat_map(|server| {
            let Some(host) = server.get("server").and_then(|value| value.as_str()) else {
                return Vec::new();
            };
            let port = server
                .get("server_port")
                .and_then(|value| value.as_u64())
                .and_then(|port| u16::try_from(port).ok())
                .unwrap_or(0);
            server_filter_ips(host, port)
        })
        .collect()
}

fn local_port_from_config_path(config_path: &PathBuf, protocol: &str) -> Option<u16> {
    let content = fs::read_to_string(config_path).ok()?;
    let config = json5::from_str::<serde_json::Value>(&content).ok()?;
    config
        .get("locals")
        .and_then(|locals| locals.as_array())
        .into_iter()
        .flatten()
        .find(|local| local.get("protocol").and_then(|value| value.as_str()) == Some(protocol))
        .and_then(|local| local.get("local_port"))
        .and_then(|value| value.as_u64())
        .and_then(|port| u16::try_from(port).ok())
}

fn local_port_running(port: u16) -> bool {
    #[cfg(target_os = "linux")]
    if let Some(listening) = tcp_port_listening(port) {
        return listening;
    }
    local_port_accepts_connection(port)
}

fn local_port_accepts_connection(port: u16) -> bool {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    TcpStream::connect_timeout(&addr, Duration::from_millis(250)).is_ok()
}

#[cfg(target_os = "linux")]
fn tcp_port_listening(port: u16) -> Option<bool> {
    let tcp4 = fs::read_to_string("/proc/net/tcp").ok()?;
    let tcp6 = fs::read_to_string("/proc/net/tcp6").ok()?;
    Some(proc_net_tcp_has_listener(&tcp4, port) || proc_net_tcp_has_listener(&tcp6, port))
}

#[cfg(target_os = "linux")]
fn proc_net_tcp_has_listener(content: &str, port: u16) -> bool {
    let port_hex = format!("{port:04X}");
    content.lines().skip(1).any(|line| {
        let mut fields = line.split_whitespace();
        let _slot = fields.next();
        let Some(local_address) = fields.next() else {
            return false;
        };
        let _remote_address = fields.next();
        let Some(state) = fields.next() else {
            return false;
        };
        state == "0A"
            && local_address
                .rsplit_once(':')
                .is_some_and(|(_, local_port)| local_port.eq_ignore_ascii_case(&port_hex))
    })
}

fn debug_port_status(port_running: bool, port_received: bool) -> &'static str {
    if !port_running {
        return "not running";
    }
    if port_received {
        "received"
    } else {
        "not received"
    }
}

fn debug_route_decision(
    mode: DebugUrlMode,
    rule_decision: Option<RouteDecision>,
    connection: Option<&ConnectionEvent>,
) -> &'static str {
    if let Some(connection) = connection {
        return connection_decision_label(connection.decision);
    }
    match (mode, rule_decision) {
        (DebugUrlMode::Redir, Some(RouteDecision::Proxy)) => "proxy",
        (DebugUrlMode::Redir, Some(RouteDecision::Direct) | None) => "direct",
        (DebugUrlMode::Http, Some(RouteDecision::Direct)) => "direct",
        (DebugUrlMode::Socks, Some(RouteDecision::Direct)) => "direct",
        (DebugUrlMode::Http | DebugUrlMode::Socks, Some(RouteDecision::Proxy) | None) => "proxy",
    }
}

fn connection_decision_label(decision: ConnectionDecision) -> &'static str {
    match decision {
        ConnectionDecision::Direct => "direct",
        ConnectionDecision::HttpProxy => "http_proxy",
        ConnectionDecision::Socks5Proxy => "socks5_proxy",
        ConnectionDecision::Redir => "redir",
        ConnectionDecision::Tun => "tun",
    }
}

fn debug_connection_matches(
    event: &ConnectionEvent,
    mode: DebugUrlMode,
    host: &str,
    resolved_ips: &[IpAddr],
    started_at: u64,
) -> bool {
    if event.timestamp < started_at || event.protocol != "tcp" {
        return false;
    }
    let decision_matches = match mode {
        DebugUrlMode::Redir => matches!(event.decision, ConnectionDecision::Redir | ConnectionDecision::Tun),
        DebugUrlMode::Http => event.decision == ConnectionDecision::HttpProxy,
        DebugUrlMode::Socks => event.decision == ConnectionDecision::Socks5Proxy,
    };
    if !decision_matches {
        return false;
    }
    debug_connection_target_matches(event, host, resolved_ips)
}

fn debug_connection_target_matches(event: &ConnectionEvent, host: &str, resolved_ips: &[IpAddr]) -> bool {
    event
        .destination_domain
        .as_deref()
        .is_some_and(|domain| domain_matches_debug_host(domain, host))
        || event
            .domain
            .as_deref()
            .is_some_and(|domain| domain_matches_debug_host(domain, host))
        || event
            .destination_ip
            .is_some_and(|ip| resolved_ips.iter().any(|resolved| *resolved == ip))
}

fn server_filter_ips(host: &str, port: u16) -> Vec<IpAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return vec![ip];
    }
    (host, port)
        .to_socket_addrs()
        .map(|addrs| addrs.map(|addr| addr.ip()).collect())
        .unwrap_or_default()
}

fn debug_curl_args(url: &str, mode: DebugUrlMode, port: Option<u16>) -> io::Result<Vec<String>> {
    let mut args = vec![
        "-4".to_owned(),
        "-sS".to_owned(),
        "--max-time".to_owned(),
        "6".to_owned(),
        "-o".to_owned(),
        null_device().to_owned(),
        "-w".to_owned(),
        "http_code=%{http_code}\n\
time_namelookup=%{time_namelookup}\n\
time_connect=%{time_connect}\n\
time_appconnect=%{time_appconnect}\n\
time_starttransfer=%{time_starttransfer}\n\
time_total=%{time_total}\n"
            .to_owned(),
    ];
    match (mode, port) {
        (DebugUrlMode::Redir, _) => {
            args.push("--noproxy".to_owned());
            args.push("*".to_owned());
        }
        (DebugUrlMode::Http, Some(port)) => {
            args.push("-x".to_owned());
            args.push(format!("http://127.0.0.1:{port}"));
        }
        (DebugUrlMode::Socks, Some(port)) => {
            args.push("-x".to_owned());
            args.push(format!("socks5h://127.0.0.1:{port}"));
        }
        (mode, None) => {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("{} port not running", mode.as_str()),
            ));
        }
    }
    args.push(url.to_owned());
    Ok(args)
}

fn intended_debug_curl_command(url: &str, mode: DebugUrlMode, port: Option<u16>) -> String {
    match debug_curl_args(url, mode, port) {
        Ok(args) => format_curl_command(&args),
        Err(err) => format!("not executed: {err}"),
    }
}

fn format_curl_command(args: &[String]) -> String {
    let mut parts = [
        "env",
        "-u",
        "http_proxy",
        "-u",
        "https_proxy",
        "-u",
        "HTTP_PROXY",
        "-u",
        "HTTPS_PROXY",
        "-u",
        "all_proxy",
        "-u",
        "ALL_PROXY",
        "-u",
        "no_proxy",
        "-u",
        "NO_PROXY",
        "curl",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<Vec<_>>();
    parts.extend(args.iter().cloned());
    parts
        .iter()
        .map(|part| shell_quote_command_arg(part))
        .collect::<Vec<_>>()
        .join(" ")
}

fn shell_quote_command_arg(arg: &str) -> String {
    if arg
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | '/' | ':' | '=' | '%' | '{' | '}'))
    {
        return arg.replace('\n', "\\n");
    }
    let escaped = arg.replace('\n', "\\n").replace('\'', "'\\''");
    format!("'{escaped}'")
}

fn run_debug_curl(url: &str, mode: DebugUrlMode, port: Option<u16>) -> io::Result<DebugCurlResult> {
    let args = debug_curl_args(url, mode, port)?;
    let command = format_curl_command(&args);

    let output = Command::new("curl")
        .args(args)
        .env_remove("HTTP_PROXY")
        .env_remove("HTTPS_PROXY")
        .env_remove("http_proxy")
        .env_remove("https_proxy")
        .env_remove("ALL_PROXY")
        .env_remove("all_proxy")
        .env_remove("NO_PROXY")
        .env_remove("no_proxy")
        .stdin(Stdio::null())
        .output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let value = |key: &str| {
        stdout
            .lines()
            .find_map(|line| line.strip_prefix(key).map(str::to_owned))
            .unwrap_or_default()
    };
    let http_code = value("http_code=");
    let error = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    Ok(DebugCurlResult {
        command,
        response_received: http_code != "000",
        http_code,
        time_namelookup: value("time_namelookup="),
        time_connect: value("time_connect="),
        time_appconnect: value("time_appconnect="),
        time_starttransfer: value("time_starttransfer="),
        time_total: value("time_total="),
        exit_code: output.status.code(),
        error: (!error.is_empty()).then_some(error),
    })
}

fn null_device() -> &'static str {
    if cfg!(windows) { "NUL" } else { "/dev/null" }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

fn query_param(query: Option<&str>, name: &str) -> Option<String> {
    let query = query?;
    query.split('&').find_map(|part| {
        let (key, value) = part.split_once('=')?;
        (key == name).then(|| {
            value
                .replace('+', " ")
                .split('%')
                .enumerate()
                .fold(String::new(), |mut acc, (idx, chunk)| {
                    if idx == 0 {
                        acc.push_str(chunk);
                    } else if chunk.len() >= 2 {
                        if let Ok(byte) = u8::from_str_radix(&chunk[..2], 16) {
                            acc.push(byte as char);
                            acc.push_str(&chunk[2..]);
                        } else {
                            acc.push('%');
                            acc.push_str(chunk);
                        }
                    } else {
                        acc.push('%');
                        acc.push_str(chunk);
                    }
                    acc
                })
        })
    })
}

fn source_ip_query(query: Option<&str>) -> Option<IpAddr> {
    query_param(query, "source_ip").and_then(|value| value.parse::<IpAddr>().ok())
}

async fn read_json<T: serde::de::DeserializeOwned>(req: Request<Incoming>) -> io::Result<T> {
    let body = req
        .into_body()
        .collect()
        .await
        .map_err(|err| io::Error::other(err.to_string()))?
        .to_bytes();
    serde_json::from_slice(&body).map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))
}

fn json_response<T: serde::Serialize>(status: StatusCode, value: &T) -> Response<ResponseBody> {
    let body = match serde_json::to_vec(value) {
        Ok(body) => body,
        Err(err) => serde_json::json!({ "error": err.to_string() }).to_string().into_bytes(),
    };
    Response::builder()
        .status(status)
        .header("content-type", "application/json; charset=utf-8")
        .body(Full::new(Bytes::from(body)))
        .expect("response")
}

fn html_response(html: &str) -> Response<ResponseBody> {
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/html; charset=utf-8")
        .body(Full::new(Bytes::from(html.to_owned())))
        .expect("response")
}

const INDEX_HTML: &str = r#"<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>shadowsocks-rust routing admin</title>
  <style>
    :root{--bg:#eef3f8;--panel:#ffffff;--ink:#102033;--muted:#667589;--line:#c8d3df;--brand:#1f5f8b;--brand2:#17486c;--soft:#e4eef7}
    html,body{height:100%}
    body{font-family:system-ui,sans-serif;margin:0;padding:24px;background:var(--bg);color:var(--ink);line-height:1.4;box-sizing:border-box;overflow:hidden}
    h1{margin:0 0 6px;color:var(--brand2)}
    nav{position:relative;display:flex;align-items:center;justify-content:center;min-height:38px;padding:0;margin:0 0 16px;background:transparent;border:0;box-shadow:none}
    .nav-tabs{position:relative;display:inline-flex;gap:18px}
    .nav-indicator{position:absolute;top:0;left:0;height:100%;border-radius:9px;background:var(--brand);transition:transform .24s ease,width .24s ease;z-index:0}
    nav button{position:relative;z-index:1;margin:0;background:var(--soft);color:var(--brand2);transition:color .18s ease,background .18s ease}
    nav button:hover{background:#d7e7f4;color:var(--brand2)}
    nav button.active{background:transparent;color:#fff}
    nav button.active:hover{background:transparent;color:#fff}
    .process-uptime{position:absolute;right:0;top:50%;transform:translateY(-50%);display:inline-flex;align-items:center;gap:6px;min-width:128px;justify-content:center;padding:6px 10px;border:1px solid var(--line);border-radius:7px;background:#f8fbfe;color:var(--muted);font-size:12px;font-weight:700;white-space:nowrap;box-sizing:border-box}
    .process-uptime strong{color:var(--brand2)}
    fieldset,.panel{border:1px solid var(--line);border-radius:10px;margin:0 0 8px;padding:9px;background:var(--panel);box-shadow:0 1px 2px #10203312}
    legend{font-weight:700;color:var(--brand2)}
    .card-title{margin:8px 0 5px;font-size:15px;color:var(--brand2)}
    label{display:block;font-size:12px;font-weight:600;margin-top:8px;color:var(--muted)}
    input,select,textarea{width:100%;box-sizing:border-box;margin:2px 0 5px;padding:6px 8px;border:1px solid var(--line);border-radius:7px;background:#fff;color:var(--ink)}
    textarea{min-height:96px;font-family:ui-monospace,monospace}
    button{margin:6px 4px 6px 0;padding:8px 12px;border:0;border-radius:7px;background:var(--brand);color:#fff;font-weight:600;cursor:pointer}
    button:hover{background:var(--brand2)}
    button:disabled{background:#b8c5d1;color:#f7fafc;cursor:not-allowed}
    button:disabled:hover{background:#b8c5d1}
    table{border-collapse:collapse;width:100%;margin-top:10px}
    th,td{border:1px solid var(--line);padding:7px;text-align:left;vertical-align:top;background:var(--panel)}
    th{background:var(--soft);color:var(--brand2)}
    .scroll-panel{overflow:auto;border:1px solid var(--line);border-radius:10px;background:var(--panel);box-shadow:0 1px 2px #10203312}
    #routeConfig .scroll-panel{overflow-x:hidden;overflow-y:auto}
    .section-scroll{height:auto;min-height:0;flex:1}
    .scroll-panel table{margin-top:0}
    .scroll-panel table,.scroll-panel th,.scroll-panel td{user-select:text}
    .scroll-panel th{position:sticky;top:0;z-index:1}
    .copyable-table td{cursor:copy}
    .copyable-table td:hover{background:#f4f9fd}
    .copyable-table td.copied{background:#dff3e8}
    .conflict-table{table-layout:fixed}
    .conflict-table th,.conflict-table td{overflow-wrap:anywhere;word-break:break-word}
    .conflict-table th:nth-child(1),.conflict-table td:nth-child(1){width:42%}
    .conflict-table th:nth-child(2),.conflict-table td:nth-child(2){width:20%}
    .conflict-table th:nth-child(3),.conflict-table td:nth-child(3){width:38%}
    pre{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:12px;overflow:auto}
    .tab{display:none;height:calc(100vh - 88px);min-height:0;overflow:hidden}.tab.active{display:block}
    #basic.tab.active,#connections.tab.active,#routeConfig.tab.active,#sys.tab.active{display:flex;flex-direction:column}
    .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:12px}
    .activity-toolbar{display:flex;align-items:center;gap:10px;margin:0 0 8px}
    .activity-toolbar button{margin:0}
    .activity-toolbar .hint{margin-left:auto}
    .activity-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));grid-template-rows:repeat(2,minmax(0,1fr));gap:16px;align-items:stretch;flex:1;min-height:0}
    .activity-card{min-width:0;min-height:0;display:flex;flex-direction:column}
    .activity-card-head{display:flex;align-items:center;gap:10px;margin:8px 0 5px}
    .activity-card-head .card-title{margin:0}
    .connections-layout{height:100%;min-height:0;flex:1;overflow:hidden;display:flex;flex-direction:column;gap:2px}
    .connections-layout .activity-toolbar{margin:0;flex:0 0 auto}
    .connections-layout .activity-grid{flex:0 0 clamp(360px,58vh,600px);grid-template-rows:minmax(0,1fr);min-height:360px}
    .basic-layout{--basic-control-width:clamp(350px,calc(21vw + 20px),450px);display:grid;grid-template-columns:var(--basic-control-width) var(--basic-control-width) minmax(0,1fr);gap:18px;align-items:start;height:calc(100% - 46px);min-height:0}
    .basic-form-panel,.basic-side-panel{min-height:0;height:var(--basic-sync-height,auto);box-sizing:border-box}
    .basic-form-panel{overflow:visible}
    #serverPanel{display:flex;flex-direction:column;justify-content:space-between;overflow:visible}
    .config-group{min-width:0}
    .basic-json-panel{display:flex;flex-direction:column;min-height:0;height:var(--basic-sync-height,auto);box-sizing:border-box}
    .basic-json-panel textarea{flex:1 1 auto;height:auto}
    .server-block{position:relative}
    .server-head{display:flex;align-items:center;gap:8px;margin-bottom:5px}
    .server-head strong{color:var(--brand2);font-size:13px}
    .modal-backdrop{display:none;position:fixed;inset:0;z-index:100;background:#10203399;padding:24px;box-sizing:border-box}
    .modal-backdrop.open{display:flex;align-items:stretch;justify-content:center}
    .modal-panel{display:flex;flex-direction:column;width:min(1200px,100%);min-height:0;background:var(--panel);border-radius:10px;border:1px solid var(--line);box-shadow:0 18px 40px #10203355;padding:12px}
    .modal-head{display:flex;align-items:center;justify-content:space-between;gap:8px;margin-bottom:8px}
    .modal-head .card-title{margin:0}
    .modal-head button{margin:0}
    .nft-ruleset{flex:1;min-height:0;margin:0;overflow:auto;padding:9px;border:1px solid var(--line);border-radius:10px;background:var(--panel);box-shadow:0 1px 2px #10203312;font-family:ui-monospace,monospace;font-size:12px;white-space:pre;color:var(--ink)}
    .basic-actions{display:flex;justify-content:center;gap:8px;margin-top:8px}
    .basic-actions button{margin:0}
    .binary-commit{text-align:center;color:var(--muted);font-size:12px;margin-top:6px;font-family:ui-monospace,monospace}
    .route-toolbar{text-align:center;margin:8px 0 0}
    .route-toolbar .hint{margin:4px 0 0}
    .route-toolbar .progress-box{margin:8px auto 0;width:min(760px,100%);box-sizing:border-box}
    .route-config-layout{display:grid;grid-template-columns:minmax(0,.9fr) minmax(0,.9fr) minmax(0,1.2fr);grid-template-rows:minmax(0,1fr);gap:12px;min-height:0;flex:1}
    .route-config-column{min-width:0;min-height:0;display:flex;flex-direction:column}
    .route-config-column .scroll-panel{min-height:0;flex:1}
    .route-config-column .progress-box{height:auto;margin:2px 0 5px;max-width:none;max-height:none;box-sizing:border-box}
    .route-rules-layout{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:12px;align-items:start;margin-top:8px;min-height:0}
    .temporary-panel{display:flex;flex-direction:column}
    .temporary-panel .route-rules-layout{flex:1;align-items:stretch;margin-top:0}
    .temporary-panel fieldset{display:flex;flex-direction:column;margin:0}
    .temporary-panel label{display:flex;flex-direction:column;flex:1;min-height:0}
    .temporary-panel textarea{flex:1;min-height:0}
    .dns-layout{display:grid;grid-template-columns:minmax(320px,420px) 1fr;gap:18px;min-height:0;flex:1}
    .connections-dns{flex:1 1 0;min-height:0;overflow:hidden}
    .connections-dns .card-title{margin-top:0}
    .connections-dns .dns-panel{height:100%;box-sizing:border-box}
    .connections-dns .dns-panel:last-child{display:flex;flex-direction:column}
    .connections-dns #dnsCacheOut{flex:1;min-height:0}
    .dns-panel{min-height:0;overflow:auto}
    .sys-layout{min-height:0;flex:1;overflow:auto}
    .status-ok{color:#18864b;font-weight:700}
    .status-warn{color:#b15d00;font-weight:700}
    .form-line{display:grid;grid-template-columns:150px 1fr;gap:5px;align-items:center;margin:4px 0}
    .form-line label{margin:0;font-size:13px}
    .form-line input[type=checkbox]{width:16px;height:16px;margin:0;justify-self:start}
    .client-select{position:relative;min-height:32px;min-width:0;width:100%;max-width:100%}
    .client-select-button{display:flex;align-items:center;justify-content:space-between;gap:8px;width:100%;margin:0;padding:7px 9px;border:1px solid var(--line);border-radius:7px;background:#f8fbfe;color:var(--ink);text-align:left}
    .client-select-button:hover{background:#eef6fd;color:var(--ink)}
    .client-select-summary{min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
    .client-select-caret{color:var(--muted);font-size:11px;flex:0 0 auto}
    .client-select-panel{display:none;position:absolute;z-index:30;top:calc(100% + 4px);left:0;right:0;max-height:220px;overflow:auto;border:1px solid var(--line);border-radius:7px;background:#fff;box-shadow:0 8px 22px #10203324;padding:5px}
    .client-select.open .client-select-panel{display:block}
    .client-row{display:flex;align-items:center;gap:6px;border-radius:6px;padding:6px 7px;background:#fff;min-width:0;cursor:pointer}
    .client-row:hover{background:#f4f9fd}
    .client-row input{width:16px;height:16px;margin:0;flex:0 0 auto}
    .client-row span{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
    .filter-inline{display:flex;align-items:center;gap:6px;min-width:220px}
    .filter-inline input{margin:0}
    #clientConfig{min-height:0;height:auto;max-height:none;overflow:auto;resize:vertical;font-size:13px}
    #routeConfig .route-config-column>.scroll-panel{height:auto}
    #routeConfig .route-rules-layout textarea{height:clamp(56px,8vh,96px);min-height:56px;resize:vertical}
    .row{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:8px;align-items:center;margin:4px 0}
    .row input{margin:0}
    .row button{margin:0;white-space:nowrap}
    .hint{color:var(--muted);font-size:12px}
    .inline-check{display:inline-flex;align-items:center;gap:4px;margin:0 0 0 10px;font-size:12px;font-weight:600;color:var(--muted)}
    .inline-check input{width:auto;margin:0}
    .record-countdown{min-width:38px;color:var(--brand2)}
    .dns-cache-clean-title{font-size:12px;font-weight:600;margin-top:8px;color:var(--muted)}
    .progress-box{margin:8px auto 0;max-width:760px;max-height:120px;overflow:auto;text-align:left;background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:10px;box-shadow:0 1px 2px #10203312}
    .progress-bar{height:10px;background:var(--soft);border-radius:999px;overflow:hidden;margin:8px 0}
    .progress-fill{height:100%;width:0;background:var(--brand)}
    .progress-completed{white-space:pre-line;margin-top:8px}
    @media(max-width:1300px){.route-config-layout{grid-template-columns:1fr}.route-config-column{min-height:260px}}
    @media(max-width:1000px){.rules-workspace{grid-template-columns:1fr}}
    @media(max-width:1100px){.activity-grid,.route-rules-layout{grid-template-columns:1fr}.activity-grid{grid-template-rows:repeat(4,minmax(0,1fr))}.connections-layout .activity-grid{grid-template-rows:repeat(2,minmax(0,1fr))}}
    @media(max-width:700px){nav{justify-content:flex-start;gap:10px}.process-uptime{position:static;transform:none;margin-left:auto;min-width:0}}
    @media(max-width:1200px){.basic-layout{--basic-control-width:minmax(340px,440px);grid-template-columns:var(--basic-control-width) var(--basic-control-width);grid-auto-rows:minmax(0,1fr)}.basic-json-panel{grid-column:1 / -1}}
    @media(max-width:900px){.basic-layout{grid-template-columns:1fr}#clientConfig{height:auto;max-height:none}.basic-json-panel{grid-column:auto}}
  </style>
</head>
<body>
  <nav>
    <div class="nav-tabs">
      <span class="nav-indicator" aria-hidden="true"></span>
      <button data-tab="basic" onclick="show('basic')">Basic</button>
      <button data-tab="connections" onclick="show('connections')">Connections</button>
      <button data-tab="routeConfig" onclick="show('routeConfig')">Route</button>
      <button data-tab="sys" onclick="show('sys')">Sys</button>
    </div>
    <div id="processUptime" class="process-uptime" title="Process uptime"><strong>Uptime</strong><span id="processUptimeValue">-</span></div>
  </nav>

  <section id="basic" class="tab active">
    <p class="hint" id="configPath"></p>
    <div class="basic-layout">
      <div id="basicFormPanel" class="basic-form-panel">
        <div class="config-group">
          <h3 class="card-title">SOCKS Local</h3>
          <fieldset>
            <div class="form-line"><label>Bind Address</label><select id="socksBind"><option>127.0.0.1</option><option>0.0.0.0</option><option>::</option></select></div>
            <div class="form-line"><label>Port</label><input id="socksPort" type="number" min="1" max="65535"></div>
          </fieldset>
        </div>
        <div class="config-group">
          <h3 class="card-title">Futu SOCKS Local</h3>
          <fieldset>
            <div class="form-line"><label>Bind Address</label><select id="futuSocksBind"><option>127.0.0.1</option><option>0.0.0.0</option><option>::</option></select></div>
            <div class="form-line"><label>Port</label><input id="futuSocksPort" type="number" min="1" max="65535" value="1082"></div>
          </fieldset>
        </div>
        <div class="config-group">
          <h3 class="card-title">HTTP Local</h3>
          <fieldset>
            <div class="form-line"><label>Bind Address</label><select id="httpBind"><option>127.0.0.1</option><option>0.0.0.0</option><option>::</option></select></div>
            <div class="form-line"><label>Port</label><input id="httpPort" type="number" min="1" max="65535"></div>
          </fieldset>
        </div>
        <div class="config-group">
          <h3 class="card-title">DNS Listener</h3>
          <fieldset>
            <div class="form-line"><label>Enable DNS</label><input id="dnsEnable" type="checkbox"></div>
            <div class="form-line"><label>Bind Address</label><select id="dnsBind"><option>127.0.0.1</option><option>0.0.0.0</option><option>::</option></select></div>
            <div class="form-line"><label>Port</label><input id="dnsPort" type="number" min="1" max="65535"></div>
            <div class="form-line"><label>Domestic DNS</label><input id="dnsDomestic" placeholder="223.5.5.5:53"></div>
            <div class="form-line"><label>Foreign DNS</label><input id="dnsForeign" placeholder="8.8.8.8:53"></div>
            <div class="form-line"><label>Cache Capacity</label><input id="dnsCacheCapacity" type="number" min="1"></div>
            <div class="form-line"><label>Cache TTL Seconds</label><input id="dnsCacheTtl" type="number" min="1"></div>
            <div class="form-line"><label>Async Refresh</label><input id="dnsCacheRefreshEnabled" type="checkbox"></div>
            <div class="form-line"><label>Refresh Batch Size</label><input id="dnsCacheRefreshBatch" type="number" min="1"></div>
            <div class="form-line"><label>Intercept Mode</label><select id="dnsInterceptMode"><option>off</option><option>firewall</option><option>tun</option><option>both</option></select></div>
            <div class="form-line"><label title="Strip AAAA records from DNS responses. Avoids browser happy-eyeballs delay on hosts without working public IPv6.">Address Family</label><select id="dnsIpv4Only"><option value="true">IPv4 only (recommended)</option><option value="false">IPv4 + IPv6</option></select></div>
          </fieldset>
        </div>
      </div>
      <div id="serverPanel" class="basic-side-panel">
        <div class="config-group">
          <h3 class="card-title">Transparent Proxy</h3>
          <fieldset>
            <div class="form-line"><label>Enable Redir</label><input id="redirEnable" type="checkbox"></div>
            <div class="form-line"><label>Global Proxy</label><input id="globalProxy" type="checkbox"></div>
            <div class="form-line"><label>Global Proxy Client</label><div id="clientGlobalProxyList" class="client-list"></div></div>
            <div class="form-line"><label>Direct Client</label><div id="clientDirectList" class="client-list"></div></div>
            <div class="form-line"><label>Bind Address</label><select id="redirBind"><option>127.0.0.1</option><option>0.0.0.0</option><option>::</option></select></div>
            <div class="form-line"><label>Port</label><input id="redirPort" type="number" min="1" max="65535"></div>
            <input id="redirMode" type="hidden">
            <div class="form-line tun-field"><label>TUN Name</label><input id="tunName" placeholder="shadowsocks-tun"></div>
            <div class="form-line tun-field"><label>TUN Address</label><input id="tunAddress" placeholder="10.255.0.1/24"></div>
            <div class="form-line tun-field"><label>TUN Destination</label><input id="tunDestination" placeholder="10.255.0.2/24"></div>
          </fieldset>
        </div>
        <div class="config-group">
          <h3 class="card-title">Server</h3>
          <div id="serverList"></div>
        </div>
      </div>
      <div id="basicJsonPanel" class="basic-json-panel">
        <h3 class="card-title">Generated JSON</h3>
        <textarea id="clientConfig"></textarea>
      </div>
    </div>
    <div class="basic-actions">
      <button id="reloadButton" onclick="loadClientConfig()">Reload</button>
      <button id="saveButton" onclick="saveClientConfig()">Save</button>
      <button id="restartButton" onclick="restartService()">Restart</button>
      <button id="nftRulesetRefresh" onclick="openNftRulesetModal()">nft table</button>
    </div>
    <div id="binaryCommit" class="binary-commit"></div>
    <div id="nftModal" class="modal-backdrop" onclick="closeNftRulesetModal(event)">
      <div class="modal-panel" onclick="event.stopPropagation()">
        <div class="modal-head">
          <h3 class="card-title">nft list ruleset</h3>
          <button type="button" onclick="closeNftRulesetModal()">Close</button>
        </div>
        <pre id="nftRuleset" class="nft-ruleset"></pre>
      </div>
    </div>
  </section>

  <section id="connections" class="tab">
    <div class="connections-layout">
      <div class="activity-toolbar">
        <label class="inline-check"><input id="activityRecord" type="checkbox" onchange="toggleActivityRecord(this.checked)"> Record <span id="activityRecordCountdown" class="record-countdown"></span></label>
        <button id="activityPause" type="button" onclick="toggleActivityPause()">Pause</button>
        <label class="filter-inline hint">Source IP <input id="activitySourceFilter" list="dhcpClientIps" placeholder="all clients" oninput="refresh('connections')"></label>
        <span id="activityPauseState" class="hint"></span>
      </div>
      <datalist id="dhcpClientIps"></datalist>
      <div class="activity-grid">
        <div class="activity-card">
          <div class="activity-card-head">
            <h3 class="card-title">Recent DNS</h3>
            <label class="inline-check"><input id="dnsShowAaaa" type="checkbox" onchange="renderDnsTable()"> Show AAAA</label>
          </div>
          <div id="dnsOut" class="scroll-panel section-scroll"></div>
        </div>
        <div class="activity-card">
          <h3 class="card-title">Recent Connections</h3>
          <div id="connOut" class="scroll-panel section-scroll"></div>
        </div>
      </div>
      <div class="dns-layout connections-dns">
        <div class="panel dns-panel">
          <h3 class="card-title">Cache Management</h3>
          <label>Domain<input id="dnsQueryDomain" placeholder="example.com"></label>
          <label>Record Type<select id="dnsQueryType"><option>A</option><option>AAAA</option></select></label>
          <button onclick="queryDnsCache()">Query Cache</button>
          <button onclick="clearDnsDomain()">Clear Domain Dns Cache</button>
          <div class="dns-cache-clean-title">Dns Cache Clean</div>
          <button onclick="clearDnsAll()">Clear All Dns Cache</button>
          <label>IP<input id="dnsQueryIp" placeholder="142.251.151.119"></label>
          <button onclick="queryDnsCacheIp()">Query Domain By IP</button>
          <p class="hint" id="dnsCacheMessage"></p>
        </div>
        <div class="dns-panel">
          <h3 class="card-title">Cached Results</h3>
          <div id="dnsCacheOut" class="scroll-panel section-scroll"></div>
        </div>
      </div>
    </div>
  </section>

  <section id="routeConfig" class="tab">
    <div class="route-config-layout">
      <div class="route-config-column">
        <h3 class="card-title">Domain Conflicts</h3>
        <div id="domainOut" class="scroll-panel section-scroll"></div>
      </div>
      <div class="route-config-column">
        <h3 class="card-title">IP Conflicts</h3>
        <div id="ipOut" class="scroll-panel section-scroll"></div>
      </div>
      <div class="route-config-column">
        <h3 class="card-title">Temporary Lists</h3>
        <div class="scroll-panel section-scroll temporary-panel">
          <div class="route-rules-layout" style="padding:9px">
            <fieldset>
              <label>Direct IP<textarea id="tmp_direct_ip"></textarea></label>
              <label>Direct Domain<textarea id="tmp_direct_domain"></textarea></label>
            </fieldset>
            <fieldset>
              <label>Proxy IP<textarea id="tmp_proxy_ip"></textarea></label>
              <label>Proxy Domain<textarea id="tmp_proxy_domain"></textarea></label>
            </fieldset>
          </div>
          <p class="hint" style="padding:0 9px 9px">Temporary lists have priority over generated direct/proxy files. proxy_ip supports "IP_OR_CIDR domain"; old one-column rows still work.</p>
        </div>
      </div>
    </div>
    <div class="route-toolbar">
      <button onclick="reloadRouteTab()">Reload</button>
      <button onclick="saveTempRules()">Save</button>
      <button onclick="downloadRules()">Download</button>
      <button onclick="generateRules()">Generate</button>
      <p class="hint">Sources are configured in Basic and refreshed weekly. Generate preserves direct_ip.txt, direct_domain.txt, and learned proxy_ip.txt rows, rebuilds proxy_domain.txt from gfw.txt, and uses geoip.dat only for IP conflict checks. Temporary Lists are saved only under data/temp and restored into memory.</p>
      <div id="ruleUpdateProgress" class="progress-box">
        <div><strong>Status:</strong> <span id="progressStatus">idle</span></div>
        <div class="progress-bar"><div id="progressFill" class="progress-fill"></div></div>
        <div><strong>Current source:</strong> <span id="progressSource">-</span></div>
        <div><strong>Progress:</strong> <span id="progressPercent">0%</span>, <strong>remaining files:</strong> <span id="progressRemaining">0</span></div>
        <div class="hint" id="progressMessage"></div>
        <div class="hint progress-completed" id="progressCompleted"></div>
      </div>
    </div>
  </section>

  <section id="sys" class="tab">
    <div class="panel sys-layout">
      <h3 class="card-title">System Checks</h3>
      <div id="sysStatusOut"></div>
      <h3 class="card-title">Debug redir</h3>
      <div class="row">
        <input id="debugRedirUrl" value="https://www.google.com/generate_204">
        <button onclick="debugUrlCheck('redir')">Debug redir</button>
      </div>
      <div id="debugRedirOut" class="scroll-panel" style="padding:9px;margin-top:8px"></div>
      <h3 class="card-title">Debug http</h3>
      <div class="row">
        <input id="debugHttpUrl" value="https://www.google.com/generate_204">
        <button onclick="debugUrlCheck('http')">Debug http</button>
      </div>
      <div id="debugHttpOut" class="scroll-panel" style="padding:9px;margin-top:8px"></div>
      <h3 class="card-title">Debug socks</h3>
      <div class="row">
        <input id="debugSocksUrl" value="https://www.google.com/generate_204">
        <button onclick="debugUrlCheck('socks')">Debug socks</button>
      </div>
      <div id="debugSocksOut" class="scroll-panel" style="padding:9px;margin-top:8px"></div>
      <h3 class="card-title">Debug IP / CIDR</h3>
      <div class="row">
        <input id="debugIp" placeholder="142.251.155.119 or 142.251.155.0/24">
        <button onclick="debugIpCheck()">Check</button>
      </div>
      <div id="debugIpOut" class="scroll-panel" style="padding:9px;margin-top:8px"></div>
    </div>
  </section>

  <script>
    let currentConfigPath='', currentRawConfig={}, servicePlatform=null;
    const defaultGeoipSources=['https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat'];
    const defaultProxyDomainSources=['https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/gfw.txt'];
    function token(){return new URLSearchParams(location.search).get('token')||''}
    async function api(path,opt={}){let timeoutMs=opt.timeoutMs||0;delete opt.timeoutMs;let timer=null,controller=null;if(timeoutMs){controller=new AbortController();opt.signal=controller.signal;timer=setTimeout(()=>controller.abort(),timeoutMs)}opt.headers=Object.assign({'x-admin-token':token()},opt.headers||{});try{let r=await fetch(path,opt);let j=await r.json();if(!r.ok)throw new Error(j.error||r.statusText);return j}finally{if(timer)clearTimeout(timer)}}
    async function platform(){if(!servicePlatform)servicePlatform=await api('/api/sys/platform');return servicePlatform}
    function isWindowsService(){return servicePlatform&&servicePlatform.target_os==='windows'}
    let activeTab='basic', activityTimer=null, activityPaused=false, recentDnsRows=[], restartInProgress=false, dhcpClients=[], lanAddresses=[];
    function updateNavIndicator(){
      let active=document.querySelector('nav button.active'), indicator=document.querySelector('.nav-indicator'), tabs=document.querySelector('.nav-tabs');
      if(!active||!indicator||!tabs)return;
      indicator.style.width=active.offsetWidth+'px';
      indicator.style.transform='translateX('+active.offsetLeft+'px)';
    }
    function show(id){
      activeTab=id;
      if(activityTimer){clearInterval(activityTimer);activityTimer=null}
      document.querySelectorAll('.tab').forEach(e=>e.classList.remove('active'));
      document.getElementById(id).classList.add('active');
      document.querySelectorAll('nav button').forEach(b=>b.classList.toggle('active',b.dataset.tab===id));
      updateNavIndicator();
      refresh(id);
      if(id==='connections')activityTimer=setInterval(()=>{if(!activityPaused)refresh('connections').catch(e=>{console.warn(e)})},1000);
      if(id==='routeConfig')activityTimer=setInterval(()=>renderRouteConflicts().catch(e=>{console.warn(e)}),3000);
    }
    function lines(v){return (v||'').split('\n').map(s=>s.trim()).filter(Boolean)}
    function setLines(id,arr){document.getElementById(id).value=(arr||[]).join('\n')}
    function num(v,d){let n=parseInt(v,10);return Number.isFinite(n)?n:d}
    function firstLocal(protocol){return (currentRawConfig.locals||[]).find(l=>l.protocol===protocol&&!l.record_proxy_ip)||{}}
    function futuSocksLocal(){return (currentRawConfig.locals||[]).find(l=>l.protocol==='socks'&&l.record_proxy_ip)||{}}
    const bindSelectIds=['socksBind','futuSocksBind','httpBind','dnsBind','redirBind'];
    function setSelect(id,value){let el=document.getElementById(id); if([...el.options].some(o=>o.value===value)){el.value=value}else{let opt=document.createElement('option');opt.value=value;opt.textContent=value;el.appendChild(opt);el.value=value}}
    function renderBindAddressOptions(){
      let values=['127.0.0.1','0.0.0.0','::',...lanAddresses.map(item=>String(item.address)).filter(Boolean)];
      values=[...new Set(values)];
      bindSelectIds.forEach(id=>{
        let el=document.getElementById(id), current=el.value;
        el.innerHTML=values.map(value=>`<option value="${esc(value)}">${esc(value)}</option>`).join('');
        if(current)setSelect(id,current);
      });
    }
    function routeIpArray(v){return Array.isArray(v)?v.map(String).filter(Boolean):[]}
    function clientLabel(ip){
      let c=dhcpClients.find(x=>clientIps(x).includes(String(ip)));
      if(!c)return ip+' offline';
      return clientDisplay(c);
    }
    function clientIps(client){
      let ips=Array.isArray(client&&client.ips)?client.ips:[];
      ips=ips.map(String).filter(Boolean);
      return [...new Set(ips)].sort((a,b)=>a.localeCompare(b,undefined,{numeric:true}));
    }
    function clientPrimaryIp(ips){return ips.find(ip=>ip.includes('.'))||ips[0]||''}
    function clientFirstIpv6(ips){return ips.find(ip=>ip.includes(':'))||''}
    function compactIpv6(ip){
      if(!ip)return '';
      let parts=ip.split(':').filter(Boolean);
      return parts.length>4?parts.slice(0,4).join(':')+':...':ip;
    }
    function clientKey(client){return clientIps(client).join('|')}
    function clientDisplay(client){
      let ips=clientIps(client), name=(client&&client.hostname)||'Unknown';
      return (name?name+' ':'')+ips.join(' ');
    }
    function clientSummary(client){
      let ips=clientIps(client), name=(client&&client.hostname)||'Unknown', primary=clientPrimaryIp(ips), firstV6=clientFirstIpv6(ips);
      let shown=[primary,compactIpv6(firstV6)].filter(Boolean), extra=Math.max(0,ips.length-shown.length);
      return (name?name+' ':'')+shown.join(' ')+(extra?(' +'+extra):'');
    }
    function clientRowsForPolicy(selectedProxy,selectedDirect){
      let rows=[], knownIps=new Set();
      dhcpClients.forEach((client,index)=>{
        let ips=clientIps(client);
        if(!ips.length)return;
        ips.forEach(ip=>knownIps.add(ip));
        rows.push({key:clientKey(client)||('client-'+index),ips,label:clientDisplay(client),summary:clientSummary(client)});
      });
      [...selectedProxy,...selectedDirect].forEach(ip=>{
        if(!knownIps.has(ip))rows.push({key:'offline-'+ip,ips:[ip],label:ip+' offline',summary:ip+' offline'});
      });
      let seen=new Set();
      return rows.filter(row=>{
        if(seen.has(row.key))return false;
        seen.add(row.key);
        return true;
      }).sort((a,b)=>a.label.localeCompare(b.label,undefined,{numeric:true}));
    }
    function renderDhcpDatalist(){
      let el=document.getElementById('dhcpClientIps');
      if(!el)return;
      el.innerHTML=dhcpClients.flatMap(c=>clientIps(c).map(ip=>`<option value="${esc(ip)}">${esc(clientDisplay(c))}</option>`)).join('');
    }
    function renderClientPolicyLists(routeRules){
      let selectedProxy=new Set(routeIpArray(routeRules.client_global_proxy_ips));
      let selectedDirect=new Set(routeIpArray(routeRules.client_direct_ips));
      let rows=clientRowsForPolicy(selectedProxy,selectedDirect);
      renderClientPolicyList('clientGlobalProxyList',rows,selectedProxy,'client-global-proxy');
      renderClientPolicyList('clientDirectList',rows,selectedDirect,'client-direct');
      renderDhcpDatalist();
    }
    function renderClientPolicyList(id,rows,selected,cls){
      let box=document.getElementById(id);
      box.className='client-select';
      let options=rows.length?rows.map(row=>`<label class="client-row"><input class="${cls}" type="checkbox" value="${esc(row.key)}" data-ips="${esc(row.ips.join(' '))}" data-summary="${esc(row.summary)}" ${row.ips.some(ip=>selected.has(ip))?'checked':''} onchange="onClientPolicyChange(this)"><span title="${esc(row.label)}">${esc(row.summary)}</span></label>`).join(''):'<div class="hint" style="padding:6px 7px">No DHCP clients</div>';
      box.innerHTML=`<button type="button" class="client-select-button" onclick="toggleClientSelect(event,'${id}')"><span class="client-select-summary"></span><span class="client-select-caret">v</span></button><div class="client-select-panel">${options}</div>`;
      updateClientSelectSummary(id);
    }
    function toggleClientSelect(event,id){
      event.preventDefault();
      event.stopPropagation();
      let box=document.getElementById(id), open=!box.classList.contains('open');
      document.querySelectorAll('.client-select.open').forEach(el=>{if(el!==box)el.classList.remove('open')});
      box.classList.toggle('open',open);
    }
    document.addEventListener('click',event=>{
      if(!event.target.closest('.client-select'))document.querySelectorAll('.client-select.open').forEach(el=>el.classList.remove('open'));
    });
    function updateClientSelectSummary(id){
      let box=document.getElementById(id), summary=box&&box.querySelector('.client-select-summary');
      if(!summary)return;
      let labels=[...box.querySelectorAll('input[type=checkbox]:checked')].map(el=>el.dataset.summary||el.value);
      if(!labels.length){summary.textContent='None';return}
      summary.textContent=labels.length===1?labels[0]:(labels.length+' selected: '+labels.slice(0,2).join(', ')+(labels.length>2?' ...':''));
    }
    function onClientPolicyChange(input){
      let other=input.classList.contains('client-global-proxy')?'client-direct':'client-global-proxy';
      if(input.checked)document.querySelectorAll('input.'+other).forEach(el=>{if(el.value===input.value)el.checked=false});
      updateClientSelectSummary('clientGlobalProxyList');
      updateClientSelectSummary('clientDirectList');
      updateClientJson();
    }
    function selectedClientIps(cls){
      let ips=[];
      document.querySelectorAll('input.'+cls+':checked').forEach(el=>ips.push(...String(el.dataset.ips||el.value).split(/\s+/).filter(Boolean)));
      return [...new Set(ips)].sort((a,b)=>a.localeCompare(b,undefined,{numeric:true}));
    }
    function serverFormHtml(server,index){
      let method=server.method||'aes-256-gcm';
      return `<fieldset class="server-block" data-index="${index}">
        <div class="server-head"><strong>Server ${index+1}</strong></div>
        <div class="form-line"><label>Enable</label><input class="server-enabled" type="checkbox" ${server.disabled===true?'':'checked'}></div>
        <div class="form-line"><label>Server Address</label><input class="server-host" value="${esc(server.server||'')}"></div>
        <div class="form-line"><label>Server Port</label><input class="server-port" type="number" min="1" max="65535" value="${esc(server.server_port||443)}"></div>
        <input class="server-method" type="hidden" value="${esc(method)}">
        <input class="server-secret" name="ss-server-secret-${index}" type="hidden" autocomplete="off" autocapitalize="none" spellcheck="false" data-lpignore="true" data-1p-ignore="true" value="${esc(server.password||'')}">
        <div class="form-line"><label>Timeout Seconds</label><input class="server-timeout" type="number" min="1" value="${esc(server.timeout||300)}"></div>
        <div class="form-line"><label>Plugin Path</label><input class="server-plugin" value="${esc(server.plugin||'')}"></div>
        <div class="form-line"><label>Plugin Options</label><input class="server-plugin-opts" value="${esc(server.plugin_opts||'')}"></div>
      </fieldset>`;
    }
    function renderServerList(){
      let servers=(currentRawConfig.servers||[]).length?currentRawConfig.servers:[{}];
      serverList.innerHTML=servers.map((server,index)=>serverFormHtml(server,index)).join('');
    }
    function readServerForms(){
      let blocks=[...document.querySelectorAll('.server-block')];
      return blocks.map(block=>{
        let server={
          server:block.querySelector('.server-host').value.trim(),
          server_port:num(block.querySelector('.server-port').value,443),
          password:block.querySelector('.server-secret').value,
          timeout:num(block.querySelector('.server-timeout').value,300),
          method:block.querySelector('.server-method').value,
          disabled:!block.querySelector('.server-enabled').checked
        };
        let plugin=block.querySelector('.server-plugin').value.trim();
        let pluginOpts=block.querySelector('.server-plugin-opts').value.trim();
        if(plugin)server.plugin=plugin;
        if(pluginOpts)server.plugin_opts=pluginOpts;
        return server;
      }).filter(server=>server.server);
    }
    function renderBasic(){
      let socks=firstLocal('socks'), futu=futuSocksLocal(), http=firstLocal('http'), redir=firstLocal('redir'), tun=firstLocal('tun'), dns=firstLocal('dns');
      let routeRules=currentRawConfig.route_rules||{};
      renderBindAddressOptions();
      setSelect('socksBind',socks.local_address||'127.0.0.1'); socksPort.value=socks.local_port||1080;
      setSelect('futuSocksBind',futu.local_address||socks.local_address||'0.0.0.0'); futuSocksPort.value=futu.local_port||1082;
      setSelect('httpBind',http.local_address||'127.0.0.1'); httpPort.value=http.local_port||1081;
      globalProxy.checked=!!routeRules.global_proxy;
      renderClientPolicyLists(routeRules);
      redirEnable.checked=!!(redir.protocol||tun.protocol)&&(redir.disabled!==true&&tun.disabled!==true);
      setSelect('redirBind',redir.local_address||'0.0.0.0'); redirPort.value=redir.local_port||12345;
      redirMode.value=redir.mode||tun.mode||'tcp_and_udp';
      tunName.value=tun.tun_interface_name||'shadowsocks-tun';
      tunAddress.value=tun.tun_interface_address||'10.255.0.1/24';
      tunDestination.value=tun.tun_interface_destination||'10.255.0.2/24';
      document.querySelectorAll('.tun-field').forEach(e=>e.style.display=isWindowsService()?'grid':'none');
      dnsEnable.checked=(!!dns.protocol&&dns.disabled!==true)||!!tun.protocol;
      if(tun.protocol&&isWindowsService()){
        setSelect('dnsBind','0.0.0.0'); dnsPort.value=53; setSelect('dnsInterceptMode','tun');
      }else{
        setSelect('dnsBind',dns.local_address||'127.0.0.1'); dnsPort.value=dns.local_port||1053;
        setSelect('dnsInterceptMode',routeRules.dns_intercept_mode||'off');
      }
      dnsDomestic.value=(dns.local_dns_address||'223.5.5.5')+':'+(dns.local_dns_port||53);
      dnsForeign.value=(dns.remote_dns_address||'8.8.8.8')+':'+(dns.remote_dns_port||53);
      dnsCacheCapacity.value=routeRules.dns_cache_capacity||10000;
      dnsCacheTtl.value=routeRules.dns_cache_ttl_seconds||604800;
      dnsCacheRefreshEnabled.checked=routeRules.dns_cache_refresh_enabled!==false;
      dnsCacheRefreshBatch.value=routeRules.dns_cache_refresh_batch_size||500;
      setSelect('dnsIpv4Only', (routeRules.dns_ipv4_only===false ? 'false' : 'true'));
      renderServerList();
      updateClientJson();
    }
    function buildClientConfig(){
      const wantsRedir=redirEnable.checked;
      const wantsGlobalProxy=wantsRedir&&globalProxy.checked;
      const wantsDns=dnsEnable.checked||wantsRedir;
      const effectiveDnsInterceptMode=wantsRedir&&!isWindowsService()&&dnsInterceptMode.value==='off'?'both':dnsInterceptMode.value;
      let locals=[
        {local_address:socksBind.value,local_port:num(socksPort.value,1080),protocol:'socks'},
        {local_address:futuSocksBind.value,local_port:num(futuSocksPort.value,1082),protocol:'socks',record_proxy_ip:true},
        {local_address:httpBind.value,local_port:num(httpPort.value,1081),protocol:'http'}
      ];
      const existingRedir=firstLocal('redir');
      if(isWindowsService()){
        locals.push({disabled:!wantsRedir,protocol:'tun',mode:redirMode.value,tun_interface_name:tunName.value.trim()||'shadowsocks-tun',tun_interface_address:tunAddress.value.trim()||'10.255.0.1/24',tun_interface_destination:tunDestination.value.trim()||'10.255.0.2/24'});
      }else{
        locals.push({disabled:!wantsRedir,local_address:redirBind.value,local_port:num(redirPort.value,12345),protocol:'redir',mode:redirMode.value,tcp_redir:existingRedir.tcp_redir||'redirect',udp_redir:existingRedir.udp_redir||'tproxy'});
      }
      const windowsTun=wantsRedir&&isWindowsService();
      let routeRules=Object.assign({},currentRawConfig.route_rules||{});
      if(!Array.isArray(routeRules.geoip_sources)||!routeRules.geoip_sources.length)routeRules.geoip_sources=defaultGeoipSources.slice();
      if(!Array.isArray(routeRules.proxy_domain_sources)||!routeRules.proxy_domain_sources.length)routeRules.proxy_domain_sources=defaultProxyDomainSources.slice();
      routeRules.dns_cache_capacity=num(dnsCacheCapacity.value,10000);
      routeRules.dns_cache_ttl_seconds=num(dnsCacheTtl.value,604800);
      routeRules.dns_cache_refresh_enabled=dnsCacheRefreshEnabled.checked;
      routeRules.dns_cache_refresh_batch_size=num(dnsCacheRefreshBatch.value,500);
      routeRules.global_proxy=wantsGlobalProxy;
      routeRules.client_global_proxy_ips=selectedClientIps('client-global-proxy');
      routeRules.client_direct_ips=selectedClientIps('client-direct');
      routeRules.dns_intercept_mode=windowsTun?'tun':(wantsRedir?(isWindowsService()&&effectiveDnsInterceptMode==='firewall'?'tun':effectiveDnsInterceptMode):'off');
      routeRules.dns_ipv4_only=(dnsIpv4Only.value!=='false');
      let domesticEntry=dnsDomestic.value.trim()||'223.5.5.5:53';
      let foreignEntry=dnsForeign.value.trim()||'8.8.8.8:53';
      let domestic=parseHostPort(domesticEntry,'223.5.5.5',53);
      let foreign=parseHostPort(foreignEntry,'8.8.8.8',53);
      const dnsPortValue=windowsTun?53:num(dnsPort.value,1053);
      const dnsBindValue=windowsTun?'0.0.0.0':dnsBind.value;
      locals.push({disabled:!wantsDns,local_address:dnsBindValue,local_port:dnsPortValue,protocol:'dns',mode:'tcp_and_udp',local_dns_address:domestic.host,local_dns_port:domestic.port,remote_dns_address:foreign.host,remote_dns_port:foreign.port,client_cache_size:64});
      let servers=readServerForms();
      return Object.assign({},currentRawConfig,{locals,servers,route_rules:routeRules});
    }
    function parseHostPort(value,hostDefault,portDefault){
      let text=(value||'').trim();
      if(!text)return {host:hostDefault,port:portDefault};
      if(text.startsWith('[')){
        let end=text.indexOf(']');
        if(end>0){
          let port=text[end+1]===':'?parseInt(text.slice(end+2),10):NaN;
          return {host:text.slice(1,end),port:Number.isFinite(port)?port:portDefault};
        }
      }
      let idx=text.lastIndexOf(':');
      if(idx>0&&text.indexOf(':')===idx){
        let port=parseInt(text.slice(idx+1),10);
        if(Number.isFinite(port))return {host:text.slice(0,idx).replace(/^\[|\]$/g,''),port};
      }
      return {host:text.replace(/^\[|\]$/g,''),port:portDefault};
    }
    function syncClientJsonHeight(){
      let layout=document.querySelector('.basic-layout'), left=document.getElementById('basicFormPanel'), panel=document.getElementById('serverPanel'), jsonPanel=document.getElementById('basicJsonPanel');
      if(!layout||!left||!panel||!jsonPanel)return;
      if(Math.abs(left.getBoundingClientRect().top-panel.getBoundingClientRect().top)>2||Math.abs(left.getBoundingClientRect().top-jsonPanel.getBoundingClientRect().top)>2){
        layout.style.removeProperty('--basic-sync-height');
        return;
      }
      layout.style.setProperty('--basic-sync-height',Math.ceil(left.scrollHeight)+'px');
    }
    function updateClientJson(){clientConfig.value=JSON.stringify(buildClientConfig(),null,2);syncClientJsonHeight()}
    async function loadClientConfig(){
      await platform();
      setBinaryCommit();
      let r=await api('/api/client-config?cache='+Date.now(),{cache:'no-store'}); currentConfigPath=r.path; configPath.textContent=r.path;
      try{currentRawConfig=r.parsed||(r.content?JSON.parse(r.content):{})}catch(e){currentRawConfig={locals:[],servers:[]}}
      currentRawConfig.locals=currentRawConfig.locals||[];
      currentRawConfig.servers=currentRawConfig.servers||[];
      currentRawConfig.route_rules=currentRawConfig.route_rules||{};
      try{lanAddresses=await api('/api/lan/addresses?cache='+Date.now(),{cache:'no-store'})}catch(e){lanAddresses=[]}
      try{dhcpClients=await api('/api/lan/dhcp-clients?cache='+Date.now(),{cache:'no-store'})}catch(e){dhcpClients=[]}
      renderBasic();
    }
    function setBinaryCommit(){let el=document.getElementById('binaryCommit');if(el){let commit=(servicePlatform&&servicePlatform.git_commit)||'unknown',time=(servicePlatform&&servicePlatform.git_commit_time_bj)||'unknown';el.textContent='commit '+commit+' | '+time}}
    async function openNftRulesetModal(){
      nftModal.classList.add('open');
      await loadNftRuleset();
    }
    function closeNftRulesetModal(event){
      if(event&&event.target!==nftModal)return;
      nftModal.classList.remove('open');
    }
    async function loadNftRuleset(){
      let pre=document.getElementById('nftRuleset');if(!pre)return;
      let btn=document.getElementById('nftRulesetRefresh');if(btn)btn.disabled=true;
      pre.textContent='loading...';
      try{
        let r=await api('/api/nft/ruleset?refresh=1&cache='+Date.now(),{cache:'no-store'});
        pre.textContent=r.ruleset||r.error||'(empty)';
      }catch(e){pre.textContent='error: '+e.message}
      finally{if(btn)btn.disabled=false}
    }
    function sleep(ms){return new Promise(resolve=>setTimeout(resolve,ms))}
    function setRestartControls(running){restartInProgress=running;restartButton.disabled=running;saveButton.disabled=running;reloadButton.disabled=running;restartButton.textContent=running?'Restarting...':'Restart'}
    async function waitForAdminReady(timeoutMs=60000){
      let deadline=Date.now()+timeoutMs,lastError=null,successes=0;
      await sleep(1200);
      while(Date.now()<deadline){
        try{
          await api('/api/sys/platform?restart_probe='+Date.now(),{cache:'no-store',timeoutMs:2500});
          successes++;
          if(successes>=2)return true;
          await sleep(500);
        }catch(e){
          successes=0;
          lastError=e;
          await sleep(1000);
        }
      }
      throw lastError||new Error('admin did not respond after restart');
    }
    async function waitForRestartComplete(doneText){
      try{
        await waitForAdminReady();
        servicePlatform=null;
        await loadClientConfig();
        await refreshProcessUptime();
        configPath.textContent=doneText;
      }catch(e){
        configPath.textContent='restart status unknown: '+e.message;
      }finally{
        setRestartControls(false);
      }
    }
    async function saveClientConfig(){if(restartInProgress)return;updateClientJson();setRestartControls(true);configPath.textContent='saving config...';let r;try{r=await api('/api/client-config',{method:'PUT',headers:{'content-type':'application/json'},body:JSON.stringify({content:clientConfig.value})})}catch(e){configPath.textContent='save failed: '+e.message;setRestartControls(false);return}if(r.unchanged){configPath.textContent=currentConfigPath+' unchanged';alert('No config changes');setRestartControls(false);return}configPath.textContent='saved, restarting service...';await waitForRestartComplete(currentConfigPath+' saved and service restarted')}
    async function restartService(){if(restartInProgress)return;setRestartControls(true);configPath.textContent='restarting service...';try{await api('/api/restart',{method:'POST'})}catch(e){console.warn(e)}await waitForRestartComplete('service restarted')}
    ['socksBind','socksPort','futuSocksBind','futuSocksPort','httpBind','httpPort','redirEnable','globalProxy','redirBind','redirPort','tunName','tunAddress','tunDestination','dnsEnable','dnsBind','dnsPort','dnsDomestic','dnsForeign','dnsCacheCapacity','dnsCacheTtl','dnsCacheRefreshEnabled','dnsCacheRefreshBatch','dnsInterceptMode','dnsIpv4Only'].forEach(id=>setTimeout(()=>document.getElementById(id).addEventListener('input',updateClientJson),0));
    setTimeout(()=>{serverList.addEventListener('input',updateClientJson);serverList.addEventListener('change',updateClientJson)},0);

    async function loadRules(){
      let tmp=await api('/api/temp-rules');
      setLines('tmp_direct_ip',tmp.direct_ip);setLines('tmp_direct_domain',tmp.direct_domain);setLines('tmp_proxy_ip',tmp.proxy_ip);setLines('tmp_proxy_domain',tmp.proxy_domain);
    }
    async function reloadRouteTab(){await loadRules();await renderRouteConflicts()}
    function tempRules(){return {direct_ip:lines(tmp_direct_ip.value),direct_domain:lines(tmp_direct_domain.value),proxy_ip:lines(tmp_proxy_ip.value),proxy_domain:lines(tmp_proxy_domain.value)}}
    async function saveTempRules(){
      await api('/api/temp-rules',{method:'PUT',headers:{'content-type':'application/json'},body:JSON.stringify(tempRules())});
      progressMessage.textContent='temporary rules saved to data/temp and applied to runtime';
    }
    let progressTimer=null;
    function renderProgress(p){
      progressStatus.textContent=p.status||'idle';
      progressSource.textContent=p.current_source||'-';
      progressPercent.textContent=(p.percent||0)+'%';
      progressRemaining.textContent=p.remaining_files??0;
      progressMessage.textContent=p.message||'';
      progressCompleted.textContent=(p.completed_messages||[]).join('\n');
      progressFill.style.width=(p.percent||0)+'%';
    }
    async function pollUpdateProgress(){
      let p=await api('/api/rules/update-progress');
      renderProgress(p);
      if(p.status==='completed'||p.status==='failed'||p.status==='idle'){
        if(progressTimer){clearInterval(progressTimer);progressTimer=null}
        await loadRules();
      }
    }
    async function startRuleJob(path,message){
      renderProgress({status:'running',current_source:'starting',percent:0,remaining_files:0,message,completed_messages:[]});
      await api(path,{method:'POST'});
      if(progressTimer)clearInterval(progressTimer);
      progressTimer=setInterval(()=>pollUpdateProgress().catch(e=>{progressMessage.textContent=e.message}),1000);
      await pollUpdateProgress();
    }
    async function downloadRules(){await startRuleJob('/api/rules/download','starting download')}
    async function generateRules(){await startRuleJob('/api/rules/update','starting generation')}
    function table(rows,cols,cls=''){return `<table class="${cls}"><thead><tr>`+cols.map(c=>'<th>'+c[0]+'</th>').join('')+'</tr></thead><tbody>'+(rows.length?rows.map(r=>'<tr>'+cols.map(c=>'<td>'+String(c[1](r)??'')+'</td>').join('')+'</tr>').join(''):`<tr><td colspan="${cols.length}" class="hint">No data</td></tr>` )+'</tbody></table>'}
    async function copyText(text){if(navigator.clipboard&&window.isSecureContext){await navigator.clipboard.writeText(text);return}let ta=document.createElement('textarea');ta.value=text;ta.style.position='fixed';ta.style.left='-9999px';document.body.appendChild(ta);ta.focus();ta.select();document.execCommand('copy');ta.remove()}
    document.addEventListener('click',async e=>{let td=e.target.closest('table.copyable-table td');if(!td||td.classList.contains('hint'))return;let text=td.innerText.trim();if(!text)return;try{await copyText(text);td.classList.add('copied');setTimeout(()=>td.classList.remove('copied'),450)}catch(err){console.warn(err)}})
    function fmtTime(ts){return ts?new Date(ts*1000).toLocaleString():''}
    function fmtDuration(seconds){
      let s=Math.max(0,Math.floor(Number(seconds)||0)),d=Math.floor(s/86400);
      s-=d*86400;
      let h=Math.floor(s/3600);s-=h*3600;
      let m=Math.floor(s/60);s-=m*60;
      let clock=String(h).padStart(2,'0')+':'+String(m).padStart(2,'0')+':'+String(s).padStart(2,'0');
      return d?d+'d '+clock:clock;
    }
    async function refreshProcessUptime(){
      let valueEl=document.getElementById('processUptimeValue'), box=document.getElementById('processUptime');
      try{
        let s=await api('/api/sys/uptime?cache='+Date.now(),{cache:'no-store',timeoutMs:2500});
        if(valueEl)valueEl.textContent=fmtDuration(s.process_uptime_seconds);
        if(box)box.title=s.process_started_at?'Started '+fmtTime(s.process_started_at):'Process uptime';
      }catch(e){
        if(valueEl)valueEl.textContent='-';
        if(box)box.title='Process uptime unavailable';
      }
    }
    function ms(v){let n=Number(v);return Number.isFinite(n)?(n*1000).toFixed(1):'-'}
    function deltaMs(end,start){let e=Number(end),s=Number(start);return Number.isFinite(e)&&Number.isFinite(s)?(Math.max(0,e-s)*1000).toFixed(1):'-'}
    function err(v){return v||'OK'}
    function esc(v){return String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
    function debugPortLabel(mode){return mode==='http'?'Http Port':(mode==='socks'?'Socks Port':'Transparent Port')}
    function debugPortValue(mode,r){return r.port_status||(!r.port_running?'not running':(r.port_received?'received':'not received'))}
    function debugEls(mode){return mode==='http'?[debugHttpUrl,debugHttpOut]:(mode==='socks'?[debugSocksUrl,debugSocksOut]:[debugRedirUrl,debugRedirOut])}
    function debugCommand(r){return `<p class="hint">Command</p><pre>${esc(r.curl_command||'-')}</pre>`}
    function debugUrlColumns(mode){let cols=[['Route Decision',x=>x.route_decision||'-'],['Proxy Domain',x=>x.proxy_domain?'yes':'no']];if(mode==='redir')cols.push(['DNS Intercepted',x=>x.dns_intercepted?'yes':'no'],['DNS Cache',x=>x.dns_cache_hit?'hit':'miss'],['Resolved IPs',x=>(x.resolved_ips||[]).join('<br>')||'-'],['NFT Proxy',x=>x.nft_proxy?'yes':'no'],['NFT Matches',x=>(x.nft_matches||[]).join('<br>')||'-']);cols.push([debugPortLabel(mode),x=>debugPortValue(mode,x)],['Response',x=>x.response_received?'received':'none'],['HTTP',x=>x.http_code||'-'],['DNS Resolve Time (ms)',x=>ms(x.time_namelookup)],['TCP Connect (ms)',x=>ms(x.time_connect)],['TLS Handshake (ms)',x=>deltaMs(x.time_appconnect,x.time_connect)],['First Byte (ms)',x=>ms(x.time_starttransfer)],['Error',x=>err(x.curl_error||(mode==='redir'?x.nft_error:null))]);return cols}
    function cleanDomain(v){return (v||'').replace(/\.$/,'')}
    async function renderConflicts(id,path){
      let rows=await api(path);
      let cols=[['Value',r=>r.value],['Regions',r=>(r.regions||[]).join(', ')],['Sources',r=>(r.sources||[]).join(', ')]];
      document.getElementById(id).innerHTML=table(rows,cols,'conflict-table')
    }
    function fmtCountdown(seconds){let s=Math.max(0,Number(seconds)||0),m=Math.floor(s/60),r=s%60;return m+':'+String(r).padStart(2,'0')}
    function updateActivityPauseButton(){activityPause.textContent=activityPaused?'Resume':'Pause';activityPause.setAttribute('aria-pressed',activityPaused?'true':'false');activityPauseState.textContent=activityPaused?'Paused':''}
    async function toggleActivityPause(){activityPaused=!activityPaused;updateActivityPauseButton();if(!activityPaused&&activeTab==='connections')await refresh('connections')}
    async function syncActivityRecordStatus(){let s=await api('/api/activity/record/status');activityRecord.checked=!!s.recording;activityRecordCountdown.textContent=s.recording?fmtCountdown(s.remaining_seconds):'';if(!s.recording&&!activityPaused){dnsOut.innerHTML='';connOut.innerHTML=''}return s}
    async function toggleActivityRecord(checked){await api(checked?'/api/activity/record/start':'/api/activity/record/stop',{method:'POST'});let s=await syncActivityRecordStatus();if(s.recording)refresh('connections')}
    function activitySourceParam(){let ip=(activitySourceFilter.value||'').trim();return ip?'?source_ip='+encodeURIComponent(ip):''}
    async function renderConnections(){let rows=await api('/api/activity/connections'+activitySourceParam());connOut.innerHTML=table(rows,[['Time',r=>fmtTime(r.timestamp)],['Source',r=>r.source_ip+':'+r.source_port],['Destination',r=>(r.destination_ip||r.destination_domain)+':'+r.destination_port],['Domain',r=>r.domain||'-'],['Protocol',r=>r.protocol],['Decision',r=>r.decision]],'copyable-table')}
    function renderDnsTable(){let rows=recentDnsRows;if(!dnsShowAaaa.checked)rows=rows.filter(r=>r.query_type!=='AAAA');dnsOut.innerHTML=table(rows,[['Time',r=>fmtTime(r.timestamp)],['Source',r=>r.source_ip||'-'],['Domain',r=>cleanDomain(r.domain)],['Type',r=>r.query_type],['Results',r=>r.error?('Error: '+r.error):(r.results||[]).join('<br>')],['Resolver',r=>r.resolver],['Cache',r=>r.cache_hit?'hit':'miss']],'copyable-table')}
    async function renderDns(){recentDnsRows=await api('/api/activity/dns'+activitySourceParam());renderDnsTable()}
    async function renderRouteConflicts(){await renderConflicts('domainOut','/api/conflicts/domain');await renderConflicts('ipOut','/api/conflicts/ip')}
    function nftCountsHtml(s){let c=s.nft_set_counts||{};if(!c.checked)return '';if(c.error)return `<p><strong>nft set entries:</strong> <span class="status-warn">unavailable</span> <span class="hint">${esc(c.error)}</span></p>`;let rows=[{set:'direct4',entries:c.direct4},{set:'direct6',entries:c.direct6},{set:'proxy4',entries:c.proxy4},{set:'proxy6',entries:c.proxy6}];return `<p><strong>nft set entries:</strong> ${c.total??0} total, ${c.proxy_total??0} proxy, ${c.direct_total??0} direct</p>`+table(rows,[['Set',r=>r.set],['Entries',r=>r.entries??0]])}
    async function renderSys(){let s=await api('/api/sys/status');let uptime=`<p><strong>Process uptime:</strong> ${fmtDuration(s.process_uptime_seconds)}</p>`;let body='';if(s.platform==='windows'){let cls=s.service_installed?'status-ok':'status-warn';body=uptime+`<p><strong>Platform:</strong> Windows</p><p><strong>Transparent backend:</strong> TUN</p><p><strong>Service:</strong> <span class="${cls}">${s.service_installed?'installed':'missing'}</span> ${s.service_name||''}</p><p><strong>TUN Adapter:</strong> ${s.tun_adapter||'shadowsocks-tun'} (${s.tun_adapter_status||'not active'})</p><p><strong>Deploy command:</strong></p><pre>${s.install_command||''}</pre>`}else{let cls=s.nft_installed?'status-ok':'status-warn';let tableCls=s.dns_table_installed?'status-ok':'status-warn';body=uptime+`<p><strong>nftables:</strong> <span class="${cls}">${s.nft_installed?'installed':'missing'}</span></p><p><strong>Version:</strong> ${s.nft_version||'-'}</p><p><strong>DNS nft table:</strong> <span class="${tableCls}">${s.dns_table_installed?'installed':'missing'}</span></p>${nftCountsHtml(s)}<p><strong>Ubuntu install command:</strong></p><pre>${s.install_command||''}</pre>${s.error?'<p class="hint">Error: '+s.error+'</p>':''}`}sysStatusOut.innerHTML=body}
    async function debugUrlCheck(mode){let [input,out]=debugEls(mode);let url=input.value.trim();if(!url){out.innerHTML='<p class="hint">Enter a URL first</p>';return}out.innerHTML='<p class="hint">Running debug, timeout 6s...</p>';let r=await api('/api/sys/debug-url',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({url,mode})});out.innerHTML=debugCommand(r)+table([r],debugUrlColumns(mode))}
    async function debugIpCheck(){let query=debugIp.value.trim();if(!query){debugIpOut.innerHTML='<p class="hint">Enter an IP or CIDR first</p>';return}let r=await api('/api/sys/debug-ip',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({query})});debugIpOut.innerHTML=table([r],[['Query',x=>x.query],['Valid',x=>x.valid?'yes':'no'],['proxy_ip.txt',x=>x.proxy_file?'yes':'no'],['proxy Matches',x=>(x.proxy_file_matches||[]).join('<br>')||'-'],['NFT Checked',x=>x.nft_checked?'yes':'no'],['NFT proxy',x=>x.nft_proxy?'yes':'no'],['NFT Matches',x=>(x.nft_matches||[]).join('<br>')||'-'],['Error',x=>err(x.error||x.nft_error)]])}
    async function queryDnsCache(){let domain=dnsQueryDomain.value.trim();if(!domain){dnsCacheOut.innerHTML='<p class="hint">Enter a domain</p>';return}let rows=await api('/api/dns/cache/query?domain='+encodeURIComponent(domain));let type=dnsQueryType.value;rows=rows.filter(r=>!type||r.query_type===type);dnsCacheOut.innerHTML=table(rows,[['Domain',r=>r.domain],['Type',r=>r.query_type],['Resolver',r=>r.resolver],['Results',r=>(r.results||[]).join('<br>')],['Expires',r=>fmtTime(r.expires_at)]])}
    async function queryDnsCacheIp(){let ip=dnsQueryIp.value.trim();if(!ip){dnsCacheOut.innerHTML='<p class="hint">Enter an IP</p>';return}let rows=await api('/api/dns/cache/query-ip?ip='+encodeURIComponent(ip));dnsCacheOut.innerHTML=table(rows,[['IP',r=>r.ip],['Domain',r=>r.domain],['Type',r=>r.query_type],['Resolver',r=>r.resolver],['Expires',r=>fmtTime(r.expires_at)]])}
    async function clearDnsDomain(){let domain=dnsQueryDomain.value.trim();if(!domain){dnsCacheMessage.textContent='Enter a domain first';return}let r=await api('/api/dns/cache/clear',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({domain})});dnsCacheMessage.textContent='Cleared '+r.cleared+' entries';await queryDnsCache()}
    async function clearDnsAll(){let r=await api('/api/dns/cache/clear',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({})});dnsCacheMessage.textContent='Cleared '+r.cleared+' entries';dnsCacheOut.innerHTML=''}
    async function refresh(id){try{if(id==='basic')await loadClientConfig();if(id==='routeConfig')await reloadRouteTab();if(id==='sys')await renderSys();if(id==='connections'){updateActivityPauseButton();if(activityPaused)return;let s=await syncActivityRecordStatus();if(s.recording){await renderDns();await renderConnections()}}}catch(e){alert(e.message)}}
    document.querySelector("nav button[data-tab=\"basic\"]").classList.add('active');
    window.addEventListener('resize',()=>{updateNavIndicator();syncClientJsonHeight()});
    requestAnimationFrame(updateNavIndicator);
    refreshProcessUptime();
    setInterval(refreshProcessUptime,1000);
    loadClientConfig();
  </script>
</body>
</html>"#;

#[derive(Debug)]
#[pin_project]
struct TokioIo<T> {
    #[pin]
    inner: T,
}

impl<T> TokioIo<T> {
    fn new(inner: T) -> Self {
        Self { inner }
    }
}

impl<T> hyper::rt::Read for TokioIo<T>
where
    T: tokio::io::AsyncRead,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        let n = unsafe {
            let mut tbuf = tokio::io::ReadBuf::uninit(buf.as_mut());
            match tokio::io::AsyncRead::poll_read(self.project().inner, cx, &mut tbuf) {
                Poll::Ready(Ok(())) => tbuf.filled().len(),
                other => return other,
            }
        };

        unsafe {
            buf.advance(n);
        }
        Poll::Ready(Ok(()))
    }
}

impl<T> hyper::rt::Write for TokioIo<T>
where
    T: tokio::io::AsyncWrite,
{
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, std::io::Error>> {
        tokio::io::AsyncWrite::poll_write(self.project().inner, cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        tokio::io::AsyncWrite::poll_flush(self.project().inner, cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        tokio::io::AsyncWrite::poll_shutdown(self.project().inner, cx)
    }

    fn is_write_vectored(&self) -> bool {
        tokio::io::AsyncWrite::is_write_vectored(&self.inner)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<Result<usize, std::io::Error>> {
        tokio::io::AsyncWrite::poll_write_vectored(self.project().inner, cx, bufs)
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::collections::HashSet;

    use serde_json::json;

    use super::{Ipv6Neighbor, append_ipv6_neighbors_from_rows, proc_net_tcp_has_listener};

    #[test]
    fn proc_net_tcp_listener_detects_listen_state() {
        let content = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:3039 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 5600722";

        assert!(proc_net_tcp_has_listener(content, 12345));
    }

    #[test]
    fn proc_net_tcp_listener_ignores_non_listen_state() {
        let content = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:3039 0200007F:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 5600722";

        assert!(!proc_net_tcp_has_listener(content, 12345));
    }

    #[test]
    fn ipv6_neighbor_rows_keep_multiple_public_addresses_for_same_mac() {
        let rows = vec![
            json!({
                "dst": "2409:8d5a:e04:7ad4:2135:e989:ee18:c7aa",
                "dev": "br-lan",
                "lladdr": "5A:9E:98:45:AD:56",
                "state": ["STALE"]
            }),
            json!({
                "dst": "2409:8d5a:e04:7ad4:aaaa:bbbb:cccc:dddd",
                "dev": "br-lan",
                "lladdr": "5a:9e:98:45:ad:56",
                "state": ["REACHABLE"]
            }),
            json!({
                "dst": "fe80::8fc:8b41:7c5e:546c",
                "dev": "br-lan",
                "lladdr": "5a:9e:98:45:ad:56",
                "state": ["STALE"]
            }),
            json!({
                "dst": "2409:8d5a:e04:7ad4:d0d9:6f6d:e318:1019",
                "dev": "br-lan",
                "state": ["FAILED"]
            }),
            json!({
                "dst": "2409:8d5a:e04:7ad4:691:62ff:feb4:3127",
                "dev": "br-lan",
                "state": ["INCOMPLETE"]
            }),
        ];
        let mut seen = HashSet::new();
        let mut neighbors: Vec<Ipv6Neighbor> = Vec::new();

        append_ipv6_neighbors_from_rows(&rows, &mut seen, &mut neighbors);

        assert_eq!(neighbors.len(), 2);
        assert_eq!(neighbors[0].mac, "5a:9e:98:45:ad:56");
        assert_eq!(
            neighbors[0].ip,
            "2409:8d5a:e04:7ad4:2135:e989:ee18:c7aa"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
        );
        assert_eq!(
            neighbors[1].ip,
            "2409:8d5a:e04:7ad4:aaaa:bbbb:cccc:dddd"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
        );
    }
}
