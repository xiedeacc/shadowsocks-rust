//! Embedded web admin for routing rules and DNS split.

use std::{
    convert::Infallible,
    fs, io,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    pin::Pin,
    process::{Command, Stdio},
    sync::Arc,
    task::{Context, Poll},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request, Response, StatusCode, body::Incoming, server::conn::http1, service::service_fn};
use log::{error, info, trace};
use pin_project::pin_project;
use tokio::{net::TcpListener, time};

use crate::{
    config::WebAdminConfig,
    local::routing::{ManualDomainRule, ManualIpRule, RoutingState, RuleLists},
};

type ResponseBody = Full<Bytes>;

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
            client_config_path: self.config.client_config_path,
            routing_state: self.routing_state,
        })
    }
}

pub struct WebAdmin {
    listener: TcpListener,
    token: Option<String>,
    client_config_path: PathBuf,
    routing_state: RoutingState,
}

impl WebAdmin {
    pub async fn run(self) -> io::Result<()> {
        info!("shadowsocks web admin listening on {}", self.listener.local_addr()?);
        let handler = Arc::new(WebAdminHandler {
            token: self.token,
            client_config_path: self.client_config_path,
            routing_state: self.routing_state,
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
    client_config_path: PathBuf,
    routing_state: RoutingState,
}

impl WebAdminHandler {
    async fn serve(self: Arc<Self>, req: Request<Incoming>, peer_addr: SocketAddr) -> Result<Response<ResponseBody>, Infallible> {
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
                let content = match fs::read_to_string(&self.client_config_path) {
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
                        "path": self.client_config_path,
                        "content": content,
                        "parsed": parsed,
                    }),
                ))
            }
            (Method::PUT, "/api/client-config") => {
                let payload: ClientConfigPayload = read_json(req).await?;
                if let Some(parent) = self.client_config_path.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::write(&self.client_config_path, payload.content)?;
                restart_service_after_response();
                Ok(json_response(
                    StatusCode::OK,
                    &serde_json::json!({ "ok": true, "restart": true }),
                ))
            }
            (Method::GET, "/api/config/rules") => {
                Ok(json_response(StatusCode::OK, &self.routing_state.snapshot().await))
            }
            (Method::PUT, "/api/config/rules") => {
                let route_sources: RouteSourcesPayload = read_json(req).await?;
                let mut sources = self.routing_state.snapshot().await.sources;
                if let Some(value) = route_sources.geoip_sources {
                    sources.geoip_sources = value;
                }
                if let Some(value) = route_sources.geosite_sources {
                    sources.geosite_sources = value;
                }
                if let Some(value) = route_sources.direct_domain_sources {
                    sources.direct_domain_sources = value;
                }
                if let Some(value) = route_sources.bypass_domain_sources {
                    sources.bypass_domain_sources = value;
                }
                self.routing_state.set_sources(sources).await;
                Ok(json_response(StatusCode::OK, &serde_json::json!({ "ok": true })))
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
                let mut sources = self.routing_state.snapshot().await.sources;
                let dns: DnsPayload = read_json(req).await?;
                sources.domestic_dns = dns.domestic_dns;
                sources.foreign_dns = dns.foreign_dns;
                self.routing_state.set_sources(sources).await;
                Ok(json_response(StatusCode::OK, &serde_json::json!({ "ok": true })))
            }
            (Method::GET, "/api/temp-rules") => Ok(json_response(
                StatusCode::OK,
                &self.routing_state.snapshot().await.temporary,
            )),
            (Method::PUT, "/api/temp-rules") => {
                let rules: RuleLists = read_json(req).await?;
                self.routing_state.set_temporary_rules(rules).await?;
                Ok(json_response(StatusCode::OK, &serde_json::json!({ "ok": true })))
            }
            (Method::GET, "/api/manual-ip") => Ok(json_response(
                StatusCode::OK,
                &self.routing_state.manual_ip_rules().await,
            )),
            (Method::PUT, "/api/manual-ip") => {
                let rule: ManualIpRule = read_json(req).await?;
                if rule.region.trim().is_empty() {
                    self.routing_state.remove_manual_ip_rule(&rule.cidr).await?;
                } else {
                    self.routing_state.set_manual_ip_rule(rule).await?;
                }
                Ok(json_response(StatusCode::OK, &serde_json::json!({ "ok": true })))
            }
            (Method::GET, "/api/manual-domain") => Ok(json_response(
                StatusCode::OK,
                &self.routing_state.manual_domain_rules().await,
            )),
            (Method::PUT, "/api/manual-domain") => {
                let rule: ManualDomainRule = read_json(req).await?;
                if rule.region.trim().is_empty() {
                    self.routing_state.remove_manual_domain_rule(&rule.domain).await?;
                } else {
                    self.routing_state.set_manual_domain_rule(rule).await?;
                }
                Ok(json_response(StatusCode::OK, &serde_json::json!({ "ok": true })))
            }
            (Method::GET, "/api/conflicts/ip") => {
                Ok(json_response(StatusCode::OK, &self.routing_state.ip_conflicts().await))
            }
            (Method::GET, "/api/conflicts/domain") => Ok(json_response(
                StatusCode::OK,
                &self.routing_state.domain_conflicts().await,
            )),
            (Method::GET, "/api/activity/connections") => {
                Ok(json_response(StatusCode::OK, &self.routing_state.recent_connections(&self.server_filters()).await))
            }
            (Method::GET, "/api/activity/unhit-ip") => Ok(json_response(
                StatusCode::OK,
                &self.routing_state.recent_unhit_ips().await,
            )),
            (Method::GET, "/api/activity/unhit-dns") => Ok(json_response(
                StatusCode::OK,
                &self.routing_state.recent_unhit_domains().await,
            )),
            (Method::GET, "/api/activity/dns") => {
                Ok(json_response(StatusCode::OK, &self.routing_state.recent_dns().await))
            }
            (Method::GET, "/api/sys/status") => Ok(json_response(StatusCode::OK, &self.sys_status().await)),
            (Method::POST, "/api/sys/debug-url") => {
                let payload: DebugUrlPayload = read_json(req).await?;
                Ok(json_response(StatusCode::OK, &self.debug_url(payload.url).await?))
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
        let (ip_conflicts, domain_conflicts) = self.routing_state.direct_bypass_file_conflicts().await;
        let mut status = nft_status();
        if let Some(object) = status.as_object_mut() {
            object.insert("ip_conflicts".to_owned(), serde_json::json!(ip_conflicts));
            object.insert("domain_conflicts".to_owned(), serde_json::json!(domain_conflicts));
        }
        status
    }

    async fn debug_url(&self, url: String) -> io::Result<serde_json::Value> {
        let url = normalize_debug_url(&url)?;
        let host = debug_url_host(&url)?;
        let started_at = unix_now();
        self.routing_state.enable_connection_activity().await;
        let decision = self.routing_state.route_domain(&host).await;
        let cached_before = self
            .routing_state
            .dns_cache_query(&host)
            .await
            .into_iter()
            .any(|entry| entry.query_type.eq_ignore_ascii_case("A") && Some(entry.resolver) == decision);

        let curl_result = tokio::task::spawn_blocking({
            let url = url.clone();
            move || run_debug_curl(&url)
        })
        .await
        .map_err(io::Error::other)??;

        let dns_events = self.routing_state.recent_dns().await;
        let matching_dns = dns_events
            .iter()
            .filter(|event| event.timestamp >= started_at && domain_matches_debug_host(&event.domain, &host))
            .cloned()
            .collect::<Vec<_>>();
        let resolved_ips = matching_dns
            .iter()
            .flat_map(|event| event.results.iter().copied())
            .collect::<Vec<_>>();
        let connections = self.routing_state.recent_connections(&self.server_filters()).await;
        let transparent_connection = connections.iter().find(|event| {
            event.timestamp >= started_at
                && event.decision == crate::local::routing::ConnectionDecision::Redir
                && event
                    .destination_ip
                    .is_some_and(|ip| resolved_ips.iter().any(|resolved| *resolved == ip))
        });

        Ok(serde_json::json!({
            "url": url,
            "host": host,
            "bypass_domain": matches!(decision, Some(crate::local::routing::RouteDecision::Proxy)),
            "route_decision": decision,
            "dns_intercepted": !matching_dns.is_empty(),
            "dns_cache_hit": cached_before,
            "resolved_ips": resolved_ips,
            "transparent_port_received": transparent_connection.is_some(),
            "response_received": curl_result.response_received,
            "http_code": curl_result.http_code,
            "curl_exit_code": curl_result.exit_code,
            "curl_error": curl_result.error,
        }))
    }

    fn server_filters(&self) -> Vec<IpAddr> {
        let Ok(content) = fs::read_to_string(&self.client_config_path) else {
            return Vec::new();
        };
        let Ok(config) = json5::from_str::<serde_json::Value>(&content) else {
            return Vec::new();
        };
        config
            .get("servers")
            .and_then(|servers| servers.as_array())
            .into_iter()
            .flatten()
            .filter_map(|server| {
                server.get("server")?.as_str()?.parse::<IpAddr>().ok()
            })
            .collect()
    }
}

#[derive(serde::Deserialize)]
struct DnsPayload {
    domestic_dns: Vec<String>,
    foreign_dns: Vec<String>,
}

#[derive(serde::Deserialize)]
struct RouteSourcesPayload {
    geoip_sources: Option<Vec<String>>,
    geosite_sources: Option<Vec<String>>,
    direct_domain_sources: Option<Vec<String>>,
    bypass_domain_sources: Option<Vec<String>>,
}

#[derive(serde::Deserialize)]
struct DnsCacheClearPayload {
    domain: Option<String>,
}

#[derive(serde::Deserialize)]
struct DebugUrlPayload {
    url: String,
}

#[derive(serde::Deserialize)]
struct DebugIpPayload {
    query: String,
}

#[derive(serde::Deserialize)]
struct ClientConfigPayload {
    content: String,
}

struct DebugCurlResult {
    response_received: bool,
    http_code: String,
    exit_code: Option<i32>,
    error: Option<String>,
}

fn restart_service_after_response() {
    thread::spawn(|| {
        std::thread::sleep(Duration::from_millis(300));
        if let Err(err) = Command::new("systemctl").args(["restart", "shadowsocks-client.service"]).status() {
            log::warn!("failed to restart shadowsocks-client.service after config save: {}", err);
        }
    });
}

fn nft_status() -> serde_json::Value {
    let install_command = "sudo apt update && sudo apt install -y nftables";
    match Command::new("nft").arg("--version").output() {
        Ok(output) if output.status.success() => {
            let version = String::from_utf8_lossy(&output.stdout).trim().to_owned();
            let table_ok = Command::new("nft")
                .args(["list", "table", "inet", "ssrust_dns"])
                .status()
                .is_ok_and(|status| status.success());
            serde_json::json!({
                "nft_installed": true,
                "nft_version": version,
                "dns_table_installed": table_ok,
                "install_command": install_command,
            })
        }
        Ok(output) => serde_json::json!({
            "nft_installed": false,
            "nft_version": "",
            "dns_table_installed": false,
            "install_command": install_command,
            "error": String::from_utf8_lossy(&output.stderr).trim(),
        }),
        Err(err) => serde_json::json!({
            "nft_installed": false,
            "nft_version": "",
            "dns_table_installed": false,
            "install_command": install_command,
            "error": err.to_string(),
        }),
    }
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
    domain.trim_end_matches('.').eq_ignore_ascii_case(host.trim_end_matches('.'))
}

fn run_debug_curl(url: &str) -> io::Result<DebugCurlResult> {
    let output = Command::new("curl")
        .args([
            "-4",
            "-sS",
            "--max-time",
            "6",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            url,
        ])
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
    let http_code = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    let error = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    Ok(DebugCurlResult {
        response_received: http_code != "000",
        http_code,
        exit_code: output.status.code(),
        error: (!error.is_empty()).then_some(error),
    })
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
    nav{display:flex;justify-content:center;padding:0;margin:0 0 16px;background:transparent;border:0;box-shadow:none}
    .nav-tabs{position:relative;display:inline-flex;gap:18px}
    .nav-indicator{position:absolute;top:0;left:0;height:100%;border-radius:9px;background:var(--brand);transition:transform .24s ease,width .24s ease;z-index:0}
    nav button{position:relative;z-index:1;margin:0;background:var(--soft);color:var(--brand2);transition:color .18s ease,background .18s ease}
    nav button:hover{background:#d7e7f4;color:var(--brand2)}
    nav button.active{background:transparent;color:#fff}
    nav button.active:hover{background:transparent;color:#fff}
    fieldset,.panel{border:1px solid var(--line);border-radius:10px;margin:0 0 8px;padding:9px;background:var(--panel);box-shadow:0 1px 2px #10203312}
    legend{font-weight:700;color:var(--brand2)}
    .card-title{margin:8px 0 5px;font-size:15px;color:var(--brand2)}
    label{display:block;font-size:12px;font-weight:600;margin-top:8px;color:var(--muted)}
    input,select,textarea{width:100%;box-sizing:border-box;margin:2px 0 5px;padding:6px 8px;border:1px solid var(--line);border-radius:7px;background:#fff;color:var(--ink)}
    textarea{min-height:96px;font-family:ui-monospace,monospace}
    button{margin:6px 4px 6px 0;padding:8px 12px;border:0;border-radius:7px;background:var(--brand);color:#fff;font-weight:600;cursor:pointer}
    button:hover{background:var(--brand2)}
    table{border-collapse:collapse;width:100%;margin-top:10px}
    th,td{border:1px solid var(--line);padding:7px;text-align:left;vertical-align:top;background:var(--panel)}
    th{background:var(--soft);color:var(--brand2)}
    .scroll-panel{overflow:auto;border:1px solid var(--line);border-radius:10px;background:var(--panel);box-shadow:0 1px 2px #10203312}
    .section-scroll{height:auto;min-height:0;flex:1}
    .scroll-panel table{margin-top:0}
    .scroll-panel table,.scroll-panel th,.scroll-panel td{user-select:text}
    .scroll-panel th{position:sticky;top:0;z-index:1}
    .conflict-table{table-layout:fixed}
    .conflict-table th:nth-child(1),.conflict-table td:nth-child(1){width:38%}
    .conflict-table th:nth-child(2),.conflict-table td:nth-child(2){width:17%}
    .conflict-table th:nth-child(3),.conflict-table td:nth-child(3){width:32%}
    .conflict-table th:nth-child(4),.conflict-table td:nth-child(4){width:13%}
    .conflict-table td{word-break:break-word}
    pre{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:12px;overflow:auto}
    .tab{display:none;height:calc(100vh - 88px);min-height:0;overflow:hidden}.tab.active{display:block}
    #basic.tab.active,#dns.tab.active,#routeConfig.tab.active,#sys.tab.active{display:flex;flex-direction:column}
    .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:12px}
    .activity-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));grid-template-rows:repeat(2,minmax(0,1fr));gap:16px;align-items:stretch;height:100%;min-height:0}
    .activity-card{min-width:0;min-height:0;display:flex;flex-direction:column}
    .basic-layout{display:grid;grid-template-columns:minmax(380px,540px) 1fr;gap:18px;align-items:stretch;height:calc(100% - 46px);min-height:0}
    .basic-form-panel{overflow:auto;min-height:0}
    .basic-json-panel{display:flex;flex-direction:column;min-height:0}
    .basic-json-panel textarea{flex:1}
    .basic-actions{margin-top:8px}
    .route-toolbar{text-align:center;margin:8px 0 0}
    .route-toolbar .hint{margin:4px 0 0}
    .route-config-layout{display:grid;grid-template-columns:repeat(2,minmax(320px,1fr));grid-template-rows:repeat(2,minmax(0,1fr));gap:16px;min-height:0;flex:1}
    .route-config-column{min-width:0;min-height:0;display:flex;flex-direction:column}
    .route-config-column .scroll-panel{min-height:0;flex:1}
    .rules-workspace{display:grid;grid-template-columns:minmax(0,1fr) minmax(260px,.8fr);gap:12px;align-items:stretch;min-height:0;flex:1}
    .rules-workspace #rulesJson{height:auto;min-height:0;flex:1}
    .rules-workspace .progress-box{height:auto;margin:2px 0 5px;max-width:none;max-height:none;box-sizing:border-box}
    .route-rules-layout{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:12px;align-items:start;margin-top:8px;min-height:0}
    .temporary-panel{display:flex;flex-direction:column}
    .temporary-panel .route-rules-layout{flex:1;align-items:stretch;margin-top:0}
    .temporary-panel fieldset{display:flex;flex-direction:column;margin:0}
    .temporary-panel label{display:flex;flex-direction:column;flex:1;min-height:0}
    .temporary-panel textarea{flex:1;min-height:0}
    .dns-layout{display:grid;grid-template-columns:minmax(320px,420px) 1fr;gap:18px;min-height:0;flex:1}
    .dns-panel{min-height:0;overflow:auto}
    .sys-layout{min-height:0;flex:1;overflow:auto}
    .status-ok{color:#18864b;font-weight:700}
    .status-warn{color:#b15d00;font-weight:700}
    .form-line{display:grid;grid-template-columns:150px 1fr;gap:10px;align-items:center;margin:4px 0}
    .form-line label{margin:0;font-size:13px}
    .form-line input[type=checkbox]{width:16px;height:16px;margin:0;justify-self:start}
    #clientConfig{min-height:0;height:auto;max-height:none;overflow:auto;resize:vertical;font-size:13px}
    #rulesJson{min-height:100px;height:auto;max-height:none;overflow:auto;resize:vertical;font-size:13px;flex:1}
    #routeConfig .route-config-column>.scroll-panel{height:auto}
    #routeConfig .route-rules-layout textarea{height:clamp(56px,8vh,96px);min-height:56px;resize:vertical}
    .row{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:8px;align-items:center;margin:4px 0}
    .row input{margin:0}
    .row button{margin:0;white-space:nowrap}
    .hint{color:var(--muted);font-size:12px}
    .inline-check{display:inline-flex;align-items:center;gap:4px;margin:0 0 0 10px;font-size:12px;font-weight:600;color:var(--muted)}
    .inline-check input{width:auto;margin:0}
    .progress-box{margin:8px auto 0;max-width:760px;max-height:120px;overflow:auto;text-align:left;background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:10px;box-shadow:0 1px 2px #10203312}
    .progress-bar{height:10px;background:var(--soft);border-radius:999px;overflow:hidden;margin:8px 0}
    .progress-fill{height:100%;width:0;background:var(--brand)}
    .progress-completed{white-space:pre-line;margin-top:8px}
    @media(max-width:1300px){.route-config-layout{grid-template-columns:1fr}.route-config-column{min-height:260px}}
    @media(max-width:1000px){.rules-workspace{grid-template-columns:1fr}}
    @media(max-width:1100px){.activity-grid,.route-rules-layout{grid-template-columns:1fr}.activity-grid{grid-template-rows:repeat(4,minmax(0,1fr))}}
    @media(max-width:900px){.basic-layout{grid-template-columns:1fr}#clientConfig,#rulesJson{height:auto;max-height:none}}
  </style>
</head>
<body>
  <nav>
    <div class="nav-tabs">
      <span class="nav-indicator" aria-hidden="true"></span>
      <button data-tab="basic" onclick="show('basic')">Basic</button>
      <button data-tab="connections" onclick="show('connections')">Connections</button>
      <button data-tab="dns" onclick="show('dns')">DNS</button>
      <button data-tab="routeConfig" onclick="show('routeConfig')">Route</button>
      <button data-tab="sys" onclick="show('sys')">Sys</button>
    </div>
  </nav>

  <section id="basic" class="tab active">
    <p class="hint" id="configPath"></p>
    <div class="basic-layout">
      <div class="basic-form-panel">
        <h3 class="card-title">SOCKS Local</h3>
        <fieldset>
          <div class="form-line"><label>Bind Address</label><select id="socksBind"><option>127.0.0.1</option><option>0.0.0.0</option></select></div>
          <div class="form-line"><label>Port</label><input id="socksPort" type="number" min="1" max="65535"></div>
        </fieldset>
        <h3 class="card-title">HTTP Local</h3>
        <fieldset>
          <div class="form-line"><label>Bind Address</label><select id="httpBind"><option>127.0.0.1</option><option>0.0.0.0</option></select></div>
          <div class="form-line"><label>Port</label><input id="httpPort" type="number" min="1" max="65535"></div>
        </fieldset>
        <h3 class="card-title">Transparent Proxy</h3>
        <fieldset>
          <div class="form-line"><label>Enable Redir</label><input id="redirEnable" type="checkbox"></div>
          <div class="form-line"><label>Bind Address</label><select id="redirBind"><option>127.0.0.1</option><option>0.0.0.0</option></select></div>
          <div class="form-line"><label>Port</label><input id="redirPort" type="number" min="1" max="65535"></div>
          <div class="form-line"><label>Mode</label><select id="redirMode"><option>tcp_only</option><option>tcp_and_udp</option></select></div>
          <div class="form-line"><label>TCP Redir</label><select id="tcpRedir"><option>redirect</option><option>tproxy</option></select></div>
          <div class="form-line"><label>UDP Redir</label><select id="udpRedir"><option>tproxy</option></select></div>
        </fieldset>
        <h3 class="card-title">DNS Listener</h3>
        <fieldset>
          <div class="form-line"><label>Enable DNS</label><input id="dnsEnable" type="checkbox"></div>
          <div class="form-line"><label>Bind Address</label><select id="dnsBind"><option>127.0.0.1</option><option>0.0.0.0</option></select></div>
          <div class="form-line"><label>Port</label><input id="dnsPort" type="number" min="1" max="65535"></div>
          <label>Domestic DNS</label>
          <div id="dnsDomesticList"></div>
          <button type="button" onclick="addDns('dnsDomesticList')">+ Domestic DNS</button>
          <label>Foreign DNS</label>
          <div id="dnsForeignList"></div>
          <button type="button" onclick="addDns('dnsForeignList')">+ Foreign DNS</button>
          <div class="form-line"><label>Cache Capacity</label><input id="dnsCacheCapacity" type="number" min="1"></div>
          <div class="form-line"><label>Cache TTL Seconds</label><input id="dnsCacheTtl" type="number" min="1"></div>
          <div class="form-line"><label>Async Refresh</label><input id="dnsCacheRefreshEnabled" type="checkbox"></div>
          <div class="form-line"><label>Refresh Batch Size</label><input id="dnsCacheRefreshBatch" type="number" min="1"></div>
          <div class="form-line"><label>Intercept Mode</label><select id="dnsInterceptMode"><option>off</option><option>firewall</option><option>tun</option><option>both</option></select></div>
        </fieldset>
        <h3 class="card-title">Server</h3>
        <fieldset>
          <div class="form-line"><label>Server Address</label><input id="serverHost"></div>
          <div class="form-line"><label>Server Port</label><input id="serverPort" type="number" min="1" max="65535"></div>
          <div class="form-line"><label>Method</label><select id="method">
            <option>aes-128-gcm</option><option>aes-256-gcm</option><option>chacha20-ietf-poly1305</option>
            <option>2022-blake3-aes-128-gcm</option><option>2022-blake3-aes-256-gcm</option>
          </select></div>
          <div class="form-line"><label>Password</label><input id="serverSecret" name="ss-server-secret" type="text" autocomplete="off" autocapitalize="none" spellcheck="false" data-lpignore="true" data-1p-ignore="true"></div>
          <div class="form-line"><label>Timeout Seconds</label><input id="timeout" type="number" min="1"></div>
          <div class="form-line"><label>Plugin Path</label><input id="plugin"></div>
          <div class="form-line"><label>Plugin Options</label><input id="pluginOpts"></div>
        </fieldset>
      </div>
      <div class="basic-json-panel">
        <h3 class="card-title">Generated JSON</h3>
        <textarea id="clientConfig"></textarea>
      </div>
    </div>
    <div class="basic-actions">
      <button onclick="loadClientConfig()">Reload</button>
      <button onclick="saveClientConfig()">Save</button>
      <button onclick="restartService()">Restart</button>
    </div>
  </section>

  <section id="dns" class="tab">
    <div class="dns-layout">
      <div class="panel dns-panel">
        <h3 class="card-title">Cache Management</h3>
        <div><strong>Size:</strong> <span id="dnsCacheSize">0</span> / <span id="dnsCacheCapacityOut">0</span></div>
        <div><strong>TTL:</strong> <span id="dnsCacheTtlOut">0</span> seconds</div>
        <div class="form-line"><label>Async Refresh</label><input id="dnsCacheRefreshEnabledDns" type="checkbox"></div>
        <div class="form-line"><label>Refresh Batch Size</label><input id="dnsCacheRefreshBatchDns" type="number" min="1"></div>
        <button onclick="saveDnsCacheSettings()">Save Refresh Settings</button>
        <label>Domain<input id="dnsQueryDomain" placeholder="example.com"></label>
        <label>Record Type<select id="dnsQueryType"><option>A</option><option>AAAA</option></select></label>
        <button onclick="queryDnsCache()">Query Cache</button>
        <label>IP<input id="dnsQueryIp" placeholder="142.251.151.119"></label>
        <button onclick="queryDnsCacheIp()">Query Domain By IP</button>
        <button onclick="clearDnsDomain()">Clear Domain</button>
        <button onclick="clearDnsAll()">Clear All Cache</button>
        <p class="hint" id="dnsCacheMessage"></p>
      </div>
      <div class="dns-panel">
        <h3 class="card-title">Cached Results</h3>
        <div id="dnsCacheOut" class="scroll-panel section-scroll"></div>
      </div>
    </div>
  </section>

  <section id="connections" class="tab">
    <div class="activity-grid">
      <div class="activity-card">
        <h3 class="card-title">Recent DNS <label class="inline-check"><input id="recentDnsRecord" type="checkbox" checked> Record</label></h3>
        <div id="dnsOut" class="scroll-panel section-scroll"></div>
      </div>
      <div class="activity-card">
        <h3 class="card-title">Recent Connections</h3>
        <div id="connOut" class="scroll-panel section-scroll"></div>
      </div>
      <div class="activity-card">
        <h3 class="card-title">Unhit DNS</h3>
        <div id="unhitDnsOut" class="scroll-panel section-scroll"></div>
      </div>
      <div class="activity-card">
        <h3 class="card-title">Unhit IP</h3>
        <div id="unhitIpOut" class="scroll-panel section-scroll"></div>
      </div>
    </div>
  </section>

  <section id="routeConfig" class="tab">
    <div class="route-config-layout">
      <div class="route-config-column">
        <h3 class="card-title">Rules</h3>
        <div class="rules-workspace">
          <textarea id="rulesJson"></textarea>
          <div id="ruleUpdateProgress" class="progress-box">
            <div><strong>Status:</strong> <span id="progressStatus">idle</span></div>
            <div class="progress-bar"><div id="progressFill" class="progress-fill"></div></div>
            <div><strong>Current source:</strong> <span id="progressSource">-</span></div>
            <div><strong>Progress:</strong> <span id="progressPercent">0%</span>, <strong>remaining files:</strong> <span id="progressRemaining">0</span></div>
            <div class="hint" id="progressMessage"></div>
            <div class="hint progress-completed" id="progressCompleted"></div>
          </div>
        </div>
      </div>
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
              <label>Bypass IP<textarea id="tmp_bypass_ip"></textarea></label>
              <label>Bypass Domain<textarea id="tmp_bypass_domain"></textarea></label>
            </fieldset>
          </div>
          <p class="hint" style="padding:0 9px 9px">Temporary lists have priority over generated direct/bypass files. 一行一个配置，无需分隔符。</p>
        </div>
      </div>
    </div>
    <div class="route-toolbar">
      <button onclick="loadRules()">Reload</button>
      <button onclick="saveRules()">Save</button>
      <button onclick="downloadRules()">Download</button>
      <button onclick="generateRules()">Generate</button>
      <p class="hint">Manual selections and manual_domain.txt/manual_ip.txt changes take effect after Generate.</p>
    </div>
  </section>

  <section id="sys" class="tab">
    <div class="panel sys-layout">
      <h3 class="card-title">System Checks</h3>
      <div id="sysStatusOut"></div>
      <h3 class="card-title">Debug URL</h3>
      <div class="row">
        <input id="debugUrl" value="http://www.google.com/generate_204">
        <button onclick="debugUrlCheck()">Debug</button>
      </div>
      <div id="debugUrlOut" class="scroll-panel" style="padding:9px;margin-top:8px"></div>
      <h3 class="card-title">Debug IP / CIDR</h3>
      <div class="row">
        <input id="debugIp" placeholder="142.251.155.119 or 142.251.155.0/24">
        <button onclick="debugIpCheck()">Check</button>
      </div>
      <div id="debugIpOut" class="scroll-panel" style="padding:9px;margin-top:8px"></div>
    </div>
  </section>

  <script>
    let currentConfigPath='', currentRawConfig={}, rulesSnapshot={};
    const routeSourceKeys=['geoip_sources','geosite_sources','direct_domain_sources','bypass_domain_sources'];
    const dnsKeys=['domestic_dns','foreign_dns','dns_cache_capacity','dns_cache_ttl_seconds','dns_cache_refresh_enabled','dns_cache_refresh_batch_size','dns_intercept_mode','dns_listen_address','dns_listen_port'];
    const sourceKeys=[...routeSourceKeys,...dnsKeys];
    function token(){return new URLSearchParams(location.search).get('token')||''}
    async function api(path,opt={}){opt.headers=Object.assign({'x-admin-token':token()},opt.headers||{});let r=await fetch(path,opt);let j=await r.json();if(!r.ok)throw new Error(j.error||r.statusText);return j}
    let activeTab='basic', activityTimer=null;
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
      if(id==='connections')activityTimer=setInterval(()=>refresh('connections').catch(e=>{console.warn(e)}),1000);
      if(id==='routeConfig')activityTimer=setInterval(()=>renderRouteConflicts().catch(e=>{console.warn(e)}),3000);
    }
    function lines(v){return (v||'').split('\n').map(s=>s.trim()).filter(Boolean)}
    function setLines(id,arr){document.getElementById(id).value=(arr||[]).join('\n')}
    function num(v,d){let n=parseInt(v,10);return Number.isFinite(n)?n:d}
    function firstLocal(protocol){return (currentRawConfig.locals||[]).find(l=>l.protocol===protocol)||{}}
    function firstServer(){return (currentRawConfig.servers||[])[0]||{}}
    function setSelect(id,value){let el=document.getElementById(id); if([...el.options].some(o=>o.value===value)){el.value=value}else{el.value=el.options[0].value}}
    function renderBasic(){
      let socks=firstLocal('socks'), http=firstLocal('http'), redir=firstLocal('redir'), dns=firstLocal('dns'), server=firstServer();
      let routeRules=currentRawConfig.route_rules||{};
      setSelect('socksBind',socks.local_address||'127.0.0.1'); socksPort.value=socks.local_port||1080;
      setSelect('httpBind',http.local_address||'127.0.0.1'); httpPort.value=http.local_port||1081;
      redirEnable.checked=!!redir.protocol;
      setSelect('redirBind',redir.local_address||'0.0.0.0'); redirPort.value=redir.local_port||12345;
      setSelect('redirMode',redir.mode||'tcp_and_udp'); setSelect('tcpRedir',redir.tcp_redir||'redirect'); setSelect('udpRedir',redir.udp_redir||'tproxy');
      dnsEnable.checked=!!dns.protocol;
      setSelect('dnsBind',dns.local_address||'0.0.0.0'); dnsPort.value=dns.local_port||1053;
      renderDnsList('dnsDomesticList',routeRules.domestic_dns||[(dns.local_dns_address||'223.5.5.5')+':'+(dns.local_dns_port||53)]);
      renderDnsList('dnsForeignList',routeRules.foreign_dns||[(dns.remote_dns_address||'8.8.8.8')+':'+(dns.remote_dns_port||53)]);
      dnsCacheCapacity.value=routeRules.dns_cache_capacity||100000;
      dnsCacheTtl.value=routeRules.dns_cache_ttl_seconds||604800;
      dnsCacheRefreshEnabled.checked=routeRules.dns_cache_refresh_enabled!==false;
      dnsCacheRefreshBatch.value=routeRules.dns_cache_refresh_batch_size||500;
      setSelect('dnsInterceptMode',routeRules.dns_intercept_mode||'off');
      serverHost.value=server.server||''; serverPort.value=server.server_port||443; setSelect('method',server.method||'aes-256-gcm');
      serverSecret.value=server.password||''; timeout.value=server.timeout||300; plugin.value=server.plugin||''; pluginOpts.value=server.plugin_opts||'';
      updateClientJson();
    }
    function buildClientConfig(){
      let locals=[
        {local_address:socksBind.value,local_port:num(socksPort.value,1080),protocol:'socks'},
        {local_address:httpBind.value,local_port:num(httpPort.value,1081),protocol:'http'}
      ];
      if(redirEnable.checked){
        locals.push({local_address:redirBind.value,local_port:num(redirPort.value,12345),protocol:'redir',mode:redirMode.value,tcp_redir:tcpRedir.value,udp_redir:udpRedir.value});
      }
      let routeRules=Object.assign({},currentRawConfig.route_rules||{});
      routeRules.dns_cache_capacity=num(dnsCacheCapacity.value,100000);
      routeRules.dns_cache_ttl_seconds=num(dnsCacheTtl.value,604800);
      routeRules.dns_cache_refresh_enabled=dnsCacheRefreshEnabled.checked;
      routeRules.dns_cache_refresh_batch_size=num(dnsCacheRefreshBatch.value,500);
      routeRules.dns_intercept_mode=dnsInterceptMode.value;
      routeRules.dns_listen_address=dnsBind.value;
      routeRules.dns_listen_port=num(dnsPort.value,1053);
      let domesticDns=readDns('dnsDomesticList');
      let foreignDns=readDns('dnsForeignList');
      routeRules.domestic_dns=domesticDns.length?domesticDns:['223.5.5.5:53'];
      routeRules.foreign_dns=foreignDns.length?foreignDns:['8.8.8.8:53'];
      if(dnsEnable.checked){
        let domestic=parseHostPort(routeRules.domestic_dns[0],'223.5.5.5',53);
        let foreign=parseHostPort(routeRules.foreign_dns[0],'8.8.8.8',53);
        locals.push({local_address:dnsBind.value,local_port:num(dnsPort.value,1053),protocol:'dns',mode:'tcp_and_udp',local_dns_address:domestic.host,local_dns_port:domestic.port,remote_dns_address:foreign.host,remote_dns_port:foreign.port,client_cache_size:64});
      }
      let server={server:serverHost.value.trim(),server_port:num(serverPort.value,443),password:serverSecret.value,timeout:num(timeout.value,300),method:method.value};
      if(plugin.value.trim())server.plugin=plugin.value.trim();
      if(pluginOpts.value.trim())server.plugin_opts=pluginOpts.value.trim();
      return Object.assign({},currentRawConfig,{locals,servers:[server],route_rules:routeRules});
    }
    function parseHostPort(value,hostDefault,portDefault){
      let text=(value||'').trim();
      if(!text)return {host:hostDefault,port:portDefault};
      let idx=text.lastIndexOf(':');
      if(idx>0&&text.indexOf(']')<idx){
        let port=parseInt(text.slice(idx+1),10);
        if(Number.isFinite(port))return {host:text.slice(0,idx).replace(/^\[|\]$/g,''),port};
      }
      return {host:text.replace(/^\[|\]$/g,''),port:portDefault};
    }
    function updateClientJson(){clientConfig.value=JSON.stringify(buildClientConfig(),null,2)}
    function dnsRow(containerId,value=''){let div=document.createElement('div');div.className='row';div.innerHTML=`<input value="${value.replaceAll('"','&quot;')}" placeholder="8.8.8.8:53"><button type="button">Remove</button>`;div.querySelector('button').onclick=()=>{div.remove();updateClientJson()};div.querySelector('input').oninput=updateClientJson;document.getElementById(containerId).appendChild(div)}
    function addDns(containerId){dnsRow(containerId);updateClientJson()}
    function readDns(containerId){return [...document.querySelectorAll('#'+containerId+' input')].map(i=>i.value.trim()).filter(Boolean)}
    function renderDnsList(containerId,values){document.getElementById(containerId).innerHTML='';(values||[]).forEach(v=>dnsRow(containerId,v));if(!(values||[]).length)dnsRow(containerId,'')}
    async function loadClientConfig(){
      let r=await api('/api/client-config'); currentConfigPath=r.path; configPath.textContent=r.path;
      try{currentRawConfig=r.parsed||(r.content?JSON.parse(r.content):{})}catch(e){currentRawConfig={locals:[],servers:[]}}
      currentRawConfig.locals=currentRawConfig.locals||[];
      currentRawConfig.servers=currentRawConfig.servers||[];
      currentRawConfig.route_rules=currentRawConfig.route_rules||{};
      renderBasic();
    }
    async function saveClientConfig(){updateClientJson(); await api('/api/client-config',{method:'PUT',headers:{'content-type':'application/json'},body:JSON.stringify({content:clientConfig.value})}); configPath.textContent=currentConfigPath+' saved, restarting service...'}
    async function restartService(){await api('/api/restart',{method:'POST'}); configPath.textContent='restarting service...'}
    ['socksBind','socksPort','httpBind','httpPort','redirEnable','redirBind','redirPort','redirMode','tcpRedir','udpRedir','dnsEnable','dnsBind','dnsPort','dnsCacheCapacity','dnsCacheTtl','dnsCacheRefreshEnabled','dnsCacheRefreshBatch','dnsInterceptMode','serverHost','serverPort','method','serverSecret','timeout','plugin','pluginOpts'].forEach(id=>setTimeout(()=>document.getElementById(id).addEventListener('input',updateClientJson),0));

    function sourceRow(key,value=''){let div=document.createElement('div');div.className='row';div.innerHTML=`<input value="${value.replaceAll('"','&quot;')}"><button type="button">Remove</button>`;div.querySelector('button').onclick=()=>{div.remove();updateRulesJson()};div.querySelector('input').oninput=updateRulesJson;document.getElementById(key).appendChild(div)}
    function addSource(key){sourceRow(key);updateRulesJson()}
    function readSource(key){return [...document.querySelectorAll('#'+key+' input')].map(i=>i.value.trim()).filter(Boolean)}
    function renderSource(key,values){document.getElementById(key).innerHTML='';(values||[]).forEach(v=>sourceRow(key,v));if(!(values||[]).length)sourceRow(key,'')}
    function tempRules(){return {direct_ip:lines(tmp_direct_ip.value),direct_domain:lines(tmp_direct_domain.value),bypass_ip:lines(tmp_bypass_ip.value),bypass_domain:lines(tmp_bypass_domain.value)}}
    function sourcesFromForm(){return (rulesSnapshot&&rulesSnapshot.sources)||{}}
    function routeRuleSourcesForJson(sources){let copy=Object.assign({},sources||{});dnsKeys.forEach(key=>delete copy[key]);return copy}
    function updateRulesJson(snapshot=rulesSnapshot){rulesJson.value=JSON.stringify({sources:routeRuleSourcesForJson((snapshot&&snapshot.sources)||{})},null,2)}
    function rulesPayloadFromJson(){
      let payload=JSON.parse(rulesJson.value||'{}');
      if(payload.sources){dnsKeys.forEach(key=>delete payload.sources[key])}
      let sources=routeRuleSourcesForJson(payload.sources||{});
      let temporary=tempRules();
      return {sources,temporary};
    }
    async function loadRules(){
      rulesSnapshot=await api('/api/config/rules'); let tmp=await api('/api/temp-rules');
      setLines('tmp_direct_ip',tmp.direct_ip);setLines('tmp_direct_domain',tmp.direct_domain);setLines('tmp_bypass_ip',tmp.bypass_ip);setLines('tmp_bypass_domain',tmp.bypass_domain);
      updateRulesJson(rulesSnapshot);
    }
    async function saveRules(){
      let payload=rulesPayloadFromJson();
      await api('/api/config/rules',{method:'PUT',headers:{'content-type':'application/json'},body:JSON.stringify(payload.sources)});
      await api('/api/temp-rules',{method:'PUT',headers:{'content-type':'application/json'},body:JSON.stringify(payload.temporary)});
      await loadRules();
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
    async function updateRules(){
      await saveRules();
      renderProgress({status:'running',current_source:'starting',percent:0,remaining_files:0,message:'starting',completed_messages:[]});
      await api('/api/rules/update',{method:'POST'});
      if(progressTimer)clearInterval(progressTimer);
      progressTimer=setInterval(()=>pollUpdateProgress().catch(e=>{progressMessage.textContent=e.message}),1000);
      await pollUpdateProgress();
    }
    async function startRuleJob(path,message){
      await saveRules();
      renderProgress({status:'running',current_source:'starting',percent:0,remaining_files:0,message,completed_messages:[]});
      await api(path,{method:'POST'});
      if(progressTimer)clearInterval(progressTimer);
      progressTimer=setInterval(()=>pollUpdateProgress().catch(e=>{progressMessage.textContent=e.message}),1000);
      await pollUpdateProgress();
    }
    async function downloadRules(){await startRuleJob('/api/rules/download','starting download')}
    async function generateRules(){await startRuleJob('/api/rules/update','starting generation')}
    function table(rows,cols,cls=''){return `<table class="${cls}"><thead><tr>`+cols.map(c=>'<th>'+c[0]+'</th>').join('')+'</tr></thead><tbody>'+(rows.length?rows.map(r=>'<tr>'+cols.map(c=>'<td>'+String(c[1](r)??'')+'</td>').join('')+'</tr>').join(''):`<tr><td colspan="${cols.length}" class="hint">No data</td></tr>` )+'</tbody></table>'}
    function fmtTime(ts){return ts?new Date(ts*1000).toLocaleString():''}
    function cleanDomain(v){return (v||'').replace(/\.$/,'')}
    let manualSelectEditing=false;
    function beginManualSelectEdit(){manualSelectEditing=true}
    function endManualSelectEdit(){setTimeout(()=>{manualSelectEditing=false},400)}
    async function setManualIp(cidr,region){manualSelectEditing=false;await api('/api/manual-ip',{method:'PUT',headers:{'content-type':'application/json'},body:JSON.stringify({cidr,region})});await renderConflicts('ipOut','/api/conflicts/ip',{force:true})}
    async function setManualDomain(domain,region){manualSelectEditing=false;await api('/api/manual-domain',{method:'PUT',headers:{'content-type':'application/json'},body:JSON.stringify({domain,region})});await renderConflicts('domainOut','/api/conflicts/domain',{force:true})}
    function manualSelect(row,manual,onchange){
      let regions=['direct','bypass'];
      let selected=manual[row.value]||'';
      return `<select onpointerdown="beginManualSelectEdit()" onfocus="beginManualSelectEdit()" onblur="endManualSelectEdit()" onchange="${onchange}('${row.value}',this.value)"><option value="">Auto</option>${regions.map(region=>`<option value="${region}"${region===selected?' selected':''}>${region}</option>`).join('')}</select>`;
    }
    async function renderConflicts(id,path,opt={}){
      if(manualSelectEditing&&!opt.force)return;
      let rows=await api(path);
      if(manualSelectEditing&&!opt.force)return;
      let manual={};
      let cols=[['Value',r=>r.value]];
      if(id==='ipOut'){
        (await api('/api/manual-ip')).forEach(rule=>manual[rule.cidr]=rule.region);
        cols.push(['Regions',r=>(r.regions||[]).join(', ')],['Sources',r=>(r.sources||[]).join(', ')],['Select',r=>manualSelect(r,manual,'setManualIp')]);
      }
      if(id==='domainOut'){
        (await api('/api/manual-domain')).forEach(rule=>manual[rule.domain]=rule.region);
        cols.push(['Regions',r=>(r.regions||[]).join(', ')],['Sources',r=>(r.sources||[]).join(', ')],['Select',r=>manualSelect(r,manual,'setManualDomain')]);
      }
      document.getElementById(id).innerHTML=table(rows,cols,'conflict-table')
    }
    async function renderConnections(){let rows=await api('/api/activity/connections');connOut.innerHTML=table(rows,[['Time',r=>fmtTime(r.timestamp)],['Source',r=>r.source_ip+':'+r.source_port],['Destination',r=>(r.destination_ip||r.destination_domain)+':'+r.destination_port],['Domain',r=>r.domain||'-'],['Protocol',r=>r.protocol],['Decision',r=>r.decision]])}
    async function renderUnhitIp(){let rows=await api('/api/activity/unhit-ip');unhitIpOut.innerHTML=table(rows,[['Time',r=>fmtTime(r.timestamp)],['IP',r=>r.ip]])}
    async function renderUnhitDns(){let rows=await api('/api/activity/unhit-dns');unhitDnsOut.innerHTML=table(rows,[['Time',r=>fmtTime(r.timestamp)],['Domain',r=>r.domain]])}
    async function renderDns(){if(recentDnsRecord&&!recentDnsRecord.checked)return;let rows=await api('/api/activity/dns');dnsOut.innerHTML=table(rows,[['Time',r=>fmtTime(r.timestamp)],['Domain',r=>cleanDomain(r.domain)],['Type',r=>r.query_type],['Results',r=>(r.results||[]).join('<br>')],['Resolver',r=>r.resolver],['Cache',r=>r.cache_hit?'hit':'miss']])}
    async function renderRouteConflicts(){await renderConflicts('domainOut','/api/conflicts/domain');await renderConflicts('ipOut','/api/conflicts/ip')}
    async function renderSys(){let s=await api('/api/sys/status');let cls=s.nft_installed?'status-ok':'status-warn';let tableCls=s.dns_table_installed?'status-ok':'status-warn';let ip=(s.ip_conflicts||[]),domain=(s.domain_conflicts||[]);sysStatusOut.innerHTML=`<p><strong>nftables:</strong> <span class="${cls}">${s.nft_installed?'installed':'missing'}</span></p><p><strong>Version:</strong> ${s.nft_version||'-'}</p><p><strong>DNS nft table:</strong> <span class="${tableCls}">${s.dns_table_installed?'installed':'missing'}</span></p><p><strong>Ubuntu install command:</strong></p><pre>${s.install_command}</pre>${s.error?'<p class="hint">Error: '+s.error+'</p>':''}<h3 class="card-title">direct_ip.txt / bypass_ip.txt Conflicts</h3>${ip.length?'<pre>'+ip.join('\\n')+'</pre>':'<p class="hint">No conflicts</p>'}<h3 class="card-title">direct_domain.txt / bypass_domain.txt Conflicts</h3>${domain.length?'<pre>'+domain.join('\\n')+'</pre>':'<p class="hint">No conflicts</p>'}`}
    async function debugUrlCheck(){let url=debugUrl.value.trim();if(!url){debugUrlOut.innerHTML='<p class="hint">Enter a URL first</p>';return}debugUrlOut.innerHTML='<p class="hint">Running debug, timeout 6s...</p>';let r=await api('/api/sys/debug-url',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({url})});debugUrlOut.innerHTML=table([r],[['URL',x=>x.url],['Bypass Domain',x=>x.bypass_domain?'yes':'no'],['DNS Intercepted',x=>x.dns_intercepted?'yes':'no'],['DNS Cache',x=>x.dns_cache_hit?'hit':'miss'],['Resolved IPs',x=>(x.resolved_ips||[]).join('<br>')||'-'],['Transparent Port',x=>x.transparent_port_received?'received':'not received'],['Response',x=>x.response_received?'received':'none'],['HTTP',x=>x.http_code||'-'],['Error',x=>x.curl_error||'-']])}
    async function debugIpCheck(){let query=debugIp.value.trim();if(!query){debugIpOut.innerHTML='<p class="hint">Enter an IP or CIDR first</p>';return}let r=await api('/api/sys/debug-ip',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({query})});debugIpOut.innerHTML=table([r],[['Query',x=>x.query],['Valid',x=>x.valid?'yes':'no'],['bypass_ip.txt',x=>x.bypass_file?'yes':'no'],['bypass Matches',x=>(x.bypass_file_matches||[]).join('<br>')||'-'],['NFT Checked',x=>x.nft_checked?'yes':'no'],['NFT bypass',x=>x.nft_bypass?'yes':'no'],['NFT Matches',x=>(x.nft_matches||[]).join('<br>')||'-'],['Error',x=>x.error||x.nft_error||'-']])}
    function syncDnsRefreshToBasic(){dnsCacheRefreshEnabled.checked=dnsCacheRefreshEnabledDns.checked;dnsCacheRefreshBatch.value=dnsCacheRefreshBatchDns.value;updateClientJson()}
    async function saveDnsCacheSettings(){syncDnsRefreshToBasic();await saveClientConfig();dnsCacheMessage.textContent='Refresh settings saved, restarting service...'}
    async function renderDnsCacheStats(){let s=await api('/api/dns/cache/stats');dnsCacheSize.textContent=s.size;dnsCacheCapacityOut.textContent=s.capacity;dnsCacheTtlOut.textContent=s.ttl_seconds;dnsCacheRefreshEnabledDns.checked=s.refresh_enabled!==false;dnsCacheRefreshBatchDns.value=s.refresh_batch_size||500}
    async function queryDnsCache(){await renderDnsCacheStats();let domain=dnsQueryDomain.value.trim();if(!domain){dnsCacheOut.innerHTML='<p class="hint">Enter a domain</p>';return}let rows=await api('/api/dns/cache/query?domain='+encodeURIComponent(domain));let type=dnsQueryType.value;rows=rows.filter(r=>!type||r.query_type===type);dnsCacheOut.innerHTML=table(rows,[['Domain',r=>r.domain],['Type',r=>r.query_type],['Resolver',r=>r.resolver],['Results',r=>(r.results||[]).join('<br>')],['Expires',r=>fmtTime(r.expires_at)]])}
    async function queryDnsCacheIp(){await renderDnsCacheStats();let ip=dnsQueryIp.value.trim();if(!ip){dnsCacheOut.innerHTML='<p class="hint">Enter an IP</p>';return}let rows=await api('/api/dns/cache/query-ip?ip='+encodeURIComponent(ip));dnsCacheOut.innerHTML=table(rows,[['IP',r=>r.ip],['Domain',r=>r.domain],['Type',r=>r.query_type],['Resolver',r=>r.resolver],['Expires',r=>fmtTime(r.expires_at)]])}
    async function clearDnsDomain(){let domain=dnsQueryDomain.value.trim();if(!domain){dnsCacheMessage.textContent='Enter a domain first';return}let r=await api('/api/dns/cache/clear',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({domain})});dnsCacheMessage.textContent='Cleared '+r.cleared+' entries';await queryDnsCache()}
    async function clearDnsAll(){let r=await api('/api/dns/cache/clear',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({})});dnsCacheMessage.textContent='Cleared '+r.cleared+' entries';dnsCacheOut.innerHTML='';await renderDnsCacheStats()}
    async function refresh(id){try{if(id==='basic')await loadClientConfig();if(id==='dns')await renderDnsCacheStats();if(id==='routeConfig'){await loadRules();await renderRouteConflicts()}if(id==='sys')await renderSys();if(id==='connections'){await renderDns();await renderConnections();await renderUnhitDns();await renderUnhitIp()}}catch(e){alert(e.message)}}
    document.querySelector("nav button[data-tab=\"basic\"]").classList.add('active');
    window.addEventListener('resize',updateNavIndicator);
    requestAnimationFrame(updateNavIndicator);
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
