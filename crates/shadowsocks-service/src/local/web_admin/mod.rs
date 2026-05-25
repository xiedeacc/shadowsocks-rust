//! Embedded web admin for routing rules and DNS split.

use std::{
    convert::Infallible,
    fs, io,
    path::PathBuf,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    thread,
    time::Duration,
};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request, Response, StatusCode, body::Incoming, server::conn::http1, service::service_fn};
use log::{error, info, trace};
use pin_project::pin_project;
use tokio::{net::TcpListener, time};

use crate::{
    config::WebAdminConfig,
    local::routing::{ManualDomainRule, ManualIpRule, RoutingSources, RoutingState, RuleLists},
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
                    .serve_connection(io, service_fn(move |req| handler.clone().serve(req)))
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
    async fn serve(self: Arc<Self>, req: Request<Incoming>) -> Result<Response<ResponseBody>, Infallible> {
        Ok(match self.handle(req).await {
            Ok(resp) => resp,
            Err(err) => json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &serde_json::json!({ "error": err.to_string() }),
            ),
        })
    }

    async fn handle(&self, req: Request<Incoming>) -> io::Result<Response<ResponseBody>> {
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
            (Method::GET, "/api/client-config") => {
                let content = match fs::read_to_string(&self.client_config_path) {
                    Ok(content) => content,
                    Err(err) if err.kind() == io::ErrorKind::NotFound => String::new(),
                    Err(err) => return Err(err),
                };
                Ok(json_response(
                    StatusCode::OK,
                    &serde_json::json!({
                        "path": self.client_config_path,
                        "content": content,
                    }),
                ))
            }
            (Method::PUT, "/api/client-config") => {
                let payload: ClientConfigPayload = read_json(req).await?;
                if let Some(parent) = self.client_config_path.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::write(&self.client_config_path, payload.content)?;
                Ok(json_response(StatusCode::OK, &serde_json::json!({ "ok": true })))
            }
            (Method::GET, "/api/config/rules") => {
                Ok(json_response(StatusCode::OK, &self.routing_state.snapshot().await))
            }
            (Method::PUT, "/api/config/rules") => {
                let sources: RoutingSources = read_json(req).await?;
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
                    if let Err(err) = runtime.block_on(routing_state.update_from_sources()) {
                        log::warn!("failed to update route rules from sources: {}", err);
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
                self.routing_state.set_temporary_rules(rules).await;
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
            (Method::GET, "/api/activity/connections") => Ok(json_response(
                StatusCode::OK,
                &self.routing_state.recent_connections().await,
            )),
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
}

#[derive(serde::Deserialize)]
struct DnsPayload {
    domestic_dns: Vec<String>,
    foreign_dns: Vec<String>,
}

#[derive(serde::Deserialize)]
struct ClientConfigPayload {
    content: String,
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
    nav{padding:0;margin:0 0 16px;background:transparent;border:0;box-shadow:none}
    nav button{margin:0 8px 0 0;background:var(--soft);color:var(--brand2)}
    nav button:hover{background:#d7e7f4;color:var(--brand2)}
    nav button.active{background:var(--brand);color:#fff}
    nav button.active:hover{background:var(--brand2);color:#fff}
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
    .scroll-panel th{position:sticky;top:0;z-index:1}
    .conflict-table{table-layout:fixed}
    .conflict-table th:nth-child(1),.conflict-table td:nth-child(1){width:38%}
    .conflict-table th:nth-child(2),.conflict-table td:nth-child(2){width:17%}
    .conflict-table th:nth-child(3),.conflict-table td:nth-child(3){width:32%}
    .conflict-table th:nth-child(4),.conflict-table td:nth-child(4){width:13%}
    .conflict-table td{word-break:break-word}
    pre{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:12px;overflow:auto}
    .tab{display:none;height:calc(100vh - 88px);min-height:0;overflow:hidden}.tab.active{display:block}
    #basic.tab.active,#routeConfig.tab.active{display:flex;flex-direction:column}
    .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:12px}
    .activity-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));grid-template-rows:repeat(3,minmax(0,1fr));gap:16px;align-items:stretch;height:100%;min-height:0}
    .activity-card{min-width:0;min-height:0;display:flex;flex-direction:column}
    .basic-layout{display:grid;grid-template-columns:minmax(380px,540px) 1fr;gap:18px;align-items:stretch;height:calc(100% - 46px);min-height:0}
    .basic-form-panel{overflow:auto;min-height:0}
    .basic-json-panel{display:flex;flex-direction:column;min-height:0}
    .basic-json-panel textarea{flex:1}
    .basic-actions{margin-top:8px}
    .route-rules-layout{display:grid;grid-template-columns:minmax(320px,1fr) minmax(320px,1fr);gap:18px;align-items:start;margin-top:8px;min-height:0}
    .form-line{display:grid;grid-template-columns:150px 1fr;gap:10px;align-items:center;margin:4px 0}
    .form-line label{margin:0;font-size:13px}
    .form-line input[type=checkbox]{width:16px;height:16px;margin:0;justify-self:start}
    #clientConfig{min-height:0;height:auto;max-height:none;overflow:auto;resize:vertical;font-size:13px}
    #rulesJson{min-height:100px;height:auto;max-height:none;overflow:auto;resize:vertical;font-size:13px;flex:1}
    #routeConfig .route-rules-layout textarea{height:clamp(56px,8vh,96px);min-height:56px;resize:vertical}
    .row{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:8px;align-items:center;margin:4px 0}
    .row input{margin:0}
    .row button{margin:0;white-space:nowrap}
    .hint{color:var(--muted);font-size:12px}
    .progress-box{margin:8px auto 0;max-width:760px;max-height:120px;overflow:auto;text-align:left;background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:10px;box-shadow:0 1px 2px #10203312}
    .progress-bar{height:10px;background:var(--soft);border-radius:999px;overflow:hidden;margin:8px 0}
    .progress-fill{height:100%;width:0;background:var(--brand)}
    .progress-completed{white-space:pre-line;margin-top:8px}
    @media(max-width:1100px){.activity-grid,.route-rules-layout{grid-template-columns:1fr}.activity-grid{grid-template-rows:repeat(6,minmax(0,1fr))}}
    @media(max-width:900px){.basic-layout{grid-template-columns:1fr}#clientConfig,#rulesJson{height:auto;max-height:none}}
  </style>
</head>
<body>
  <nav>
    <button onclick="show('basic')">Basic Config</button>
    <button onclick="show('connections')">Connections</button>
    <button onclick="show('routeConfig')">Generated Route Config</button>
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
        <h3 class="card-title">Server</h3>
        <fieldset>
          <div class="form-line"><label>Server Address</label><input id="serverHost"></div>
          <div class="form-line"><label>Server Port</label><input id="serverPort" type="number" min="1" max="65535"></div>
          <div class="form-line"><label>Method</label><select id="method">
            <option>aes-128-gcm</option><option>aes-256-gcm</option><option>chacha20-ietf-poly1305</option>
            <option>2022-blake3-aes-128-gcm</option><option>2022-blake3-aes-256-gcm</option>
          </select></div>
          <div class="form-line"><label>Password</label><input id="password" type="password"></div>
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
      <button onclick="saveClientConfig()">Save Generated JSON</button>
    </div>
  </section>

  <section id="connections" class="tab">
    <div class="activity-grid">
      <div class="activity-card">
        <h3 class="card-title">Recent DNS</h3>
        <div id="dnsOut" class="scroll-panel section-scroll"></div>
      </div>
      <div class="activity-card">
        <h3 class="card-title">Recent Connections</h3>
        <div id="connOut" class="scroll-panel section-scroll"></div>
      </div>
      <div class="activity-card">
        <h3 class="card-title">Domain Conflicts</h3>
        <div id="domainOut" class="scroll-panel section-scroll"></div>
      </div>
      <div class="activity-card">
        <h3 class="card-title">IP Conflicts</h3>
        <div id="ipOut" class="scroll-panel section-scroll"></div>
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
    <h3 class="card-title">Rules</h3>
    <textarea id="rulesJson"></textarea>
    <div>
      <button onclick="loadRules()">Reload Rules</button>
      <button onclick="saveRules()">Save Rules</button>
    </div>
    <h3 class="card-title">Temporary Lists</h3>
    <div class="route-rules-layout">
      <fieldset>
        <label>Direct IP<textarea id="tmp_direct_ip"></textarea></label>
        <label>Direct Domain<textarea id="tmp_direct_domain"></textarea></label>
      </fieldset>
      <fieldset>
        <label>Bypass IP<textarea id="tmp_bypass_ip"></textarea></label>
        <label>Bypass Domain<textarea id="tmp_bypass_domain"></textarea></label>
      </fieldset>
    </div>
    <p class="hint">Temporary lists have priority over generated direct/bypass files. 一行一个配置，无需分隔符。</p>
    <div style="text-align:center;margin-top:20px">
      <button onclick="updateRules()">Download and Generate Persistent Files</button>
    </div>
    <p class="hint" style="text-align:center">Downloads are cached in data/source. Downloads are first written to data/source/temp and only replace the source file after success.</p>
    <div id="ruleUpdateProgress" class="progress-box">
      <div><strong>Status:</strong> <span id="progressStatus">idle</span></div>
      <div class="progress-bar"><div id="progressFill" class="progress-fill"></div></div>
      <div><strong>Current source:</strong> <span id="progressSource">-</span></div>
      <div><strong>Progress:</strong> <span id="progressPercent">0%</span>, <strong>remaining files:</strong> <span id="progressRemaining">0</span></div>
      <div class="hint" id="progressMessage"></div>
      <div class="hint progress-completed" id="progressCompleted"></div>
    </div>
  </section>

  <script>
    let currentConfigPath='', currentRawConfig={}, rulesSnapshot={};
    const routeSourceKeys=['geoip_sources','geosite_sources','direct_domain_sources','bypass_domain_sources'];
    const dnsKeys=['domestic_dns','foreign_dns'];
    const sourceKeys=[...routeSourceKeys,...dnsKeys];
    function token(){return new URLSearchParams(location.search).get('token')||''}
    async function api(path,opt={}){opt.headers=Object.assign({'x-admin-token':token()},opt.headers||{});let r=await fetch(path,opt);let j=await r.json();if(!r.ok)throw new Error(j.error||r.statusText);return j}
    let activeTab='basic', activityTimer=null;
    function show(id){
      activeTab=id;
      if(activityTimer){clearInterval(activityTimer);activityTimer=null}
      document.querySelectorAll('.tab').forEach(e=>e.classList.remove('active'));
      document.getElementById(id).classList.add('active');
      document.querySelectorAll('nav button').forEach(b=>b.classList.toggle('active',b.getAttribute('onclick')===`show('${id}')`));
      refresh(id);
      if(id==='connections')activityTimer=setInterval(()=>refresh('connections').catch(e=>{console.warn(e)}),3000);
    }
    function lines(v){return (v||'').split('\n').map(s=>s.trim()).filter(Boolean)}
    function setLines(id,arr){document.getElementById(id).value=(arr||[]).join('\n')}
    function num(v,d){let n=parseInt(v,10);return Number.isFinite(n)?n:d}
    function firstLocal(protocol){return (currentRawConfig.locals||[]).find(l=>l.protocol===protocol)||{}}
    function firstServer(){return (currentRawConfig.servers||[])[0]||{}}
    function setSelect(id,value){let el=document.getElementById(id); if([...el.options].some(o=>o.value===value)){el.value=value}else{el.value=el.options[0].value}}
    function renderBasic(){
      let socks=firstLocal('socks'), http=firstLocal('http'), redir=firstLocal('redir'), server=firstServer();
      setSelect('socksBind',socks.local_address||'127.0.0.1'); socksPort.value=socks.local_port||1080;
      setSelect('httpBind',http.local_address||'127.0.0.1'); httpPort.value=http.local_port||1081;
      redirEnable.checked=!!redir.protocol;
      setSelect('redirBind',redir.local_address||'0.0.0.0'); redirPort.value=redir.local_port||12345;
      setSelect('redirMode',redir.mode||'tcp_and_udp'); setSelect('tcpRedir',redir.tcp_redir||'redirect'); setSelect('udpRedir',redir.udp_redir||'tproxy');
      serverHost.value=server.server||''; serverPort.value=server.server_port||443; setSelect('method',server.method||'aes-256-gcm');
      password.value=server.password||''; timeout.value=server.timeout||300; plugin.value=server.plugin||''; pluginOpts.value=server.plugin_opts||'';
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
      let server={server:serverHost.value.trim(),server_port:num(serverPort.value,443),password:password.value,timeout:num(timeout.value,300),method:method.value};
      if(plugin.value.trim())server.plugin=plugin.value.trim();
      if(pluginOpts.value.trim())server.plugin_opts=pluginOpts.value.trim();
      return Object.assign({},currentRawConfig,{locals,servers:[server]});
    }
    function updateClientJson(){clientConfig.value=JSON.stringify(buildClientConfig(),null,2)}
    async function loadClientConfig(){
      let r=await api('/api/client-config'); currentConfigPath=r.path; configPath.textContent=r.path;
      try{currentRawConfig=r.content?JSON.parse(r.content):{}}catch(e){currentRawConfig={locals:[],servers:[]}; clientConfig.value=r.content||''; return}
      renderBasic();
    }
    async function saveClientConfig(){updateClientJson(); await api('/api/client-config',{method:'PUT',headers:{'content-type':'application/json'},body:JSON.stringify({content:clientConfig.value})}); await loadClientConfig()}
    ['socksBind','socksPort','httpBind','httpPort','redirEnable','redirBind','redirPort','redirMode','tcpRedir','udpRedir','serverHost','serverPort','method','password','timeout','plugin','pluginOpts'].forEach(id=>setTimeout(()=>document.getElementById(id).addEventListener('input',updateClientJson),0));

    function sourceRow(key,value=''){let div=document.createElement('div');div.className='row';div.innerHTML=`<input value="${value.replaceAll('"','&quot;')}"><button type="button">Remove</button>`;div.querySelector('button').onclick=()=>{div.remove();updateRulesJson()};div.querySelector('input').oninput=updateRulesJson;document.getElementById(key).appendChild(div)}
    function addSource(key){sourceRow(key);updateRulesJson()}
    function readSource(key){return [...document.querySelectorAll('#'+key+' input')].map(i=>i.value.trim()).filter(Boolean)}
    function renderSource(key,values){document.getElementById(key).innerHTML='';(values||[]).forEach(v=>sourceRow(key,v));if(!(values||[]).length)sourceRow(key,'')}
    function tempRules(){return {direct_ip:lines(tmp_direct_ip.value),direct_domain:lines(tmp_direct_domain.value),bypass_ip:lines(tmp_bypass_ip.value),bypass_domain:lines(tmp_bypass_domain.value)}}
    function sourcesFromForm(){return (rulesSnapshot&&rulesSnapshot.sources)||{}}
    function updateRulesJson(snapshot=rulesSnapshot){rulesJson.value=JSON.stringify({sources:(snapshot&&snapshot.sources)||{}},null,2)}
    function rulesPayloadFromJson(){
      let payload=JSON.parse(rulesJson.value||'{}');
      let sources=Object.assign({},(rulesSnapshot&&rulesSnapshot.sources)||{},payload.sources||{});
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
    function table(rows,cols,cls=''){if(!rows.length)return '<p class="hint">No data</p>';return `<table class="${cls}"><thead><tr>`+cols.map(c=>'<th>'+c[0]+'</th>').join('')+'</tr></thead><tbody>'+rows.map(r=>'<tr>'+cols.map(c=>'<td>'+String(c[1](r)??'')+'</td>').join('')+'</tr>').join('')+'</tbody></table>'}
    function fmtTime(ts){return ts?new Date(ts*1000).toLocaleString():''}
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
    async function renderConnections(){let rows=await api('/api/activity/connections');connOut.innerHTML=table(rows,[['Time',r=>fmtTime(r.timestamp)],['Source',r=>r.source_ip+':'+r.source_port],['Destination',r=>(r.destination_ip||r.destination_domain)+':'+r.destination_port],['Protocol',r=>r.protocol],['Decision',r=>r.decision]])}
    async function renderUnhitIp(){let rows=await api('/api/activity/unhit-ip');unhitIpOut.innerHTML=table(rows,[['Time',r=>fmtTime(r.timestamp)],['IP',r=>r.ip]])}
    async function renderUnhitDns(){let rows=await api('/api/activity/unhit-dns');unhitDnsOut.innerHTML=table(rows,[['Time',r=>fmtTime(r.timestamp)],['Domain',r=>r.domain]])}
    async function renderDns(){let rows=await api('/api/activity/dns');dnsOut.innerHTML=table(rows,[['Time',r=>fmtTime(r.timestamp)],['Domain',r=>r.domain],['Type',r=>r.query_type],['Results',r=>(r.results||[]).join('<br>')],['Resolver',r=>r.resolver]])}
    async function refresh(id){try{if(id==='basic')await loadClientConfig();if(id==='routeConfig')await loadRules();if(id==='connections'){await renderDns();await renderConnections();await renderConflicts('domainOut','/api/conflicts/domain');await renderConflicts('ipOut','/api/conflicts/ip');await renderUnhitDns();await renderUnhitIp()}}catch(e){alert(e.message)}}
    document.querySelector("nav button[onclick=\"show('basic')\"]").classList.add('active');
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
