//! Shadowsocks Local Server

#[cfg(all(feature = "local-dns", feature = "local-web-admin", target_os = "linux"))]
use std::net::{IpAddr, ToSocketAddrs};
use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use futures::future;
use log::trace;
#[cfg(all(windows, feature = "local-tun"))]
use log::{info, warn};
use shadowsocks::{
    config::Mode,
    net::{AcceptOpts, ConnectOpts},
};

#[cfg(feature = "local-flow-stat")]
use crate::{config::LocalFlowStatAddress, net::FlowStat};
use crate::{
    config::{Config, ConfigType, ProtocolType},
    dns::build_dns_resolver,
    utils::ServerHandle,
};

use self::{
    context::ServiceContext,
    loadbalancing::{PingBalancer, PingBalancerBuilder},
};

#[cfg(all(feature = "local-dns", feature = "local-web-admin", target_os = "linux"))]
use self::dns::intercept_linux::DnsInterceptGuard;
#[cfg(feature = "local-dns")]
use self::dns::{Dns, DnsBuilder};
#[cfg(feature = "local-fake-dns")]
use self::fake_dns::{FakeDns, FakeDnsBuilder};
#[cfg(feature = "local-http")]
use self::http::{Http, HttpBuilder};
#[cfg(feature = "local-online-config")]
use self::online_config::{OnlineConfigService, OnlineConfigServiceBuilder};
#[cfg(feature = "local-redir")]
use self::redir::{Redir, RedirBuilder};
use self::socks::{Socks, SocksBuilder};
#[cfg(feature = "local-tun")]
use self::tun::{Tun, TunBuilder};
#[cfg(feature = "local-tunnel")]
use self::tunnel::{Tunnel, TunnelBuilder};
#[cfg(feature = "local-web-admin")]
use self::{
    routing::{DnsRuntimeState, RoutingState},
    web_admin::{WebAdmin, WebAdminBuilder},
};

#[cfg(all(feature = "local-dns", feature = "local-web-admin"))]
use shadowsocks::relay::socks5::Address;
#[cfg(all(feature = "local-dns", feature = "local-web-admin"))]
use self::dns::config::NameServerAddr;
#[cfg(all(feature = "local-dns", feature = "local-web-admin"))]
use crate::config::LocalConfig;

pub mod context;
#[cfg(feature = "local-dns")]
pub mod dns;
#[cfg(feature = "local-fake-dns")]
pub mod fake_dns;
#[cfg(feature = "local-http")]
pub mod http;
pub mod loadbalancing;
pub mod net;
#[cfg(feature = "local-online-config")]
pub mod online_config;
#[cfg(feature = "local-redir")]
pub mod redir;
#[cfg(feature = "local-web-admin")]
pub mod routing;
pub mod socks;
#[cfg(feature = "local-tun")]
pub mod tun;
#[cfg(feature = "local-tunnel")]
pub mod tunnel;
pub mod utils;
#[cfg(feature = "local-web-admin")]
pub mod web_admin;

/// Default TCP Keep Alive timeout
///
/// This is borrowed from Go's `net` library's default setting
pub(crate) const LOCAL_DEFAULT_KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(15);

/// Local Server instance
pub struct Server {
    balancer: PingBalancer,
    socks_servers: Vec<Socks>,
    #[cfg(feature = "local-tunnel")]
    tunnel_servers: Vec<Tunnel>,
    #[cfg(feature = "local-http")]
    http_servers: Vec<Http>,
    #[cfg(feature = "local-tun")]
    tun_servers: Vec<Tun>,
    #[cfg(feature = "local-dns")]
    dns_servers: Vec<Dns>,
    #[cfg(all(feature = "local-dns", feature = "local-web-admin", target_os = "linux"))]
    dns_intercept_guards: Vec<DnsInterceptGuard>,
    #[cfg(feature = "local-redir")]
    redir_servers: Vec<Redir>,
    #[cfg(feature = "local-fake-dns")]
    fake_dns_servers: Vec<FakeDns>,
    #[cfg(feature = "local-flow-stat")]
    local_stat_addr: Option<LocalFlowStatAddress>,
    #[cfg(feature = "local-flow-stat")]
    flow_stat: Arc<FlowStat>,
    #[cfg(feature = "local-online-config")]
    online_config: Option<OnlineConfigService>,
    #[cfg(feature = "local-web-admin")]
    web_admin: Option<WebAdmin>,
}

impl Server {
    /// Create a shadowsocks local server
    pub async fn new(config: Config) -> io::Result<Self> {
        assert!(config.config_type == ConfigType::Local && !config.local.is_empty());

        trace!("{:?}", config);

        // Warning for Stream Ciphers
        // NOTE: This will only check servers in config.
        #[cfg(feature = "stream-cipher")]
        for inst in config.server.iter() {
            let server = &inst.config;

            if server.method().is_stream() {
                log::warn!(
                    "stream cipher {} for server {} have inherent weaknesses (see discussion in https://github.com/shadowsocks/shadowsocks-org/issues/36). \
                    DO NOT USE. It will be removed in the future.",
                    server.method(),
                    server.addr()
                );
            }
        }

        #[cfg(all(unix, not(target_os = "android")))]
        if let Some(nofile) = config.nofile {
            use crate::sys::set_nofile;
            if let Err(err) = set_nofile(nofile) {
                log::warn!("set_nofile {} failed, error: {}", nofile, err);
            }
        }

        // Global ServiceContext template
        // Each Local instance will hold a copy of its fields
        let mut context = ServiceContext::new();

        #[cfg(all(windows, feature = "local-tun"))]
        let (outbound_bind_interface, outbound_bind_addr) = {
            let has_tun = config
                .local
                .iter()
                .any(|l| !l.config.disabled && matches!(l.config.protocol, ProtocolType::Tun));
            let need_auto = has_tun
                && config.outbound_bind_interface.is_none()
                && config.outbound_bind_addr.is_none();
            if need_auto {
                match tun::detect_windows_physical_endpoint() {
                    Some((iface, ip)) => {
                        info!("[TUN] auto-detected outbound bind: iface={iface} ip={ip}");
                        (Some(iface), Some(ip))
                    }
                    None => {
                        warn!("[TUN] unable to detect outbound bind endpoint; outbound TCP may loop through TUN (os error 10049)");
                        (config.outbound_bind_interface.clone(), config.outbound_bind_addr)
                    }
                }
            } else {
                (config.outbound_bind_interface.clone(), config.outbound_bind_addr)
            }
        };
        #[cfg(not(all(windows, feature = "local-tun")))]
        let outbound_bind_interface = config.outbound_bind_interface.clone();
        #[cfg(not(all(windows, feature = "local-tun")))]
        let outbound_bind_addr = config.outbound_bind_addr;

        // H-5: when firewall transparent proxy also captures the router's OWN
        // output (proxy_local_output), tag sslocal's outbound sockets with a
        // dedicated fwmark so the output redirect/tproxy chains can exempt them
        // by identity (`meta mark <mark> return`) — a loop guard that, unlike the
        // SS-server-IP `return` rule, cannot go stale for a domain-name server.
        // Prefer a user-configured outbound_fwmark if present.
        #[cfg(all(feature = "local-dns", feature = "local-web-admin", target_os = "linux"))]
        let local_output_exempt_mark: Option<u32> = if matches!(
            config.route_rules.dns_intercept_mode.as_str(),
            "firewall" | "both"
        ) && config.route_rules.proxy_local_output
        {
            Some(
                config
                    .outbound_fwmark
                    .unwrap_or(self::dns::intercept_linux::LOCAL_OUTPUT_EXEMPT_MARK_DEFAULT),
            )
        } else {
            None
        };

        let mut connect_opts = ConnectOpts {
            #[cfg(any(target_os = "linux", target_os = "android"))]
            fwmark: config.outbound_fwmark,
            #[cfg(target_os = "freebsd")]
            user_cookie: config.outbound_user_cookie,

            #[cfg(target_os = "android")]
            vpn_protect_path: config.outbound_vpn_protect_path,

            bind_interface: outbound_bind_interface,
            bind_local_addr: outbound_bind_addr.map(|ip| SocketAddr::new(ip, 0)),

            ..Default::default()
        };
        connect_opts.tcp.send_buffer_size = config.outbound_send_buffer_size;
        connect_opts.tcp.recv_buffer_size = config.outbound_recv_buffer_size;
        connect_opts.tcp.nodelay = config.no_delay;
        connect_opts.tcp.fastopen = config.fast_open;
        connect_opts.tcp.keepalive = config.keep_alive.or(Some(LOCAL_DEFAULT_KEEPALIVE_TIMEOUT));
        connect_opts.tcp.mptcp = config.mptcp;
        connect_opts.udp.mtu = config.udp_mtu;
        connect_opts.udp.allow_fragmentation = config.outbound_udp_allow_fragmentation;
        #[cfg(all(feature = "local-dns", feature = "local-web-admin", target_os = "linux"))]
        if let Some(mark) = local_output_exempt_mark {
            connect_opts.fwmark = Some(mark);
        }
        context.set_connect_opts(connect_opts);

        let mut accept_opts = AcceptOpts {
            ipv6_only: config.ipv6_only,
            ..Default::default()
        };
        accept_opts.tcp.send_buffer_size = config.inbound_send_buffer_size;
        accept_opts.tcp.recv_buffer_size = config.inbound_recv_buffer_size;
        accept_opts.tcp.nodelay = config.no_delay;
        accept_opts.tcp.fastopen = config.fast_open;
        accept_opts.tcp.keepalive = config.keep_alive.or(Some(LOCAL_DEFAULT_KEEPALIVE_TIMEOUT));
        accept_opts.tcp.mptcp = config.mptcp;
        accept_opts.udp.mtu = config.udp_mtu;
        context.set_accept_opts(accept_opts);

        #[cfg(all(feature = "local-dns", feature = "local-web-admin", target_os = "linux"))]
        let dns_intercept_proxy_exempt_endpoints = collect_dns_intercept_proxy_exempt_endpoints(&config);

        if let Some(resolver) = build_dns_resolver(
            config.dns,
            config.ipv6_first,
            config.dns_cache_size,
            context.connect_opts_ref(),
        )
        .await
        {
            context.set_dns_resolver(Arc::new(resolver));
        }

        if config.ipv6_first {
            context.set_ipv6_first(config.ipv6_first);
        }

        if let Some(acl) = config.acl {
            context.set_acl(Arc::new(acl));
        }

        #[cfg(feature = "local-web-admin")]
        let routing_state = {
            let routing_state = RoutingState::load(config.route_rules.clone()).await?;
            context.set_routing_state(routing_state.clone());

            // -----------------------------------------------------------
            // Diagnostic task #1 — periodic snapshot logger.
            //
            // Once a minute we read collection sizes and the cumulative
            // hot-path counters and emit two structured lines into the
            // log. We *also* keep the previous tick's counter values so
            // we can print per-minute deltas — this is what tells us
            // whether `prune_dns_cache` / nft fork+exec / sync file
            // append are eating wall-clock under load.
            //
            // The task is detached: it lives for the process lifetime
            // and is aborted cleanly when the runtime shuts down.
            // -----------------------------------------------------------
            tokio::spawn({
                let state = routing_state.clone();
                async move {
                    let mut interval = tokio::time::interval(Duration::from_secs(60));
                    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                    // Skip the immediate first tick to avoid emitting a
                    // useless "all zeros" snapshot during boot.
                    interval.tick().await;
                    let mut prev_prune_calls: u64 = 0;
                    let mut prev_prune_ns: u64 = 0;
                    let mut prev_nft_calls: u64 = 0;
                    let mut prev_nft_ns: u64 = 0;
                    let mut prev_append_calls: u64 = 0;
                    let mut prev_append_ns: u64 = 0;
                    let mut prev_add_calls: u64 = 0;
                    let mut prev_add_ns: u64 = 0;
                    let mut prev_tick = std::time::Instant::now();
                    loop {
                        interval.tick().await;
                        let d = state.runtime_diagnostics().await;

                        let now = std::time::Instant::now();
                        let elapsed_ms = now.duration_since(prev_tick).as_millis().max(1);
                        prev_tick = now;

                        // Per-tick deltas. Saturating subtraction so we
                        // can't underflow even if some future caller
                        // resets a counter (none do today).
                        let dprune_calls = d.prune_dns_cache_calls.saturating_sub(prev_prune_calls);
                        let dprune_ns = d.prune_dns_cache_total_ns.saturating_sub(prev_prune_ns);
                        let dnft_calls = d.nft_invocations.saturating_sub(prev_nft_calls);
                        let dnft_ns = d.nft_total_ns.saturating_sub(prev_nft_ns);
                        let dappend_calls = d.append_lines_calls.saturating_sub(prev_append_calls);
                        let dappend_ns = d.append_lines_total_ns.saturating_sub(prev_append_ns);
                        let dadd_calls = d.add_dns_results_calls.saturating_sub(prev_add_calls);
                        let dadd_ns = d.add_dns_results_total_ns.saturating_sub(prev_add_ns);

                        prev_prune_calls = d.prune_dns_cache_calls;
                        prev_prune_ns = d.prune_dns_cache_total_ns;
                        prev_nft_calls = d.nft_invocations;
                        prev_nft_ns = d.nft_total_ns;
                        prev_append_calls = d.append_lines_calls;
                        prev_append_ns = d.append_lines_total_ns;
                        prev_add_calls = d.add_dns_results_calls;
                        prev_add_ns = d.add_dns_results_total_ns;

                        // Wall-clock duty cycle: how many ms out of the
                        // tick window did each hot path occupy. >100ms /
                        // 60_000ms ≈ 0.17% so we can spot >1% trivially.
                        let dprune_ms = dprune_ns / 1_000_000;
                        let dnft_ms = dnft_ns / 1_000_000;
                        let dappend_ms = dappend_ns / 1_000_000;
                        let dadd_ms = dadd_ns / 1_000_000;

                        log::info!(
                            "routing diagnostics: dns_cache={}/{} order={} ttl={}s \
                             dns_events={} conns={} flow_dec={} reverse={} \
                             persist_direct_ip={} persist_proxy_ip={} \
                             tmp_direct_ip={} tmp_proxy_ip={}",
                            d.dns_cache_size,
                            d.dns_cache_capacity,
                            d.dns_cache_order_len,
                            d.dns_cache_ttl_seconds,
                            d.dns_events,
                            d.connections,
                            d.flow_decisions,
                            d.reverse_domains,
                            d.persistent_direct_ip,
                            d.persistent_proxy_ip,
                            d.temporary_direct_ip,
                            d.temporary_proxy_ip,
                        );
                        log::info!(
                            "routing hot-paths (last {}ms): \
                             prune calls={} time={}ms | \
                             nft invocations={} time={}ms | \
                             append calls={} time={}ms | \
                             add_dns_results calls={} time={}ms",
                            elapsed_ms,
                            dprune_calls,
                            dprune_ms,
                            dnft_calls,
                            dnft_ms,
                            dappend_calls,
                            dappend_ms,
                            dadd_calls,
                            dadd_ms,
                        );
                    }
                }
            });

            // -----------------------------------------------------------
            // Diagnostic task #2 — passive routing-lock health probe.
            //
            // Every 5s we attempt a *read* lock with a 2s timeout. If
            // the lock isn't granted in 2s, the routing RwLock is
            // effectively wedged: some writer is holding it for >2s,
            // which on this hardware means a thread is blocked on disk
            // I/O, a stuck `nft` subprocess, or a deadlock. The probe
            // is read-only and never blocks any other path, so it's
            // safe to leave on in production.
            //
            // The lock-wait latency itself is logged whenever it
            // exceeds 50ms — at that point we know writers are
            // dominating the lock and the next forensic step is to
            // check the hot-path delta logger above.
            // -----------------------------------------------------------
            tokio::spawn({
                let state = routing_state.clone();
                async move {
                    let mut interval = tokio::time::interval(Duration::from_secs(5));
                    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                    loop {
                        interval.tick().await;
                        let started = std::time::Instant::now();
                        match tokio::time::timeout(
                            Duration::from_secs(2),
                            state.runtime_diagnostics(),
                        )
                        .await
                        {
                            Ok(_) => {
                                let waited = started.elapsed();
                                if waited >= Duration::from_millis(50) {
                                    log::warn!(
                                        "routing read probe took {}ms (lock contended)",
                                        waited.as_millis()
                                    );
                                }
                            }
                            Err(_) => {
                                log::error!(
                                    "routing read probe TIMED OUT (>2s) — write lock is wedged \
                                     or runtime is starved; check sslocal-probe diagnostics dump"
                                );
                            }
                        }
                    }
                }
            });

            // -----------------------------------------------------------
            // Diagnostic task #3 — SIGUSR1 force-dump.
            //
            // The OpenWrt-side probe script (sslocal-probe.sh) sends
            // SIGUSR1 to sslocal the moment it detects 5 consecutive
            // 2-second timeouts on www.google.com via the transparent
            // proxy. On receipt we (a) immediately emit a full
            // diagnostic snapshot at error level so it's hard to miss
            // when grepping the log, and (b) try a non-blocking 1.5s
            // read-lock attempt so we can tell — at the exact moment
            // probes started failing — whether the routing lock was
            // already stuck.
            // -----------------------------------------------------------
            #[cfg(unix)]
            tokio::spawn({
                let state = routing_state.clone();
                async move {
                    let mut sig =
                        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined1())
                        {
                            Ok(s) => s,
                            Err(err) => {
                                log::warn!("failed to install SIGUSR1 handler: {}", err);
                                return;
                            }
                        };
                    log::info!("SIGUSR1 routing-state dump handler installed");
                    while sig.recv().await.is_some() {
                        let started = std::time::Instant::now();
                        let snapshot =
                            tokio::time::timeout(Duration::from_millis(1500), state.runtime_diagnostics())
                                .await;
                        let waited_ms = started.elapsed().as_millis();
                        match snapshot {
                            Ok(d) => log::error!(
                                "SIGUSR1 dump (lock waited {}ms): \
                                 dns_cache={}/{} order={} \
                                 dns_events={} conns={} flow_dec={} reverse={} \
                                 persist_direct_ip={} persist_proxy_ip={} \
                                 tmp_direct_ip={} tmp_proxy_ip={} | \
                                 cumulative: prune calls={} time_ns={} | \
                                 nft invocations={} time_ns={} | \
                                 append calls={} time_ns={} | \
                                 add_dns_results calls={} time_ns={}",
                                waited_ms,
                                d.dns_cache_size,
                                d.dns_cache_capacity,
                                d.dns_cache_order_len,
                                d.dns_events,
                                d.connections,
                                d.flow_decisions,
                                d.reverse_domains,
                                d.persistent_direct_ip,
                                d.persistent_proxy_ip,
                                d.temporary_direct_ip,
                                d.temporary_proxy_ip,
                                d.prune_dns_cache_calls,
                                d.prune_dns_cache_total_ns,
                                d.nft_invocations,
                                d.nft_total_ns,
                                d.append_lines_calls,
                                d.append_lines_total_ns,
                                d.add_dns_results_calls,
                                d.add_dns_results_total_ns,
                            ),
                            Err(_) => log::error!(
                                "SIGUSR1 dump: routing read lock timed out after 1.5s — \
                                 writer holding the lock for >1.5s"
                            ),
                        }
                    }
                }
            });

            routing_state
        };

        context.set_security_config(&config.security);

        if !config.outbound_proxy.is_empty() {
            let has_udp = config
                .local
                .iter()
                .any(|local| !local.config.disabled && local.config.mode.enable_udp());
            if has_udp {
                let preview = crate::net::OutboundProxyClient::from_config(&config.outbound_proxy);
                if !preview.supports_udp() {
                    log::warn!(
                        "outbound proxy chain contains non-SOCKS5 hop(s); UDP traffic will use the Direct path. \
                         Configure a SOCKS5-only chain to enable UDP relay."
                    );
                }
            }
            context.set_outbound_proxies(config.outbound_proxy);
        }

        assert!(
            config.local.iter().any(|local| !local.config.disabled),
            "no enabled local server configuration"
        );

        // Create a service balancer for choosing between multiple servers
        let balancer = {
            let mut mode: Option<Mode> = None;

            for local in &config.local {
                if local.config.disabled {
                    continue;
                }
                mode = Some(match mode {
                    None => local.config.mode,
                    Some(m) => m.merge(local.config.mode),
                });
            }

            let mode = mode.unwrap_or(Mode::TcpOnly);

            // Load balancer will hold an individual ServiceContext
            let mut balancer_builder = PingBalancerBuilder::new(Arc::new(context.clone()), mode);

            // max_server_rtt have to be set before add_server
            if let Some(rtt) = config.balancer.max_server_rtt {
                balancer_builder.max_server_rtt(rtt);
            }

            if let Some(intv) = config.balancer.check_interval {
                balancer_builder.check_interval(intv);
            }

            if let Some(intv) = config.balancer.check_best_interval {
                balancer_builder.check_best_interval(intv);
            }

            for server in config.server {
                balancer_builder.add_server(server);
            }

            balancer_builder.build().await?
        };

        let mut local_server = Self {
            balancer: balancer.clone(),
            socks_servers: Vec::new(),
            #[cfg(feature = "local-tunnel")]
            tunnel_servers: Vec::new(),
            #[cfg(feature = "local-http")]
            http_servers: Vec::new(),
            #[cfg(feature = "local-tun")]
            tun_servers: Vec::new(),
            #[cfg(feature = "local-dns")]
            dns_servers: Vec::new(),
            #[cfg(all(feature = "local-dns", feature = "local-web-admin", target_os = "linux"))]
            dns_intercept_guards: Vec::new(),
            #[cfg(feature = "local-redir")]
            redir_servers: Vec::new(),
            #[cfg(feature = "local-fake-dns")]
            fake_dns_servers: Vec::new(),
            #[cfg(feature = "local-flow-stat")]
            local_stat_addr: config.local_stat_addr,
            #[cfg(feature = "local-flow-stat")]
            flow_stat: context.flow_stat(),
            #[cfg(feature = "local-online-config")]
            online_config: match config.online_config {
                None => None,
                Some(online_config) => {
                    let mut builder = OnlineConfigServiceBuilder::new(
                        Arc::new(context.clone()),
                        online_config.config_url,
                        balancer.clone(),
                    );
                    if let Some(update_interval) = online_config.update_interval {
                        builder.set_update_interval(update_interval);
                    }
                    Some(builder.build().await?)
                }
            },
            #[cfg(feature = "local-web-admin")]
            web_admin: match config.web_admin {
                None => None,
                Some(web_admin) => Some(WebAdminBuilder::new(web_admin, routing_state.clone()).build().await?),
            },
        };

        #[cfg(all(feature = "local-dns", feature = "local-web-admin", target_os = "linux"))]
        let dns_intercept_mode = config.route_rules.dns_intercept_mode.clone();

        // Always scrub any firewall state left behind by a previous run BEFORE
        // we (maybe) reinstall it. Doing this UNCONDITIONALLY — not only when
        // interception is disabled — also covers the dangerous firewall-mode
        // cases the old guard missed: a prior run SIGKILL'd/panicked in firewall
        // mode whose `setup_nft` rebuild never happens this run because there is
        // no enabled DNS listener (or it falls back to a different backend).
        // Without this, the orphan `inet ssrust_redir` redirect table keeps
        // black-holing DNS. `setup_nft` also deletes+recreates the table, so the
        // extra delete here is harmless. Drop-based cleanup only fires on a
        // graceful shutdown; SIGKILL / panic=abort / power loss skip it, so this
        // startup scrub plus the init `cleanup_firewall`/watchdog are the safety
        // net for those paths.
        #[cfg(all(feature = "local-dns", feature = "local-web-admin", target_os = "linux"))]
        {
            self::dns::intercept_linux::cleanup_stale_nft_table();
        }

        // Derive runtime DNS endpoints (domestic / foreign upstreams +
        // listen address) from the *first* `protocol: dns` listener.
        // Used by:
        //   * the firewall / TUN DNS interceptor — needs the listen
        //     port to redirect to and the upstream IPs to exempt
        //     (otherwise the local DNS server's own queries would loop
        //     back into the redirect rule);
        //   * the web admin `GET /api/dns` view.
        // After this refactor `route_rules.{domestic,foreign}_dns` and
        // `route_rules.dns_listen_*` no longer exist in the JSON
        // schema — `locals[].dns` is the single source of truth.
        #[cfg(all(feature = "local-dns", feature = "local-web-admin"))]
        let primary_dns_listener = config
            .local
            .iter()
            .find(|local| !local.config.disabled && matches!(local.config.protocol, ProtocolType::Dns));
        #[cfg(feature = "local-web-admin")]
        let dns_runtime_state = {
            #[cfg(feature = "local-dns")]
            {
                primary_dns_listener
                    .map(|local| derive_dns_runtime_state(&local.config))
                    .unwrap_or_default()
            }
            #[cfg(not(feature = "local-dns"))]
            {
                crate::local::routing::DnsRuntimeState::default()
            }
        };
        #[cfg(feature = "local-web-admin")]
        routing_state.set_dns_runtime(dns_runtime_state.clone()).await;
        #[cfg(all(feature = "local-dns", feature = "local-web-admin", target_os = "linux"))]
        let dns_intercept_exempt_ips = collect_dns_intercept_exempt_ips(&dns_runtime_state);
        #[cfg(all(feature = "local-dns", feature = "local-web-admin", target_os = "linux"))]
        let dns_intercept_redir_port = config
            .local
            .iter()
            .find(|local| !local.config.disabled && matches!(local.config.protocol, ProtocolType::Redir))
            .and_then(|local| local.config.addr.as_ref().map(|addr| addr.port()));
        #[cfg(all(feature = "local-dns", feature = "local-web-admin", target_os = "linux"))]
        let dns_intercept_client_ip_rules = self::dns::intercept_linux::ClientIpRules {
            global_proxy: config.route_rules.client_global_proxy_ips.clone(),
            direct: config.route_rules.client_direct_ips.clone(),
        };

        for local_instance in config.local {
            let local_config = local_instance.config;
            if local_config.disabled {
                continue;
            }

            // Clone from global ServiceContext instance
            // It will shares Shadowsocks' global context, and FlowStat, DNS reverse cache
            let mut context = context.clone();

            #[cfg(feature = "local-web-admin")]
            context.set_record_proxy_ip(local_config.record_proxy_ip);

            // Private ACL
            if let Some(acl) = local_instance.acl {
                context.set_acl(Arc::new(acl))
            }

            let context = Arc::new(context);
            let balancer = balancer.clone();

            match local_config.protocol {
                ProtocolType::Socks => {
                    let client_addr = match local_config.addr {
                        Some(a) => a,
                        None => return Err(io::Error::other("socks requires local address")),
                    };

                    let mut server_builder = SocksBuilder::with_context(context.clone(), client_addr, balancer);
                    server_builder.set_mode(local_config.mode);
                    server_builder.set_socks5_auth(local_config.socks5_auth);
                    #[cfg(feature = "local-http")]
                    server_builder.set_http_auth(local_config.http_auth);

                    if let Some(c) = config.udp_max_associations {
                        server_builder.set_udp_capacity(c);
                    }
                    if let Some(d) = config.udp_timeout {
                        server_builder.set_udp_expiry_duration(d);
                    }
                    if let Some(b) = local_config.udp_addr {
                        server_builder.set_udp_bind_addr(b.clone());
                    }
                    if let Some(b) = local_config.udp_associate_addr {
                        server_builder.set_udp_associate_addr(b.clone());
                    }

                    #[cfg(target_os = "macos")]
                    if let Some(n) = local_config.launchd_tcp_socket_name {
                        server_builder.set_launchd_tcp_socket_name(n);
                    }
                    #[cfg(target_os = "macos")]
                    if let Some(n) = local_config.launchd_udp_socket_name {
                        server_builder.set_launchd_udp_socket_name(n);
                    }

                    let server = server_builder.build().await?;
                    local_server.socks_servers.push(server);
                }
                #[cfg(feature = "local-tunnel")]
                ProtocolType::Tunnel => {
                    let client_addr = match local_config.addr {
                        Some(a) => a,
                        None => return Err(io::Error::other("tunnel requires local address")),
                    };

                    let forward_addr = local_config.forward_addr.expect("tunnel requires forward address");

                    let mut server_builder =
                        TunnelBuilder::with_context(context.clone(), forward_addr.clone(), client_addr, balancer);

                    if let Some(c) = config.udp_max_associations {
                        server_builder.set_udp_capacity(c);
                    }
                    if let Some(d) = config.udp_timeout {
                        server_builder.set_udp_expiry_duration(d);
                    }
                    server_builder.set_mode(local_config.mode);
                    if let Some(udp_addr) = local_config.udp_addr {
                        server_builder.set_udp_bind_addr(udp_addr);
                    }

                    #[cfg(target_os = "macos")]
                    if let Some(n) = local_config.launchd_tcp_socket_name {
                        server_builder.set_launchd_tcp_socket_name(n);
                    }
                    #[cfg(target_os = "macos")]
                    if let Some(n) = local_config.launchd_udp_socket_name {
                        server_builder.set_launchd_udp_socket_name(n);
                    }

                    let server = server_builder.build().await?;
                    local_server.tunnel_servers.push(server);
                }
                #[cfg(feature = "local-http")]
                ProtocolType::Http => {
                    let client_addr = match local_config.addr {
                        Some(a) => a,
                        None => return Err(io::Error::other("http requires local address")),
                    };

                    #[allow(unused_mut)]
                    let mut builder = HttpBuilder::with_context(context.clone(), client_addr, balancer);
                    builder.set_http_auth(local_config.http_auth);

                    #[cfg(target_os = "macos")]
                    if let Some(n) = local_config.launchd_tcp_socket_name {
                        builder.set_launchd_tcp_socket_name(n);
                    }

                    let server = builder.build().await?;
                    local_server.http_servers.push(server);
                }
                #[cfg(feature = "local-redir")]
                ProtocolType::Redir => {
                    let client_addr = match local_config.addr {
                        Some(a) => a,
                        None => return Err(io::Error::other("redir requires local address")),
                    };

                    let mut server_builder = RedirBuilder::with_context(context.clone(), client_addr, balancer);
                    if let Some(c) = config.udp_max_associations {
                        server_builder.set_udp_capacity(c);
                    }
                    if let Some(d) = config.udp_timeout {
                        server_builder.set_udp_expiry_duration(d);
                    }
                    server_builder.set_mode(local_config.mode);
                    server_builder.set_tcp_redir(local_config.tcp_redir);
                    server_builder.set_udp_redir(local_config.udp_redir);
                    if let Some(udp_addr) = local_config.udp_addr {
                        server_builder.set_udp_bind_addr(udp_addr);
                    }

                    let server = server_builder.build().await?;
                    local_server.redir_servers.push(server);
                }
                #[cfg(feature = "local-dns")]
                ProtocolType::Dns => {
                    let client_addr = match local_config.addr {
                        Some(a) => a,
                        None => return Err(io::Error::other("dns requires local address")),
                    };
                    // Capture the listen port before `client_addr` is moved into
                    // the DnsBuilder; the firewall redirect (installed after the
                    // listener binds, below) needs it.
                    #[cfg(all(feature = "local-dns", feature = "local-web-admin", target_os = "linux"))]
                    let dns_listen_port = client_addr.port();

                    let mut server_builder = {
                        let local_addr = local_config.local_dns_addr.expect("missing local_dns_addr");
                        let remote_addr = local_config.remote_dns_addr.expect("missing remote_dns_addr");
                        let client_cache_size = local_config.client_cache_size.unwrap_or(5);

                        DnsBuilder::with_context(
                            context.clone(),
                            client_addr,
                            local_addr.clone(),
                            remote_addr.clone(),
                            balancer,
                            client_cache_size,
                        )
                    };
                    server_builder.set_mode(local_config.mode);

                    #[cfg(target_os = "macos")]
                    if let Some(n) = local_config.launchd_tcp_socket_name {
                        server_builder.set_launchd_tcp_socket_name(n);
                    }
                    #[cfg(target_os = "macos")]
                    if let Some(n) = local_config.launchd_udp_socket_name {
                        server_builder.set_launchd_udp_socket_name(n);
                    }

                    let server = server_builder.build().await?;

                    // Install the firewall redirect ONLY AFTER the DNS listener
                    // has bound (build() above binds :client_addr). Installing it
                    // earlier opened a startup window where `dport 53 redirect`
                    // pointed at an unbound port, briefly black-holing DNS.
                    #[cfg(all(feature = "local-dns", feature = "local-web-admin", target_os = "linux"))]
                    if matches!(dns_intercept_mode.as_str(), "firewall" | "both") {
                        let global_proxy = config.route_rules.global_proxy;
                        match self::dns::intercept_linux::setup_firewall_redirect(
                            dns_listen_port,
                            dns_intercept_redir_port,
                            &dns_intercept_exempt_ips,
                            &dns_intercept_proxy_exempt_endpoints,
                            global_proxy,
                            config.route_rules.proxy_local_output,
                            &dns_intercept_client_ip_rules,
                            local_output_exempt_mark,
                            config.route_rules.dns_ipv4_only,
                        ) {
                            Ok(guard) => {
                                if let Err(err) = routing_state.sync_persistent_ip_rules_to_firewall().await {
                                    log::warn!("failed to load persistent IP rules into nft sets: {}", err);
                                }
                                local_server.dns_intercept_guards.push(guard);
                            }
                            Err(err) => log::warn!("failed to setup DNS firewall interception: {}", err),
                        }
                    }

                    local_server.dns_servers.push(server);
                }
                #[cfg(feature = "local-tun")]
                ProtocolType::Tun => {
                    let mut builder = TunBuilder::new(context.clone(), balancer);
                    if let Some(address) = local_config.tun_interface_address {
                        builder.address(address);
                    }
                    if let Some(address) = local_config.tun_interface_destination {
                        builder.destination(address);
                    }
                    if let Some(name) = local_config.tun_interface_name {
                        builder.name(&name);
                    }
                    if let Some(c) = config.udp_max_associations {
                        builder.udp_capacity(c);
                    }
                    if let Some(d) = config.udp_timeout {
                        builder.udp_expiry_duration(d);
                    }
                    builder.mode(local_config.mode);
                    #[cfg(unix)]
                    if let Some(fd) = local_config.tun_device_fd {
                        builder.file_descriptor(fd);
                    } else if let Some(ref fd_path) = local_config.tun_device_fd_from_path {
                        use std::fs;

                        use log::info;
                        use shadowsocks::net::UnixListener;

                        let _ = fs::remove_file(fd_path);

                        let listener = match UnixListener::bind(fd_path) {
                            Ok(l) => l,
                            Err(err) => {
                                log::error!("failed to bind uds path \"{}\", error: {}", fd_path.display(), err);
                                return Err(err);
                            }
                        };

                        info!("waiting tun's file descriptor from {}", fd_path.display());

                        loop {
                            let (mut stream, peer_addr) = listener.accept().await?;
                            trace!("accepted {:?} for receiving tun file descriptor", peer_addr);

                            let mut buffer = [0u8; 1024];
                            let mut fd_buffer = [0];

                            match stream.recv_with_fd(&mut buffer, &mut fd_buffer).await {
                                Ok((n, fd_size)) => {
                                    if fd_size == 0 {
                                        log::error!(
                                            "client {:?} didn't send file descriptors with buffer.size {} bytes",
                                            peer_addr,
                                            n
                                        );
                                        continue;
                                    }

                                    info!("got file descriptor {} for tun from {:?}", fd_buffer[0], peer_addr);

                                    builder.file_descriptor(fd_buffer[0]);
                                    break;
                                }
                                Err(err) => {
                                    log::error!(
                                        "failed to receive file descriptors from {:?}, error: {}",
                                        peer_addr,
                                        err
                                    );
                                }
                            }
                        }
                    }
                    let server = builder.build().await?;
                    local_server.tun_servers.push(server);
                }
                #[cfg(feature = "local-fake-dns")]
                ProtocolType::FakeDns => {
                    let client_addr = match local_config.addr {
                        Some(a) => a,
                        None => return Err(io::Error::other("dns requires local address")),
                    };

                    let mut builder = FakeDnsBuilder::new(client_addr);
                    if let Some(n) = local_config.fake_dns_ipv4_network {
                        builder.set_ipv4_network(n);
                    }
                    if let Some(n) = local_config.fake_dns_ipv6_network {
                        builder.set_ipv6_network(n);
                    }
                    if let Some(exp) = local_config.fake_dns_record_expire_duration {
                        builder.set_expire_duration(exp);
                    }
                    if let Some(p) = local_config.fake_dns_database_path {
                        builder.set_database_path(p);
                    }
                    let server = builder.build().await?;
                    #[cfg(feature = "local-fake-dns")]
                    context.add_fake_dns_manager(server.clone_manager()).await;

                    local_server.fake_dns_servers.push(server);
                }
            }
        }

        Ok(local_server)
    }

    /// Run local server
    pub async fn run(self) -> io::Result<()> {
        let mut vfut = Vec::new();

        for svr in self.socks_servers {
            vfut.push(ServerHandle(tokio::spawn(svr.run())));
        }

        #[cfg(feature = "local-tunnel")]
        for svr in self.tunnel_servers {
            vfut.push(ServerHandle(tokio::spawn(svr.run())));
        }

        #[cfg(feature = "local-http")]
        for svr in self.http_servers {
            vfut.push(ServerHandle(tokio::spawn(svr.run())));
        }

        #[cfg(feature = "local-tun")]
        for svr in self.tun_servers {
            vfut.push(ServerHandle(tokio::spawn(svr.run())));
        }

        #[cfg(feature = "local-dns")]
        for svr in self.dns_servers {
            vfut.push(ServerHandle(tokio::spawn(svr.run())));
        }

        #[cfg(feature = "local-redir")]
        for svr in self.redir_servers {
            vfut.push(ServerHandle(tokio::spawn(svr.run())));
        }

        #[cfg(feature = "local-fake-dns")]
        for svr in self.fake_dns_servers {
            vfut.push(ServerHandle(tokio::spawn(svr.run())));
        }

        #[cfg(feature = "local-flow-stat")]
        if let Some(stat_addr) = self.local_stat_addr {
            // For Android's flow statistic

            let report_fut = flow_report_task(stat_addr, self.flow_stat);
            vfut.push(ServerHandle(tokio::spawn(report_fut)));
        }

        #[cfg(feature = "local-online-config")]
        if let Some(online_config) = self.online_config {
            vfut.push(ServerHandle(tokio::spawn(online_config.run())));
        }

        #[cfg(feature = "local-web-admin")]
        if let Some(web_admin) = self.web_admin {
            vfut.push(ServerHandle(tokio::spawn(web_admin.run())));
        }

        let (res, ..) = future::select_all(vfut).await;
        res
    }

    /// Get the internal server balancer
    pub fn server_balancer(&self) -> &PingBalancer {
        &self.balancer
    }

    /// Get SOCKS server instances
    pub fn socks_servers(&self) -> &[Socks] {
        &self.socks_servers
    }

    /// Get Tunnel server instances
    #[cfg(feature = "local-tunnel")]
    pub fn tunnel_servers(&self) -> &[Tunnel] {
        &self.tunnel_servers
    }

    /// Get HTTP server instances
    #[cfg(feature = "local-http")]
    pub fn http_servers(&self) -> &[Http] {
        &self.http_servers
    }

    /// Get Tun server instances
    #[cfg(feature = "local-tun")]
    pub fn tun_servers(&self) -> &[Tun] {
        &self.tun_servers
    }

    /// Get DNS server instances
    #[cfg(feature = "local-dns")]
    pub fn dns_servers(&self) -> &[Dns] {
        &self.dns_servers
    }

    /// Get Redir server instances
    #[cfg(feature = "local-redir")]
    pub fn redir_servers(&self) -> &[Redir] {
        &self.redir_servers
    }

    /// Get Fake DNS instances
    #[cfg(feature = "local-fake-dns")]
    pub fn fake_dns_servers(&self) -> &[FakeDns] {
        &self.fake_dns_servers
    }
}

#[cfg(all(feature = "local-dns", feature = "local-web-admin", target_os = "linux"))]
/// Build the IPs that the Linux DNS firewall interceptor must exempt
/// from `dport 53 redirect` rules — namely the upstream resolvers that
/// the local DNS server itself talks to. Without these exemptions, the
/// local DNS server's outbound queries to e.g. `223.5.5.5:53` would be
/// rewritten to `127.0.0.1:1053`, looping back into itself.
#[cfg(all(feature = "local-dns", feature = "local-web-admin", target_os = "linux"))]
fn collect_dns_intercept_exempt_ips(state: &DnsRuntimeState) -> Vec<IpAddr> {
    let mut ips = state
        .domestic_dns
        .iter()
        .chain(state.foreign_dns.iter())
        .filter_map(|server| {
            let host = server
                .rsplit_once(':')
                .map(|(host, _)| host)
                .unwrap_or(server)
                .trim()
                .trim_start_matches('[')
                .trim_end_matches(']');
            host.parse::<IpAddr>().ok()
        })
        .collect::<Vec<_>>();
    ips.sort_unstable();
    ips.dedup();
    ips
}

/// Build exact endpoints that must not be captured by local transparent
/// proxy OUTPUT rules. These are the upstream Shadowsocks servers themselves:
/// if they are redirected into the redir listener, sslocal recursively proxies
/// its own transport connection.
#[cfg(all(feature = "local-dns", feature = "local-web-admin", target_os = "linux"))]
fn collect_dns_intercept_proxy_exempt_endpoints(config: &Config) -> Vec<(IpAddr, u16)> {
    let mut endpoints = Vec::new();
    for server in &config.server {
        match server.config.addr() {
            shadowsocks::config::ServerAddr::SocketAddr(addr) => endpoints.push((addr.ip(), addr.port())),
            shadowsocks::config::ServerAddr::DomainName(host, port) => {
                if let Ok(ip) = host.parse::<IpAddr>() {
                    endpoints.push((ip, *port));
                } else if let Ok(addrs) = (host.as_str(), *port).to_socket_addrs() {
                    endpoints.extend(addrs.map(|addr| (addr.ip(), *port)));
                }
            }
        }
    }
    endpoints.sort_unstable();
    endpoints.dedup();
    endpoints
}

/// Snapshot the DNS runtime state from a single `protocol: dns` listener.
/// Returns the upstream resolver pair as `host:port` strings (matching
/// the legacy `route_rules.{domestic,foreign}_dns` text format consumed
/// by the rest of the routing layer) and the listener's bound address.
#[cfg(all(feature = "local-dns", feature = "local-web-admin"))]
fn derive_dns_runtime_state(local: &LocalConfig) -> DnsRuntimeState {
    fn name_server_addr_to_string(addr: &NameServerAddr) -> Option<String> {
        match addr {
            NameServerAddr::SocketAddr(sa) => Some(sa.to_string()),
            #[cfg(unix)]
            NameServerAddr::UnixSocketAddr(_) => None,
        }
    }
    fn address_to_string(addr: &Address) -> String {
        match addr {
            Address::SocketAddress(sa) => sa.to_string(),
            Address::DomainNameAddress(host, port) => format!("{}:{}", host, port),
        }
    }

    let domestic_dns = local
        .local_dns_addr
        .as_ref()
        .and_then(name_server_addr_to_string)
        .map(|s| vec![s])
        .unwrap_or_default();
    let foreign_dns = local
        .remote_dns_addr
        .as_ref()
        .map(|addr| vec![address_to_string(addr)])
        .unwrap_or_default();
    let listen = local.addr.as_ref().and_then(|addr| match addr {
        shadowsocks::config::ServerAddr::SocketAddr(sa) => Some(*sa),
        // domain-typed local listen address is not supported here; the
        // listener requires a numeric address anyway.
        shadowsocks::config::ServerAddr::DomainName(..) => None,
    });
    DnsRuntimeState {
        domestic_dns,
        foreign_dns,
        listen,
    }
}

#[cfg(feature = "local-flow-stat")]
async fn flow_report_task(stat_addr: LocalFlowStatAddress, flow_stat: Arc<FlowStat>) -> io::Result<()> {
    use std::slice;

    use log::debug;
    use tokio::{io::AsyncWriteExt, time};

    // Local flow statistic report RPC
    let timeout = Duration::from_secs(1);

    loop {
        // keep it as libev's default, 0.5 seconds
        time::sleep(Duration::from_millis(500)).await;

        let tx = flow_stat.tx();
        let rx = flow_stat.rx();

        let buf: [u64; 2] = [tx, rx];
        let buf = unsafe { slice::from_raw_parts(buf.as_ptr() as *const _, 16) };

        match stat_addr {
            #[cfg(unix)]
            LocalFlowStatAddress::UnixStreamPath(ref stat_path) => {
                use tokio::net::UnixStream;

                let mut stream = match time::timeout(timeout, UnixStream::connect(stat_path)).await {
                    Ok(Ok(s)) => s,
                    Ok(Err(err)) => {
                        debug!("send client flow statistic error: {}", err);
                        continue;
                    }
                    Err(..) => {
                        debug!("send client flow statistic error: timeout");
                        continue;
                    }
                };

                match time::timeout(timeout, stream.write_all(buf)).await {
                    Ok(Ok(..)) => {}
                    Ok(Err(err)) => {
                        debug!("send client flow statistic error: {}", err);
                    }
                    Err(..) => {
                        debug!("send client flow statistic error: timeout");
                    }
                }
            }
            LocalFlowStatAddress::TcpStreamAddr(stat_addr) => {
                use tokio::net::TcpStream;

                let mut stream = match time::timeout(timeout, TcpStream::connect(stat_addr)).await {
                    Ok(Ok(s)) => s,
                    Ok(Err(err)) => {
                        debug!("send client flow statistic error: {}", err);
                        continue;
                    }
                    Err(..) => {
                        debug!("send client flow statistic error: timeout");
                        continue;
                    }
                };

                match time::timeout(timeout, stream.write_all(buf)).await {
                    Ok(Ok(..)) => {}
                    Ok(Err(err)) => {
                        debug!("send client flow statistic error: {}", err);
                    }
                    Err(..) => {
                        debug!("send client flow statistic error: timeout");
                    }
                }
            }
        }
    }
}

/// Create then run a Local Server
pub async fn run(config: Config) -> io::Result<()> {
    Server::new(config).await?.run().await
}
