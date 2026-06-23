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
            if let Some(row) = state.recent_connections(&HashSet::new(), None).await.into_iter().find(|row| {
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
    fn global_proxy_system_rows_only_assume_redir_for_public_non_dns() {
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
        assert!(system_connection_should_be_redir(&event));

        event.destination_port = 53;
        assert!(!system_connection_should_be_redir(&event));

        event.destination_port = 443;
        event.destination_ip = Some("192.168.2.1".parse().unwrap());
        assert!(!system_connection_should_be_redir(&event));
    }

    #[test]
    fn proxy_local_output_defaults_off() {
        let mut config = RouteRulesConfig::default();
        assert!(!RoutingSources::from(&config).proxy_local_output);

        config.proxy_local_output = true;
        assert!(RoutingSources::from(&config).proxy_local_output);
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
            "224.0.0.1",
            "239.255.255.250",
            "240.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "fc00::1",
            "fdff::1",
            "fe80::1",
            "ff02::1",
        ] {
            assert!(is_fixed_direct_ip(&ip.parse().unwrap()), "{ip}");
        }

        for ip in [
            "1.1.1.1",
            "100.128.0.1",
            "172.32.0.1",
            "198.20.0.1",
            "223.5.5.5",
            "2001:db8::1",
        ] {
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

        assert!(state.recent_connections(&HashSet::new(), None).await.is_empty());
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
        assert!(state.recent_connections(&HashSet::new(), None).await.is_empty());
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
    async fn recent_activity_filters_by_source_ip() {
        let dir = temp_rules_dir("record-source-filter");
        let mut config = RouteRulesConfig::default();
        config.rules_dir = dir;
        config.geoip_sources.clear();
        config.proxy_domain_sources.clear();
        let state = RoutingState::load(config).await.unwrap();
        state.start_activity_recording().await.unwrap();

        let source_a = "192.168.2.166:40001".parse::<SocketAddr>().unwrap();
        let source_b = "192.168.2.188:40002".parse::<SocketAddr>().unwrap();
        let destination_a = "203.0.113.10".parse::<IpAddr>().unwrap();
        let destination_b = "203.0.113.11".parse::<IpAddr>().unwrap();
        state
            .record_connection(
                source_a,
                &Address::SocketAddress(SocketAddr::new(destination_a, 443)),
                "tcp",
                ConnectionDecision::Socks5Proxy,
            )
            .await;
        state
            .record_connection(
                source_b,
                &Address::SocketAddress(SocketAddr::new(destination_b, 443)),
                "tcp",
                ConnectionDecision::Direct,
            )
            .await;
        state
            .record_dns(
                Some(source_a.ip()),
                "api-a.example".to_owned(),
                "A".to_owned(),
                vec![destination_a],
                RouteDecision::Proxy,
                false,
            )
            .await;
        state
            .record_dns(
                Some(source_b.ip()),
                "api-b.example".to_owned(),
                "A".to_owned(),
                vec![destination_b],
                RouteDecision::Direct,
                false,
            )
            .await;

        let _ = wait_for_recorded_connection(&state, source_a, destination_a, 443).await;
        let _ = wait_for_recorded_connection(&state, source_b, destination_b, 443).await;
        for _ in 0..50 {
            if state.recent_dns(Some(source_a.ip())).await.len() == 1 {
                break;
            }
            time::sleep(Duration::from_millis(10)).await;
        }

        let connections = state.recent_connections(&HashSet::new(), Some(source_a.ip())).await;
        assert_eq!(connections.len(), 1);
        assert_eq!(connections[0].source_ip, source_a.ip());

        let dns = state.recent_dns(Some(source_a.ip())).await;
        assert_eq!(dns.len(), 1);
        assert_eq!(dns[0].domain, "api-a.example");
    }

    #[tokio::test]
    async fn learned_socks_proxy_ip_is_saved_to_temporary_proxy_list() {
        let dir = temp_rules_dir("socks-learn-temp-proxy-ip");
        let mut config = RouteRulesConfig::default();
        config.rules_dir = dir.clone();
        config.geoip_sources.clear();
        config.proxy_domain_sources.clear();
        let state = RoutingState::load(config).await.unwrap();
        let ip = "203.0.113.77".parse::<IpAddr>().unwrap();

        assert!(state.add_temporary_proxy_ip(ip).await.unwrap());
        assert!(!state.add_temporary_proxy_ip(ip).await.unwrap());

        let snapshot = state.snapshot().await;
        assert!(!snapshot.temporary.proxy_ip.iter().any(|rule| rule == "203.0.113.77"));
        let proxy_temp = read_lines(temp_file_path(&dir, TEMP_PROXY_IP_FILE)).unwrap();
        assert!(!proxy_temp.iter().any(|rule| rule == "203.0.113.77"));

        assert!(read_lines(dir.join(FUTU_IP_FILE)).unwrap().is_empty());
        assert!(state.persist_futu_records_now().await.unwrap());
        let futu_ips = read_lines(dir.join(FUTU_IP_FILE)).unwrap();
        assert!(futu_ips.iter().any(|rule| rule == "203.0.113.77"));
        let proxy_temp = read_lines(temp_file_path(&dir, TEMP_PROXY_IP_FILE)).unwrap();
        assert!(proxy_temp.iter().any(|rule| rule == "203.0.113.77"));
        assert!(!state.persist_futu_records_now().await.unwrap());
    }

    #[tokio::test]
    async fn learned_socks_proxy_domain_is_saved_to_futu_url_only() {
        let dir = temp_rules_dir("socks-learn-futu-url");
        let mut config = RouteRulesConfig::default();
        config.rules_dir = dir.clone();
        config.geoip_sources.clear();
        config.proxy_domain_sources.clear();
        let state = RoutingState::load(config).await.unwrap();
        let target = Address::DomainNameAddress("Api.FutuExample.COM.".to_owned(), 443);

        assert!(state.add_temporary_proxy_target(&target).await.unwrap());
        assert!(!state.add_temporary_proxy_target(&target).await.unwrap());

        assert!(read_lines(dir.join(FUTU_URL_FILE)).unwrap().is_empty());
        let proxy_temp = read_lines(temp_file_path(&dir, TEMP_PROXY_IP_FILE)).unwrap();
        assert!(proxy_temp.is_empty());

        assert!(state.persist_futu_records_now().await.unwrap());
        let futu_urls = read_lines(dir.join(FUTU_URL_FILE)).unwrap();
        assert_eq!(futu_urls, vec!["api.futuexample.com:443".to_owned()]);
        assert!(!state.persist_futu_records_now().await.unwrap());
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
    async fn client_global_proxy_source_uses_proxy_resolver_even_for_direct_domain() {
        let dir = temp_rules_dir("client-global-proxy-source-dns");
        write_lines_atomic(dir.join(DIRECT_IP_FILE), &[]).unwrap();
        write_lines_atomic(dir.join(DIRECT_DOMAIN_FILE), &["direct.example".to_owned()]).unwrap();
        write_lines_atomic(dir.join(PROXY_IP_FILE), &[]).unwrap();
        write_lines_atomic(dir.join(PROXY_DOMAIN_FILE), &[]).unwrap();

        let source_ip = "192.168.2.216".parse().unwrap();
        let mut config = RouteRulesConfig::default();
        config.rules_dir = dir;
        config.client_global_proxy_ips = vec![source_ip];
        let state = RoutingState::load(config).await.unwrap();

        assert_eq!(
            state.route_domain_for_source("direct.example", Some(source_ip)).await,
            Some(RouteDecision::Proxy)
        );
        assert_eq!(
            state.route_domain_for_source("unknown.example", Some(source_ip)).await,
            Some(RouteDecision::Proxy)
        );
        assert_eq!(
            state.route_domain_for_source("direct.example", None).await,
            Some(RouteDecision::Direct)
        );
    }

    #[tokio::test]
    async fn global_proxy_still_honors_direct_client_source() {
        let dir = temp_rules_dir("global-proxy-direct-client-source-dns");
        write_lines_atomic(dir.join(DIRECT_IP_FILE), &[]).unwrap();
        write_lines_atomic(dir.join(DIRECT_DOMAIN_FILE), &[]).unwrap();
        write_lines_atomic(dir.join(PROXY_IP_FILE), &[]).unwrap();
        write_lines_atomic(dir.join(PROXY_DOMAIN_FILE), &["proxy.example".to_owned()]).unwrap();

        let source_ip = "192.168.2.216".parse().unwrap();
        let mut config = RouteRulesConfig::default();
        config.rules_dir = dir;
        config.global_proxy = true;
        config.client_global_proxy_ips = vec![source_ip];
        config.client_direct_ips = vec![source_ip];
        let state = RoutingState::load(config).await.unwrap();

        assert_eq!(
            state.route_domain_for_source("proxy.example", Some(source_ip)).await,
            Some(RouteDecision::Direct)
        );
        assert_eq!(
            state.route_domain_for_source("unknown.example", Some(source_ip)).await,
            Some(RouteDecision::Direct)
        );
        assert_eq!(
            state.route_domain_for_source("unknown.example", None).await,
            Some(RouteDecision::Proxy)
        );
    }

    #[tokio::test]
    async fn source_override_dns_results_do_not_update_global_route_sets() {
        let dir = temp_rules_dir("source-override-dns-no-global-update");
        write_lines_atomic(dir.join(DIRECT_IP_FILE), &[]).unwrap();
        write_lines_atomic(dir.join(DIRECT_DOMAIN_FILE), &["direct.example".to_owned()]).unwrap();
        write_lines_atomic(dir.join(PROXY_IP_FILE), &[]).unwrap();
        write_lines_atomic(dir.join(PROXY_DOMAIN_FILE), &["proxy.example".to_owned()]).unwrap();

        let source_ip = "192.168.2.216".parse().unwrap();
        let mut config = RouteRulesConfig::default();
        config.rules_dir = dir;
        config.client_global_proxy_ips = vec![source_ip];
        let state = RoutingState::load(config).await.unwrap();

        assert_eq!(
            state.route_domain_for_source_detail("direct.example", Some(source_ip)).await,
            Some(SourceRouteDecision {
                decision: RouteDecision::Proxy,
                update_route_sets: false,
            })
        );
        assert_eq!(
            state.route_domain_for_source_detail("unknown.example", Some(source_ip)).await,
            Some(SourceRouteDecision {
                decision: RouteDecision::Proxy,
                update_route_sets: false,
            })
        );
        assert_eq!(
            state.route_domain_for_source_detail("proxy.example", Some(source_ip)).await,
            Some(SourceRouteDecision {
                decision: RouteDecision::Proxy,
                update_route_sets: true,
            })
        );
        assert_eq!(
            state.route_domain_for_source_detail("proxy.example", None).await,
            Some(SourceRouteDecision {
                decision: RouteDecision::Proxy,
                update_route_sets: true,
            })
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
    async fn clear_persistent_proxy_ip_updates_file_and_memory() {
        let dir = temp_rules_dir("clear-persistent-proxy-ip");
        write_lines_atomic(dir.join(DIRECT_IP_FILE), &[]).unwrap();
        write_lines_atomic(dir.join(PROXY_IP_FILE), &["203.0.113.10 example.com".to_owned()]).unwrap();
        write_lines_atomic(dir.join(DIRECT_DOMAIN_FILE), &[]).unwrap();
        write_lines_atomic(dir.join(PROXY_DOMAIN_FILE), &[]).unwrap();

        let mut config = RouteRulesConfig::default();
        config.rules_dir = dir.clone();
        config.geoip_sources.clear();
        config.proxy_domain_sources.clear();
        let state = RoutingState::load(config).await.unwrap();
        let ip = "203.0.113.10".parse().unwrap();

        assert_eq!(state.route_ip(&ip).await, Some(RouteDecision::Proxy));
        assert_eq!(state.clear_persistent_proxy_ip().await.unwrap(), 1);
        assert!(read_lines(dir.join(PROXY_IP_FILE)).unwrap().is_empty());
        assert_eq!(state.route_ip(&ip).await, None);

        let inner = state.inner.read().await;
        assert!(inner.persistent_raw.proxy_ip.is_empty());
        assert!(inner.persistent.proxy_ip_exact.is_empty());
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
    async fn direct_dns_results_sync_nft_only_for_global_proxy_exceptions() {
        let dir = temp_rules_dir("dns-direct-nft-sync-needed");
        write_lines_atomic(dir.join(DIRECT_IP_FILE), &[]).unwrap();
        write_lines_atomic(dir.join(PROXY_IP_FILE), &["203.0.113.10 a.example.com".to_owned()]).unwrap();
        write_lines_atomic(dir.join(DIRECT_DOMAIN_FILE), &["direct.example".to_owned()]).unwrap();
        write_lines_atomic(dir.join(PROXY_DOMAIN_FILE), &[]).unwrap();

        let mut config = RouteRulesConfig::default();
        config.rules_dir = dir;
        config.geoip_sources.clear();
        config.proxy_domain_sources.clear();
        let state = RoutingState::load(config).await.unwrap();
        let unrelated = "203.0.113.20".parse().unwrap();
        let proxy_conflict = "203.0.113.10".parse().unwrap();
        let inner = state.inner.read().await;

        assert!(!direct_dns_result_needs_nft_sync(&inner, &unrelated, false));
        assert!(!direct_dns_result_needs_nft_sync(&inner, &proxy_conflict, false));
        assert!(direct_dns_result_needs_nft_sync(&inner, &unrelated, true));
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

    #[test]
    fn nft_route_index_matches_exact_and_cidr_entries() {
        let index = nft_route_index_from_nets(
            &[IpNet::from("198.51.100.10".parse::<IpAddr>().unwrap())],
            &[
                "203.0.113.0/24".parse().unwrap(),
                "2001:db8::/32".parse().unwrap(),
            ],
        );

        assert!(nft_route_index_matches(
            &index,
            RouteDecision::Direct,
            &"198.51.100.10".parse().unwrap()
        ));
        assert!(nft_route_index_matches(
            &index,
            RouteDecision::Proxy,
            &"203.0.113.55".parse().unwrap()
        ));
        assert!(nft_route_index_matches(
            &index,
            RouteDecision::Proxy,
            &"2001:db8::1234".parse().unwrap()
        ));
        assert!(!nft_route_index_matches(
            &index,
            RouteDecision::Proxy,
            &"198.51.100.10".parse().unwrap()
        ));
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
        assert!(proxy_dns_result_needs_nft_sync(&inner, &ip));
    }

    #[tokio::test]
    async fn cached_proxy_dns_result_skips_sync_when_already_indexed() {
        let dir = temp_rules_dir("dns-cache-hit-proxy-no-sync");
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

        assert!(state.dns_results_need_sync(RouteDecision::Proxy, &[ip]).await);
        state.inner.write().await.nft_route_index = nft_route_index_from_nets(&[], &[IpNet::from(ip)]);
        assert!(!state.dns_results_need_sync(RouteDecision::Proxy, &[ip]).await);
    }

    #[tokio::test]
    async fn cached_direct_dns_result_syncs_global_proxy_exception_until_indexed() {
        let dir = temp_rules_dir("dns-cache-hit-direct-global-sync");
        write_lines_atomic(dir.join(DIRECT_IP_FILE), &[]).unwrap();
        write_lines_atomic(dir.join(PROXY_IP_FILE), &[]).unwrap();
        write_lines_atomic(dir.join(DIRECT_DOMAIN_FILE), &["direct.example".to_owned()]).unwrap();
        write_lines_atomic(dir.join(PROXY_DOMAIN_FILE), &[]).unwrap();

        let mut config = RouteRulesConfig::default();
        config.rules_dir = dir;
        config.global_proxy = true;
        config.geoip_sources.clear();
        config.proxy_domain_sources.clear();
        let state = RoutingState::load(config).await.unwrap();
        let ip = "203.0.113.20".parse().unwrap();

        assert!(state.dns_results_need_sync(RouteDecision::Direct, &[ip]).await);
        state.inner.write().await.nft_route_index = nft_route_index_from_nets(&[IpNet::from(ip)], &[]);
        assert!(!state.dns_results_need_sync(RouteDecision::Direct, &[ip]).await);
    }

    #[cfg(all(target_os = "linux", feature = "local-dns"))]
    #[tokio::test]
    async fn proxy_conntrack_flush_ips_include_only_active_public_proxy_exact_ips() {
        let dir = temp_rules_dir("proxy-conntrack-flush-ips");
        write_lines_atomic(dir.join(DIRECT_IP_FILE), &["198.51.100.20/32".to_owned()]).unwrap();
        write_lines_atomic(
            dir.join(PROXY_IP_FILE),
            &[
                "160.79.104.10 claude.com".to_owned(),
                "198.51.100.20 direct-conflict.example".to_owned(),
                "192.168.2.50 private.example".to_owned(),
            ],
        )
        .unwrap();
        write_lines_atomic(dir.join(DIRECT_DOMAIN_FILE), &[]).unwrap();
        write_lines_atomic(dir.join(PROXY_DOMAIN_FILE), &[]).unwrap();

        let mut config = RouteRulesConfig::default();
        config.rules_dir = dir;
        config.geoip_sources.clear();
        config.proxy_domain_sources.clear();
        let state = RoutingState::load(config).await.unwrap();
        let inner = state.inner.read().await;

        assert_eq!(
            proxy_conntrack_flush_ips(&inner),
            vec!["160.79.104.10".parse::<IpAddr>().unwrap()]
        );
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

    #[test]
    fn compile_ip_rules_separates_exact_from_cidr() {
        let lines = vec![
            "203.0.113.10".to_owned(),
            "203.0.113.11/32".to_owned(),
            "203.0.113.0/24".to_owned(),
            "2001:db8::1/128 api.example".to_owned(),
            "2001:db8:1::/48".to_owned(),
        ];

        let (cidrs, exact, domainless_exact) = compile_ip_rules(&lines, true);

        assert!(exact.contains(&"203.0.113.10".parse().unwrap()));
        assert!(exact.contains(&"203.0.113.11".parse().unwrap()));
        assert!(exact.contains(&"2001:db8::1".parse().unwrap()));
        assert!(domainless_exact.contains(&"203.0.113.10".parse().unwrap()));
        assert!(domainless_exact.contains(&"203.0.113.11".parse().unwrap()));
        assert!(!domainless_exact.contains(&"2001:db8::1".parse().unwrap()));
        assert_eq!(
            cidrs,
            vec![
                parse_ip_net("203.0.113.0/24").unwrap(),
                parse_ip_net("2001:db8:1::/48").unwrap(),
            ]
        );
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
    async fn dns_cache_lookup_ignores_expired_without_prune() {
        let dir = temp_rules_dir("dns-cache-expired-no-prune");
        let mut config = RouteRulesConfig::default();
        config.rules_dir = dir;
        config.dns_cache_capacity = 1024;
        config.dns_cache_ttl_seconds = 60;

        let state = RoutingState::load(config).await.unwrap();
        state
            .dns_cache_insert(
                "expired.example",
                "A",
                RouteDecision::Direct,
                Message::query(),
                vec!["1.1.1.1".parse().unwrap()],
            )
            .await;

        let key = dns_cache_key("expired.example", "A", RouteDecision::Direct);
        let expired_at = now().saturating_sub(1);
        {
            let mut inner = state.inner.write().await;
            let old_expires_at = inner.dns_cache.get(&key).unwrap().expires_at;
            remove_dns_cache_expiration(&mut inner, &key, old_expires_at);
            inner.dns_cache.get_mut(&key).unwrap().expires_at = expired_at;
            insert_dns_cache_expiration(&mut inner, key, expired_at);
        }

        assert!(
            state
                .dns_cache_lookup("expired.example", "A", RouteDecision::Direct)
                .await
                .is_none()
        );
        assert_eq!(state.dns_cache_stats().await.size, 1);
    }

    #[tokio::test]
    async fn dns_cache_skips_empty_and_error_responses() {
        let dir = temp_rules_dir("dns-cache-skip-empty-error");
        let mut config = RouteRulesConfig::default();
        config.rules_dir = dir;

        let state = RoutingState::load(config).await.unwrap();
        state
            .dns_cache_insert(
                "empty.example",
                "A",
                RouteDecision::Direct,
                Message::query(),
                Vec::new(),
            )
            .await;
        assert_eq!(state.dns_cache_stats().await.size, 0);
        assert!(
            state
                .dns_cache_lookup("empty.example", "A", RouteDecision::Direct)
                .await
                .is_none()
        );

        let mut servfail = Message::query();
        servfail.metadata.response_code = ResponseCode::ServFail;
        state
            .dns_cache_insert(
                "error.example",
                "A",
                RouteDecision::Direct,
                servfail,
                vec!["1.1.1.1".parse().unwrap()],
            )
            .await;
        assert_eq!(state.dns_cache_stats().await.size, 0);
        assert!(
            state
                .dns_cache_lookup("error.example", "A", RouteDecision::Direct)
                .await
                .is_none()
        );
    }

    #[test]
    fn dns_cache_accepts_real_service_binding_responses() {
        let mut message = Message::response(1, hickory_resolver::proto::op::OpCode::Query);
        let name = hickory_resolver::proto::rr::Name::from_ascii("example.com.").unwrap();
        let svcb = hickory_resolver::proto::rr::rdata::SVCB::new(
            1,
            hickory_resolver::proto::rr::Name::root(),
            Vec::new(),
        );
        message.answers.push(hickory_resolver::proto::rr::Record::from_rdata(
            name,
            60,
            RData::HTTPS(hickory_resolver::proto::rr::rdata::HTTPS(svcb)),
        ));

        assert!(dns_cache_message_is_cacheable("HTTPS", &message, &[]));
        assert!(!dns_cache_message_is_cacheable("A", &message, &[]));
        assert!(!dns_cache_message_is_cacheable(
            "HTTPS",
            &Message::response(1, hickory_resolver::proto::op::OpCode::Query),
            &[]
        ));
    }

    #[tokio::test]
    async fn dns_cache_persists_and_loads_from_disk() {
        let dir = temp_rules_dir("dns-cache-persist");
        let mut config = RouteRulesConfig::default();
        config.rules_dir = dir.clone();
        config.dns_cache_ttl_seconds = 60;

        let state = RoutingState::load(config).await.unwrap();
        state
            .dns_cache_insert(
                "Persist.EXAMPLE.",
                "A",
                RouteDecision::Proxy,
                Message::query(),
                vec!["8.8.8.8".parse().unwrap()],
            )
            .await;
        state.persist_dns_cache_now().await.unwrap();
        assert!(!fs::read_to_string(dns_cache_file_path(&dir)).unwrap().is_empty());

        let mut config = RouteRulesConfig::default();
        config.rules_dir = dir;
        let reloaded = RoutingState::load(config).await.unwrap();
        let rows = reloaded.dns_cache_query("persist.example").await;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].resolver, RouteDecision::Proxy);
        assert_eq!(rows[0].results[0].to_string(), "8.8.8.8");
        assert!(
            reloaded
                .dns_cache_lookup("persist.example", "A", RouteDecision::Proxy)
                .await
                .is_some()
        );
    }

    #[tokio::test]
    async fn dns_cache_persistence_keeps_resolver_separate() {
        let dir = temp_rules_dir("dns-cache-persist-resolver");
        let mut config = RouteRulesConfig::default();
        config.rules_dir = dir.clone();

        let state = RoutingState::load(config).await.unwrap();
        state
            .dns_cache_insert(
                "resolver.example",
                "A",
                RouteDecision::Proxy,
                Message::query(),
                vec!["8.8.8.8".parse().unwrap()],
            )
            .await;
        state
            .dns_cache_insert(
                "resolver.example",
                "A",
                RouteDecision::Direct,
                Message::query(),
                vec!["223.5.5.5".parse().unwrap()],
            )
            .await;
        state.persist_dns_cache_now().await.unwrap();

        let mut config = RouteRulesConfig::default();
        config.rules_dir = dir;
        let reloaded = RoutingState::load(config).await.unwrap();

        let rows = reloaded.dns_cache_query("resolver.example").await;
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().any(|row| {
            row.resolver == RouteDecision::Proxy && row.results == vec!["8.8.8.8".parse::<IpAddr>().unwrap()]
        }));
        assert!(rows.iter().any(|row| {
            row.resolver == RouteDecision::Direct && row.results == vec!["223.5.5.5".parse::<IpAddr>().unwrap()]
        }));
    }

    #[tokio::test]
    async fn dns_cache_clear_all_truncates_persistent_file() {
        let dir = temp_rules_dir("dns-cache-clear-persist");
        let mut config = RouteRulesConfig::default();
        config.rules_dir = dir.clone();

        let state = RoutingState::load(config).await.unwrap();
        state
            .dns_cache_insert(
                "clear.example",
                "A",
                RouteDecision::Direct,
                Message::query(),
                vec!["9.9.9.9".parse().unwrap()],
            )
            .await;
        state.persist_dns_cache_now().await.unwrap();
        assert!(!fs::read_to_string(dns_cache_file_path(&dir)).unwrap().is_empty());

        assert_eq!(state.dns_cache_clear(None).await, 1);
        assert_eq!(fs::read_to_string(dns_cache_file_path(&dir)).unwrap(), "");

        let mut config = RouteRulesConfig::default();
        config.rules_dir = dir;
        let reloaded = RoutingState::load(config).await.unwrap();
        assert_eq!(reloaded.dns_cache_stats().await.size, 0);
    }

    #[test]
    fn dns_cache_prune_requires_saturday_and_monthly_interval() {
        let saturday = 1_704_499_200; // 2024-01-06 00:00:00 UTC.
        let friday = saturday - SECONDS_PER_DAY;

        assert!(is_saturday_utc(saturday));
        assert!(!is_saturday_utc(friday));
        assert!(dns_cache_prune_is_due(0, saturday));
        assert!(!dns_cache_prune_is_due(0, friday));
        assert!(!dns_cache_prune_is_due(
            saturday - DNS_CACHE_PRUNE_INTERVAL_SECONDS + 1,
            saturday
        ));
        assert!(dns_cache_prune_is_due(
            saturday - DNS_CACHE_PRUNE_INTERVAL_SECONDS,
            saturday
        ));
    }

    #[test]
    fn dns_cache_persist_due_hourly_any_day() {
        // DR-4: the cache must persist on a regular cadence (≈ hourly when dirty)
        // on ANY day, not only Saturdays, so learned mappings survive a reboot.
        let friday = 1_704_412_800; // 2024-01-05 00:00:00 UTC (a Friday).
        let one_hour = 60 * 60;

        // Due on a non-Saturday once at least an hour has elapsed.
        assert!(dns_cache_persist_is_due(0, friday));
        assert!(dns_cache_persist_is_due(friday, friday + one_hour));
        // Not yet due within the hour.
        assert!(!dns_cache_persist_is_due(friday, friday + one_hour - 1));
        assert!(!dns_cache_persist_is_due(friday, friday));
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

    // #6: the CidrRanges LPM index must be exactly equivalent to the linear
    // `nets.iter().any(|n| n.contains(ip))` it replaces on the learning path.
    #[test]
    fn cidr_ranges_membership_matches_linear_scan() {
        // Fixed edge cases: /0, /32, adjacency, overlap, boundaries, v6.
        let fixed: Vec<IpNet> = [
            "0.0.0.0/0",
            "10.0.0.0/8",
            "10.0.0.0/9",
            "192.168.0.0/16",
            "192.168.1.1/32",
            "255.255.255.255/32",
            "1.2.3.0/24",
            "1.2.4.0/24",
            "::/0",
            "2001:db8::/32",
            "fe80::/10",
            "::1/128",
        ]
        .iter()
        .map(|s| s.parse().unwrap())
        .collect();
        let ranges = CidrRanges::build(&fixed);
        for probe in [
            "0.0.0.0",
            "10.128.0.1",
            "192.168.1.1",
            "192.168.1.2",
            "1.2.3.255",
            "1.2.4.0",
            "9.9.9.9",
            "::1",
            "2001:db8::1",
            "2001:db9::1",
            "fe80::abcd",
        ] {
            let ip: IpAddr = probe.parse().unwrap();
            assert_eq!(ranges.contains(&ip), rules_match_ip(&fixed, &ip), "fixed probe {probe}");
        }

        // Randomised fuzz (deterministic LCG, no extra deps): random IPv4 CIDR
        // sets vs random IPv4 probes — the new index must agree with the scan.
        let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut next = || {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (state >> 33) as u32
        };
        for _ in 0..300 {
            let count = (next() % 40) as usize;
            let nets: Vec<IpNet> = (0..count)
                .map(|_| {
                    let addr = std::net::Ipv4Addr::from(next());
                    let prefix = (next() % 33) as u8;
                    IpNet::V4(ipnet::Ipv4Net::new(addr, prefix).unwrap().trunc())
                })
                .collect();
            let ranges = CidrRanges::build(&nets);
            for _ in 0..40 {
                let ip = IpAddr::V4(std::net::Ipv4Addr::from(next()));
                assert_eq!(
                    ranges.contains(&ip),
                    rules_match_ip(&nets, &ip),
                    "v4 fuzz ip={ip}"
                );
            }
        }

        // Same fuzz for IPv6 — geoip_cn genuinely contains v6 prefixes, so the
        // v6 contains/merge path must be randomly exercised too (review gap).
        // (Compose a u128 inline from four LCG draws; a separate closure would
        // double-borrow `next`.)
        for _ in 0..300 {
            let count = (next() % 40) as usize;
            let nets: Vec<IpNet> = (0..count)
                .map(|_| {
                    let bits = ((next() as u128) << 96)
                        | ((next() as u128) << 64)
                        | ((next() as u128) << 32)
                        | (next() as u128);
                    let addr = std::net::Ipv6Addr::from(bits);
                    let prefix = (next() % 129) as u8;
                    IpNet::V6(ipnet::Ipv6Net::new(addr, prefix).unwrap().trunc())
                })
                .collect();
            let ranges = CidrRanges::build(&nets);
            for _ in 0..40 {
                let bits = ((next() as u128) << 96)
                    | ((next() as u128) << 64)
                    | ((next() as u128) << 32)
                    | (next() as u128);
                let ip = IpAddr::V6(std::net::Ipv6Addr::from(bits));
                assert_eq!(
                    ranges.contains(&ip),
                    rules_match_ip(&nets, &ip),
                    "v6 fuzz ip={ip}"
                );
            }
        }
    }

    #[test]
    fn futu_ip_file_is_merged_into_temporary_proxy_list() {
        let dir = temp_rules_dir("futu-ip-merge");
        write_lines_atomic(
            dir.join(FUTU_IP_FILE),
            &[
                "1.14.192.0/18".to_owned(),
                "203.0.113.7".to_owned(),
                "198.51.100.9/32".to_owned(),
            ],
        )
        .unwrap();
        write_lines_atomic(
            temp_file_path(&dir, TEMP_PROXY_IP_FILE),
            &["203.0.113.7/32".to_owned(), "101.32.0.0/16".to_owned()],
        )
        .unwrap();

        let mut rows = read_futu_ip_entries(&dir).unwrap().into_iter().collect::<Vec<_>>();
        rows.sort();
        merge_futu_ip_into_proxy_temp(&dir, &rows).unwrap();

        let mut got = read_lines(temp_file_path(&dir, TEMP_PROXY_IP_FILE)).unwrap();
        got.sort();
        let mut want = vec![
            "1.14.192.0/18".to_owned(),
            "101.32.0.0/16".to_owned(),
            "198.51.100.9".to_owned(),
            "203.0.113.7/32".to_owned(),
        ];
        want.sort();
        assert_eq!(got, want);
    }
