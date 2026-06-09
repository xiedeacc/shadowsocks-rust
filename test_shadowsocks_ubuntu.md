# Shadowsocks Test Report

- Generated: `2026-06-09T00:41:50Z`
- Target: `ubuntu`
- Config: `/usr/local/shadowsocks/conf/shadowsocks-client.json`
- Admin endpoint used by tester: `http://127.0.0.1:9090`
- DNS intercept mode: `both`
- Transparent firewall: `nft`
- Redir readiness: `ready`
- Ports: socks `1080`, http `1081`, redir `12345`, dns `1053`

## Transport Probes

| Mode | Endpoint | Route Decision | Proxy Domain | DNS Intercepted | DNS Cache | Resolved IPs | OK | HTTP | Remote IP | DNS Resolve Time (ms) | Visit Time (ms) | TCP Connect (ms) | TLS Handshake (ms) | First Byte (ms) | Exit | Error |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| redir | transparent redir:12345 | direct | no | yes | hit | 157.148.69.186, 157.148.69.151 | yes | 200 | 157.148.69.186 | 25.7 | 84.0 | 38.8 | 71.0 | 84.0 | 0 | OK |
| http | http://127.0.0.1:1081 | http_proxy | no | - | - | - | yes | 200 | 127.0.0.1 | 0.0 | 255.6 | 0.1 | 156.5 | 255.6 | 0 | OK |
| socks | socks5h://127.0.0.1:1080 | socks5_proxy | no | - | - | - | yes | 200 | 127.0.0.1 | 0.0 | 249.3 | 0.1 | 154.1 | 249.3 | 0 | OK |
| redir | transparent redir:12345 | redir | yes | yes | hit | 142.251.152.119, 142.251.157.119, 142.251.150.119, 142.251.154.119, 142.251.155.119, 142.251.153.119, 142.251.151.119, 142.251.156.119 | yes | 204 | 142.251.152.119 | 0.6 | 110.1 | 0.7 | 60.0 | 110.0 | 0 | OK |
| http | http://127.0.0.1:1081 | http_proxy | yes | - | - | - | yes | 204 | 127.0.0.1 | 0.0 | 115.4 | 0.1 | 62.1 | 115.3 | 0 | OK |
| socks | socks5h://127.0.0.1:1080 | socks5_proxy | yes | - | - | - | yes | 204 | 127.0.0.1 | 0.0 | 109.0 | 0.1 | 58.6 | 108.9 | 0 | OK |

## Admin Debug redir/http/socks

### Debug redir

```text
https://www.baidu.com: env -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY -u all_proxy -u ALL_PROXY -u no_proxy -u NO_PROXY curl -4 -sS --max-time 6 -o /dev/null -w 'http_code=%{http_code}\ntime_namelookup=%{time_namelookup}\ntime_connect=%{time_connect}\ntime_appconnect=%{time_appconnect}\ntime_starttransfer=%{time_starttransfer}\ntime_total=%{time_total}\n' --noproxy '*' 'https://www.baidu.com?deubg_random=18b742dfed7791a64d576f4'
https://www.google.com/generate_204: env -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY -u all_proxy -u ALL_PROXY -u no_proxy -u NO_PROXY curl -4 -sS --max-time 6 -o /dev/null -w 'http_code=%{http_code}\ntime_namelookup=%{time_namelookup}\ntime_connect=%{time_connect}\ntime_appconnect=%{time_appconnect}\ntime_starttransfer=%{time_starttransfer}\ntime_total=%{time_total}\n' --noproxy '*' 'https://www.google.com/generate_204?deubg_random=18b742e06d1765a44d576f7'
```

| Route Decision | Proxy Domain | DNS Intercepted | DNS Cache | Resolved IPs | NFT Proxy | NFT Matches | Transparent Port | Response | HTTP | DNS Resolve Time (ms) | TCP Connect (ms) | TLS Handshake (ms) | First Byte (ms) | Curl Exit | Error |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ---: | ---: | ---: | ---: | ---: | --- |
| direct | no | yes | hit | 157.148.69.186, 157.148.69.151 | no | - | not received | true | 200 | 26.6 | 39.5 | 70.5 | 83.5 | 0 | OK |
| redir | yes | yes | hit | 142.251.152.119, 142.251.157.119, 142.251.150.119, 142.251.154.119, 142.251.155.119, 142.251.153.119, 142.251.151.119, 142.251.156.119 | yes | 142.251.150.119/32, 142.251.151.119/32, 142.251.152.119/32, 142.251.153.119/32, 142.251.154.119/32, 142.251.155.119/32, 142.251.156.119/32, 142.251.157.119/32 | received | true | 204 | 0.6 | 0.6 | 58.5 | 110.7 | 0 | OK |

### Debug http

```text
https://www.baidu.com: env -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY -u all_proxy -u ALL_PROXY -u no_proxy -u NO_PROXY curl -4 -sS --max-time 6 -o /dev/null -w 'http_code=%{http_code}\ntime_namelookup=%{time_namelookup}\ntime_connect=%{time_connect}\ntime_appconnect=%{time_appconnect}\ntime_starttransfer=%{time_starttransfer}\ntime_total=%{time_total}\n' -x http://127.0.0.1:1081 'https://www.baidu.com?deubg_random=18b742e019987c0b4d576f5'
https://www.google.com/generate_204: env -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY -u all_proxy -u ALL_PROXY -u no_proxy -u NO_PROXY curl -4 -sS --max-time 6 -o /dev/null -w 'http_code=%{http_code}\ntime_namelookup=%{time_namelookup}\ntime_connect=%{time_connect}\ntime_appconnect=%{time_appconnect}\ntime_starttransfer=%{time_starttransfer}\ntime_total=%{time_total}\n' -x http://127.0.0.1:1081 'https://www.google.com/generate_204?deubg_random=18b742e0804635b04d576f8'
```

| Route Decision | Proxy Domain | Http Port | Response | HTTP | DNS Resolve Time (ms) | TCP Connect (ms) | TLS Handshake (ms) | First Byte (ms) | Curl Exit | Error |
| --- | --- | --- | --- | --- | ---: | ---: | ---: | ---: | ---: | --- |
| http_proxy | no | received | true | 200 | 0.0 | 0.1 | 356.6 | 460.2 | 0 | OK |
| http_proxy | yes | received | true | 204 | 0.0 | 0.1 | 63.3 | 122.1 | 0 | OK |

### Debug socks

```text
https://www.baidu.com: env -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY -u all_proxy -u ALL_PROXY -u no_proxy -u NO_PROXY curl -4 -sS --max-time 6 -o /dev/null -w 'http_code=%{http_code}\ntime_namelookup=%{time_namelookup}\ntime_connect=%{time_connect}\ntime_appconnect=%{time_appconnect}\ntime_starttransfer=%{time_starttransfer}\ntime_total=%{time_total}\n' -x socks5h://127.0.0.1:1080 'https://www.baidu.com?deubg_random=18b742e0492b1fa94d576f6'
https://www.google.com/generate_204: env -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY -u all_proxy -u ALL_PROXY -u no_proxy -u NO_PROXY curl -4 -sS --max-time 6 -o /dev/null -w 'http_code=%{http_code}\ntime_namelookup=%{time_namelookup}\ntime_connect=%{time_connect}\ntime_appconnect=%{time_appconnect}\ntime_starttransfer=%{time_starttransfer}\ntime_total=%{time_total}\n' -x socks5h://127.0.0.1:1080 'https://www.google.com/generate_204?deubg_random=18b742e09369ae574d576f9'
```

| Route Decision | Proxy Domain | Socks Port | Response | HTTP | DNS Resolve Time (ms) | TCP Connect (ms) | TLS Handshake (ms) | First Byte (ms) | Curl Exit | Error |
| --- | --- | --- | --- | --- | ---: | ---: | ---: | ---: | ---: | --- |
| socks5_proxy | no | received | true | 200 | 0.0 | 0.1 | 173.7 | 269.7 | 0 | OK |
| socks5_proxy | yes | received | true | 204 | 0.0 | 0.1 | 60.9 | 110.8 | 0 | OK |

## Raw Admin Debug JSON

### redir https://www.baidu.com

```json
{
  "connection_recorded": false,
  "curl_command": "env -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY -u all_proxy -u ALL_PROXY -u no_proxy -u NO_PROXY curl -4 -sS --max-time 6 -o /dev/null -w 'http_code=%{http_code}\\ntime_namelookup=%{time_namelookup}\\ntime_connect=%{time_connect}\\ntime_appconnect=%{time_appconnect}\\ntime_starttransfer=%{time_starttransfer}\\ntime_total=%{time_total}\\n' --noproxy '*' 'https://www.baidu.com?deubg_random=18b742dfed7791a64d576f4'",
  "curl_error": null,
  "curl_exit_code": 0,
  "debug_mode": "redir",
  "debug_random": "18b742dfed7791a64d576f4",
  "debug_random_param": "deubg_random",
  "debug_url": "https://www.baidu.com?deubg_random=18b742dfed7791a64d576f4",
  "dns_cache_hit": true,
  "dns_intercepted": true,
  "host": "www.baidu.com",
  "http_code": "200",
  "http_port_received": false,
  "http_port_running": true,
  "local_port": 12345,
  "nft_checked": true,
  "nft_error": null,
  "nft_matches": [],
  "nft_proxy": false,
  "port_received": false,
  "port_running": true,
  "port_status": "not received",
  "proxy_domain": false,
  "resolved_ips": [
    "157.148.69.186",
    "157.148.69.151"
  ],
  "response_received": true,
  "route_decision": "direct",
  "rule_route_decision": null,
  "socks_port_received": false,
  "socks_port_running": true,
  "time_appconnect": "0.070535",
  "time_connect": "0.039541",
  "time_namelookup": "0.026560",
  "time_starttransfer": "0.083536",
  "time_total": "0.083582",
  "transparent_connection_recorded": false,
  "transparent_port_received": false,
  "transparent_port_running": true,
  "url": "https://www.baidu.com",
  "admin_request_exit_code": 0,
  "admin_request_error": null
}

```

### http https://www.baidu.com

```json
{
  "connection_recorded": true,
  "curl_command": "env -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY -u all_proxy -u ALL_PROXY -u no_proxy -u NO_PROXY curl -4 -sS --max-time 6 -o /dev/null -w 'http_code=%{http_code}\\ntime_namelookup=%{time_namelookup}\\ntime_connect=%{time_connect}\\ntime_appconnect=%{time_appconnect}\\ntime_starttransfer=%{time_starttransfer}\\ntime_total=%{time_total}\\n' -x http://127.0.0.1:1081 'https://www.baidu.com?deubg_random=18b742e019987c0b4d576f5'",
  "curl_error": null,
  "curl_exit_code": 0,
  "debug_mode": "http",
  "debug_random": "18b742e019987c0b4d576f5",
  "debug_random_param": "deubg_random",
  "debug_url": "https://www.baidu.com?deubg_random=18b742e019987c0b4d576f5",
  "dns_cache_hit": null,
  "dns_intercepted": null,
  "host": "www.baidu.com",
  "http_code": "200",
  "http_port_received": true,
  "http_port_running": true,
  "local_port": 1081,
  "nft_checked": false,
  "nft_error": null,
  "nft_matches": [],
  "nft_proxy": null,
  "port_received": true,
  "port_running": true,
  "port_status": "received",
  "proxy_domain": false,
  "resolved_ips": [],
  "response_received": true,
  "route_decision": "http_proxy",
  "rule_route_decision": null,
  "socks_port_received": false,
  "socks_port_running": true,
  "time_appconnect": "0.356632",
  "time_connect": "0.000081",
  "time_namelookup": "0.000012",
  "time_starttransfer": "0.460167",
  "time_total": "0.460209",
  "transparent_connection_recorded": false,
  "transparent_port_received": false,
  "transparent_port_running": true,
  "url": "https://www.baidu.com",
  "admin_request_exit_code": 0,
  "admin_request_error": null
}

```

### socks https://www.baidu.com

```json
{
  "connection_recorded": true,
  "curl_command": "env -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY -u all_proxy -u ALL_PROXY -u no_proxy -u NO_PROXY curl -4 -sS --max-time 6 -o /dev/null -w 'http_code=%{http_code}\\ntime_namelookup=%{time_namelookup}\\ntime_connect=%{time_connect}\\ntime_appconnect=%{time_appconnect}\\ntime_starttransfer=%{time_starttransfer}\\ntime_total=%{time_total}\\n' -x socks5h://127.0.0.1:1080 'https://www.baidu.com?deubg_random=18b742e0492b1fa94d576f6'",
  "curl_error": null,
  "curl_exit_code": 0,
  "debug_mode": "socks",
  "debug_random": "18b742e0492b1fa94d576f6",
  "debug_random_param": "deubg_random",
  "debug_url": "https://www.baidu.com?deubg_random=18b742e0492b1fa94d576f6",
  "dns_cache_hit": null,
  "dns_intercepted": null,
  "host": "www.baidu.com",
  "http_code": "200",
  "http_port_received": false,
  "http_port_running": true,
  "local_port": 1080,
  "nft_checked": false,
  "nft_error": null,
  "nft_matches": [],
  "nft_proxy": null,
  "port_received": true,
  "port_running": true,
  "port_status": "received",
  "proxy_domain": false,
  "resolved_ips": [],
  "response_received": true,
  "route_decision": "socks5_proxy",
  "rule_route_decision": null,
  "socks_port_received": true,
  "socks_port_running": true,
  "time_appconnect": "0.173710",
  "time_connect": "0.000063",
  "time_namelookup": "0.000010",
  "time_starttransfer": "0.269668",
  "time_total": "0.269710",
  "transparent_connection_recorded": false,
  "transparent_port_received": false,
  "transparent_port_running": true,
  "url": "https://www.baidu.com",
  "admin_request_exit_code": 0,
  "admin_request_error": null
}

```

### redir https://www.google.com/generate_204

```json
{
  "connection_recorded": true,
  "curl_command": "env -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY -u all_proxy -u ALL_PROXY -u no_proxy -u NO_PROXY curl -4 -sS --max-time 6 -o /dev/null -w 'http_code=%{http_code}\\ntime_namelookup=%{time_namelookup}\\ntime_connect=%{time_connect}\\ntime_appconnect=%{time_appconnect}\\ntime_starttransfer=%{time_starttransfer}\\ntime_total=%{time_total}\\n' --noproxy '*' 'https://www.google.com/generate_204?deubg_random=18b742e06d1765a44d576f7'",
  "curl_error": null,
  "curl_exit_code": 0,
  "debug_mode": "redir",
  "debug_random": "18b742e06d1765a44d576f7",
  "debug_random_param": "deubg_random",
  "debug_url": "https://www.google.com/generate_204?deubg_random=18b742e06d1765a44d576f7",
  "dns_cache_hit": true,
  "dns_intercepted": true,
  "host": "www.google.com",
  "http_code": "204",
  "http_port_received": false,
  "http_port_running": true,
  "local_port": 12345,
  "nft_checked": true,
  "nft_error": null,
  "nft_matches": [
    "142.251.150.119/32",
    "142.251.151.119/32",
    "142.251.152.119/32",
    "142.251.153.119/32",
    "142.251.154.119/32",
    "142.251.155.119/32",
    "142.251.156.119/32",
    "142.251.157.119/32"
  ],
  "nft_proxy": true,
  "port_received": true,
  "port_running": true,
  "port_status": "received",
  "proxy_domain": true,
  "resolved_ips": [
    "142.251.152.119",
    "142.251.157.119",
    "142.251.150.119",
    "142.251.154.119",
    "142.251.155.119",
    "142.251.153.119",
    "142.251.151.119",
    "142.251.156.119"
  ],
  "response_received": true,
  "route_decision": "redir",
  "rule_route_decision": "proxy",
  "socks_port_received": false,
  "socks_port_running": true,
  "time_appconnect": "0.058457",
  "time_connect": "0.000645",
  "time_namelookup": "0.000585",
  "time_starttransfer": "0.110734",
  "time_total": "0.110783",
  "transparent_connection_recorded": true,
  "transparent_port_received": true,
  "transparent_port_running": true,
  "url": "https://www.google.com/generate_204",
  "admin_request_exit_code": 0,
  "admin_request_error": null
}

```

### http https://www.google.com/generate_204

```json
{
  "connection_recorded": true,
  "curl_command": "env -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY -u all_proxy -u ALL_PROXY -u no_proxy -u NO_PROXY curl -4 -sS --max-time 6 -o /dev/null -w 'http_code=%{http_code}\\ntime_namelookup=%{time_namelookup}\\ntime_connect=%{time_connect}\\ntime_appconnect=%{time_appconnect}\\ntime_starttransfer=%{time_starttransfer}\\ntime_total=%{time_total}\\n' -x http://127.0.0.1:1081 'https://www.google.com/generate_204?deubg_random=18b742e0804635b04d576f8'",
  "curl_error": null,
  "curl_exit_code": 0,
  "debug_mode": "http",
  "debug_random": "18b742e0804635b04d576f8",
  "debug_random_param": "deubg_random",
  "debug_url": "https://www.google.com/generate_204?deubg_random=18b742e0804635b04d576f8",
  "dns_cache_hit": null,
  "dns_intercepted": null,
  "host": "www.google.com",
  "http_code": "204",
  "http_port_received": true,
  "http_port_running": true,
  "local_port": 1081,
  "nft_checked": false,
  "nft_error": null,
  "nft_matches": [],
  "nft_proxy": null,
  "port_received": true,
  "port_running": true,
  "port_status": "received",
  "proxy_domain": true,
  "resolved_ips": [],
  "response_received": true,
  "route_decision": "http_proxy",
  "rule_route_decision": "proxy",
  "socks_port_received": false,
  "socks_port_running": true,
  "time_appconnect": "0.063252",
  "time_connect": "0.000072",
  "time_namelookup": "0.000011",
  "time_starttransfer": "0.122102",
  "time_total": "0.122148",
  "transparent_connection_recorded": false,
  "transparent_port_received": false,
  "transparent_port_running": true,
  "url": "https://www.google.com/generate_204",
  "admin_request_exit_code": 0,
  "admin_request_error": null
}

```

### socks https://www.google.com/generate_204

```json
{
  "connection_recorded": true,
  "curl_command": "env -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY -u all_proxy -u ALL_PROXY -u no_proxy -u NO_PROXY curl -4 -sS --max-time 6 -o /dev/null -w 'http_code=%{http_code}\\ntime_namelookup=%{time_namelookup}\\ntime_connect=%{time_connect}\\ntime_appconnect=%{time_appconnect}\\ntime_starttransfer=%{time_starttransfer}\\ntime_total=%{time_total}\\n' -x socks5h://127.0.0.1:1080 'https://www.google.com/generate_204?deubg_random=18b742e09369ae574d576f9'",
  "curl_error": null,
  "curl_exit_code": 0,
  "debug_mode": "socks",
  "debug_random": "18b742e09369ae574d576f9",
  "debug_random_param": "deubg_random",
  "debug_url": "https://www.google.com/generate_204?deubg_random=18b742e09369ae574d576f9",
  "dns_cache_hit": null,
  "dns_intercepted": null,
  "host": "www.google.com",
  "http_code": "204",
  "http_port_received": false,
  "http_port_running": true,
  "local_port": 1080,
  "nft_checked": false,
  "nft_error": null,
  "nft_matches": [],
  "nft_proxy": null,
  "port_received": true,
  "port_running": true,
  "port_status": "received",
  "proxy_domain": true,
  "resolved_ips": [],
  "response_received": true,
  "route_decision": "socks5_proxy",
  "rule_route_decision": "proxy",
  "socks_port_received": true,
  "socks_port_running": true,
  "time_appconnect": "0.060859",
  "time_connect": "0.000094",
  "time_namelookup": "0.000017",
  "time_starttransfer": "0.110773",
  "time_total": "0.110809",
  "transparent_connection_recorded": false,
  "transparent_port_received": false,
  "transparent_port_running": true,
  "url": "https://www.google.com/generate_204",
  "admin_request_exit_code": 0,
  "admin_request_error": null
}

```

## Result

All required probes passed.
