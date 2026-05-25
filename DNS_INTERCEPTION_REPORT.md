# DNS Interception Technical Report

This project implements DNS interception for Linux/OpenWrt first. Other platforms
need platform-specific packet capture mechanisms and usually require a TUN/VPN
style path.

## Linux and OpenWrt

Supported paths:

- Firewall redirect: `route_rules.dns_intercept_mode = "firewall"` or `"both"`
  installs best-effort NAT redirect rules for UDP/TCP port 53 to the configured
  local DNS listener.
- TUN: `route_rules.dns_intercept_mode = "tun"` or `"both"` redirects UDP DNS
  packets seen inside the TUN path to the configured local DNS listener.

The firewall helper prefers `nftables` and falls back to `iptables`. The rules
redirect `PREROUTING` traffic from LAN clients and `OUTPUT` traffic from local
applications. `OUTPUT` rules exclude the current process UID to reduce DNS loops
when the local DNS relay sends queries to upstream resolvers.

Operational notes:

- Firewall interception requires root privileges or equivalent capabilities.
- UID-based loop prevention is imperfect when many services run as the same UID,
  especially on small OpenWrt systems running as root.
- TCP/UDP port 53 is intercepted. Encrypted DNS protocols such as DoH, DoT, DoQ,
  and DNS over HTTP/3 are not port-53 DNS and require TLS/SNI/IP routing policies
  or browser/client policy controls.
- IPv6 redirection depends on firewall backend support and local DNS listener
  binding. Validate both IPv4 and IPv6 on each target firmware image.

## Windows

Windows does not have a portable, built-in equivalent to Linux NAT output
redirect rules that an application can safely install and own.

Possible mechanisms:

- TUN/Wintun: recommended for this project. Capture packets in a virtual network
  adapter and route DNS packets through the local split DNS path.
- Windows Filtering Platform (WFP): powerful but requires a driver/service and a
  deeper Windows-specific implementation.
- WinDivert: practical for experiments, but it depends on a third-party driver
  and administrative privileges.

Recommendation: use the existing TUN architecture for Windows DNS interception.

## macOS

Possible mechanisms:

- `pf` anchors can redirect port 53, but require root privileges and careful
  lifecycle management.
- Network Extension Packet Tunnel Provider can capture DNS in a TUN/VPN model.
- System resolver configuration can point DNS to the local listener, but it does
  not intercept clients that bypass the system resolver.

Recommendation: use a Packet Tunnel Provider for robust capture; use `pf` only
for developer or administrator-managed deployments.

## Android

Android provides `VpnService`, which is the appropriate DNS interception path.
The VPN service captures packets via a TUN interface, and the application must
protect its own upstream sockets to avoid routing loops.

Recommendation: implement DNS interception in the TUN path and ensure all
Shadowsocks and upstream DNS sockets use Android protected socket support.

## iOS

iOS does not allow general-purpose firewall redirect by normal applications.
Packet capture must use NetworkExtension, normally a Packet Tunnel Provider, and
requires the appropriate Apple entitlement.

Recommendation: support DNS interception only through NetworkExtension/TUN.

## Common Risks

- DNS loops if local DNS upstream traffic is intercepted again.
- TCP DNS handling is necessary for truncated UDP responses and some resolvers.
- Encrypted DNS cannot be transparently decoded by port-53 interception.
- Cache TTL policy must balance correctness and the requested long-lived cache.
- Split DNS changes can dynamically add IPs to generated direct/bypass lists; file
  writes should remain atomic and bounded.
