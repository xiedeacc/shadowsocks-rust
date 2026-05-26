//! Shadowsocks Local server serving on a Tun interface

#[cfg(unix)]
use std::os::unix::io::RawFd;
#[cfg(windows)]
use std::process::{Command, Stdio};
use std::{
    io, mem,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use byte_string::ByteStr;
use cfg_if::cfg_if;
use ipnet::IpNet;
use log::{debug, error, info, trace, warn};
use shadowsocks::config::Mode;
#[cfg(windows)]
use shadowsocks::config::ServerAddr;
use smoltcp::wire::{IpProtocol, TcpPacket, UdpPacket};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::mpsc,
    time,
};

cfg_if! {
    if #[cfg(any(target_os = "ios",
                 target_os = "macos",
                 target_os = "linux",
                 target_os = "android",
                 target_os = "windows",
                 target_os = "freebsd"))] {
        use tun::{
            create_as_async, AsyncDevice, Configuration as TunConfiguration, AbstractDevice, Error as TunError, Layer,
        };
    } else {
        mod fake_tun;
        use self::fake_tun::{
            AbstractDevice, AsyncDevice, Configuration as TunConfiguration, Error as TunError, Layer, create_as_async,
        };
    }
}

use crate::local::{context::ServiceContext, loadbalancing::PingBalancer};

use self::{ip_packet::IpPacket, tcp::TcpTun, udp::UdpTun, virt_device::TokenBuffer};

mod ip_packet;
mod tcp;
mod udp;
mod virt_device;

/// Tun service builder
pub struct TunBuilder {
    context: Arc<ServiceContext>,
    balancer: PingBalancer,
    tun_config: TunConfiguration,
    udp_expiry_duration: Option<Duration>,
    udp_capacity: Option<usize>,
    mode: Mode,
}

/// TunConfiguration contains a HANDLE, which is a *mut c_void on Windows.
unsafe impl Send for TunBuilder {}

impl TunBuilder {
    /// Create a Tun service builder
    pub fn new(context: Arc<ServiceContext>, balancer: PingBalancer) -> Self {
        Self {
            context,
            balancer,
            tun_config: TunConfiguration::default(),
            udp_expiry_duration: None,
            udp_capacity: None,
            mode: Mode::TcpOnly,
        }
    }

    pub fn address(&mut self, addr: IpNet) {
        self.tun_config.address(addr.addr()).netmask(addr.netmask());
    }

    pub fn destination(&mut self, addr: IpNet) {
        self.tun_config.destination(addr.addr());
    }

    pub fn name(&mut self, name: &str) {
        self.tun_config.tun_name(name);
    }

    #[cfg(unix)]
    pub fn file_descriptor(&mut self, fd: RawFd) {
        self.tun_config.raw_fd(fd);
    }

    pub fn udp_expiry_duration(&mut self, udp_expiry_duration: Duration) {
        self.udp_expiry_duration = Some(udp_expiry_duration);
    }

    pub fn udp_capacity(&mut self, udp_capacity: usize) {
        self.udp_capacity = Some(udp_capacity);
    }

    pub fn mode(&mut self, mode: Mode) {
        self.mode = mode;
    }

    /// Build Tun server
    pub async fn build(mut self) -> io::Result<Tun> {
        self.tun_config.layer(Layer::L3).up();

        // XXX: tun2 set IFF_NO_PI by default.
        //
        // #[cfg(target_os = "linux")]
        // self.tun_config.platform_config(|tun_config| {
        //     // IFF_NO_PI preventing excessive buffer reallocating
        //     tun_config.packet_information(false);
        // });

        let device = match create_as_async(&self.tun_config) {
            Ok(d) => d,
            Err(TunError::Io(err)) => return Err(err),
            Err(err) => return Err(io::Error::other(err)),
        };

        let tun_address = match (device.address(), device.netmask()) {
            (Ok(address), Ok(netmask)) => IpNet::with_netmask(address, netmask).ok(),
            _ => None,
        };

        let (udp, udp_cleanup_interval, udp_keepalive_rx) = UdpTun::new(
            self.context.clone(),
            self.balancer.clone(),
            self.udp_expiry_duration,
            self.udp_capacity,
        );

        #[cfg(windows)]
        let bypass_route_ips = self
            .balancer
            .servers()
            .filter_map(|server| match server.server_config().addr() {
                ServerAddr::SocketAddr(addr) => Some(addr.ip()),
                ServerAddr::DomainName(..) => None,
            })
            .collect();

        let tcp = TcpTun::new(
            self.context.clone(),
            self.balancer,
            device.mtu().unwrap_or(1500) as u32,
            tun_address,
        );

        #[cfg(windows)]
        let tun_name_for_cleanup = device.tun_name().ok();

        Ok(Tun {
            device,
            tcp,
            udp,
            #[cfg(windows)]
            context: self.context,
            udp_cleanup_interval,
            udp_keepalive_rx,
            mode: self.mode,
            #[cfg(windows)]
            bypass_route_ips,
            #[cfg(windows)]
            tun_name_for_cleanup,
        })
    }
}

/// Tun service
pub struct Tun {
    device: AsyncDevice,
    tcp: TcpTun,
    udp: UdpTun,
    #[cfg(windows)]
    context: Arc<ServiceContext>,
    udp_cleanup_interval: Duration,
    udp_keepalive_rx: mpsc::Receiver<SocketAddr>,
    mode: Mode,
    #[cfg(windows)]
    bypass_route_ips: Vec<IpAddr>,
    /// Cached TUN interface name; used by the Windows Drop impl to roll
    /// back catch-all routes if the process exits without the deploy
    /// script's cleanup running (e.g. killed via Task Manager).
    #[cfg(windows)]
    tun_name_for_cleanup: Option<String>,
}

#[cfg(windows)]
impl Drop for Tun {
    fn drop(&mut self) {
        if let Some(name) = self.tun_name_for_cleanup.take() {
            // Best-effort: log and ignore failures; the deploy script's
            // cleanup is still the canonical recovery path.
            if let Err(err) = remove_windows_tun_routes(&name) {
                warn!("[TUN] failed to remove catch-all routes for '{}' on shutdown: {}", name, err);
            } else {
                info!("[TUN] removed catch-all routes for '{}' on shutdown", name);
            }
        }
    }
}

impl Tun {
    /// Start serving
    pub async fn run(mut self) -> io::Result<()> {
        info!(
            "shadowsocks tun device {}, mode {}",
            self.device.tun_name().or_else(|r| Ok::<_, ()>(r.to_string())).unwrap(),
            self.mode,
        );

        let address = match self.device.address() {
            Ok(a) => a,
            Err(err) => {
                error!("[TUN] failed to get device address, error: {}", err);
                return Err(io::Error::other(err));
            }
        };

        let netmask = match self.device.netmask() {
            Ok(n) => n,
            Err(err) => {
                error!("[TUN] failed to get device netmask, error: {}", err);
                return Err(io::Error::other(err));
            }
        };

        let address_net = match IpNet::with_netmask(address, netmask) {
            Ok(n) => n,
            Err(err) => {
                error!("[TUN] invalid address {}, netmask {}, error: {}", address, netmask, err);
                return Err(io::Error::other(err));
            }
        };

        info!(
            "[TUN] device {} ready: network={} address={} netmask={} mode={}",
            self.device.tun_name().or_else(|r| Ok::<_, ()>(r.to_string())).unwrap(),
            address_net,
            address,
            netmask,
            self.mode,
        );

        #[cfg(windows)]
        if let Ok(name) = self.device.tun_name() {
            let bypass_ips = self.windows_bypass_route_ips().await;
            if bypass_ips.is_empty() {
                info!(
                    "[TUN] no direct-route exceptions to install for '{}'; relying on deploy script for catch-all routes",
                    name
                );
            } else {
                // These are /32 routes installed on the *physical* adapter
                // so the listed destinations bypass the TUN catch-all and
                // sslocal can reach them directly (otherwise its own
                // outbound to e.g. the SS server or the local DNS upstream
                // would be re-captured by TUN and deadlock).
                info!(
                    "[TUN] installing direct-route exceptions on physical adapter (so these bypass '{}' catch-all): {}",
                    name,
                    bypass_ips
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
            if let Err(err) = install_windows_bypass_routes(&name, &bypass_ips) {
                warn!(
                    "[TUN] failed to install Windows direct-route exceptions (deploy script's routes still apply): {}",
                    err
                );
            } else {
                info!("[TUN] direct-route exceptions installed for '{}'", name);
            }
        }

        let address_broadcast = address_net.broadcast();

        let create_packet_buffer = || {
            const PACKET_BUFFER_SIZE: usize = 65536;
            let mut packet_buffer = TokenBuffer::with_capacity(PACKET_BUFFER_SIZE);
            unsafe {
                packet_buffer.set_len(PACKET_BUFFER_SIZE);
            }
            packet_buffer
        };

        let mut packet_buffer = create_packet_buffer();
        let mut udp_cleanup_timer = time::interval(self.udp_cleanup_interval);

        loop {
            tokio::select! {
                // tun device
                n = self.device.read(&mut packet_buffer) => {
                    let n = n?;
                    unsafe {
                        packet_buffer.set_len(n);
                    }

                    trace!("[TUN] received IP packet {:?}", ByteStr::new(&packet_buffer));

                    let frame = mem::replace(&mut packet_buffer, create_packet_buffer());
                    if let Err(err) = self.handle_tun_frame(&address_broadcast, frame).await {
                        error!("[TUN] handle IP frame failed, error: {}", err);
                    }
                }

                // UDP channel sent back
                packet = self.udp.recv_packet() => {
                    match self.device.write(&packet).await {
                        Ok(n) => {
                            if n < packet.len() {
                                warn!("[TUN] sent IP packet (UDP), but truncated. sent {} < {}, {:?}", n, packet.len(), ByteStr::new(&packet));
                            } else {
                                trace!("[TUN] sent IP packet (UDP) {:?}", ByteStr::new(&packet));
                            }
                        }
                        Err(err) => {
                            error!("[TUN] failed to set packet information, error: {}, {:?}", err, ByteStr::new(&packet));
                        }
                    }
                }

                // UDP cleanup expired associations
                _ = udp_cleanup_timer.tick() => {
                    self.udp.cleanup_expired().await;
                }

                // UDP keep-alive associations
                peer_addr_opt = self.udp_keepalive_rx.recv() => {
                    let peer_addr = peer_addr_opt.expect("UDP keep-alive channel closed unexpectedly");
                    self.udp.keep_alive(&peer_addr).await;
                }

                // TCP channel sent back
                packet = self.tcp.recv_packet() => {
                    match self.device.write(&packet).await {
                        Ok(n) => {
                            if n < packet.len() {
                                warn!("[TUN] sent IP packet (TCP), but truncated. sent {} < {}, {:?}", n, packet.len(), ByteStr::new(&packet));
                            } else {
                                trace!("[TUN] sent IP packet (TCP) {:?}", ByteStr::new(&packet));
                            }
                        }
                        Err(err) => {
                            error!("[TUN] failed to set packet information, error: {}, {:?}", err, ByteStr::new(&packet));
                        }
                    }
                }
            }
        }
    }

    async fn handle_tun_frame(
        &mut self,
        device_broadcast_addr: &IpAddr,
        frame: TokenBuffer,
    ) -> smoltcp::wire::Result<()> {
        let packet = match IpPacket::new_checked(frame.as_ref())? {
            Some(packet) => packet,
            None => {
                warn!("unrecognized IP packet {:?}", ByteStr::new(&frame));
                return Ok(());
            }
        };

        trace!("[TUN] {:?}", packet);

        let src_ip_addr = packet.src_addr();
        let dst_ip_addr = packet.dst_addr();
        let src_non_unicast = src_ip_addr == *device_broadcast_addr
            || match src_ip_addr {
                IpAddr::V4(v4) => v4.is_broadcast() || v4.is_multicast() || v4.is_unspecified(),
                IpAddr::V6(v6) => v6.is_multicast() || v6.is_unspecified(),
            };
        let dst_non_unicast = dst_ip_addr == *device_broadcast_addr
            || match dst_ip_addr {
                IpAddr::V4(v4) => v4.is_broadcast() || v4.is_multicast() || v4.is_unspecified(),
                IpAddr::V6(v6) => v6.is_multicast() || v6.is_unspecified(),
            };

        if src_non_unicast || dst_non_unicast {
            trace!(
                "[TUN] IP packet {} (unicast? {}) -> {} (unicast? {}) throwing away",
                src_ip_addr, !src_non_unicast, dst_ip_addr, !dst_non_unicast
            );
            return Ok(());
        }

        match packet.protocol() {
            IpProtocol::Tcp => {
                if !self.mode.enable_tcp() {
                    trace!("received TCP packet but mode is {}, throwing away", self.mode);
                    return Ok(());
                }

                let tcp_packet = match TcpPacket::new_checked(packet.payload()) {
                    Ok(p) => p,
                    Err(err) => {
                        error!(
                            "invalid TCP packet err: {}, src_ip: {}, dst_ip: {}, payload: {:?}",
                            err,
                            packet.src_addr(),
                            packet.dst_addr(),
                            ByteStr::new(packet.payload())
                        );
                        return Ok(());
                    }
                };

                let src_port = tcp_packet.src_port();
                let dst_port = tcp_packet.dst_port();

                let src_addr = SocketAddr::new(packet.src_addr(), src_port);
                let dst_addr = SocketAddr::new(packet.dst_addr(), dst_port);

                trace!(
                    "[TUN] TCP packet {} (unicast? {}) -> {} (unicast? {}) {}",
                    src_addr, !src_non_unicast, dst_addr, !dst_non_unicast, tcp_packet
                );

                // TCP first handshake packet.
                if let Err(err) = self.tcp.handle_packet(src_addr, dst_addr, &tcp_packet).await {
                    error!(
                        "handle TCP packet failed, error: {}, {} <-> {}, packet: {:?}",
                        err, src_addr, dst_addr, tcp_packet
                    );
                }

                self.tcp.drive_interface_state(frame).await;
            }
            IpProtocol::Udp => {
                if !self.mode.enable_udp() {
                    trace!("received UDP packet but mode is {}, throwing away", self.mode);
                    return Ok(());
                }

                let udp_packet = match UdpPacket::new_checked(packet.payload()) {
                    Ok(p) => p,
                    Err(err) => {
                        error!(
                            "invalid UDP packet err: {}, src_ip: {}, dst_ip: {}, payload: {:?}",
                            err,
                            packet.src_addr(),
                            packet.dst_addr(),
                            ByteStr::new(packet.payload())
                        );
                        return Ok(());
                    }
                };

                let src_port = udp_packet.src_port();
                let dst_port = udp_packet.dst_port();

                let src_addr = SocketAddr::new(src_ip_addr, src_port);
                let dst_addr = SocketAddr::new(packet.dst_addr(), dst_port);

                let payload = udp_packet.payload();
                trace!(
                    "[TUN] UDP packet {} (unicast? {}) -> {} (unicast? {}) {}",
                    src_addr, !src_non_unicast, dst_addr, !dst_non_unicast, udp_packet
                );

                if let Err(err) = self.udp.handle_packet(src_addr, dst_addr, payload).await {
                    error!("handle UDP packet failed, err: {}, packet: {:?}", err, udp_packet);
                }
            }
            IpProtocol::Icmp | IpProtocol::Icmpv6 => {
                // ICMP is handled by TCP's Interface.
                // smoltcp's interface will always send replies to EchoRequest
                self.tcp.drive_interface_state(frame).await;
            }
            _ => {
                debug!("IP packet ignored (protocol: {:?})", packet.protocol());
                return Ok(());
            }
        }

        Ok(())
    }

    /// Collect IPs that sslocal itself will *directly* connect to and
    /// therefore need /32 exceptions on the physical adapter so its
    /// outbound packets don't loop back into the TUN catch-all.
    ///
    /// What belongs here:
    ///   - SS server IPs       — sslocal opens raw TCP/UDP to them
    ///   - `domestic_dns` IPs  — `DnsClient::lookup_local` queries
    ///                           these directly (no proxy)
    ///
    /// What does NOT belong here:
    ///   - `foreign_dns` IPs — those queries are wrapped in the SS
    ///     protocol and addressed to the SS server. sslocal never
    ///     opens a raw socket to e.g. `8.8.8.8`, so a /32 exception
    ///     for it is wasted (and would actually be *harmful* if a
    ///     future code path ever did open a direct socket to it,
    ///     because that path would silently sidestep the proxy).
    #[cfg(windows)]
    async fn windows_bypass_route_ips(&self) -> Vec<IpAddr> {
        let mut route_ips = self.bypass_route_ips.clone();
        #[cfg(feature = "local-web-admin")]
        if let Some(routing_state) = self.context.routing_state() {
            for dns in routing_state.domestic_dns().await {
                if let Some(ip) = parse_dns_server_ip(&dns) {
                    route_ips.push(ip);
                }
            }
        }
        route_ips.sort_unstable();
        route_ips.dedup();
        route_ips
    }
}

#[cfg(windows)]
fn parse_dns_server_ip(value: &str) -> Option<IpAddr> {
    let value = value.trim();
    if let Ok(addr) = value.parse::<IpAddr>() {
        return Some(addr);
    }
    if let Ok(addr) = value.parse::<SocketAddr>() {
        return Some(addr.ip());
    }
    let host = value.rsplit_once(':').map_or(value, |(host, _)| host);
    host.trim_matches(['[', ']']).parse::<IpAddr>().ok()
}

#[cfg(windows)]
fn install_windows_bypass_routes(tun_name: &str, server_ips: &[IpAddr]) -> io::Result<()> {
    let route_ips = server_ips
        .iter()
        .filter(|ip| ip.is_ipv4())
        .map(|ip| format!("'{}'", ip))
        .collect::<Vec<_>>()
        .join(",");
    let script = format!(
        r#"
$ErrorActionPreference = 'Stop'
$tunName = {tun_name}
$adapter = Get-NetAdapter -Name $tunName -ErrorAction Stop
$defaultRoute = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
    Where-Object {{ $_.InterfaceIndex -ne $adapter.ifIndex -and $_.NextHop -ne '0.0.0.0' }} |
    Sort-Object RouteMetric, InterfaceMetric |
    Select-Object -First 1
if (-not $defaultRoute) {{ throw 'physical default route was not found' }}
Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
    Where-Object {{ $_.InterfaceIndex -eq $adapter.ifIndex }} |
    Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
foreach ($prefix in @('0.0.0.0/1','128.0.0.0/1')) {{
    Get-NetRoute -AddressFamily IPv4 -DestinationPrefix $prefix -ErrorAction SilentlyContinue |
        Where-Object {{ $_.InterfaceIndex -eq $adapter.ifIndex }} |
        Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
    New-NetRoute -DestinationPrefix $prefix -InterfaceIndex $adapter.ifIndex -NextHop '0.0.0.0' -RouteMetric 1 -PolicyStore ActiveStore | Out-Null
}}
foreach ($prefix in @('10.0.0.0/8','100.64.0.0/10','127.0.0.0/8','169.254.0.0/16','172.16.0.0/12','192.168.0.0/16','198.18.0.0/15')) {{
    Get-NetRoute -AddressFamily IPv4 -DestinationPrefix $prefix -ErrorAction SilentlyContinue |
        Where-Object {{ $_.InterfaceIndex -eq $defaultRoute.InterfaceIndex }} |
        Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
    New-NetRoute -DestinationPrefix $prefix -InterfaceIndex $defaultRoute.InterfaceIndex -NextHop $defaultRoute.NextHop -RouteMetric 1 -PolicyStore ActiveStore | Out-Null
}}
$defaultRouteV6 = Get-NetRoute -AddressFamily IPv6 -DestinationPrefix '::/0' -ErrorAction SilentlyContinue |
    Where-Object {{ $_.InterfaceIndex -ne $adapter.ifIndex }} |
    Sort-Object RouteMetric, InterfaceMetric |
    Select-Object -First 1
if ($defaultRouteV6) {{
    foreach ($prefix in @('fc00::/7','fe80::/10')) {{
        Get-NetRoute -AddressFamily IPv6 -DestinationPrefix $prefix -ErrorAction SilentlyContinue |
            Where-Object {{ $_.InterfaceIndex -eq $defaultRouteV6.InterfaceIndex }} |
            Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
        New-NetRoute -DestinationPrefix $prefix -InterfaceIndex $defaultRouteV6.InterfaceIndex -NextHop $defaultRouteV6.NextHop -RouteMetric 1 -PolicyStore ActiveStore | Out-Null
    }}
}}
foreach ($routeIp in @({route_ips})) {{
    if (-not $routeIp) {{ continue }}
    $prefix = "$routeIp/32"
    Get-NetRoute -AddressFamily IPv4 -DestinationPrefix $prefix -ErrorAction SilentlyContinue |
        Where-Object {{ $_.InterfaceIndex -eq $defaultRoute.InterfaceIndex }} |
        Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
    New-NetRoute -DestinationPrefix $prefix -InterfaceIndex $defaultRoute.InterfaceIndex -NextHop $defaultRoute.NextHop -RouteMetric 1 -PolicyStore ActiveStore | Out-Null
}}
if ($defaultRoute.NextHop -and $defaultRoute.NextHop -ne '0.0.0.0') {{
    $gatewayPrefix = "$($defaultRoute.NextHop)/32"
    Get-NetRoute -AddressFamily IPv4 -DestinationPrefix $gatewayPrefix -ErrorAction SilentlyContinue |
        Where-Object {{ $_.InterfaceIndex -eq $defaultRoute.InterfaceIndex }} |
        Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
    New-NetRoute -DestinationPrefix $gatewayPrefix -InterfaceIndex $defaultRoute.InterfaceIndex -NextHop $defaultRoute.NextHop -RouteMetric 1 -PolicyStore ActiveStore | Out-Null
}}
"#,
        tun_name = powershell_quote(tun_name),
        route_ips = route_ips,
    );

    let output = Command::new("powershell")
        .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", &script])
        .stdin(Stdio::null())
        .output()?;
    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        Err(io::Error::other(if stderr.is_empty() {
            format!("powershell exited with {}", output.status)
        } else {
            stderr
        }))
    }
}

#[cfg(windows)]
pub fn detect_windows_physical_interface() -> Option<String> {
    detect_windows_physical_endpoint().map(|(alias, _)| alias)
}

/// Locate the physical IPv4 default-route interface and return both its
/// `InterfaceAlias` (for `IP_UNICAST_IF`) and its first non-link-local
/// IPv4 address (for `bind_local_addr`).
///
/// We need both to plug `WSAEADDRNOTAVAIL` (`os error 10049`) on direct
/// connects from the TUN bypass path:
///
///   * `IP_UNICAST_IF` alone tells Windows *which interface* to route
///     out via, but in some scenarios (multiple TUN catch-alls, weak
///     host model interactions) the source address still gets picked
///     from the TUN adapter, and `connect()` then fails because that
///     source is not valid on the chosen interface.
///   * Setting `bind_local_addr` to the Ethernet IP forces the source
///     to a valid local address before `connect()`, so Windows' route
///     selection is consistent with the bound source.
#[cfg(windows)]
pub fn detect_windows_physical_endpoint() -> Option<(String, IpAddr)> {
    let script = r#"
$ErrorActionPreference = 'SilentlyContinue'
$defaultRoute = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' |
    Where-Object { $_.NextHop -ne '0.0.0.0' } |
    Sort-Object RouteMetric, InterfaceMetric |
    Select-Object -First 1
if (-not $defaultRoute) { exit 1 }
$adapter = Get-NetAdapter -InterfaceIndex $defaultRoute.InterfaceIndex
if (-not $adapter) { exit 1 }
$ip = Get-NetIPAddress -InterfaceIndex $defaultRoute.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.PrefixOrigin -ne 'WellKnown' -and $_.IPAddress -notlike '169.254.*' } |
    Sort-Object -Property @{Expression={ if ($_.PrefixOrigin -eq 'Dhcp') { 0 } else { 1 } }} |
    Select-Object -First 1
if (-not $ip) { exit 1 }
Write-Output ("{0}|{1}" -f $adapter.InterfaceAlias, $ip.IPAddress)
"#;
    let output = Command::new("powershell")
        .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script])
        .stdin(Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let line = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    let (alias, ip) = line.split_once('|')?;
    let alias = alias.trim().to_owned();
    let ip = ip.trim().parse::<IpAddr>().ok()?;
    if alias.is_empty() { None } else { Some((alias, ip)) }
}

#[cfg(windows)]
fn powershell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

/// Best-effort removal of every IPv4 route attached to the named TUN
/// adapter. Used by the Windows [`Drop`] impl as a last-line defence so
/// catch-all `0.0.0.0/1` + `128.0.0.0/1` routes don't survive a hard
/// kill of `sslocal.exe`. The deploy script still owns the canonical
/// cleanup (it also restores DNS and the physical adapter routes).
#[cfg(windows)]
fn remove_windows_tun_routes(tun_name: &str) -> io::Result<()> {
    let script = format!(
        r#"
$ErrorActionPreference = 'SilentlyContinue'
$tunName = {tun_name}
$adapter = Get-NetAdapter -Name $tunName -ErrorAction SilentlyContinue
if (-not $adapter) {{ exit 0 }}
Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object {{ $_.InterfaceIndex -eq $adapter.ifIndex }} |
    Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
"#,
        tun_name = powershell_quote(tun_name),
    );

    let output = Command::new("powershell")
        .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", &script])
        .stdin(Stdio::null())
        .output()?;
    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        Err(io::Error::other(if stderr.is_empty() {
            format!("powershell exited with {}", output.status)
        } else {
            stderr
        }))
    }
}
