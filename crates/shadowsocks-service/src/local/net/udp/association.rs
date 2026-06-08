//! UDP Association Managing

use std::{
    cell::RefCell,
    io,
    marker::PhantomData,
    net::{SocketAddr, SocketAddrV6},
    sync::Arc,
    time::Duration,
};

use bytes::Bytes;
use futures::future;
use log::{debug, error, trace, warn};
use lru_time_cache::LruCache;
use rand::{RngExt, rngs::SmallRng};
use tokio::{sync::mpsc, task::JoinHandle, time};

use shadowsocks::{
    config::ServerConfig,
    lookup_then,
    net::{AddrFamily, ConnectOpts, TcpStream as ShadowTcpStream, UdpSocket as ShadowUdpSocket},
    relay::{
        Address,
        udprelay::{MAXIMUM_UDP_PAYLOAD_SIZE, ProxySocket, options::UdpSocketControlData, proxy_socket::UdpSocketType},
    },
};

#[cfg(feature = "local-web-admin")]
use crate::local::routing::{ConnectionDecision, RouteDecision};
use crate::{
    local::{context::ServiceContext, loadbalancing::PingBalancer, utils::address_is_fixed_direct},
    net::{
        MonProxySocket, OutboundProxyDatagram, TcpDialer, UDP_ASSOCIATION_KEEP_ALIVE_CHANNEL_SIZE,
        UDP_ASSOCIATION_SEND_CHANNEL_SIZE, packet_window::PacketWindowFilter,
    },
};

/// Build the Proxy socket appropriate for `svr_cfg`, transparently
/// going through the configured outbound chain when one is present and
/// fully SOCKS5. Otherwise UDP uses the Direct path.
async fn create_proxy_socket(
    context: &ServiceContext,
    svr_cfg: &ServerConfig,
    connect_opts: &ConnectOpts,
) -> io::Result<ProxyRelaySocket> {
    let use_chain = context.outbound_client().map(|c| c.supports_udp()).unwrap_or(false);

    if use_chain {
        let client = context
            .outbound_client()
            .expect("outbound_client checked above")
            .clone();
        let dialer = LocalTcpDialer {
            context: Arc::new(context.clone()),
            opts: connect_opts.clone(),
        };
        let target: Address = svr_cfg.udp_external_addr().into();
        let datagram = client
            .associate_udp(&context.context(), &dialer, connect_opts, target)
            .await?;
        let proxy_socket = ProxySocket::from_socket(UdpSocketType::Client, context.context(), svr_cfg, datagram);
        let mon = MonProxySocket::from_socket(proxy_socket, context.flow_stat());
        Ok(ProxyRelaySocket::Chained(mon))
    } else {
        let socket = ProxySocket::connect_with_opts(context.context(), svr_cfg, connect_opts).await?;
        let mon = MonProxySocket::from_socket(socket, context.flow_stat());
        Ok(ProxyRelaySocket::Direct(mon))
    }
}

/// `TcpDialer` adapter that uses the local service context's connect options.
struct LocalTcpDialer {
    context: Arc<ServiceContext>,
    opts: ConnectOpts,
}

impl TcpDialer for LocalTcpDialer {
    async fn dial(&self, addr: &Address) -> io::Result<ShadowTcpStream> {
        ShadowTcpStream::connect_remote_with_opts(self.context.context_ref(), addr, &self.opts).await
    }
}

/// Proxy UDP socket, either Direct (single hop to ss-server) or routed
/// through a SOCKS5-only outbound proxy chain.
#[allow(clippy::large_enum_variant)]
enum ProxyRelaySocket {
    Direct(MonProxySocket<ShadowUdpSocket>),
    Chained(MonProxySocket<OutboundProxyDatagram>),
}

impl ProxyRelaySocket {
    async fn send_with_ctrl(&self, addr: &Address, control: &UdpSocketControlData, data: &[u8]) -> io::Result<()> {
        match self {
            Self::Direct(s) => s.send_with_ctrl(addr, control, data).await,
            Self::Chained(s) => s.send_with_ctrl(addr, control, data).await,
        }
    }

    async fn recv_with_ctrl(&self, buf: &mut [u8]) -> io::Result<(usize, Address, Option<UdpSocketControlData>)> {
        match self {
            Self::Direct(s) => s.recv_with_ctrl(buf).await,
            Self::Chained(s) => s.recv_with_ctrl(buf).await,
        }
    }
}

/// Writer for sending packets back to client
#[trait_variant::make(Send)]
pub trait UdpInboundWrite {
    /// Sends packet `data` received from `remote_addr` back to `peer_addr`
    async fn send_to(&self, peer_addr: SocketAddr, remote_addr: &Address, data: &[u8]) -> io::Result<()>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UdpAssociationKind {
    Socks5,
    Redir,
    Tun,
    Tunnel,
}

impl UdpAssociationKind {
    #[cfg(feature = "local-web-admin")]
    fn proxied_connection_decision(self) -> Option<ConnectionDecision> {
        match self {
            Self::Socks5 => Some(ConnectionDecision::Socks5Proxy),
            Self::Redir => Some(ConnectionDecision::Redir),
            Self::Tun => Some(ConnectionDecision::Tun),
            Self::Tunnel => None,
        }
    }
}

type AssociationMap<W> = LruCache<SocketAddr, UdpAssociation<W>>;

/// UDP association manager
pub struct UdpAssociationManager<W>
where
    W: UdpInboundWrite + Clone + Send + Sync + Unpin + 'static,
{
    respond_writer: W,
    context: Arc<ServiceContext>,
    assoc_map: AssociationMap<W>,
    keepalive_tx: mpsc::Sender<SocketAddr>,
    balancer: PingBalancer,
    kind: UdpAssociationKind,
    server_session_expire_duration: Duration,
}

impl<W> UdpAssociationManager<W>
where
    W: UdpInboundWrite + Clone + Send + Sync + Unpin + 'static,
{
    /// Create a new `UdpAssociationManager`
    ///
    /// Returns (`UdpAssociationManager`, Cleanup Interval, Keep-alive Receiver<SocketAddr>)
    pub fn new(
        context: Arc<ServiceContext>,
        respond_writer: W,
        time_to_live: Option<Duration>,
        capacity: Option<usize>,
        balancer: PingBalancer,
        kind: UdpAssociationKind,
    ) -> (Self, Duration, mpsc::Receiver<SocketAddr>) {
        let time_to_live = time_to_live.unwrap_or(crate::DEFAULT_UDP_EXPIRY_DURATION);
        let assoc_map = match capacity {
            Some(capacity) => LruCache::with_expiry_duration_and_capacity(time_to_live, capacity),
            None => LruCache::with_expiry_duration(time_to_live),
        };

        let (keepalive_tx, keepalive_rx) = mpsc::channel(UDP_ASSOCIATION_KEEP_ALIVE_CHANNEL_SIZE);

        (
            Self {
                respond_writer,
                context,
                assoc_map,
                keepalive_tx,
                balancer,
                kind,
                server_session_expire_duration: time_to_live,
            },
            time_to_live,
            keepalive_rx,
        )
    }

    /// Sends `data` from `peer_addr` to `target_addr`
    #[cfg_attr(not(feature = "local-fake-dns"), allow(unused_mut))]
    pub async fn send_to(&mut self, peer_addr: SocketAddr, mut target_addr: Address, data: &[u8]) -> io::Result<()> {
        #[cfg(feature = "local-fake-dns")]
        if let Some(mapped_addr) = self.context.try_map_fake_address(&target_addr).await {
            target_addr = mapped_addr;
        }

        // Check or (re)create an association

        if let Some(assoc) = self.assoc_map.get(&peer_addr) {
            return assoc.try_send((target_addr, Bytes::copy_from_slice(data)));
        }

        let assoc = UdpAssociation::new(
            self.context.clone(),
            peer_addr,
            self.keepalive_tx.clone(),
            self.balancer.clone(),
            self.kind,
            self.respond_writer.clone(),
            self.server_session_expire_duration,
        );

        debug!("created udp association for {}", peer_addr);

        assoc.try_send((target_addr, Bytes::copy_from_slice(data)))?;
        self.assoc_map.insert(peer_addr, assoc);

        Ok(())
    }

    /// Cleanup expired associations
    pub async fn cleanup_expired(&mut self) {
        self.assoc_map.iter();
    }

    /// Keep-alive association
    pub async fn keep_alive(&mut self, peer_addr: &SocketAddr) {
        self.assoc_map.get(peer_addr);
    }
}

struct UdpAssociation<W>
where
    W: UdpInboundWrite + Send + Sync + Unpin + 'static,
{
    assoc_handle: JoinHandle<()>,
    sender: mpsc::Sender<(Address, Bytes)>,
    writer: PhantomData<W>,
}

impl<W> Drop for UdpAssociation<W>
where
    W: UdpInboundWrite + Send + Sync + Unpin + 'static,
{
    fn drop(&mut self) {
        self.assoc_handle.abort();
    }
}

impl<W> UdpAssociation<W>
where
    W: UdpInboundWrite + Send + Sync + Unpin + 'static,
{
    fn new(
        context: Arc<ServiceContext>,
        peer_addr: SocketAddr,
        keepalive_tx: mpsc::Sender<SocketAddr>,
        balancer: PingBalancer,
        kind: UdpAssociationKind,
        respond_writer: W,
        server_session_expire_duration: Duration,
    ) -> Self {
        let (assoc_handle, sender) = UdpAssociationContext::create(
            context,
            peer_addr,
            keepalive_tx,
            balancer,
            kind,
            respond_writer,
            server_session_expire_duration,
        );
        Self {
            assoc_handle,
            sender,
            writer: PhantomData,
        }
    }

    fn try_send(&self, data: (Address, Bytes)) -> io::Result<()> {
        if self.sender.try_send(data).is_err() {
            let err = io::Error::other("udp relay channel full");
            return Err(err);
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct ServerContext {
    packet_window_filter: PacketWindowFilter,
}

#[derive(Clone)]
struct ServerSessionContext {
    server_session_map: LruCache<u64, ServerContext>,
}

impl ServerSessionContext {
    fn new(session_expire_duration: Duration) -> Self {
        Self {
            server_session_map: LruCache::with_expiry_duration(session_expire_duration),
        }
    }
}

struct UdpAssociationContext<W>
where
    W: UdpInboundWrite + Send + Sync + Unpin + 'static,
{
    context: Arc<ServiceContext>,
    peer_addr: SocketAddr,
    direct_ipv4_socket: Option<ShadowUdpSocket>,
    direct_ipv6_socket: Option<ShadowUdpSocket>,
    proxy_socket: Option<ProxyRelaySocket>,
    keepalive_tx: mpsc::Sender<SocketAddr>,
    keepalive_flag: bool,
    balancer: PingBalancer,
    kind: UdpAssociationKind,
    respond_writer: W,
    client_session_id: u64,
    client_packet_id: u64,
    server_session: Option<ServerSessionContext>,
    server_session_expire_duration: Duration,
}

impl<W> Drop for UdpAssociationContext<W>
where
    W: UdpInboundWrite + Send + Sync + Unpin + 'static,
{
    fn drop(&mut self) {
        debug!("udp association for {} is closed", self.peer_addr);
    }
}

thread_local! {
    static CLIENT_SESSION_RNG: RefCell<SmallRng> = RefCell::new(rand::make_rng());
}

/// Generate an AEAD-2022 Client SessionID
#[inline]
pub fn generate_client_session_id() -> u64 {
    loop {
        let id = CLIENT_SESSION_RNG.with(|rng| rng.borrow_mut().random());
        if id != 0 {
            break id;
        }
    }
}

impl<W> UdpAssociationContext<W>
where
    W: UdpInboundWrite + Send + Sync + Unpin + 'static,
{
    fn create(
        context: Arc<ServiceContext>,
        peer_addr: SocketAddr,
        keepalive_tx: mpsc::Sender<SocketAddr>,
        balancer: PingBalancer,
        kind: UdpAssociationKind,
        respond_writer: W,
        server_session_expire_duration: Duration,
    ) -> (JoinHandle<()>, mpsc::Sender<(Address, Bytes)>) {
        // Pending packets UDP_ASSOCIATION_SEND_CHANNEL_SIZE for each association should be good enough for a server.
        // If there are plenty of packets stuck in the channel, dropping excessive packets is a good way to protect the server from
        // being OOM.
        let (sender, receiver) = mpsc::channel(UDP_ASSOCIATION_SEND_CHANNEL_SIZE);

        let mut assoc = Self {
            context,
            peer_addr,
            direct_ipv4_socket: None,
            direct_ipv6_socket: None,
            proxy_socket: None,
            keepalive_tx,
            keepalive_flag: false,
            balancer,
            kind,
            respond_writer,
            // client_session_id must be random generated,
            // server use this ID to identify every independent clients.
            client_session_id: generate_client_session_id(),
            client_packet_id: 0,
            server_session: None,
            server_session_expire_duration,
        };
        let handle = tokio::spawn(async move { assoc.dispatch_packet(receiver).await });

        (handle, sender)
    }

    async fn dispatch_packet(&mut self, mut receiver: mpsc::Receiver<(Address, Bytes)>) {
        let mut direct_ipv4_buffer = Vec::new();
        let mut direct_ipv6_buffer = Vec::new();
        let mut proxy_buffer = Vec::new();
        let mut keepalive_interval = time::interval(Duration::from_secs(1));

        loop {
            tokio::select! {
                packet_received_opt = receiver.recv() => {
                    let (target_addr, data) = match packet_received_opt {
                        Some(d) => d,
                        None => {
                            trace!("udp association for {} -> ... channel closed", self.peer_addr);
                            break;
                        }
                    };

                    self.dispatch_received_packet(&target_addr, &data).await;
                }

                received_opt = receive_from_direct_opt(&self.direct_ipv4_socket, &mut direct_ipv4_buffer), if self.direct_ipv4_socket.is_some() => {
                    let (n, addr) = match received_opt {
                        Ok(r) => r,
                        Err(err) => {
                            error!("udp relay {} <- ... (Direct) failed, error: {}", self.peer_addr, err);
                            // Socket failure. Reset for recreation.
                            self.direct_ipv4_socket = None;
                            continue;
                        }
                    };

                    let addr = Address::from(addr);
                    self.send_received_respond_packet(&addr, &direct_ipv4_buffer[..n], true).await;
                }

                received_opt = receive_from_direct_opt(&self.direct_ipv6_socket, &mut direct_ipv6_buffer), if self.direct_ipv6_socket.is_some() => {
                    let (n, addr) = match received_opt {
                        Ok(r) => r,
                        Err(err) => {
                            error!("udp relay {} <- ... (Direct) failed, error: {}", self.peer_addr, err);
                            // Socket failure. Reset for recreation.
                            self.direct_ipv6_socket = None;
                            continue;
                        }
                    };

                    let addr = Address::from(addr);
                    self.send_received_respond_packet(&addr, &direct_ipv6_buffer[..n], true).await;
                }

                received_opt = receive_from_proxy_opt(&self.proxy_socket, &mut proxy_buffer), if self.proxy_socket.is_some() => {
                    let (n, addr, control_opt) = match received_opt {
                        Ok(r) => r,
                        Err(err) => {
                            error!("udp relay {} <- ... (Proxy) failed, error: {}", self.peer_addr, err);
                            // Socket failure. Reset for recreation.
                            self.proxy_socket = None;
                            continue;
                        }
                    };

                    if let Some(control) = control_opt {
                        // Check if Packet ID is in the window

                        let session = self.server_session.get_or_insert_with(|| {
                            ServerSessionContext::new(self.server_session_expire_duration)
                        });

                        let packet_id = control.packet_id;
                        let session_context = session
                            .server_session_map
                            .entry(control.server_session_id)
                            .or_insert_with(|| {
                                trace!(
                                    "udp server with session {} for {} created",
                                    control.client_session_id,
                                    self.peer_addr,
                                );

                                ServerContext {
                                    packet_window_filter: PacketWindowFilter::new()
                                }
                            });

                        if !session_context.packet_window_filter.validate_packet_id(packet_id, u64::MAX) {
                            error!("udp {} packet_id {} out of window", self.peer_addr, packet_id);
                            continue;
                        }
                    }

                    self.send_received_respond_packet(&addr, &proxy_buffer[..n], false).await;
                }

                _ = keepalive_interval.tick() => {
                    if self.keepalive_flag {
                        if self.keepalive_tx.try_send(self.peer_addr).is_err() {
                            debug!("udp relay {} keep-alive failed, channel full or closed", self.peer_addr);
                        } else {
                            self.keepalive_flag = false;
                        }
                    }
                }
            }
        }

        #[inline]
        async fn receive_from_direct_opt(
            socket: &Option<ShadowUdpSocket>,
            buf: &mut Vec<u8>,
        ) -> io::Result<(usize, SocketAddr)> {
            match *socket {
                None => future::pending().await,
                Some(ref s) => {
                    if buf.is_empty() {
                        buf.resize(MAXIMUM_UDP_PAYLOAD_SIZE, 0);
                    }
                    s.recv_from(buf).await
                }
            }
        }

        #[inline]
        async fn receive_from_proxy_opt(
            socket: &Option<ProxyRelaySocket>,
            buf: &mut Vec<u8>,
        ) -> io::Result<(usize, Address, Option<UdpSocketControlData>)> {
            match *socket {
                None => future::pending().await,
                Some(ref s) => {
                    if buf.is_empty() {
                        buf.resize(MAXIMUM_UDP_PAYLOAD_SIZE, 0);
                    }
                    s.recv_with_ctrl(buf).await
                }
            }
        }
    }

    async fn dispatch_received_packet(&mut self, target_addr: &Address, data: &[u8]) {
        let direct = self.target_should_dispatch_direct(target_addr).await;

        #[cfg(feature = "local-web-admin")]
        if let Some(routing_state) = self.context.routing_state() {
            if let Some(decision) = self.connection_decision(target_addr, direct) {
                routing_state
                    .record_connection(self.peer_addr, target_addr, "udp", decision)
                    .await;
            }
        }

        trace!(
            "udp relay {} -> {} ({}) with {} bytes",
            self.peer_addr,
            target_addr,
            if direct { "Direct" } else { "Proxy" },
            data.len()
        );

        if direct {
            if let Err(err) = self.dispatch_received_direct_packet(target_addr, data).await {
                error!(
                    "udp relay {} -> {} (Direct) with {} bytes, error: {}",
                    self.peer_addr,
                    target_addr,
                    data.len(),
                    err
                );
            }
        } else if let Err(err) = self.dispatch_received_proxy_packet(target_addr, data).await {
            error!(
                "udp relay {} -> {} (Proxy) with {} bytes, error: {}",
                self.peer_addr,
                target_addr,
                data.len(),
                err
            );
        }
    }

    async fn target_should_dispatch_direct(&self, target_addr: &Address) -> bool {
        if self.balancer.is_empty() {
            return true;
        }

        match self.kind {
            UdpAssociationKind::Socks5 => address_is_fixed_direct(target_addr),
            UdpAssociationKind::Redir | UdpAssociationKind::Tun | UdpAssociationKind::Tunnel => {
                self.route_target_is_direct(target_addr).await
            }
        }
    }

    #[cfg(feature = "local-web-admin")]
    fn connection_decision(&self, target_addr: &Address, direct: bool) -> Option<ConnectionDecision> {
        match self.kind {
            UdpAssociationKind::Socks5 => Some(if direct {
                ConnectionDecision::Direct
            } else {
                ConnectionDecision::Socks5Proxy
            }),
            UdpAssociationKind::Redir | UdpAssociationKind::Tun => {
                if address_is_fixed_direct(target_addr) {
                    Some(ConnectionDecision::Direct)
                } else {
                    self.kind.proxied_connection_decision()
                }
            }
            UdpAssociationKind::Tunnel => None,
        }
    }

    async fn route_target_is_direct(&self, target_addr: &Address) -> bool {
        #[cfg(feature = "local-web-admin")]
        {
            matches!(self.context.route_target(target_addr).await, RouteDecision::Direct)
        }
        #[cfg(not(feature = "local-web-admin"))]
        {
            self.context.target_is_direct_by_acl(target_addr).await
        }
    }

    async fn dispatch_received_direct_packet(&mut self, target_addr: &Address, data: &[u8]) -> io::Result<()> {
        match *target_addr {
            Address::SocketAddress(sa) => self.send_received_direct_packet(sa, data).await,
            Address::DomainNameAddress(ref dname, port) => {
                lookup_then!(self.context.context_ref(), dname, port, |sa| {
                    self.send_received_direct_packet(sa, data).await
                })
                .map(|_| ())
            }
        }
    }

    async fn send_received_direct_packet(&mut self, mut target_addr: SocketAddr, data: &[u8]) -> io::Result<()> {
        const UDP_SOCKET_SUPPORT_DUAL_STACK: bool = cfg!(any(
            target_os = "linux",
            target_os = "android",
            target_os = "macos",
            target_os = "ios",
            target_os = "watchos",
            target_os = "tvos",
            target_os = "freebsd",
            target_os = "windows",
        ));

        let socket = if UDP_SOCKET_SUPPORT_DUAL_STACK {
            match self.direct_ipv6_socket {
                Some(ref mut socket) => socket,
                None => {
                    let socket =
                        ShadowUdpSocket::connect_any_with_opts(AddrFamily::Ipv6, self.context.connect_opts_ref())
                            .await?;
                    self.direct_ipv6_socket.insert(socket)
                }
            }
        } else {
            match target_addr {
                SocketAddr::V4(..) => match self.direct_ipv4_socket {
                    Some(ref mut socket) => socket,
                    None => {
                        let socket =
                            ShadowUdpSocket::connect_any_with_opts(&target_addr, self.context.connect_opts_ref())
                                .await?;
                        self.direct_ipv4_socket.insert(socket)
                    }
                },
                SocketAddr::V6(..) => match self.direct_ipv6_socket {
                    Some(ref mut socket) => socket,
                    None => {
                        let socket =
                            ShadowUdpSocket::connect_any_with_opts(&target_addr, self.context.connect_opts_ref())
                                .await?;
                        self.direct_ipv6_socket.insert(socket)
                    }
                },
            }
        };

        if UDP_SOCKET_SUPPORT_DUAL_STACK && let SocketAddr::V4(saddr) = target_addr {
            let mapped_ip = saddr.ip().to_ipv6_mapped();
            target_addr = SocketAddr::V6(SocketAddrV6::new(mapped_ip, saddr.port(), 0, 0));
        }

        let n = socket.send_to(data, target_addr).await?;
        if n != data.len() {
            warn!(
                "{} -> {} sent {} bytes != expected {} bytes",
                self.peer_addr,
                target_addr,
                n,
                data.len()
            );
        }

        Ok(())
    }

    async fn dispatch_received_proxy_packet(&mut self, target_addr: &Address, data: &[u8]) -> io::Result<()> {
        // Increase Packet ID before send
        self.client_packet_id = match self.client_packet_id.checked_add(1) {
            Some(i) => i,
            None => {
                // FIXME: client_packet_id overflowed. What's the proper way to handle this?
                //
                // Reopen a new session is not perfect, because the remote target will receive packets from a different address.
                // For most application protocol, like QUIC, it is fine to change client address.
                //
                // But it will happen only when a client continuously send 18446744073709551616 packets without renewing the socket.

                let new_session_id = generate_client_session_id();

                warn!(
                    "{} -> {} (Proxy) packet id overflowed. socket reset and session renewed ({} -> {})",
                    self.peer_addr, target_addr, self.client_session_id, new_session_id
                );

                self.proxy_socket.take();
                self.client_packet_id = 1;
                self.client_session_id = new_session_id;

                self.client_packet_id
            }
        };

        let socket = match self.proxy_socket {
            Some(ref mut socket) => socket,
            None => {
                // Create a new connection to proxy server
                let server = self.balancer.best_udp_server();
                let svr_cfg = server.server_config();

                let proxy = create_proxy_socket(self.context.as_ref(), svr_cfg, server.connect_opts_ref()).await?;

                self.proxy_socket.insert(proxy)
            }
        };

        let mut control = UdpSocketControlData::default();
        control.client_session_id = self.client_session_id;
        control.packet_id = self.client_packet_id;

        match socket.send_with_ctrl(target_addr, &control, data).await {
            Ok(..) => return Ok(()),
            Err(err) => {
                debug!(
                    "{} -> {} (Proxy) sending {} bytes failed, error: {}",
                    self.peer_addr,
                    target_addr,
                    data.len(),
                    err
                );

                // Drop the socket and reconnect to another server.
                self.proxy_socket = None;
            }
        }

        Ok(())
    }

    async fn send_received_respond_packet(&mut self, addr: &Address, data: &[u8], direct: bool) {
        trace!(
            "udp relay {} <- {} ({}) received {} bytes",
            self.peer_addr,
            addr,
            if direct { "Direct" } else { "Proxy" },
            data.len(),
        );

        // Keep association alive in map
        self.keepalive_flag = true;

        // Send back to client
        match self.respond_writer.send_to(self.peer_addr, addr, data).await {
            Err(err) => {
                warn!(
                    "udp failed to send back {} bytes to client {}, from target {} ({}), error: {}",
                    data.len(),
                    self.peer_addr,
                    addr,
                    if direct { "Direct" } else { "Proxy" },
                    err
                );
            }
            Ok(..) => {
                trace!(
                    "udp relay {} <- {} ({}) with {} bytes",
                    self.peer_addr,
                    addr,
                    if direct { "Direct" } else { "Proxy" },
                    data.len()
                );
            }
        }
    }
}
