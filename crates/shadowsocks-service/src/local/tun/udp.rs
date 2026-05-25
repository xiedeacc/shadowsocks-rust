use std::{
    io::{self, ErrorKind},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use bytes::{BufMut, BytesMut};
use etherparse::PacketBuilder;
use log::debug;
use shadowsocks::relay::socks5::Address;
use tokio::{net::UdpSocket, sync::mpsc, time};

use crate::{
    local::{
        context::ServiceContext,
        loadbalancing::PingBalancer,
        net::{UdpAssociationManager, UdpInboundWrite},
    },
    net::utils::to_ipv4_mapped,
};

pub struct UdpTun {
    context: Arc<ServiceContext>,
    tun_rx: mpsc::Receiver<BytesMut>,
    writer: UdpTunInboundWriter,
    manager: UdpAssociationManager<UdpTunInboundWriter>,
}

impl UdpTun {
    pub fn new(
        context: Arc<ServiceContext>,
        balancer: PingBalancer,
        time_to_live: Option<Duration>,
        capacity: Option<usize>,
    ) -> (Self, Duration, mpsc::Receiver<SocketAddr>) {
        let (tun_tx, tun_rx) = mpsc::channel(64);
        let writer = UdpTunInboundWriter::new(tun_tx);
        let (manager, cleanup_interval, keepalive_rx) =
            UdpAssociationManager::new(context.clone(), writer.clone(), time_to_live, capacity, balancer);

        (
            Self {
                context,
                tun_rx,
                writer,
                manager,
            },
            cleanup_interval,
            keepalive_rx,
        )
    }

    pub async fn handle_packet(
        &mut self,
        src_addr: SocketAddr,
        dst_addr: SocketAddr,
        payload: &[u8],
    ) -> io::Result<()> {
        debug!("UDP {} -> {} payload.size: {} bytes", src_addr, dst_addr, payload.len());
        #[cfg(feature = "local-web-admin")]
        if dst_addr.port() == 53
            && let Some(routing_state) = self.context.routing_state()
            && let Some(target) = routing_state.dns_tun_intercept_target().await
        {
            if let Err(err) = self.handle_dns_packet(src_addr, dst_addr, target, payload).await {
                debug!("TUN DNS interception failed, fallback to UDP relay: {}", err);
            } else {
                return Ok(());
            }
        }

        if let Err(err) = self.manager.send_to(src_addr, dst_addr.into(), payload).await {
            debug!(
                "UDP {} -> {} payload.size: {} bytes failed, error: {}",
                src_addr,
                dst_addr,
                payload.len(),
                err,
            );
        }
        Ok(())
    }

    #[cfg(feature = "local-web-admin")]
    async fn handle_dns_packet(
        &self,
        src_addr: SocketAddr,
        original_dst_addr: SocketAddr,
        dns_listener_addr: SocketAddr,
        payload: &[u8],
    ) -> io::Result<()> {
        let bind_addr = match dns_listener_addr {
            SocketAddr::V4(..) => "0.0.0.0:0",
            SocketAddr::V6(..) => "[::]:0",
        };
        let dns_listener_addr = match dns_listener_addr {
            SocketAddr::V4(addr) if addr.ip().is_unspecified() => {
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), addr.port())
            }
            SocketAddr::V6(addr) if addr.ip().is_unspecified() => {
                SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), addr.port())
            }
            addr => addr,
        };
        let socket = UdpSocket::bind(bind_addr).await?;
        socket.send_to(payload, dns_listener_addr).await?;

        let mut response = vec![0u8; 4096];
        let (n, _) = time::timeout(Duration::from_secs(5), socket.recv_from(&mut response))
            .await
            .map_err(|_| io::Error::new(ErrorKind::TimedOut, "TUN DNS query timed out"))??;
        response.truncate(n);
        self.writer
            .send_to(src_addr, &original_dst_addr.into(), &response)
            .await
    }

    #[cfg(not(feature = "local-web-admin"))]
    async fn handle_dns_packet(
        &self,
        _src_addr: SocketAddr,
        _original_dst_addr: SocketAddr,
        _dns_listener_addr: SocketAddr,
        _payload: &[u8],
    ) -> io::Result<()> {
        Err(io::Error::other("local-web-admin disabled"))
    }

    pub async fn recv_packet(&mut self) -> BytesMut {
        match self.tun_rx.recv().await {
            Some(b) => b,
            None => unreachable!("channel closed unexpectedly"),
        }
    }

    #[inline(always)]
    pub async fn cleanup_expired(&mut self) {
        self.manager.cleanup_expired().await;
    }

    #[inline(always)]
    pub async fn keep_alive(&mut self, peer_addr: &SocketAddr) {
        self.manager.keep_alive(peer_addr).await;
    }
}

#[derive(Clone)]
struct UdpTunInboundWriter {
    tun_tx: mpsc::Sender<BytesMut>,
}

impl UdpTunInboundWriter {
    fn new(tun_tx: mpsc::Sender<BytesMut>) -> Self {
        Self { tun_tx }
    }
}

impl UdpInboundWrite for UdpTunInboundWriter {
    async fn send_to(&self, peer_addr: SocketAddr, remote_addr: &Address, data: &[u8]) -> io::Result<()> {
        let addr = match *remote_addr {
            Address::SocketAddress(sa) => {
                // Try to convert IPv4 mapped IPv6 address if server is running on dual-stack mode
                match (peer_addr, sa) {
                    (SocketAddr::V4(..), SocketAddr::V4(..)) | (SocketAddr::V6(..), SocketAddr::V6(..)) => sa,
                    (SocketAddr::V4(..), SocketAddr::V6(v6)) => {
                        // If peer is IPv4, then remote_addr can only be IPv4-mapped-IPv6
                        match to_ipv4_mapped(v6.ip()) {
                            Some(v4) => SocketAddr::new(IpAddr::from(v4), v6.port()),
                            None => {
                                return Err(io::Error::new(
                                    ErrorKind::InvalidData,
                                    "source and destination type unmatch",
                                ));
                            }
                        }
                    }
                    (SocketAddr::V6(..), SocketAddr::V4(v4)) => {
                        // Convert remote_addr to IPv4-mapped-IPv6
                        SocketAddr::new(IpAddr::from(v4.ip().to_ipv6_mapped()), v4.port())
                    }
                }
            }
            Address::DomainNameAddress(..) => {
                let err = io::Error::new(
                    ErrorKind::InvalidInput,
                    "tun destination must not be an domain name address",
                );
                return Err(err);
            }
        };

        let packet = match (peer_addr, addr) {
            (SocketAddr::V4(peer), SocketAddr::V4(remote)) => {
                let builder =
                    PacketBuilder::ipv4(remote.ip().octets(), peer.ip().octets(), 20).udp(remote.port(), peer.port());

                let packet = BytesMut::with_capacity(builder.size(data.len()));
                let mut packet_writer = packet.writer();
                builder.write(&mut packet_writer, data).expect("PacketBuilder::write");

                packet_writer.into_inner()
            }
            (SocketAddr::V6(peer), SocketAddr::V6(remote)) => {
                let builder =
                    PacketBuilder::ipv6(remote.ip().octets(), peer.ip().octets(), 20).udp(remote.port(), peer.port());

                let packet = BytesMut::with_capacity(builder.size(data.len()));
                let mut packet_writer = packet.writer();
                builder.write(&mut packet_writer, data).expect("PacketBuilder::write");

                packet_writer.into_inner()
            }
            _ => {
                return Err(io::Error::new(
                    ErrorKind::InvalidData,
                    "source and destination type unmatch",
                ));
            }
        };

        self.tun_tx.send(packet).await.expect("tun_tx::send");
        Ok(())
    }
}
