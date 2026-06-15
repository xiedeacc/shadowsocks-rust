//! Shadowsocks Local Utilities

use std::{
    io,
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use log::{debug, trace};
use shadowsocks::{
    config::ServerConfig,
    relay::{socks5::Address, tcprelay::utils::copy_encrypted_bidirectional},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, copy_bidirectional},
    time,
};

use crate::local::net::AutoProxyIo;

pub(crate) fn is_fixed_direct_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let octets = ip.octets();
            octets[0] == 0
                || octets[0] == 10
                || (octets[0] == 100 && (64..=127).contains(&octets[1]))
                || octets[0] == 127
                || (octets[0] == 169 && octets[1] == 254)
                || (octets[0] == 172 && (16..=31).contains(&octets[1]))
                || (octets[0] == 192 && octets[1] == 168)
                || (octets[0] == 198 && (18..=19).contains(&octets[1]))
                || octets[0] >= 224
        }
        IpAddr::V6(ip) => {
            ip.is_unspecified()
                || ip.is_loopback()
                || (ip.segments()[0] & 0xfe00) == 0xfc00
                || (ip.segments()[0] & 0xffc0) == 0xfe80
                || (ip.segments()[0] & 0xff00) == 0xff00
        }
    }
}

pub(crate) fn address_is_fixed_direct(addr: &Address) -> bool {
    match addr {
        Address::SocketAddress(addr) => is_fixed_direct_ip(&addr.ip()),
        Address::DomainNameAddress(..) => false,
    }
}

pub(crate) async fn establish_tcp_tunnel<P, S>(
    svr_cfg: &ServerConfig,
    plain: &mut P,
    shadow: &mut S,
    peer_addr: SocketAddr,
    target_addr: &Address,
) -> io::Result<()>
where
    P: AsyncRead + AsyncWrite + Unpin,
    S: AsyncRead + AsyncWrite + AutoProxyIo + Unpin,
{
    if shadow.is_proxied() {
        debug!(
            "established tcp tunnel {} <-> {} through server {} (outbound: {})",
            peer_addr,
            target_addr,
            svr_cfg.tcp_external_addr(),
            svr_cfg.addr(),
        );
    } else {
        return establish_tcp_tunnel_bypassed(plain, shadow, peer_addr, target_addr).await;
    }

    // https://github.com/shadowsocks/shadowsocks-rust/issues/232
    //
    // Protocols like FTP, clients will wait for servers to send Welcome Message without sending anything.
    //
    // Wait at most 500ms, and then sends handshake packet to remote servers.
    {
        let mut buffer = [0u8; 8192];
        match time::timeout(Duration::from_millis(500), plain.read(&mut buffer)).await {
            Ok(Ok(0)) => {
                // EOF. Just terminate right here.
                return Ok(());
            }
            Ok(Ok(n)) => {
                // Send the first packet.
                shadow.write_all(&buffer[..n]).await?;
            }
            Ok(Err(err)) => return Err(err),
            Err(..) => {
                // Timeout. Send handshake to server.
                let _ = shadow.write(&[]).await?;

                trace!(
                    "tcp tunnel {} -> {} (Proxy) sent handshake without data",
                    peer_addr, target_addr
                );
            }
        }
    }

    match copy_encrypted_bidirectional(svr_cfg.method(), shadow, plain).await {
        Ok((wn, rn)) => {
            trace!(
                "tcp tunnel {} <-> {} (Proxy) closed, L2R {} bytes, R2L {} bytes",
                peer_addr, target_addr, rn, wn
            );
        }
        Err(err) => {
            trace!(
                "tcp tunnel {} <-> {} (Proxy) closed with error: {}",
                peer_addr, target_addr, err
            );
        }
    }

    Ok(())
}

pub(crate) async fn establish_tcp_tunnel_bypassed<P, S>(
    plain: &mut P,
    shadow: &mut S,
    peer_addr: SocketAddr,
    target_addr: &Address,
) -> io::Result<()>
where
    P: AsyncRead + AsyncWrite + Unpin,
    S: AsyncRead + AsyncWrite + Unpin,
{
    debug!("established tcp tunnel {} <-> {} Direct", peer_addr, target_addr);

    match copy_bidirectional(plain, shadow).await {
        Ok((rn, wn)) => {
            trace!(
                "tcp tunnel {} <-> {} (Direct) closed, L2R {} bytes, R2L {} bytes",
                peer_addr, target_addr, rn, wn
            );
        }
        Err(err) => {
            trace!(
                "tcp tunnel {} <-> {} (Direct) closed with error: {}",
                peer_addr, target_addr, err
            );
        }
    }

    Ok(())
}
