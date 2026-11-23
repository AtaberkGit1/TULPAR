//! OS socket protection (Android `VpnService.protect` / iOS non-tunnel binding).

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::{TcpSocket, TcpStream, UdpSocket};
use yolac_dns::upstream::{BoxFuture, UpstreamDialer};

/// Implemented by platform integrations (e.g. Android JNI calling `VpnService.protect(fd)`).
pub trait SocketProtector: Send + Sync {
    fn protect_fd(&self, fd: i32) -> io::Result<()>;
}

pub struct NoopProtector;

impl SocketProtector for NoopProtector {
    fn protect_fd(&self, _fd: i32) -> io::Result<()> {
        Ok(())
    }
}

/// Opens a TCP connection whose underlying socket FD is protected before `connect()`.
pub async fn connect_protected_tcp(
    addr: SocketAddr,
    protector: &dyn SocketProtector,
) -> io::Result<TcpStream> {
    let socket = match addr {
        SocketAddr::V4(_) => TcpSocket::new_v4()?,
        SocketAddr::V6(_) => TcpSocket::new_v6()?,
    };
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        protector.protect_fd(socket.as_raw_fd())?;
    }
    #[cfg(not(unix))]
    {
        let _ = protector;
    }

    let stream = socket.connect(addr).await?;
    let _ = stream.set_nodelay(true);
    Ok(stream)
}

/// Opens an ephemeral UDP socket whose FD is protected from VPN routing loops.
pub async fn bind_protected_udp(
    is_v6: bool,
    protector: &dyn SocketProtector,
) -> io::Result<UdpSocket> {
    let bind_addr: SocketAddr = if is_v6 {
        "[::]:0".parse().expect("valid v6 addr")
    } else {
        "0.0.0.0:0".parse().expect("valid v4 addr")
    };
    let sock = UdpSocket::bind(bind_addr).await?;
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        protector.protect_fd(sock.as_raw_fd())?;
    }
    #[cfg(not(unix))]
    {
        let _ = protector;
    }
    Ok(sock)
}

/// `yolac_dns::upstream::UpstreamDialer` backed by `SocketProtector` so encrypted DNS
/// sockets never loop back into the device TUN interface.
pub struct ProtectedDialer {
    protector: Arc<dyn SocketProtector>,
}

impl ProtectedDialer {
    pub fn new(protector: Arc<dyn SocketProtector>) -> Self {
        Self { protector }
    }
}

impl UpstreamDialer for ProtectedDialer {
    fn connect(&self, addr: SocketAddr) -> BoxFuture<'_, io::Result<TcpStream>> {
        Box::pin(async move { connect_protected_tcp(addr, self.protector.as_ref()).await })
    }
}
