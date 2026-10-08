//! Noticing a client that vanished without closing its connection.
//!
//! A client whose network went away (Wi-Fi dropped, laptop asleep, a new
//! address) sends no FIN or RST, so the server's side of the connection stays
//! open. With the OS defaults it stays open for minutes while unacknowledged
//! data is retransmitted, and for hours on an idle link before keepalive
//! probes start. Meanwhile [`RdpServer::run`](crate::RdpServer::run) keeps
//! serving the dead connection, and a reconnecting client waits behind it.

use core::time::Duration;
use std::io;

use socket2::{SockRef, TcpKeepalive};
use tokio::net::TcpStream;

/// Keepalive probes an idle connection gets before it counts as dead.
const KEEPALIVE_PROBES: u32 = 3;
const SHORTEST: Duration = Duration::from_secs(1);

/// Has the OS drop `stream` once its peer has stopped answering for about
/// `timeout`: keepalive probes over the second half of it on an idle link,
/// and, while data is in flight, a limit on how long retransmissions may fail,
/// which keepalive does not cover.
pub(crate) fn drop_after_silence(stream: &TcpStream, timeout: Duration) -> io::Result<()> {
    let socket = SockRef::from(stream);
    let half = (timeout / 2).max(SHORTEST);
    let keepalive = TcpKeepalive::new()
        .with_time(half)
        .with_interval((half / KEEPALIVE_PROBES).max(SHORTEST))
        .with_retries(KEEPALIVE_PROBES);
    socket.set_tcp_keepalive(&keepalive)?;
    #[cfg(any(target_os = "linux", target_os = "android", target_os = "fuchsia"))]
    socket.set_tcp_user_timeout(Some(timeout.max(SHORTEST)))?;
    #[cfg(target_vendor = "apple")]
    drop_after_failed_retransmissions(stream, timeout)?;
    Ok(())
}

/// `TCP_RXT_CONNDROPTIME`, the Apple counterpart of Linux's `TCP_USER_TIMEOUT`.
#[cfg(target_vendor = "apple")]
fn drop_after_failed_retransmissions(stream: &TcpStream, timeout: Duration) -> io::Result<()> {
    use std::os::fd::AsRawFd as _;

    /// From <netinet/tcp.h>: seconds of failing retransmissions after which
    /// the connection is dropped. The libc crate does not define it.
    const TCP_RXT_CONNDROPTIME: libc::c_int = 0x80;

    let seconds = libc::c_int::try_from(timeout.max(SHORTEST).as_secs()).unwrap_or(libc::c_int::MAX);
    let len = libc::socklen_t::try_from(size_of::<libc::c_int>()).expect("an int's size fits a socklen_t");
    // SAFETY: the descriptor belongs to `stream`, which outlives the call, and
    // the value points at an int of the length given.
    let status = unsafe {
        libc::setsockopt(
            stream.as_raw_fd(),
            libc::IPPROTO_TCP,
            TCP_RXT_CONNDROPTIME,
            (&raw const seconds).cast(),
            len,
        )
    };
    if status == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn an_accepted_connection_gets_keepalive_and_a_retransmission_limit() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("address");
        let _client = TcpStream::connect(addr).await.expect("connect");
        let (stream, _) = listener.accept().await.expect("accept");

        drop_after_silence(&stream, Duration::from_secs(30)).expect("configured");

        let socket = SockRef::from(&stream);
        assert!(socket.keepalive().expect("SO_KEEPALIVE"));
        assert_eq!(socket.tcp_keepalive_time().expect("idle"), Duration::from_secs(15));
        assert_eq!(socket.tcp_keepalive_interval().expect("interval"), Duration::from_secs(5));
        assert_eq!(socket.tcp_keepalive_retries().expect("probes"), KEEPALIVE_PROBES);
        #[cfg(target_vendor = "apple")]
        {
            use std::os::fd::AsRawFd as _;

            let mut seconds: libc::c_int = 0;
            let mut len = libc::socklen_t::try_from(size_of::<libc::c_int>()).expect("fits");
            // SAFETY: the descriptor belongs to `stream`, and `seconds` and
            // `len` are valid for writes of the sizes given.
            let status = unsafe {
                libc::getsockopt(
                    stream.as_raw_fd(),
                    libc::IPPROTO_TCP,
                    0x80,
                    (&raw mut seconds).cast(),
                    &raw mut len,
                )
            };
            assert_eq!(status, 0);
            assert_eq!(seconds, 30);
        }
    }
}
