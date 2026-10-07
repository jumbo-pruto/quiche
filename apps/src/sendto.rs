// Copyright (C) 2021, Cloudflare, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright notice,
//       this list of conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use std::cmp;

use std::io;

use std::net::SocketAddr;

/// For Linux, try to detect GSO is available.
#[cfg(target_os = "linux")]
pub fn detect_gso(socket: &mio::net::UdpSocket, segment_size: usize) -> bool {
    use nix::sys::socket::setsockopt;
    use nix::sys::socket::sockopt::UdpGsoSegment;
    use std::os::unix::io::AsFd;

    setsockopt(&socket.as_fd(), UdpGsoSegment, &(segment_size as i32)).is_ok()
}

/// For non-Linux, there is no GSO support.
#[cfg(not(target_os = "linux"))]
pub fn detect_gso(_socket: &mio::net::UdpSocket, _segment_size: usize) -> bool {
    false
}

/// Send packets using sendmsg() with GSO.
#[cfg(target_os = "linux")]
fn send_to_gso_pacing(
    socket: &mio::net::UdpSocket, buf: &[u8], send_info: &quiche::SendInfo,
    segment_size: usize,
) -> io::Result<usize> {
    use nix::sys::socket::sendmsg;
    use nix::sys::socket::ControlMessage;
    use nix::sys::socket::MsgFlags;
    use nix::sys::socket::SockaddrStorage;
    use std::io::IoSlice;
    use std::os::unix::io::AsRawFd;

    let iov = [IoSlice::new(buf)];
    let segment_size = segment_size as u16;
    let dst = SockaddrStorage::from(send_info.to);
    let sockfd = socket.as_raw_fd();

    // GSO option.
    let cmsg_gso = ControlMessage::UdpGsoSegments(&segment_size);

    // Pacing option.
    let send_time = std_time_to_u64(&send_info.at);
    let cmsg_txtime = ControlMessage::TxTime(&send_time);

    match sendmsg(
        sockfd,
        &iov,
        &[cmsg_gso, cmsg_txtime],
        MsgFlags::empty(),
        Some(&dst),
    ) {
        Ok(v) => Ok(v),
        Err(e) => Err(e.into()),
    }
}

/// For non-Linux platforms.
#[cfg(not(target_os = "linux"))]
fn send_to_gso_pacing(
    _socket: &mio::net::UdpSocket, _buf: &[u8], _send_info: &quiche::SendInfo,
    _segment_size: usize,
) -> io::Result<usize> {
    panic!("send_to_gso() should not be called on non-linux platforms");
}

/// A wrapper function of send_to().
///
/// When GSO and SO_TXTIME are enabled, send packets using send_to_gso().
/// Otherwise, send packets using socket.send_to().
pub fn send_to(
    socket: &mio::net::UdpSocket, buf: &[u8], send_info: &quiche::SendInfo,
    segment_size: usize, pacing: bool, enable_gso: bool,
) -> io::Result<usize> {
    if pacing && enable_gso {
        match send_to_gso_pacing(socket, buf, send_info, segment_size) {
            Ok(v) => {
                return Ok(v);
            },
            Err(e) => {
                return Err(e);
            },
        }
    }

    let mut off = 0;
    let mut left = buf.len();
    let mut written = 0;

    while left > 0 {
        let pkt_len = cmp::min(left, segment_size);

        {
            let v = socket.send_to(&buf[off..off + pkt_len], send_info.to)?;
            written += v;
        }

        off += pkt_len;
        left -= pkt_len;
    }

    Ok(written)
}

/// Converts a [`quiche::EcnCodepoint`] into the two-bit ECN field value
/// carried in the IP header.
#[cfg(target_os = "linux")]
fn ecn_field(ecn: quiche::EcnCodepoint) -> u8 {
    match ecn {
        quiche::EcnCodepoint::NotEct => 0,
        quiche::EcnCodepoint::Ect1 => 1,
        quiche::EcnCodepoint::Ect0 => 2,
        quiche::EcnCodepoint::Ce => 3,
    }
}

/// Same as [`send_to_gso_pacing()`], but additionally marks the datagram
/// with `ecn` via an `IP_TOS`/`IPV6_TCLASS` ancillary message.
///
/// Since a single `sendmsg()` call (and thus a single GSO batch) can only
/// carry one ECN codepoint, callers must ensure `buf` only contains
/// segments that were all decided with this same `ecn` value.
#[cfg(target_os = "linux")]
fn send_to_gso_pacing_with_ecn(
    socket: &mio::net::UdpSocket, buf: &[u8], send_info: &quiche::SendInfo,
    segment_size: usize, ecn: quiche::EcnCodepoint,
) -> io::Result<usize> {
    use nix::sys::socket::sendmsg;
    use nix::sys::socket::ControlMessage;
    use nix::sys::socket::MsgFlags;
    use nix::sys::socket::SockaddrStorage;
    use std::io::IoSlice;
    use std::os::unix::io::AsRawFd;

    let iov = [IoSlice::new(buf)];
    let segment_size = segment_size as u16;
    let dst = SockaddrStorage::from(send_info.to);
    let sockfd = socket.as_raw_fd();

    let cmsg_gso = ControlMessage::UdpGsoSegments(&segment_size);

    let send_time = std_time_to_u64(&send_info.at);
    let cmsg_txtime = ControlMessage::TxTime(&send_time);

    let field = ecn_field(ecn);
    let tos = field;
    let tclass = field as i32;

    let result = if send_info.to.is_ipv4() {
        let cmsg_ecn = ControlMessage::Ipv4Tos(&tos);
        sendmsg(
            sockfd,
            &iov,
            &[cmsg_gso, cmsg_txtime, cmsg_ecn],
            MsgFlags::empty(),
            Some(&dst),
        )
    } else {
        let cmsg_ecn = ControlMessage::Ipv6TClass(&tclass);
        sendmsg(
            sockfd,
            &iov,
            &[cmsg_gso, cmsg_txtime, cmsg_ecn],
            MsgFlags::empty(),
            Some(&dst),
        )
    };

    result.map_err(|e| e.into())
}

/// For non-Linux platforms.
#[cfg(not(target_os = "linux"))]
fn send_to_gso_pacing_with_ecn(
    _socket: &mio::net::UdpSocket, _buf: &[u8], _send_info: &quiche::SendInfo,
    _segment_size: usize, _ecn: quiche::EcnCodepoint,
) -> io::Result<usize> {
    panic!(
        "send_to_gso_pacing_with_ecn() should not be called on non-linux platforms"
    );
}

/// Sends a single datagram marked with `ecn` via an `IP_TOS`/`IPV6_TCLASS`
/// ancillary message.
#[cfg(target_os = "linux")]
fn send_to_with_ecn_single(
    socket: &mio::net::UdpSocket, buf: &[u8], to: SocketAddr,
    ecn: quiche::EcnCodepoint,
) -> io::Result<usize> {
    use nix::sys::socket::sendmsg;
    use nix::sys::socket::ControlMessage;
    use nix::sys::socket::MsgFlags;
    use nix::sys::socket::SockaddrStorage;
    use std::io::IoSlice;
    use std::os::unix::io::AsRawFd;

    let iov = [IoSlice::new(buf)];
    let dst = SockaddrStorage::from(to);
    let sockfd = socket.as_raw_fd();

    let field = ecn_field(ecn);
    let tos = field;
    let tclass = field as i32;

    let result = if to.is_ipv4() {
        let cmsg_ecn = ControlMessage::Ipv4Tos(&tos);
        sendmsg(sockfd, &iov, &[cmsg_ecn], MsgFlags::empty(), Some(&dst))
    } else {
        let cmsg_ecn = ControlMessage::Ipv6TClass(&tclass);
        sendmsg(sockfd, &iov, &[cmsg_ecn], MsgFlags::empty(), Some(&dst))
    };

    result.map_err(|e| e.into())
}

/// Same as [`send_to()`], but additionally marks outgoing datagrams with
/// the given ECN codepoint, via an `IP_TOS`/`IPV6_TCLASS` ancillary message
/// on Linux. On other platforms, or when `ecn` is
/// [`quiche::EcnCodepoint::NotEct`], falls back to the plain,
/// non-ECN-marking [`send_to()`].
///
/// When GSO is used, `buf` must only contain segments that were all
/// decided with this same `ecn` value: a GSO batch cannot carry more than
/// one ECN codepoint.
pub fn send_to_with_ecn(
    socket: &mio::net::UdpSocket, buf: &[u8], send_info: &quiche::SendInfo,
    segment_size: usize, pacing: bool, enable_gso: bool,
    ecn: quiche::EcnCodepoint,
) -> io::Result<usize> {
    if ecn == quiche::EcnCodepoint::NotEct {
        return send_to(socket, buf, send_info, segment_size, pacing, enable_gso);
    }

    #[cfg(not(target_os = "linux"))]
    {
        send_to(socket, buf, send_info, segment_size, pacing, enable_gso)
    }

    #[cfg(target_os = "linux")]
    {
        if pacing && enable_gso {
            return send_to_gso_pacing_with_ecn(
                socket,
                buf,
                send_info,
                segment_size,
                ecn,
            );
        }

        let mut off = 0;
        let mut left = buf.len();
        let mut written = 0;

        while left > 0 {
            let pkt_len = cmp::min(left, segment_size);

            let v = send_to_with_ecn_single(
                socket,
                &buf[off..off + pkt_len],
                send_info.to,
                ecn,
            )?;
            written += v;

            off += pkt_len;
            left -= pkt_len;
        }

        Ok(written)
    }
}

#[cfg(target_os = "linux")]
fn std_time_to_u64(time: &std::time::Instant) -> u64 {
    const NANOS_PER_SEC: u64 = 1_000_000_000;

    const INSTANT_ZERO: std::time::Instant =
        unsafe { std::mem::transmute(std::time::UNIX_EPOCH) };

    let raw_time = time.duration_since(INSTANT_ZERO);

    let sec = raw_time.as_secs();
    let nsec = raw_time.subsec_nanos();

    sec * NANOS_PER_SEC + nsec as u64
}

/// Enables reporting of the ECN codepoint from the IP header of received
/// datagrams as ancillary (`cmsg`) data, for both IPv4 (`IP_RECVTOS`) and
/// IPv6 (`IPV6_RECVTCLASS`).
///
/// Either option can fail depending on the socket's address family; such
/// failures are ignored, since [`recv_from_with_ecn()`] simply reports no
/// codepoint in that case.
#[cfg(target_os = "linux")]
pub fn enable_ecn_reporting(socket: &mio::net::UdpSocket) {
    use nix::sys::socket::setsockopt;
    use nix::sys::socket::sockopt::IpRecvTos;
    use nix::sys::socket::sockopt::Ipv6RecvTClass;
    use std::os::unix::io::AsFd;

    let fd = socket.as_fd();
    setsockopt(&fd, IpRecvTos, &true).ok();
    setsockopt(&fd, Ipv6RecvTClass, &true).ok();
}

/// For non-Linux, ECN reporting is not supported.
#[cfg(not(target_os = "linux"))]
pub fn enable_ecn_reporting(_socket: &mio::net::UdpSocket) {}

/// Converts a two-bit ECN field value, as carried in a `cmsg`, into the
/// corresponding [`quiche::EcnCodepoint`].
#[cfg(target_os = "linux")]
fn ecn_codepoint_from_field(field: u8) -> quiche::EcnCodepoint {
    match field & 0x03 {
        0 => quiche::EcnCodepoint::NotEct,
        1 => quiche::EcnCodepoint::Ect1,
        2 => quiche::EcnCodepoint::Ect0,
        _ => quiche::EcnCodepoint::Ce,
    }
}

/// Same as `socket.recv_from()`, but additionally reports the ECN codepoint
/// carried in the IP header of the received datagram, when `socket` was
/// prepared with [`enable_ecn_reporting()`] and the platform supports it.
#[cfg(target_os = "linux")]
pub fn recv_from_with_ecn(
    socket: &mio::net::UdpSocket, buf: &mut [u8],
) -> io::Result<(usize, SocketAddr, Option<quiche::EcnCodepoint>)> {
    use nix::sys::socket::recvmsg;
    use nix::sys::socket::ControlMessageOwned;
    use nix::sys::socket::MsgFlags;
    use nix::sys::socket::SockaddrStorage;
    use std::io::IoSliceMut;
    use std::os::unix::io::AsRawFd;

    let mut cmsg_buf = nix::cmsg_space!(u8, i32);
    let mut iov = [IoSliceMut::new(buf)];

    let msg = recvmsg::<SockaddrStorage>(
        socket.as_raw_fd(),
        &mut iov,
        Some(&mut cmsg_buf),
        MsgFlags::empty(),
    )
    .map_err(|e| io::Error::from_raw_os_error(e as i32))?;

    let from = msg
        .address
        .as_ref()
        .and_then(|addr| {
            addr.as_sockaddr_in()
                .map(|sin| SocketAddr::from(*sin))
                .or_else(|| {
                    addr.as_sockaddr_in6().map(|sin6| SocketAddr::from(*sin6))
                })
        })
        .ok_or_else(|| {
            io::Error::other("recvmsg() returned no source address")
        })?;

    let ecn = msg.cmsgs().ok().and_then(|mut cmsgs| {
        cmsgs.find_map(|c| match c {
            ControlMessageOwned::Ipv4Tos(tos) =>
                Some(ecn_codepoint_from_field(tos)),

            ControlMessageOwned::Ipv6TClass(tc) =>
                Some(ecn_codepoint_from_field(tc as u8)),

            _ => None,
        })
    });

    Ok((msg.bytes, from, ecn))
}

/// For non-Linux, falls back to a plain, non-ECN-reporting receive.
#[cfg(not(target_os = "linux"))]
pub fn recv_from_with_ecn(
    socket: &mio::net::UdpSocket, buf: &mut [u8],
) -> io::Result<(usize, SocketAddr, Option<quiche::EcnCodepoint>)> {
    let (len, from) = socket.recv_from(buf)?;
    Ok((len, from, None))
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    use std::net::UdpSocket as StdUdpSocket;
    use std::os::unix::io::AsRawFd;

    /// Sends a datagram marked with the given IP_TOS value and asserts that
    /// `recv_from_with_ecn()` reports the expected codepoint for it.
    fn assert_roundtrip_ecn(tos: libc::c_int, expected: quiche::EcnCodepoint) {
        let receiver =
            mio::net::UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        enable_ecn_reporting(&receiver);

        let recv_addr = receiver.local_addr().unwrap();

        let sender = StdUdpSocket::bind("127.0.0.1:0").unwrap();

        // SAFETY: `tos` outlives the call and matches the expected type/size.
        let ret = unsafe {
            libc::setsockopt(
                sender.as_raw_fd(),
                libc::IPPROTO_IP,
                libc::IP_TOS,
                &tos as *const libc::c_int as *const libc::c_void,
                std::mem::size_of_val(&tos) as libc::socklen_t,
            )
        };
        assert_eq!(ret, 0, "setsockopt(IP_TOS) failed");

        sender.send_to(b"hello", recv_addr).unwrap();

        // Loopback delivery is effectively immediate, but retry briefly in
        // case the datagram has not yet reached the receive queue.
        let mut buf = [0; 16];
        let mut result = recv_from_with_ecn(&receiver, &mut buf);
        for _ in 0..50 {
            if result.is_ok() {
                break;
            }

            std::thread::sleep(std::time::Duration::from_millis(10));
            result = recv_from_with_ecn(&receiver, &mut buf);
        }

        let (len, _from, ecn) = result.unwrap();
        assert_eq!(&buf[..len], b"hello");
        assert_eq!(ecn, Some(expected));
    }

    #[test]
    fn recv_from_with_ecn_reports_ect0() {
        assert_roundtrip_ecn(0x02, quiche::EcnCodepoint::Ect0);
    }

    #[test]
    fn recv_from_with_ecn_reports_not_ect() {
        assert_roundtrip_ecn(0x00, quiche::EcnCodepoint::NotEct);
    }

    /// `send_to_with_ecn()` actually marks the outgoing datagram's IP
    /// header with the requested codepoint, round-tripped through
    /// `recv_from_with_ecn()` on the receiving end.
    fn assert_send_roundtrip_ecn(ecn: quiche::EcnCodepoint) {
        let receiver =
            mio::net::UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        enable_ecn_reporting(&receiver);
        let recv_addr = receiver.local_addr().unwrap();

        let sender =
            mio::net::UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let send_info = quiche::SendInfo {
            from: sender.local_addr().unwrap(),
            to: recv_addr,
            at: std::time::Instant::now(),
        };

        send_to_with_ecn(&sender, b"hello", &send_info, 5, false, false, ecn)
            .unwrap();

        let mut buf = [0; 16];
        let mut result = recv_from_with_ecn(&receiver, &mut buf);
        for _ in 0..50 {
            if result.is_ok() {
                break;
            }

            std::thread::sleep(std::time::Duration::from_millis(10));
            result = recv_from_with_ecn(&receiver, &mut buf);
        }

        let (len, _from, recv_ecn) = result.unwrap();
        assert_eq!(&buf[..len], b"hello");
        assert_eq!(recv_ecn, Some(ecn));
    }

    #[test]
    fn send_to_with_ecn_marks_ect0() {
        assert_send_roundtrip_ecn(quiche::EcnCodepoint::Ect0);
    }

    #[test]
    fn send_to_with_ecn_marks_not_ect() {
        assert_send_roundtrip_ecn(quiche::EcnCodepoint::NotEct);
    }
}
