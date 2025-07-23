// SPDX-License-Identifier: MIT OR Apache-2.0
/*
 * MCTP support through Linux kernel-based sockets
 *
 * Copyright (c) 2024 Code Construct
 */

#![warn(missing_docs)]

//! Interface for the Linux socket-based MCTP support.
//!
//! This crate provides some minimal wrappers around standard [`libc`] socket
//! operations, using MCTP-specific addressing structures.
//!
//! [`MctpSocket`] provides support for blocking socket operations
//! [sendto](MctpSocket::sendto), [`recvfrom`](MctpSocket::recvfrom) and
//! [`bind`](MctpSocket::bind).
//!
//! ```no_run
//! use mctp_linux;
//!
//! let sock = mctp_linux::MctpSocket::new()?;
//! let bind_addr = mctp_linux::MctpSockAddr::new(
//!     mctp::MCTP_ADDR_ANY.0,
//!     mctp_linux::MCTP_NET_ANY,
//!     1,
//!     0
//! );
//! sock.bind(&bind_addr)?;
//!
//! let mut buf = [0; 64];
//! let (len, src) = sock.recvfrom(&mut buf)?;
//! # Ok::<(), std::io::Error>(())
//! ```
//!
//! [`MctpLinuxReq`] provides a thin wrapper that represents a remote endpoint,
//! referenced by EID. It creates a single socket for communication with that
//! endpoint. This is a convenience for simple consumers that perform
//! single-endpoint communication; general MCTP requesters may want a different
//! socket model.

use core::mem;
use smol::Async;
use std::fmt;
use std::io::Error;
use std::os::unix::io::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::time::Duration;

use mctp::{
    Eid, MsgIC, MsgType, Result, Tag, TagValue, MCTP_ADDR_ANY, MCTP_TAG_OWNER,
};

/* until we have these in libc... */
const AF_MCTP: libc::sa_family_t = 45;
#[repr(C)]
#[allow(non_camel_case_types)]
struct sockaddr_mctp {
    smctp_family: libc::sa_family_t,
    __smctp_pad0: u16,
    smctp_network: u32,
    smctp_addr: u8,
    smctp_type: u8,
    smctp_tag: u8,
    __smctp_pad1: u8,
}

/// Special value for Network ID: any network
pub const MCTP_NET_ANY: u32 = 0x00;

/// Address information for a socket
pub struct MctpSockAddr(sockaddr_mctp);

impl MctpSockAddr {
    /// Create a new address, for the given local EID, network, message type,
    /// and tag value.
    pub fn new(eid: u8, net: u32, typ: u8, tag: u8) -> Self {
        MctpSockAddr(sockaddr_mctp {
            smctp_family: AF_MCTP,
            __smctp_pad0: 0,
            smctp_network: net,
            smctp_addr: eid,
            smctp_type: typ,
            smctp_tag: tag,
            __smctp_pad1: 0,
        })
    }

    fn zero() -> Self {
        Self::new(0, MCTP_NET_ANY, 0, 0)
    }

    fn as_raw(&self) -> (*const libc::sockaddr, libc::socklen_t) {
        (
            &self.0 as *const sockaddr_mctp as *const libc::sockaddr,
            mem::size_of::<sockaddr_mctp>() as libc::socklen_t,
        )
    }

    fn as_raw_mut(&mut self) -> (*mut libc::sockaddr, libc::socklen_t) {
        (
            &mut self.0 as *mut sockaddr_mctp as *mut libc::sockaddr,
            mem::size_of::<sockaddr_mctp>() as libc::socklen_t,
        )
    }
}

impl fmt::Debug for MctpSockAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "McptSockAddr(family={}, net={}, addr={}, type={}, tag={})",
            self.0.smctp_family,
            self.0.smctp_network,
            self.0.smctp_addr,
            self.0.smctp_type,
            self.0.smctp_tag
        )
    }
}

/// Creates a `Tag` from a smctp_tag field.
fn tag_from_smctp(to: u8) -> Tag {
    let t = TagValue(to & !MCTP_TAG_OWNER);
    if to & MCTP_TAG_OWNER == 0 {
        Tag::Unowned(t)
    } else {
        Tag::Owned(t)
    }
}

/// Creates a `Tag` to a smctp_tag field.
fn tag_to_smctp(tag: &Tag) -> u8 {
    let to_bit = if tag.is_owner() { MCTP_TAG_OWNER } else { 0 };
    tag.tag().0 | to_bit
}

// helper for IO error construction
fn last_os_error() -> mctp::Error {
    mctp::Error::Io(Error::last_os_error())
}

/// MCTP socket object.
pub struct MctpSocket(OwnedFd);

impl MctpSocket {
    /// Create a new MCTP socket. This can then be used for send/receive
    /// operations.
    pub fn new() -> Result<Self> {
        let rc = unsafe {
            libc::socket(
                AF_MCTP.into(),
                libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
                0,
            )
        };
        if rc < 0 {
            return Err(last_os_error());
        }
        // safety: the fd is valid, and we have exclusive ownership
        let fd = unsafe { OwnedFd::from_raw_fd(rc) };
        Ok(MctpSocket(fd))
    }

    // Inner recvfrom, returning an io::Error on failure. This can be
    // used with async wrappers.
    // This uses MSG_TRUNC so the returned length may be larger than buf.len()
    fn io_recvfrom(
        &self,
        buf: &mut [u8],
    ) -> std::io::Result<(usize, MctpSockAddr)> {
        let mut addr = MctpSockAddr::zero();
        let (addr_ptr, mut addr_len) = addr.as_raw_mut();
        let buf_ptr = buf.as_mut_ptr() as *mut libc::c_void;
        let buf_len = buf.len() as libc::size_t;
        let fd = self.as_raw_fd();

        let rc = unsafe {
            libc::recvfrom(
                fd,
                buf_ptr,
                buf_len,
                libc::MSG_TRUNC,
                addr_ptr,
                &mut addr_len,
            )
        };

        if rc < 0 {
            Err(Error::last_os_error())
        } else {
            Ok((rc as usize, addr))
        }
    }

    /// Blocking receive from a socket, into `buf`, returning a length
    /// and source address
    ///
    /// Essentially a wrapper around [libc::recvfrom], using MCTP-specific
    /// addressing.
    pub fn recvfrom(&self, buf: &mut [u8]) -> Result<(usize, MctpSockAddr)> {
        let (len, addr) = self.io_recvfrom(buf).map_err(mctp::Error::Io)?;
        if len > buf.len() {
            return Err(mctp::Error::NoSpace);
        }
        Ok((len, addr))
    }

    fn io_sendto(
        &self,
        buf: &[u8],
        addr: &MctpSockAddr,
    ) -> std::io::Result<usize> {
        let (addr_ptr, addr_len) = addr.as_raw();
        let buf_ptr = buf.as_ptr() as *const libc::c_void;
        let buf_len = buf.len() as libc::size_t;
        let fd = self.as_raw_fd();

        let rc = unsafe {
            libc::sendto(fd, buf_ptr, buf_len, 0, addr_ptr, addr_len)
        };

        if rc < 0 {
            Err(Error::last_os_error())
        } else {
            Ok(rc as usize)
        }
    }

    /// Blocking send to a socket, given a buffer and address, returning
    /// the number of bytes sent.
    ///
    /// Essentially a wrapper around [libc::sendto].
    pub fn sendto(&self, buf: &[u8], addr: &MctpSockAddr) -> Result<usize> {
        self.io_sendto(buf, addr).map_err(mctp::Error::Io)
    }

    /// Bind the socket to a local address.
    pub fn bind(&self, addr: &MctpSockAddr) -> Result<()> {
        let (addr_ptr, addr_len) = addr.as_raw();
        let fd = self.as_raw_fd();

        let rc = unsafe { libc::bind(fd, addr_ptr, addr_len) };

        if rc < 0 {
            Err(last_os_error())
        } else {
            Ok(())
        }
    }

    /// Set the read timeout.
    ///
    /// A valid of `None` will have no timeout.
    pub fn set_read_timeout(&self, dur: Option<Duration>) -> Result<()> {
        // Avoid warnings about using time_t with musl. See comment in read_timeout().
        #![allow(deprecated)]

        let dur = dur.unwrap_or(Duration::ZERO);
        let tv = libc::timeval {
            tv_sec: dur.as_secs() as libc::time_t,
            tv_usec: dur.subsec_micros() as libc::suseconds_t,
        };
        let fd = self.as_raw_fd();
        let rc = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                (&tv as *const libc::timeval) as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            )
        };

        if rc < 0 {
            Err(last_os_error())
        } else {
            Ok(())
        }
    }

    /// Retrieves the read timeout
    ///
    /// A value of `None` indicates no timeout.
    pub fn read_timeout(&self) -> Result<Option<Duration>> {
        // Avoid warnings about using time_t with musl. It is safe here since we are
        // only using it directly with libc, that should be compiled with the
        // same definitions as libc crate. https://github.com/rust-lang/libc/issues/1848
        #![allow(deprecated)]

        let mut tv = std::mem::MaybeUninit::<libc::timeval>::uninit();
        let mut tv_len =
            std::mem::size_of::<libc::timeval>() as libc::socklen_t;
        let fd = self.as_raw_fd();
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                tv.as_mut_ptr() as *mut libc::c_void,
                &mut tv_len as *mut libc::socklen_t,
            )
        };

        if rc < 0 {
            Err(last_os_error())
        } else {
            let tv = unsafe { tv.assume_init() };
            if tv.tv_sec < 0 || tv.tv_usec < 0 {
                // Negative timeout from socket
                return Err(mctp::Error::Other);
            }

            if tv.tv_sec == 0 && tv.tv_usec == 0 {
                Ok(None)
            } else {
                Ok(Some(
                    Duration::from_secs(tv.tv_sec as u64)
                        + Duration::from_micros(tv.tv_usec as u64),
                ))
            }
        }
    }
}

impl std::os::fd::AsRawFd for MctpSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

impl AsFd for MctpSocket {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}

/// MCTP socket for async use
pub struct MctpSocketAsync(Async<MctpSocket>);

impl MctpSocketAsync {
    /// Create a new async MCTP socket
    pub fn new() -> Result<Self> {
        let sock = MctpSocket::new()?;
        let sock = Async::new(sock).map_err(mctp::Error::Io)?;

        Ok(Self(sock))
    }

    /// Bind the socket to a local address.
    pub fn bind(&self, addr: &MctpSockAddr) -> Result<()> {
        self.0.as_ref().bind(addr)
    }

    /// Receive a message from this socket
    ///
    /// Returns the length of buffer read, and the peer address.
    pub async fn recvfrom(
        &self,
        buf: &mut [u8],
    ) -> Result<(usize, MctpSockAddr)> {
        let (len, addr) = self
            .0
            .read_with(|io| io.io_recvfrom(buf))
            .await
            .map_err(mctp::Error::Io)?;
        if len > buf.len() {
            return Err(mctp::Error::NoSpace);
        }
        Ok((len, addr))
    }

    /// Send a message to a given address
    ///
    /// Returns the number of bytes sent
    pub async fn sendto(
        &self,
        buf: &[u8],
        addr: &MctpSockAddr,
    ) -> Result<usize> {
        self.0
            .write_with(|io| io.io_sendto(buf, addr))
            .await
            .map_err(mctp::Error::Io)
    }
}

/// Encapsulation of a remote endpoint: a socket and an Endpoint ID.
pub struct MctpLinuxReq {
    eid: Eid,
    net: u32,
    sock: MctpSocket,
    sent: bool,
}

impl MctpLinuxReq {
    /// Create a new `MctpLinuxReq` with EID `eid`
    pub fn new(eid: Eid, net: Option<u32>) -> Result<Self> {
        let net = net.unwrap_or(MCTP_NET_ANY);
        Ok(Self {
            eid,
            net,
            sock: MctpSocket::new()?,
            sent: false,
        })
    }

    /// Borrow the internal MCTP socket
    pub fn as_socket(&mut self) -> &mut MctpSocket {
        &mut self.sock
    }

    /// Returns the MCTP Linux network, or None for the default `MCTP_NET_ANY`
    pub fn net(&self) -> Option<u32> {
        if self.net == MCTP_NET_ANY {
            None
        } else {
            Some(self.net)
        }
    }
}

impl mctp::ReqChannel for MctpLinuxReq {
    /// Send a MCTP message
    ///
    /// Linux MCTP can also send a preallocated owned tag, but that is not
    /// yet supported in `MctpLinuxReq`.
    fn send_vectored(
        &mut self,
        typ: MsgType,
        ic: MsgIC,
        bufs: &[&[u8]],
    ) -> Result<()> {
        let typ_ic = mctp::encode_type_ic(typ, ic);
        let addr = MctpSockAddr::new(
            self.eid.0,
            self.net,
            typ_ic,
            mctp::MCTP_TAG_OWNER,
        );
        // TODO: implement sendmsg() with iovecs
        let concat = bufs
            .iter()
            .flat_map(|b| b.iter().cloned())
            .collect::<Vec<u8>>();
        self.sock.sendto(&concat, &addr)?;
        self.sent = true;
        Ok(())
    }

    fn recv<'f>(
        &mut self,
        buf: &'f mut [u8],
    ) -> Result<(MsgType, MsgIC, &'f mut [u8])> {
        if !self.sent {
            return Err(mctp::Error::BadArgument);
        }
        let (sz, addr) = self.sock.recvfrom(buf)?;
        let src = Eid(addr.0.smctp_addr);
        let (typ, ic) = mctp::decode_type_ic(addr.0.smctp_type);
        if src != self.eid {
            // Kernel gave us a message from a different sender?
            return Err(mctp::Error::Other);
        }
        Ok((typ, ic, &mut buf[..sz]))
    }

    fn remote_eid(&self) -> Eid {
        self.eid
    }
}

/// Encapsulation of a remote endpoint: a socket and an Endpoint ID.
pub struct MctpLinuxAsyncReq {
    eid: Eid,
    net: u32,
    sock: MctpSocketAsync,
    sent: bool,
}

impl MctpLinuxAsyncReq {
    /// Create a new asynchronous request channel.
    pub fn new(eid: Eid, net: Option<u32>) -> Result<Self> {
        let net = net.unwrap_or(MCTP_NET_ANY);
        Ok(Self {
            eid,
            net,
            sock: MctpSocketAsync::new()?,
            sent: false,
        })
    }
}

impl mctp::AsyncReqChannel for MctpLinuxAsyncReq {
    fn remote_eid(&self) -> Eid {
        self.eid
    }

    async fn send_vectored(
        &mut self,
        typ: MsgType,
        ic: MsgIC,
        bufs: &[&[u8]],
    ) -> Result<()> {
        let typ_ic = mctp::encode_type_ic(typ, ic);
        let addr = MctpSockAddr::new(
            self.eid.0,
            self.net,
            typ_ic,
            mctp::MCTP_TAG_OWNER,
        );
        let concat = bufs
            .iter()
            .flat_map(|b| b.iter().cloned())
            .collect::<Vec<u8>>();
        self.sock.sendto(&concat, &addr).await?;
        self.sent = true;
        Ok(())
    }

    async fn recv<'f>(
        &mut self,
        buf: &'f mut [u8],
    ) -> Result<(MsgType, MsgIC, &'f mut [u8])> {
        if !self.sent {
            return Err(mctp::Error::BadArgument);
        }
        let (sz, addr) = self.sock.recvfrom(buf).await?;
        let src = Eid(addr.0.smctp_addr);
        let (typ, ic) = mctp::decode_type_ic(addr.0.smctp_type);
        if src != self.eid {
            return Err(mctp::Error::Other);
        }
        Ok((typ, ic, &mut buf[..sz]))
    }
}

/// A Listener for Linux MCTP messages
pub struct MctpLinuxListener {
    sock: MctpSocket,
    net: u32,
    typ: MsgType,
}

impl MctpLinuxListener {
    /// Create a new `MctpLinuxListener`.
    ///
    /// This will listen for MCTP message type `typ`, on an optional
    /// Linux network `net`. `None` network defaults to `MCTP_NET_ANY`.
    pub fn new(typ: MsgType, net: Option<u32>) -> Result<Self> {
        let sock = MctpSocket::new()?;
        // Linux requires MCTP_ADDR_ANY for binds.
        let net = net.unwrap_or(MCTP_NET_ANY);
        let addr = MctpSockAddr::new(
            MCTP_ADDR_ANY.0,
            net,
            typ.0,
            mctp::MCTP_TAG_OWNER,
        );
        sock.bind(&addr)?;
        Ok(Self { sock, net, typ })
    }

    /// Borrow the internal MCTP socket
    pub fn as_socket(&mut self) -> &mut MctpSocket {
        &mut self.sock
    }

    /// Returns the MCTP Linux network, or None for the default `MCTP_NET_ANY`
    pub fn net(&self) -> Option<u32> {
        if self.net == MCTP_NET_ANY {
            None
        } else {
            Some(self.net)
        }
    }
}

impl mctp::Listener for MctpLinuxListener {
    type RespChannel<'a> = MctpLinuxResp<'a>;

    fn recv<'f>(
        &mut self,
        buf: &'f mut [u8],
    ) -> Result<(MsgType, MsgIC, &'f mut [u8], MctpLinuxResp<'_>)> {
        let (sz, addr) = self.sock.recvfrom(buf)?;
        let src = Eid(addr.0.smctp_addr);
        let (typ, ic) = mctp::decode_type_ic(addr.0.smctp_type);
        let tag = tag_from_smctp(addr.0.smctp_tag);
        if let Tag::Unowned(_) = tag {
            // bind() shouldn't give non-owned packets.
            return Err(mctp::Error::InternalError);
        }
        if typ != self.typ {
            // bind() should return the requested type
            return Err(mctp::Error::InternalError);
        }
        let ep = MctpLinuxResp {
            eid: src,
            tv: tag.tag(),
            listener: self,
            typ,
        };
        Ok((typ, ic, &mut buf[..sz], ep))
    }
}

/// An MCTP Listener for asynchronous IO
pub struct MctpLinuxAsyncListener {
    sock: MctpSocketAsync,
    net: u32,
    typ: MsgType,
}

impl MctpLinuxAsyncListener {
    /// Create a new `MctpLinuxAsyncListener`.
    ///
    /// This will listen for MCTP message type `typ`, on an optional
    /// Linux network `net`. `None` network defaults to `MCTP_NET_ANY`.
    pub fn new(typ: MsgType, net: Option<u32>) -> Result<Self> {
        let sock = MctpSocketAsync::new()?;
        // Linux requires MCTP_ADDR_ANY for binds.
        let net = net.unwrap_or(MCTP_NET_ANY);
        let addr = MctpSockAddr::new(
            MCTP_ADDR_ANY.0,
            net,
            typ.0,
            mctp::MCTP_TAG_OWNER,
        );
        sock.bind(&addr)?;
        Ok(Self { sock, net, typ })
    }
}

impl mctp::AsyncListener for MctpLinuxAsyncListener {
    type RespChannel<'a> = MctpLinuxAsyncResp<'a>;

    async fn recv<'f>(
        &mut self,
        buf: &'f mut [u8],
    ) -> Result<(MsgType, MsgIC, &'f mut [u8], Self::RespChannel<'_>)> {
        let (sz, addr) = self.sock.recvfrom(buf).await?;
        let src = Eid(addr.0.smctp_addr);
        let (typ, ic) = mctp::decode_type_ic(addr.0.smctp_type);
        let tag = tag_from_smctp(addr.0.smctp_tag);
        if let Tag::Unowned(_) = tag {
            // bind() shouldn't give non-owned packets.
            return Err(mctp::Error::InternalError);
        }
        if typ != self.typ {
            // bind() should return the requested type
            return Err(mctp::Error::InternalError);
        }
        let ep = MctpLinuxAsyncResp {
            eid: src,
            tv: tag.tag(),
            listener: self,
            typ,
        };
        Ok((typ, ic, &mut buf[..sz], ep))
    }
}

/// A Linux MCTP Listener response channel
pub struct MctpLinuxResp<'a> {
    eid: Eid,
    // An unowned tag
    tv: TagValue,
    listener: &'a MctpLinuxListener,
    typ: MsgType,
}

impl mctp::RespChannel for MctpLinuxResp<'_> {
    type ReqChannel = MctpLinuxReq;

    /// Send a MCTP message
    ///
    /// Linux MCTP can also send a preallocated owned tag, but that is not
    /// yet supported in `MctpLinuxReq`.
    fn send_vectored(&mut self, ic: MsgIC, bufs: &[&[u8]]) -> Result<()> {
        let typ_ic = mctp::encode_type_ic(self.typ, ic);
        let tag = tag_to_smctp(&Tag::Unowned(self.tv));
        let addr =
            MctpSockAddr::new(self.eid.0, self.listener.net, typ_ic, tag);
        // TODO: implement sendmsg() with iovecs
        let concat = bufs
            .iter()
            .flat_map(|b| b.iter().cloned())
            .collect::<Vec<u8>>();
        self.listener.sock.sendto(&concat, &addr)?;
        Ok(())
    }

    fn remote_eid(&self) -> Eid {
        self.eid
    }

    fn req_channel(&self) -> Result<Self::ReqChannel> {
        MctpLinuxReq::new(self.eid, Some(self.listener.net))
    }
}

/// A Linux MCTP Async Listener response channel
pub struct MctpLinuxAsyncResp<'l> {
    eid: Eid,
    tv: TagValue,
    listener: &'l MctpLinuxAsyncListener,
    typ: MsgType,
}

impl<'l> mctp::AsyncRespChannel for MctpLinuxAsyncResp<'l> {
    type ReqChannel<'a>
        = MctpLinuxAsyncReq
    where
        Self: 'a;

    async fn send_vectored(&mut self, ic: MsgIC, bufs: &[&[u8]]) -> Result<()> {
        let typ_ic = mctp::encode_type_ic(self.typ, ic);
        let tag = tag_to_smctp(&Tag::Unowned(self.tv));
        let addr =
            MctpSockAddr::new(self.eid.0, self.listener.net, typ_ic, tag);
        let concat = bufs
            .iter()
            .flat_map(|b| b.iter().cloned())
            .collect::<Vec<u8>>();
        self.listener.sock.sendto(&concat, &addr).await?;
        Ok(())
    }

    fn remote_eid(&self) -> Eid {
        self.eid
    }

    fn req_channel(&self) -> Result<Self::ReqChannel<'_>> {
        MctpLinuxAsyncReq::new(self.eid, Some(self.listener.net))
    }
}

/// Helper for applications taking an MCTP address as an argument,
/// configuration, etc.
///
/// Address specifications can either be `<eid>`, or `<net>,<eid>`
///
/// EID may be either specified in decimal or hex, the latter requiring an '0x'
/// prefix.
///
/// Net must be in decimal.
///
/// If no network is specified, the default of MCTP_NET_ANY is used.
#[derive(Debug)]
pub struct MctpAddr {
    eid: Eid,
    net: Option<u32>,
}

impl std::str::FromStr for MctpAddr {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<MctpAddr, String> {
        let mut parts = s.split(',');

        let p1 = parts.next();
        let p2 = parts.next();

        let (net_str, eid_str) = match (p1, p2) {
            (Some(n), Some(e)) => (Some(n), e),
            (Some(e), None) => (None, e),
            _ => return Err("invalid MCTP address format".to_string()),
        };

        const HEX_PREFIX: &str = "0x";
        const HEX_PREFIX_LEN: usize = HEX_PREFIX.len();

        let eid = if eid_str.to_ascii_lowercase().starts_with(HEX_PREFIX) {
            u8::from_str_radix(&eid_str[HEX_PREFIX_LEN..], 16)
        } else {
            eid_str.parse()
        }
        .map_err(|e| e.to_string())?;
        let eid = Eid(eid);

        let net: Option<u32> = match net_str {
            Some(n) => Some(
                n.parse()
                    .map_err(|e: std::num::ParseIntError| e.to_string())?,
            ),
            None => None,
        };

        Ok(MctpAddr { net, eid })
    }
}

impl MctpAddr {
    /// Return the MCTP Endpoint ID for this address.
    pub fn eid(&self) -> Eid {
        self.eid
    }

    /// Return the MCTP Network ID for this address, defaulting to MCTP_NET_ANY
    /// if none was provided originally.
    pub fn net(&self) -> u32 {
        self.net.unwrap_or(MCTP_NET_ANY)
    }

    /// Create an `MctpLinuxReq` using the net & eid values in this address.
    pub fn create_endpoint(&self) -> Result<MctpLinuxReq> {
        MctpLinuxReq::new(self.eid, self.net)
    }

    /// Create an `MCTPListener`.
    ///
    /// The net of the listener comes from this address, with the MCTP
    /// message type as an argument.
    pub fn create_listener(&self, typ: MsgType) -> Result<MctpLinuxListener> {
        MctpLinuxListener::new(typ, self.net)
    }

    /// Create an `MctpLinuxAsyncReq` using the net & eid values in this address.
    pub fn create_req_async(&self) -> Result<MctpLinuxAsyncReq> {
        MctpLinuxAsyncReq::new(self.eid, self.net)
    }

    /// Create an `MctpLinuxAsyncListener`.
    pub fn create_listener_async(
        &self,
        typ: MsgType,
    ) -> Result<MctpLinuxAsyncListener> {
        MctpLinuxAsyncListener::new(typ, self.net)
    }
}
