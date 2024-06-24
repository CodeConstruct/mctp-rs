// SPDX-License-Identifier: Apache-2.0
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
//! [`MctpLinuxEp`] provides a thin wrapper that represents a remote endpoint,
//! referenced by EID. It creates a single socket for communication with that
//! endpoint. This is a convenience for simple consumers that perform
//! single-endpoint communication; general MCTP requesters may want a different
//! socket model.

use core::mem;
use std::fmt;
use std::io::Error;
use std::os::unix::io::RawFd;
use std::time::Duration;

use mctp::{
    Eid,
    MCTP_ADDR_ANY,
    MsgType,
    Result,
    Tag,
    TagValue,
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

/// Special value for Network ID: any network. May be used in `bind()`.
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

// helper for IO error construction
fn last_os_error() -> mctp::Error {
    mctp::Error::Io(Error::last_os_error())
}

/// MCTP socket object.
pub struct MctpSocket(RawFd);

impl Drop for MctpSocket {
    fn drop(&mut self) {
        unsafe { libc::close(self.0) };
    }
}

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
            return Err(last_os_error())
        }
        Ok(MctpSocket(rc))
    }

    /// Blocking receive from a socket, into `buf`, returning a length
    /// and source address
    ///
    /// Essentially a wrapper around [libc::recvfrom], using MCTP-specific
    /// addressing.
    pub fn recvfrom(&self, buf: &mut [u8]) -> Result<(usize, MctpSockAddr)> {
        let mut addr = MctpSockAddr::zero();
        let (addr_ptr, mut addr_len) = addr.as_raw_mut();
        let buf_ptr = buf.as_mut_ptr() as *mut libc::c_void;
        let buf_len = buf.len() as libc::size_t;

        let rc = unsafe {
            libc::recvfrom(self.0, buf_ptr, buf_len, 0, addr_ptr, &mut addr_len)
        };

        if rc < 0 {
            Err(last_os_error())
        } else {
            Ok((rc as usize, addr))
        }
    }

    /// Blocking send to a socket, given a buffer and address, returning
    /// the number of bytes sent.
    ///
    /// Essentially a wrapper around [libc::sendto].
    pub fn sendto(&self, buf: &[u8], addr: &MctpSockAddr) -> Result<usize> {
        let (addr_ptr, addr_len) = addr.as_raw();
        let buf_ptr = buf.as_ptr() as *const libc::c_void;
        let buf_len = buf.len() as libc::size_t;

        let rc = unsafe {
            libc::sendto(self.0, buf_ptr, buf_len, 0, addr_ptr, addr_len)
        };

        if rc < 0 {
            Err(last_os_error())
        } else {
            Ok(rc as usize)
        }
    }

    /// Bind the socket to a local address.
    pub fn bind(&self, addr: &MctpSockAddr) -> Result<()> {
        let (addr_ptr, addr_len) = addr.as_raw();

        let rc = unsafe { libc::bind(self.0, addr_ptr, addr_len) };

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
        let rc = unsafe {
            libc::setsockopt(
                self.0,
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
        let rc = unsafe {
            libc::getsockopt(
                self.0,
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
                return Err(mctp::Error::Other)
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
        self.0
    }
}

/// Encapsulation of a remote endpoint: a socket and an Endpoint ID.
pub struct MctpLinuxEp {
    eid: u8,
    net: u32,
    sock: MctpSocket,
}

impl MctpLinuxEp {
    /// Create a new MCTPEndpoint with EID `eid`
    pub fn new(eid: u8, net: u32) -> Result<Self> {
        Ok(Self {
            eid,
            net,
            sock: MctpSocket::new()?,
        })
    }

    /// Clone this endpoint.
    ///
    /// Creates a separate socket descriptor for the new endpoint.
    pub fn try_clone(&self) -> Result<Self> {
        Self::new(self.eid, self.net)
    }

    /// Borrow the internal MCTP socket
    pub fn as_socket(&mut self) -> &mut MctpSocket {
        &mut self.sock
    }
}

impl mctp::Endpoint for MctpLinuxEp {
    fn send_vectored(
        &mut self,
        typ: MsgType,
        tag: Tag,
        bufs: &[&[u8]],
    ) -> Result<()> {
        // Linux expects tag 0, owner bit set to allocate.
        let mut t = tag.tag().unwrap_or(TagValue(0)).0;
        if tag.is_owner() {
            t |= mctp::MCTP_TAG_OWNER;
        }

        let addr = MctpSockAddr::new(self.eid, self.net, typ.0, t);
        // TODO: implement sendmsg() with iovecs
        let concat = bufs
            .iter()
            .flat_map(|b| b.iter().cloned())
            .collect::<Vec<u8>>();
        self.sock.sendto(&concat, &addr)?;
        Ok(())
    }

    fn recv<'f>(&mut self, buf: &'f mut [u8]) -> Result<(&'f mut [u8], Eid, Tag)> {
        let (sz, addr) = self.sock.recvfrom(buf)?;
        if addr.0.smctp_addr != self.eid {
            // Kernel gave us a message from a different sender?
            return Err(mctp::Error::Other)
        }
        Ok((&mut buf[..sz], Eid(self.eid), Tag::from_to_field(addr.0.smctp_tag)))
    }

    /// Bind the endpoint's socket to a type value, so we can receive
    /// incoming requests from this endpoint.
    ///
    /// Note that this only specifies the local EID for the bind; there
    /// can only be one bind of that type for any one network.
    fn bind(&mut self, typ: MsgType) -> Result<()> {
        let addr =
            MctpSockAddr::new(MCTP_ADDR_ANY.0, self.net, typ.0, mctp::MCTP_TAG_OWNER);
        self.sock.bind(&addr)
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
    eid: u8,
    net: Option<u32>,
}

impl std::str::FromStr for MctpAddr {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<MctpAddr, String> {
        let mut parts = s.split(|c| c == ',');

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
    pub fn eid(&self) -> u8 {
        self.eid
    }

    /// Return the MCTP Network ID for this address, defaulting to MCTP_NET_ANY
    /// if none was provided originally.
    pub fn net(&self) -> u32 {
        self.net.unwrap_or(MCTP_NET_ANY)
    }

    /// Create an MCTPEndpoint using the net & eid values in this address.
    pub fn create_endpoint(&self) -> Result<MctpLinuxEp> {
        MctpLinuxEp::new(self.eid, self.net())
    }
}
