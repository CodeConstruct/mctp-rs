// SPDX-License-Identifier: GPL-3.0-or-later
/*
 * MCTP support through Linux kernel-based sockets
 *
 * Copyright (c) 2024 Code Construct
 */

#![warn(missing_docs)]

//! Interface for the Linux socket-based MCTP support.
//!
//! This crate provides some minimal wrappers around standard [libc] socket
//! operations, using MCTP-specific addressing structures.
//!
//! [MctpSocket] provides support for blocking socket operations
//! [sendto](MctpSocket::sendto), [recvfrom](MctpSocket::recvfrom) and
//! [bind](MctpSocket::bind).
//!
//! ```no_run
//! use mctp_linux;
//!
//! let sock = mctp_linux::MctpSocket::new()?;
//! let bind_addr = mctp_linux::MctpSockAddr::new(
//!     mctp_linux::MCTP_ADDR_ANY,
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
//! [MctpEndpoint] provides a thin wrapper that represents a remote endpoint,
//! referenced by EID. It creates a single socket for communication with that
//! endpoint. This is a convenience for simple consumers that perform
//! single-endpoint communucation; general MCTP requesters may want a different
//! socket model.

use core::mem;
use std::fmt;
use std::io::{Error, ErrorKind, Result};
use std::os::unix::io::RawFd;

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

/// The Tag Owner (TO) field; generally set in a request, clear in a response.
pub const MCTP_TAG_OWNER: u8 = 0x08;

/// Special value for Network ID: any network. May be used in bind().
pub const MCTP_NET_ANY: u32 = 0x00;

/// Specical EID value: broadcast and/or match any.
pub const MCTP_ADDR_ANY: u8 = 0xff;

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
            return Err(Error::last_os_error());
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
            Err(Error::last_os_error())
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
            Err(Error::last_os_error())
        } else {
            Ok(rc as usize)
        }
    }

    /// Bind the socket to a local address.
    pub fn bind(&self, addr: &MctpSockAddr) -> Result<()> {
        let (addr_ptr, addr_len) = addr.as_raw();

        let rc = unsafe { libc::bind(self.0, addr_ptr, addr_len) };

        if rc < 0 {
            Err(Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

/// Encapsulation of a remote endpoint: a socket and an Endpoint ID.
pub struct MctpEndpoint {
    eid: u8,
    net: u32,
    sock: MctpSocket,
}

impl MctpEndpoint {
    /// Create a new MCTPEndpoint with EID `eid`
    pub fn new(eid: u8, net: u32) -> Result<Self> {
        Ok(MctpEndpoint {
            eid,
            net,
            sock: MctpSocket::new()?,
        })
    }

    /// Send a message to this endpoint, blocking.
    pub fn send(&self, typ: u8, tag: u8, buf: &[u8]) -> Result<()> {
        let addr = MctpSockAddr::new(self.eid, self.net, typ, tag);
        self.sock.sendto(buf, &addr)?;
        Ok(())
    }

    /// Blocking recieve from this endpoint.
    pub fn recv(&self, buf: &mut [u8]) -> Result<(usize, u8)> {
        let (sz, addr) = self.sock.recvfrom(buf)?;
        if addr.0.smctp_addr != self.eid {
            return Err(Error::new(ErrorKind::Other, "invalid sender"));
        }
        Ok((sz, addr.0.smctp_tag))
    }

    /// Bind the endpoint's socket to a type value, so we can receive
    /// incoming requests from this endpoint.
    ///
    /// Note that this only specifies the local EID for the bind; there
    /// can only be one bind of that type for any one network.
    pub fn bind(&self, typ: u8) -> Result<()> {
        let addr =
            MctpSockAddr::new(MCTP_ADDR_ANY, self.net, typ, MCTP_TAG_OWNER);
        self.sock.bind(&addr)
    }
}
