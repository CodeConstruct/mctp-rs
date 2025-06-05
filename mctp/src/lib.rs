// SPDX-License-Identifier: MIT OR Apache-2.0
/*
 * MCTP common types and traits.
 *
 * Copyright (c) 2024 Code Construct
 */

// Tests may use std
#![cfg_attr(not(any(feature = "std", test)), no_std)]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! # Management Component Transport Protocol (MCTP)
//!
//! This crate provides common types and traits for MCTP.
//! Transport implementations can implement [`ReqChannel`] and [`Listener`] to
//! communicate with a remote endpoint.

use core::future::Future;

/// MCTP endpoint ID
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Eid(pub u8);

impl Eid {
    /// Construct a new normal EID.
    ///
    /// Reserved, Null, and Broadcast EIDs are rejected.
    pub const fn new_normal(eid: u8) -> Result<Eid> {
        if eid <= 7 || eid == 0xff {
            Err(Error::BadArgument)
        } else {
            Ok(Eid(eid))
        }
    }
}

impl core::fmt::Display for Eid {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        self.0.fmt(fmt)
    }
}

/// Special EID value: broadcast and/or match any.
pub const MCTP_ADDR_ANY: Eid = Eid(0xff);
/// Special EID value: NULL
pub const MCTP_ADDR_NULL: Eid = Eid(0x00);

/// MCTP Message Tag
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TagValue(pub u8);

/// Tag Owner (TO) field; generally set in a request, clear in a response.
pub const MCTP_TAG_OWNER: u8 = 0x08;

/// MCTP Message type field
///
/// Note that this does not include the Integrity Check bit; the
/// most-significant bit will always be zero.
///
/// Defined values are in DSP0239
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct MsgType(pub u8);

impl core::fmt::Display for MsgType {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        self.0.fmt(fmt)
    }
}

/// MCTP Message Integrity Check field.
#[derive(Default, Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct MsgIC(pub bool);

/// MCTP Control Protocol
pub const MCTP_TYPE_CONTROL: MsgType = MsgType(0x00);
/// PLDM
pub const MCTP_TYPE_PLDM: MsgType = MsgType(0x01);
/// NC-SI over MCTP
pub const MCTP_TYPE_NCSI: MsgType = MsgType(0x02);
/// Ethernet over MCTP
pub const MCTP_TYPE_ETHERNET: MsgType = MsgType(0x03);
/// NVMe over MCTP
pub const MCTP_TYPE_NVME: MsgType = MsgType(0x04);
/// SPDM
pub const MCTP_TYPE_SPDM: MsgType = MsgType(0x05);
/// Secured Messages using SPDM
pub const MCTP_TYPE_SPDM_SECURED: MsgType = MsgType(0x06);
/// CXL Fabric Manger
pub const MCTP_TYPE_CXL_FM: MsgType = MsgType(0x07);
/// CXL Component Command Interface
pub const MCTP_TYPE_CXL_CCI: MsgType = MsgType(0x08);
/// PCIe Management Interface
pub const MCTP_TYPE_PCIE_MI: MsgType = MsgType(0x09);
/// Vendor defined, PCIe ID
pub const MCTP_TYPE_VENDOR_PCIE: MsgType = MsgType(0x7e);
/// Vendor defined, IANA ID
pub const MCTP_TYPE_VENDOR_IANA: MsgType = MsgType(0x7f);

/// MCTP Version 1
pub const MCTP_HEADER_VERSION_1: u8 = 1;

/// MCTP minimum payload MTU
///
/// This minimum is required to be supported by all implementations
pub const MCTP_MIN_MTU: usize = 64;
/// Mask for MCTP Packet Sequence Number
pub const MCTP_SEQ_MASK: u8 = 0x03;
/// Maximum MCTP Message Tag number
pub const MCTP_TAG_MAX: u8 = 7;

/// Identifies a tag and allocation method
///
/// `Owned` and indicates that the tag is allocated locally.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum Tag {
    /// Existing tag is passed to `send()`. Owner bit is unset, used for responses.
    Unowned(TagValue),
    /// Preallocated tag is passed to `send()`, owner bit is set
    Owned(TagValue),
}

impl Tag {
    /// Returns the tag
    pub fn tag(&self) -> TagValue {
        match self {
            Self::Unowned(tag) | Self::Owned(tag) => *tag,
        }
    }

    /// Returns `true` for `Owned`
    pub fn is_owner(&self) -> bool {
        matches!(self, Self::Owned(_))
    }
}

impl core::fmt::Display for Tag {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Tag::Owned(v) => write!(fmt, "TO,{:x}", v.0),
            Tag::Unowned(v) => write!(fmt, "!TO,{:x}", v.0),
        }
    }
}

/// An error type for MCTP
///
/// The options here intend to capture typical transport failures, but also
/// allow platform-specific errors to be reported through the `Other`
/// and `Io` (on `std`) members.
///
/// Errors that are platform-specific typically cannot be handled gracefully
/// by an application (say, by deciding whether or not to retry). If a
/// new error type is needed, we can extend this enum to represent that
/// failure mode, hence the `non_exhaustive`.
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[non_exhaustive]
pub enum Error {
    /// Failure in transmit path, typically transport-specific
    TxFailure,
    /// Failure in receive path, typically transport-specific
    RxFailure,
    /// Timed out waiting for the remote peer
    TimedOut,
    /// Bad argument
    BadArgument,
    /// Invalid input
    InvalidInput,
    /// A tag cannot be allocated, or the tag specified cannot be used
    TagUnavailable,
    /// The remote peer cannot be reached
    Unreachable,
    /// The requested address is in use
    AddrInUse,
    /// Provided buffer is too small
    NoSpace,
    /// Operation is unsupported
    Unsupported,
    /// Other error type
    Other,
    /// Internal error
    InternalError,
    /// IO error from transport binding
    #[cfg(feature = "std")]
    Io(std::io::Error),
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

impl core::fmt::Display for Error {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            #[cfg(feature = "std")]
            Self::Io(i) => write!(fmt, "MCTP IO Error: {}", i),
            _ => write!(fmt, "MCTP Error: {:?}", self),
        }
    }
}

#[cfg(feature = "std")]
impl From<Error> for std::io::Error {
    fn from(e: Error) -> std::io::Error {
        std::io::Error::other(e)
    }
}

/// MCTP result type
pub type Result<T> = core::result::Result<T, Error>;

/// A trait for communicating with an MCTP peer.
///
/// This can be used by higher layer protocols to send/receive messages
/// with a remote endpoint. A `mctp::ReqChannel` instance represents an endpoint/tag pair,
/// so may be used for request-response messaging.
///
/// A `send` on a `ReqChannel` instance will associate the instance with a
/// tag, and `recv` is expected to be limited to responses matching that
/// sent tag. When multiple tags are being used simultaneously, separate `ReqChannel`
/// instances should be used. Tags will be allocated internally as trait implementation
/// detail, not exposed through the trait API.
///
/// A `ReqChannel` may be re-used to send a new allocated tag if no further
/// messages for a previous tag are expected to be received.
pub trait ReqChannel {
    /// Send a slice of buffers to this endpoint, blocking.
    ///
    /// The Tag Owner bit will be set in the sent message, either
    /// with a newly allocated tag, or with a pre-allocated tag
    /// if set.
    ///
    /// The slice of buffers will be sent as a single message
    /// (as if concatenated). Accepting multiple buffers allows
    /// higher level protocols to more easily append their own
    /// protocol headers to a payload without needing extra
    /// buffer allocations.
    ///
    /// The `integrity_check` argument is the MCTP header IC bit.
    fn send_vectored(
        &mut self,
        typ: MsgType,
        integrity_check: MsgIC,
        bufs: &[&[u8]],
    ) -> Result<()>;

    /// Send a message to this endpoint, blocking.
    ///
    /// Transport implementations will typically use the trait provided method
    /// that calls [`send_vectored`](Self::send_vectored).
    ///
    /// IC bit is unset.
    fn send(&mut self, typ: MsgType, buf: &[u8]) -> Result<()> {
        self.send_vectored(typ, MsgIC(false), &[buf])
    }

    /// Blocking receive
    ///
    /// Returns a filled slice of `buf`, MCTP message type, and IC bit.
    /// Will fail if used without a prior call to `send` or `send_vectored`.
    fn recv<'f>(
        &mut self,
        buf: &'f mut [u8],
    ) -> Result<(MsgType, MsgIC, &'f mut [u8])>;

    /// Return the remote Endpoint ID
    fn remote_eid(&self) -> Eid;
}

#[allow(missing_docs)]
/// Async equivalent of [`ReqChannel`]
pub trait AsyncReqChannel {
    fn send_vectored(
        &mut self,
        typ: MsgType,
        integrity_check: MsgIC,
        bufs: &[&[u8]],
    ) -> impl Future<Output = Result<()>>;

    fn send(
        &mut self,
        typ: MsgType,
        buf: &[u8],
    ) -> impl Future<Output = Result<()>> {
        async move { self.send_vectored(typ, MsgIC(false), &[buf]).await }
    }

    fn recv<'f>(
        &mut self,
        buf: &'f mut [u8],
    ) -> impl Future<Output = Result<(MsgType, MsgIC, &'f mut [u8])>>;

    /// Return the remote Endpoint ID
    fn remote_eid(&self) -> Eid;
}

/// A MCTP response channel
///
/// This is returned from a [`Listener`] for incoming messages, is used to send responses.
pub trait RespChannel {
    /// `ReqChannel` type returned by [`req_channel`](Self::req_channel)
    type ReqChannel: ReqChannel;

    /// Send a slice of buffers to this endpoint, blocking.
    ///
    /// The slice of buffers will be sent as a single message
    /// (as if concatenated). Accepting multiple buffers allows
    /// higher level protocols to more easily append their own
    /// protocol headers to a payload without needing extra
    /// buffer allocations.
    ///
    /// The sent message type will match that received by the
    /// corresponding `Listener`.
    ///
    /// The `integrity_check` argument is the MCTP header IC bit.
    fn send_vectored(
        &mut self,
        integrity_check: MsgIC,
        bufs: &[&[u8]],
    ) -> Result<()>;

    /// Send a message to this endpoint, blocking.
    ///
    /// Transport implementations will typically use the trait provided method
    /// that calls [`send_vectored`](Self::send_vectored).
    ///
    /// The sent message type will match that received by the
    /// corresponding `Listener`.
    ///
    /// IC bit is unset.
    fn send(&mut self, buf: &[u8]) -> Result<()> {
        self.send_vectored(MsgIC(false), &[buf])
    }

    /// Return the remote Endpoint ID
    fn remote_eid(&self) -> Eid;

    /// Constructs a new ReqChannel to the same MCTP endpoint as this RespChannel.
    fn req_channel(&self) -> Result<Self::ReqChannel>;
}

#[allow(missing_docs)]
/// Async equivalent of [`RespChannel`]
pub trait AsyncRespChannel {
    /// `ReqChannel` type returned by [`req_channel`](Self::req_channel)
    type ReqChannel<'a>: AsyncReqChannel
    where
        Self: 'a;

    /// Send a slice of buffers to this endpoint, blocking.
    ///
    /// The slice of buffers will be sent as a single message
    /// (as if concatenated). Accepting multiple buffers allows
    /// higher level protocols to more easily append their own
    /// protocol headers to a payload without needing extra
    /// buffer allocations.
    ///
    /// The sent message type will match that received by the
    /// corresponding `AsyncListener`.
    ///
    /// The `integrity_check` argument is the MCTP header IC bit.
    fn send_vectored(
        &mut self,
        integrity_check: MsgIC,
        bufs: &[&[u8]],
    ) -> impl Future<Output = Result<()>>;

    /// Send a message to this endpoint, blocking.
    ///
    /// Transport implementations will typically use the trait provided method
    /// that calls [`send_vectored`](Self::send_vectored).
    ///
    /// The sent message type will match that received by the
    /// corresponding `AsyncListener`.
    ///
    /// IC bit is unset.
    fn send(&mut self, buf: &[u8]) -> impl Future<Output = Result<()>> {
        async move { self.send_vectored(MsgIC(false), &[buf]).await }
    }

    /// Return the remote Endpoint ID
    fn remote_eid(&self) -> Eid;

    /// Constructs a new ReqChannel to the same MCTP endpoint as this RespChannel.
    // TODO: should this be async?
    fn req_channel(&self) -> Result<Self::ReqChannel<'_>>;
}

/// A MCTP listener instance
///
/// This will receive messages with TO=1. Platform-specific constructors
/// will specify the MCTP message parameters (eg, message type) to listen for.
pub trait Listener {
    /// `RespChannel` type returned by this `Listener`
    type RespChannel<'a>: RespChannel
    where
        Self: 'a;

    /// Blocking receive
    ///
    /// This receives a single MCTP message matched by the `Listener`.
    /// Returns a filled slice of `buf`, `RespChannel`, and IC bit `MsgIC`.
    ///
    /// The returned `RespChannel` should be used to send responses to the
    /// request.
    fn recv<'f>(
        &mut self,
        buf: &'f mut [u8],
    ) -> Result<(MsgType, MsgIC, &'f mut [u8], Self::RespChannel<'_>)>;
}

#[allow(missing_docs)]
/// Async equivalent of [`Listener`]
pub trait AsyncListener {
    /// `RespChannel` type returned by this `Listener`
    type RespChannel<'a>: AsyncRespChannel
    where
        Self: 'a;

    /// Blocking receive
    ///
    /// This receives a single MCTP message matched by the `Listener`.
    /// Returns a filled slice of `buf`, `RespChannel`, and IC bit `MsgIC`.
    ///
    /// The returned `RespChannel` should be used to send responses.
    fn recv<'f>(
        &mut self,
        buf: &'f mut [u8],
    ) -> impl Future<
        Output = Result<(MsgType, MsgIC, &'f mut [u8], Self::RespChannel<'_>)>,
    >;
}

const MCTP_IC_MASK: u8 = 0x80;

/// Encode message type and IC bit
///
/// For transport implementations.
pub fn encode_type_ic(typ: MsgType, ic: MsgIC) -> u8 {
    let ic_val = if ic.0 { MCTP_IC_MASK } else { 0 };
    typ.0 & !MCTP_IC_MASK | ic_val
}

/// Decode message type and IC bit
///
/// For transport implementations.
pub fn decode_type_ic(ic_typ: u8) -> (MsgType, MsgIC) {
    (
        MsgType(ic_typ & !MCTP_IC_MASK),
        MsgIC((ic_typ & MCTP_IC_MASK) != 0),
    )
}
