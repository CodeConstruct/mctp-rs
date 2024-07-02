// SPDX-License-Identifier: Apache-2.0
/*
 * MCTP common types and traits.
 *
 * Copyright (c) 2024 Code Construct
 */

// Tests may use std
#![cfg_attr(not(any(feature = "std", test)), no_std)]
#![forbid(unsafe_code)]

#![warn(missing_docs)]

//! Management Component Transport Protocol (MCTP)
//!
//! This crate provides common types and traits for MCTP.
//! Implementations can implement [`Endpoint`] to represent
//! a remote endpoint.

/// MCTP endpoint ID
#[derive(Clone, Copy, Debug)]
pub struct Eid(pub u8);

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
#[derive(Clone, Copy, Debug)]
pub struct TagValue(pub u8);

/// Tag Owner (TO) field; generally set in a request, clear in a response.
pub const MCTP_TAG_OWNER: u8 = 0x08;

/// MCTP Message type field
///
/// Note that this does not include the Integrity Check bit; the
/// most-significant bit will always be zero.
///
/// Defined values are in DSP0239
#[derive(Clone, Copy, Debug)]
pub struct MsgType(pub u8);

impl core::fmt::Display for MsgType {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        self.0.fmt(fmt)
    }
}

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
/// `Owned` and `OwnedAuto` indicate that the tag is allocated locally.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Tag {
    /// Existing tag is passed to `send()`. Owner bit is unset, used for responses.
    Unowned(TagValue),
    /// Preallocated tag is passed to `send()`, owner bit is set
    Owned(TagValue),
}

impl Tag {
    /// Creates a `Tag` from a received MCTP packet TO byte
    pub fn from_to_field(to: u8) -> Self {
        let t = TagValue(to & !MCTP_TAG_OWNER);
        if to & MCTP_TAG_OWNER == 0 {
            Self::Unowned(t)
        } else {
            Self::Owned(t)
        }
    }

    /// Returns the tag
    pub fn tag(&self) -> TagValue {
        match self {
            Self::Unowned(tag) | Self::Owned(tag) => {
                *tag
            }
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
            Tag::Unowned(v) => write!(fmt, "!TO,{:x}", v.0)
        }
    }
}

/// An error type for a `Endpoint`
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
#[non_exhaustive]
pub enum Error {
    /// Failure in transmit path, typically transport-specific
    TxFailure,
    /// Timed out waiting for the remote peer
    TimedOut,
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
impl std::error::Error for Error { }

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

/// A trait for an MCTP peer
///
/// This can be used by higher layer protocols to send/receive messages
/// to a remote endpoint.
///
/// It should be implemented by specific MCTP implementations.
pub trait Endpoint {
    /// Send a message to this endpoint, blocking.
    ///
    /// A `tag` argument will request the MCTP stack to allocate a
    /// new `Owned` tag.
    ///
    /// The slice of buffers will be sent as a single message
    /// (as if concatenated). Accepting multiple buffers allows
    /// higher level protocols to more easily append their own
    /// protocol headers to a payload without needing extra
    /// buffer allocations.
    fn send_vectored(
        &mut self,
        typ: MsgType,
        tag: Option<Tag>,
        bufs: &[&[u8]],
    ) -> Result<()>;

    /// Send a message to this endpoint, blocking.
    fn send(
        &mut self,
        typ: MsgType,
        tag: Option<Tag>,
        buf: &[u8],
    ) -> Result<()> {
        self.send_vectored(typ, tag, &[buf])
    }

    /// Blocking receive from this endpoint.
    ///
    /// Returns a filled slice of `buf`, EID, and tag.
    ///
    /// The returned [`Tag`] must be `Tag::Unowned` or
    /// `Tag::Owned`. `Owned` can only occur if `bind()` has
    /// been called.
    fn recv<'f>(
        &mut self,
        buf: &'f mut [u8],
    ) -> Result<(&'f mut [u8], Eid, Tag)>;

    /// Bind the endpoint to a type value, so we can receive
    /// incoming requests with this endpoint.
    fn bind(&mut self, typ: MsgType) -> Result<()>;
}
