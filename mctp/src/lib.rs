// Tests may use std
#![cfg_attr(not(any(feature = "std", test)), no_std)]
#![forbid(unsafe_code)]

#![warn(missing_docs)]

//! Management Component Transport Protocol (MCTP)
//!
//! This crate provides common types and traits for MCTP.
//! Implementations can implement [`MctpEndpoint`] to represent
//! a remote endpoint.

/// MCTP endpoint ID
#[derive(Clone, Copy, Debug)]
pub struct Eid(pub u8);

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
/// Defined values are in DSP0239
#[derive(Clone, Copy, Debug)]
pub struct MsgType(pub u8);

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
#[derive(Clone, Copy, Debug)]
pub enum Tag {
    /// MCTP stack will allocate a tag on `send()`, owner bit is set
    OwnedAuto,
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

    /// Returns the tag, or `None` for `OwnedAuto`
    pub fn tag(&self) -> Option<TagValue> {
        match self {
            Self::OwnedAuto => None,
            Self::Unowned(tag) | Self::Owned(tag) => {
                Some(*tag)
            }
        }
    }

    /// Returns `true` for `Owned` or `OwnedAuto`
    pub fn is_owner(&self) -> bool {
        match self {
            Self::OwnedAuto | Self::Owned(_) => true,
            Self::Unowned(_) => false,
        }
    }
}

/// An error type for a `MctpEndpoint`
pub trait MctpError: core::fmt::Display + core::fmt::Debug {}

#[cfg(feature = "std")]
impl MctpError for std::io::Error {}

/// A trait for an MCTP peer
///
/// This can be used by higher layer protocols to send/receive messages
/// to a remote endpoint.
///
/// It should be implemented by specific MCTP implementations.
pub trait MctpEndpoint {
    /// Error type returned on failure
    // TODO: use core::error::Error once stable
    // https://github.com/rust-lang/rust/issues/103765
    type Error: MctpError;

    /// Send a message to this endpoint, blocking.
    ///
    /// The slice of buffers will be sent as a single message
    /// (as if concatenated). Accepting multiple buffers allows
    /// higher level protocols to more easily append their own
    /// protocol headers to a payload without needing extra
    /// buffer allocations.
    fn send_vectored(
        &mut self,
        typ: MsgType,
        tag: Tag,
        bufs: &[&[u8]],
    ) -> Result<(), Self::Error>;

    /// Send a message to this endpoint, blocking.
    fn send(
        &mut self,
        typ: MsgType,
        tag: Tag,
        buf: &[u8],
    ) -> Result<(), Self::Error> {
        self.send_vectored(typ, tag, &[buf])
    }

    /// Blocking recieve from this endpoint.
    ///
    /// Returns a filled slice of `buf`, EID, and tag.
    ///
    /// The returned [`Tag`] must be `Tag::Unowned` or
    /// `Tag::Owned`. `Owned` can only occur if `bind()` has
    /// been called.
    fn recv<'f>(
        &mut self,
        buf: &'f mut [u8],
    ) -> Result<(&'f mut [u8], Eid, Tag), Self::Error>;

    /// Bind the endpoint to a type value, so we can receive
    /// incoming requests with this endpoint.
    fn bind(&mut self, typ: MsgType) -> Result<(), Self::Error>;
}
