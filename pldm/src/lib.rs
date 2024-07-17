// SPDX-License-Identifier: MIT OR Apache-2.0
/*
 * PLDM base message definitions.
 *
 * Copyright (c) 2023 Code Construct
 */
#![cfg_attr(not(any(feature = "std", test)), no_std)]
#![forbid(unsafe_code)]

#![warn(missing_docs)]

//! Platform Level Data Model (PLDM) base protocol support
//!
//! This crate implements some base communication primitives for PLDM,
//! used to construct higher-level PLDM messaging applications.

use mctp::Tag;

pub mod util;
use util::*;

/// Maximum size of a PLDM message, defining our buffer sizes.
///
/// The `pldm` crate currently has a maximum message size.
pub const PLDM_MAX_MSGSIZE: usize = 1024;

/// Generic PLDM error type
#[derive(Debug)]
pub enum PldmError {
    /// PLDM protocol error
    Protocol(ErrStr),
    /// MCTP communication error
    Mctp(mctp::Error),
    /// Invalid argument
    InvalidArgument,
    /// No buffer space available
    NoSpace,
}

impl core::fmt::Display for PldmError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Protocol(s) => write!(f, "PLDM protocol error: {s}"),
            Self::Mctp(s) => write!(f, "MCTP error: {s}"),
            Self::InvalidArgument => write!(f, "Invalid Argument"),
            Self::NoSpace => write!(f, "Insufficient buffer space available"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PldmError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Mctp(s) => Some(s),
            _ => None,
        }
    }
}

impl From<mctp::Error> for PldmError {
    fn from(e: mctp::Error) -> PldmError {
        PldmError::Mctp(e)
    }
}

#[cfg(feature = "alloc")]
type ErrStr = String;
#[cfg(not(feature = "alloc"))]
type ErrStr = &'static str;

/// Create a `PldmError::Protocol` from a message and optional description.
///
/// When building without `alloc` feature only the message is kept.
///
/// Example
///
/// ```
/// # let iid = 1;
/// # let actual_iid = 2;
/// use pldm::proto_error;
/// proto_error!("Mismatching IID", "Expected {iid:02x}, received {actual_iid:02x}");
/// proto_error!("Rq bit wasn't expected");
/// ```
#[macro_export]
#[cfg(feature = "alloc")]
macro_rules! proto_error {
    ($msg: expr, $desc_str: expr)
        => { $crate::PldmError::Protocol(format!("{}. {}", $msg, $desc_str)) };
    ($msg: expr)
        => { $crate::PldmError::Protocol(format!("{}.", $msg)) };
}

/// Create a `PldmError::Protocol` from a message and optional description.
///
/// When building without `alloc` feature only the message is kept.
///
/// Example
///
/// ```
/// # let iid = 1;
/// # let actual_iid = 2;
/// use pldm::proto_error;
/// proto_error!("Mismatching IID", "Expected {iid:02x}, received {actual_iid:02x}");
/// proto_error!("Rq bit wasn't expected");
/// ```
#[macro_export]
#[cfg(not(feature = "alloc"))]
macro_rules! proto_error {
    ($msg: expr, $desc_str: expr) => { $crate::PldmError::Protocol($msg) };
    ($msg: expr) => { $crate::PldmError::Protocol($msg) };
}


/// PLDM protocol return type
pub type Result<T> = core::result::Result<T, PldmError>;

#[allow(missing_docs)]
#[repr(u8)]
#[allow(non_camel_case_types)]
pub enum CCode {
    SUCCESS = 0,
    ERROR = 1,
    ERROR_INVALID_DATA = 2,
    ERROR_INVALID_LENGTH = 3,
    ERROR_NOT_READY = 4,
    ERROR_UNSUPPORTED_PLDM_CMD = 5,
    ERROR_INVALID_PLDM_TYPE = 32,
}

/// Base PLDM request type
#[derive(Debug)]
pub struct PldmRequest<'a> {
    /// MCTP tag used for the request. Set to `None` to allocate for outgoing
    /// requests, set to `Some(Tag::Owned)` for incoming requests.
    pub mctp_tag: Option<Tag>,
    /// PLDM Instance ID
    pub iid: u8,
    /// PLDM type.
    pub typ: u8,
    /// PLDM command code
    pub cmd: u8,
    /// PLDM command data payload
    pub data: VecOrSlice<'a, u8>,
}

#[cfg(feature = "alloc")]
impl<'a> PldmRequest<'a> {
    /// Converts any `PldmRequest` into one with allocated storage
    pub fn make_owned(self) -> PldmRequest<'static> {
        let d = match self.data {
            VecOrSlice::Borrowed(b) => b.to_vec().into(),
            VecOrSlice::Owned(b) => VecOrSlice::Owned(b),
        };
        PldmRequest { data: d, ..self }
    }

    /// Set the data payload for this request
    pub fn set_data(&mut self, data: Vec<u8>) {
        self.data = data.into()
    }

    /// Create a new PLDM request for a given PLDM message type and command
    ///
    /// Convert this request to a response, using the correct MCTP tag value
    /// (swapping to a non-owned tag), and the instance, type and command
    /// from the original request.
    ///
    /// Will fail if this `PldmRequest` does not have an allocated tag.
    pub fn response(&self) -> Result<PldmResponse> {
        let Some(Tag::Owned(tv)) = self.mctp_tag else {
            return Err(PldmError::InvalidArgument);
        };
        let resp_tag = Tag::Unowned(tv);
        Ok(PldmResponse {
            mctp_tag: resp_tag,
            iid: self.iid,
            typ: self.typ,
            cmd: self.cmd,
            cc: 0,
            data: Vec::new().into(),
        })
    }
}

// Constructors for allocated requests
#[cfg(feature = "alloc")]
impl PldmRequest<'static> {
    /// Create a new PLDM request for a given PLDM message type and command
    /// number.
    ///
    /// Since this creates a request, it specifies a `None`
    /// tag, for the lower-level MCTP stack to assign
    /// an actual tag value.
    pub fn new(typ: u8, cmd: u8) -> Self {
        Self::new_data(typ, cmd, Vec::new())
    }

    /// Create a new PLDM request with a data payload.
    ///
    /// Since this creates a request, it specifies a `None`
    /// tag, for the lower-level MCTP stack to assign
    /// an actual tag value.
    pub fn new_data(typ: u8, cmd: u8, data: Vec<u8>) -> Self {
        Self {
            mctp_tag: None,
            iid: 0,
            typ,
            cmd,
            data: data.into(),
        }
    }

    /// Create a PLDM request given a MCTP tag value and message data.
    ///
    /// May fail if the message data is not parsable as a PLDM message.
    /// Pass a `tag` of `None` to specify an automatically allocated owned tag.
    pub fn from_buf<'f>(tag: Option<Tag>, data: &'f [u8]) -> Result<Self> {
        PldmRequest::from_buf_borrowed(tag, data).map(|p| p.make_owned())
    }
}

impl<'a> PldmRequest<'a> {
    /// Create a new PLDM request with a data payload borrowed from a slice.
    ///
    /// Since this creates a request, it specifies a `None`
    /// tag, for the lower-level MCTP stack to assign
    /// an actual tag value.
    pub fn new_borrowed(typ: u8, cmd: u8, data: &'a [u8]) -> Self {
        Self {
            mctp_tag: None,
            iid: 0,
            typ,
            cmd,
            data: data.into(),
        }
    }

    /// Create a PLDM request given a MCTP tag value and message data.
    ///
    /// The payload is borrowed from the input data.
    /// May fail if the message data is not parsable as a PLDM message.
    pub fn from_buf_borrowed(tag: Option<Tag>, data: &'a [u8]) -> Result<PldmRequest<'a>> {
        if data.len() < 3 {
            panic!("request too short");
        }

        let iid = data[0] & 0x1f;
        let typ = data[1] & 0x3f;
        let cmd = data[2];

        Ok(PldmRequest {
            mctp_tag: tag,
            iid,
            typ,
            cmd,
            data: (&data[3..]).into(),
        })
    }

    /// Create a new PLDM request for a given PLDM message type and command
    ///
    ///
    /// Convert this request to a response, using the correct MCTP tag value
    /// (swapping to a non-owned tag), and the instance, type and command
    /// from the original request.
    ///
    /// The payload buffer is borrowed from input.
    ///
    /// May fail on invalid tag values.
    pub fn response_borrowed<'f>(&self, data: &'f [u8]) -> Result<PldmResponse<'f>> {
        let Some(Tag::Owned(tv)) = self.mctp_tag else {
            return Err(PldmError::InvalidArgument);
        };
        let resp_tag = Tag::Unowned(tv);
        Ok(PldmResponse {
            mctp_tag: resp_tag,
            iid: self.iid,
            typ: self.typ,
            cmd: self.cmd,
            cc: 0,
            data: data.into(),
        })
    }
}

/// Base PLDM response type
#[derive(Debug)]
pub struct PldmResponse<'a> {
    /// MCTP tag for this response. Will typically be a non-owned value
    /// ([`mctp::Tag::Unowned`]), as the request provided the owned tag.
    pub mctp_tag: Tag,
    /// PLDM Instance ID
    pub iid: u8,
    /// PLDM type
    pub typ: u8,
    /// PLDM command code (defined by the original request)
    pub cmd: u8,
    /// PLDM completion code
    pub cc: u8,
    /// PLDM response data payload. Does not include the cc field.
    pub data: VecOrSlice<'a, u8>,
}

#[cfg(feature = "alloc")]
impl<'a> PldmResponse<'a> {
    /// Set the data payload for this response
    pub fn set_data(&mut self, data: Vec<u8>) {
        self.data = data.into()
    }

    /// Converts any `PldmResponse` into one with allocated storage
    pub fn make_owned(self) -> PldmResponse<'static> {
        let d = match self.data {
            VecOrSlice::Borrowed(b) => b.to_vec().into(),
            VecOrSlice::Owned(b) => VecOrSlice::Owned(b),
        };
        PldmResponse { data: d, ..self }
    }
}

/// Main PLDM transfer operation.
///
/// Sends a Request, and waits for a response, blocking. This is generally
/// used by PLDM Requesters, which issue commands to Responders.
#[cfg(feature = "alloc")]
pub fn pldm_xfer<'f>(
    ep: &mut impl mctp::Endpoint,
    req: PldmRequest,
) -> Result<PldmResponse<'static>> {
    let mut rx_buf = [0u8; PLDM_MAX_MSGSIZE]; // todo: set size? peek?
    pldm_xfer_buf(ep, req, &mut rx_buf).map(|r| r.make_owned())
}

/// Main PLDM transfer operation.
///
/// Sends a Request, and waits for a response, blocking. This is generally
/// used by PLDM Requesters, which issue commands to Responders.
///
/// This function requires an external `rx_buf`.
pub fn pldm_xfer_buf<'f>(
    ep: &mut impl mctp::Endpoint,
    mut req: PldmRequest,
    rx_buf: &'f mut [u8],
) -> Result<PldmResponse<'f>> {

    pldm_tx_req(ep, &mut req)?;

    let (rx_buf, _eid, tag) = ep.recv(rx_buf)?;

    if rx_buf.len() < 4 {
        return Err(proto_error!("Short response", format!("{} bytes", rx_buf.len())));
    }

    // TODO: should check eid, but against what? Or should mctp::Endpoint impl check it?

    let iid = rx_buf[0] & 0x1f;
    let typ = rx_buf[1] & 0x3f;
    let cmd = rx_buf[2];
    let cc = rx_buf[3];

    if rsp.iid != req.iid {
        return Err(proto_error!("Incorrect instance ID in reply",
            format!("Expected 0x{:02x} got 0x{:02x}", req.iid, rsp.iid)));
    }

    if typ != req.typ {
        return Err(proto_error!("Incorrect PLDM type in reply",
            format!("Expected 0x{:02x} got 0x{:02x}", req.typ, typ)));
    }

    if cmd != req.cmd {
        return Err(proto_error!("Incorrect PLDM command in reply",
            format!("Expected 0x{:02x} got 0x{:02x}", req.cmd, cmd)));
    }

    let rsp = PldmResponse {
        mctp_tag: tag,
        iid,
        typ,
        cmd,
        cc,
        data: (&mut rx_buf[4..]).into(),
    };

    Ok(rsp)
}

/// Receive an incoming PLDM request.
///
/// This uses [`mctp::Endpoint::recv`], which performs a blocking wait for
/// incoming messages. The ep should already be bound (via
/// [`mctp::Endpoint::bind`]), listening on the PLDM message type.
///
/// Responder implementations will typically want to respond via
/// [`pldm_tx_resp`].
#[cfg(feature = "alloc")]
pub fn pldm_rx_req(
    ep: &mut impl mctp::Endpoint,
) -> Result<PldmRequest<'static>> {
    let mut rx_buf = [0u8; PLDM_MAX_MSGSIZE]; // todo: set size? peek?
    let (rx_buf, _eid, tag) = ep.recv(&mut rx_buf)?;

    let req = PldmRequest::from_buf(Some(tag), rx_buf)?;

    Ok(req)
}

/// Transmit an outgoing PLDM response
///
/// Performs a blocking send on the specified ep.
pub fn pldm_tx_resp(
    ep: &mut impl mctp::Endpoint,
    resp: &PldmResponse,
) -> Result<()> {
    let tx_buf = [resp.iid, resp.typ, resp.cmd, resp.cc];
    let txs = &[&tx_buf, resp.data.as_ref()];
    ep.send_vectored(mctp::MCTP_TYPE_PLDM, Some(resp.mctp_tag), txs)?;
    Ok(())
}

/// Transmit an outgoing PLDM request
///
/// Performs a blocking send on the specified ep. The iid will be
/// updated in `req`.
pub fn pldm_tx_req(
    ep: &mut impl mctp::Endpoint,
    req: &mut PldmRequest,
) -> Result<()> {
    // TODO IID allocation
    const REQ_IID: u8 = 0;
    req.iid = REQ_IID;

    let tx_buf = [
        1 << 7 | req.iid,
        req.typ & 0x3f,
        req.cmd,
    ];

    let txs = &[&tx_buf, req.data.as_ref()];
    ep.send_vectored(mctp::MCTP_TYPE_PLDM, req.mctp_tag, txs)?;
    Ok(())
}
