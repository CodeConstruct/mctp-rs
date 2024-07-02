// SPDX-License-Identifier: Apache-2.0
/*
 * PLDM base message definitions.
 *
 * Copyright (c) 2023 Code Construct
 */

#![warn(missing_docs)]

//! Platform Level Data Model (PLDM) base protocol support
//!
//! This crate implements some base communication primitives for PLDM,
//! used to construct higher-level PLDM messaging applications.

use thiserror::Error;

use mctp::Tag;

/// Maximum size of a PLDM message, defining our buffer sizes.
///
/// The `pldm` crate currently has a maximum message size.
pub const PLDM_MAX_MSGSIZE: usize = 1024;

/// Generic PLDM error type
#[derive(Error, Debug)]
pub enum PldmError {
    /// PLDM protocol error
    #[error("PLDM protocol error: {0}")]
    Protocol(String),
    /// MCTP communication error
    #[error("MCTP error")]
    Mctp(mctp::Error),
}

impl PldmError {
    /// Construct a new PLDM protocol error with a description
    pub fn new_proto(s: String) -> Self {
        Self::Protocol(s)
    }
}

impl From<mctp::Error> for PldmError {
    fn from(e: mctp::Error) -> PldmError {
        PldmError::Mctp(e)
    }
}

/// PLDM protocol return type
pub type Result<T> = std::result::Result<T, PldmError>;

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
pub struct PldmRequest {
    /// MCTP tag used for the request. Typically an owned tag
    /// ([`mctp::Tag::Owned`] or [`mctp::Tag::OwnedAuto`])
    pub mctp_tag: Tag,
    /// PLDM Instance ID
    pub iid: u8,
    /// PLDM type.
    pub typ: u8,
    /// PLDM command code
    pub cmd: u8,
    /// PLDM command data payload
    pub data: Vec<u8>,
}

impl PldmRequest {
    /// Create a new PLDM request for a given PLDM message type and command
    /// number. Since this creates a request, it specifies an
    /// [`mctp::Tag::OwnedAuto`] tag, for the lower-level MCTP stack to assign
    /// an actual tag value.
    pub fn new(typ: u8, cmd: u8) -> Self {
        Self {
            mctp_tag: Tag::OwnedAuto,
            iid: 0,
            typ,
            cmd,
            data: Vec::new(),
        }
    }

    /// Create a PLDM request given a MCTP tag value and message data.
    ///
    /// May fail if the message data is not parsable as a PLDM message.
    pub fn from_buf(tag: Tag, data: &[u8]) -> Result<Self> {
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
            data: data[3..].to_vec(),
        })
    }

    /// Set the data payload for this request
    pub fn set_data(&mut self, data: Vec<u8>) {
        self.data = data;
    }

    /// Convert this request to a response, using the correct MCTP tag value
    /// (swapping to a non-owned tag), and the instance, type and command
    /// from the original request.
    ///
    /// May fail on invalid tag values.
    pub fn response(&self) -> Result<PldmResponse> {
        let tag = self.mctp_tag.tag()
            .ok_or(PldmError::Protocol("OwnedAuto tag".into()))?;
        let resp_tag = Tag::Unowned(tag);
        Ok(PldmResponse {
            mctp_tag: resp_tag,
            iid: self.iid,
            typ: self.typ,
            cmd: self.cmd,
            cc: 0,
            data: Vec::new(),
        })
    }
}

/// Base PLDM response type
#[derive(Debug)]
pub struct PldmResponse {
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
    pub data: Vec<u8>,
}

/// Main PLDM transfer operation.
///
/// Sends a Request, and waits for a response, blocking. This is generally
/// used by PLDM Requesters, which issue commands to Responders.
pub fn pldm_xfer(ep: &mut impl mctp::Endpoint, req: PldmRequest) -> Result<PldmResponse> {
    const REQ_IID: u8 = 0;
    let mut tx_buf = Vec::with_capacity(req.data.len() + 2);
    tx_buf.push(1 << 7 | REQ_IID);
    tx_buf.push(req.typ & 0x3f);
    tx_buf.push(req.cmd);
    tx_buf.extend_from_slice(&req.data);

    ep.send(mctp::MCTP_TYPE_PLDM, req.mctp_tag, &tx_buf)?;

    let mut rx_buf = [0u8; PLDM_MAX_MSGSIZE]; // todo: set size? peek?
    let (rx_buf, _eid, tag) = ep.recv(&mut rx_buf)?;

    if rx_buf.len() < 4 {
        return Err(PldmError::new_proto(format!("short response, {} bytes", rx_buf.len())));
    }

    // TODO: should check eid, but against what? Or should mctp::Endpoint impl check it?

    let iid = rx_buf[0] & 0x1f;
    let typ = rx_buf[1] & 0x3f;
    let cmd = rx_buf[2];
    let cc = rx_buf[3];

    if iid != REQ_IID {
        return Err(PldmError::new_proto(format!(
            "Incorrect instance ID in reply. Expected 0x{REQ_IID:02x} got 0x{iid:02x}")));
    }

    if typ != req.typ {
        return Err(PldmError::new_proto(format!(
            "Incorrect PLDM type in reply. Expected 0x{:02x} got 0x{:02x}",
            req.typ, typ)));
    }

    if cmd != req.cmd {
        return Err(PldmError::new_proto(format!(
            "Incorrect PLDM command in reply. Expected 0x{:02x} got 0x{:02x}",
            req.cmd, cmd)));
    }

    let rsp = PldmResponse {
        mctp_tag: tag,
        iid,
        typ,
        cmd,
        cc,
        data: rx_buf[4..].to_vec(),
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
pub fn pldm_rx_req(ep: &mut impl mctp::Endpoint) -> Result<PldmRequest> {
    let mut rx_buf = [0u8; PLDM_MAX_MSGSIZE]; // todo: set size? peek?
    let (rx_buf, _eid, tag) = ep.recv(&mut rx_buf)?;

    let req = PldmRequest::from_buf(tag, rx_buf)?;

    Ok(req)
}

/// Transmit an outgoing PLDM response
///
/// Performs a blocking send on the specified ep.
pub fn pldm_tx_resp(ep: &mut impl mctp::Endpoint, resp: &PldmResponse) -> Result<()> {
    let mut tx_buf = Vec::with_capacity(resp.data.len() + 4);
    tx_buf.push(resp.iid);
    tx_buf.push(resp.typ);
    tx_buf.push(resp.cmd);
    tx_buf.push(resp.cc);
    tx_buf.extend_from_slice(&resp.data);

    ep.send(mctp::MCTP_TYPE_PLDM, resp.mctp_tag, &tx_buf)?;

    Ok(())
}
