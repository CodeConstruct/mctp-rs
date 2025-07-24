// SPDX-License-Identifier: MIT OR Apache-2.0
/*
 * PLDM base responder implementation.
 *
 * Copyright (c) 2025 Code Construct
 */

//! Platform Level Data Model (PLDM) base protocol responder support
//!
//! Using structures from the core PLDM support, implement a simple
//! responder that handles base commands, maintaining core PLDM state, mostly
//! for enumerating subtype responders on this endpoint.

use deku::{DekuContainerRead, DekuContainerWrite, DekuError};
use heapless::Vec;
use mctp::{AsyncRespChannel, Eid};

use crate::control::{self, control_ccode, Cmd, PLDM_TYPE_CONTROL};
use crate::{
    pldm_tx_resp_async, proto_error, CCode, PldmError, PldmRequest,
    PldmResponse, Result,
};

/// Unassigned terminus ID
pub const TID_UNASSIGNED: u8 = 0x00;

struct TypeData {
    id: u8,
    version: u32,
    // stored as log2
    multipart_size: Option<u8>,
    commands: [u8; 32],
}

impl TypeData {
    fn new(
        id: u8,
        version: u32,
        multipart_size: Option<u8>,
        commands: &[u8],
    ) -> Self {
        let mut t = Self {
            id,
            version,
            multipart_size,
            commands: [0u8; 32],
        };
        for c in commands {
            let idx = *c as usize / 8;
            let offs = c % 8;

            t.commands[idx] |= 1 << offs;
        }
        t
    }
}

// number of peers that we track negotiated parameters against.
const N_PEERS: usize = 8;

// per-peer data on Negotiate Transfer Parameters results.
//
// The current implementation is spec-volatingly basic: we don't handle per-type
// data, but just update our negotiated size across all types.
struct NegotiatedTransfer {
    eid: Eid,
    // log2(size)
    size: u8,
}

/// Responder object for PLDM Messaging Control and Discovery (type 0) commands.
///
/// The N const represents the number of PLDM subtype slots that we support.
/// The type-0 handler itself consumes one slot.
pub struct Responder<const N: usize> {
    tid: u8,
    types: Vec<TypeData, N>,
    // we can get our base PLDM responses into a single MCTP BTU
    buf: [u8; 64],

    // negotiated sizes for each peer
    negotiations: Vec<NegotiatedTransfer, N_PEERS>,
}

struct PldmCommandError(u8);

impl From<CCode> for PldmCommandError {
    fn from(value: CCode) -> Self {
        Self(value as u8)
    }
}

impl From<u8> for PldmCommandError {
    fn from(value: u8) -> Self {
        Self(value)
    }
}

impl From<DekuError> for PldmCommandError {
    fn from(err: DekuError) -> Self {
        let cc = match err {
            DekuError::Incomplete(_) => CCode::ERROR_INVALID_LENGTH,
            DekuError::Parse(_) => CCode::ERROR_INVALID_DATA,
            _ => CCode::ERROR,
        };
        Self(cc as u8)
    }
}

type PldmCommandResult<T> = core::result::Result<T, PldmCommandError>;

impl<const N: usize> Responder<N> {
    /// Create a new responder.
    pub fn new() -> Self {
        let mut r = Self {
            tid: TID_UNASSIGNED,
            types: Vec::new(),
            buf: [0u8; 64],
            negotiations: Vec::new(),
        };
        let t = TypeData::new(
            0,
            0xf1f1f000,
            None,
            &[Cmd::SetTID as u8, Cmd::GetTID as u8],
        );
        let _ = r.types.push(t);
        r
    }

    /// Resgister a new PLDM type with this responder.
    ///
    /// This populates data returned by the base Get PLDM Types, Get PLDM
    /// Versions and Get PLDM Commands responses.
    pub fn register_type(
        &mut self,
        id: u8,
        version: u32,
        multipart_size: Option<u16>,
        commands: &[u8],
    ) -> Result<()> {
        if id >= 64 {
            Err(PldmError::InvalidArgument)?;
        }
        let log2_sz = match multipart_size {
            Some(sz) => {
                if sz < 256 || !sz.is_power_of_two() {
                    Err(PldmError::InvalidArgument)?;
                }
                Some(sz.ilog2() as u8)
            }
            None => None,
        };
        let typ = TypeData::new(id, version, log2_sz, commands);
        self.types.push(typ).map_err(|_| PldmError::NoSpace)?;
        Ok(())
    }

    /// Query the previously-negotiated transfer size for the given EID
    /// and PLDM type
    ///
    /// Returns None if no negotiation has occurred
    pub fn negotiated_xfer_size(
        &self,
        peer: Eid,
        _pldm_type: u8,
    ) -> Option<u16> {
        self.negotiations
            .iter()
            .find(|n| n.eid == peer)
            .map(|n| 1 << n.size)
    }

    /// Handle an incoming PLDM Messaging Control and Discovery request
    pub async fn handle_async(
        &mut self,
        req: &PldmRequest<'_>,
        mut resp_chan: impl AsyncRespChannel,
    ) -> Result<()> {
        if req.typ != PLDM_TYPE_CONTROL {
            return Err(proto_error!("Unexpected pldm control request"));
        }

        let eid = resp_chan.remote_eid();

        let res = match Cmd::try_from(req.cmd) {
            Ok(Cmd::SetTID) => self.cmd_set_tid(req),
            Ok(Cmd::GetTID) => self.cmd_get_tid(req),
            Ok(Cmd::GetPLDMVersion) => self.cmd_get_version(req),
            Ok(Cmd::GetPLDMTypes) => self.cmd_get_types(req),
            Ok(Cmd::GetPLDMCommands) => self.cmd_get_commands(req),
            Ok(Cmd::NegotiateTransferParameters) => {
                self.cmd_negotiate_transfer_parameters(req, eid)
            }
            _ => Err(CCode::ERROR_UNSUPPORTED_PLDM_CMD.into()),
        };

        let resp = res.unwrap_or_else(|e| {
            let mut r = req.response_borrowed(&[]);
            r.cc = e.0;
            r
        });

        pldm_tx_resp_async(&mut resp_chan, &resp).await
    }

    fn cmd_set_tid(
        &mut self,
        req: &PldmRequest,
    ) -> PldmCommandResult<PldmResponse<'_>> {
        let data = &req.data;
        let (_rest, sreq) = control::SetTIDReq::from_bytes((data, 0))?;
        self.tid = sreq.tid;

        let resp = req.response_borrowed(&[]);
        Ok(resp)
    }

    fn cmd_get_tid(
        &mut self,
        req: &PldmRequest,
    ) -> PldmCommandResult<PldmResponse<'_>> {
        let resp = control::GetTIDResp { tid: self.tid };

        let len = resp.to_slice(&mut self.buf)?;
        let resp = req.response_borrowed(&self.buf[0..len]);
        Ok(resp)
    }

    fn cmd_get_version(
        &mut self,
        req: &PldmRequest,
    ) -> PldmCommandResult<PldmResponse<'_>> {
        let data = &req.data;
        let (_rest, vreq) = control::GetPLDMVersionReq::from_bytes((data, 0))?;

        // Get First Part?
        if vreq.xfer_op != 1 {
            Err(control_ccode::INVALID_TRANSFER_OPERATION_FLAG)?;
        }

        let typ = self
            .types
            .iter()
            .find(|t| t.id == vreq.pldm_type)
            .ok_or(control_ccode::INVALID_PLDM_TYPE_IN_REQUEST_DATA)?;

        let tmp = typ.version.to_le_bytes();
        let crc32 = crc::Crc::<u32>::new(&crc::CRC_32_ISO_HDLC);
        let crc = crc32.checksum(&tmp);

        let resp = control::GetPLDMVersionResp {
            next_handle: 0,
            xfer_flag: 0x05, /* Start and End */
            version: typ.version,
            crc,
        };

        let len = resp.to_slice(&mut self.buf)?;
        let resp = req.response_borrowed(&self.buf[0..len]);
        Ok(resp)
    }

    fn cmd_get_types(
        &mut self,
        req: &PldmRequest,
    ) -> PldmCommandResult<PldmResponse<'_>> {
        let mut resp = control::GetPLDMTypesResp { types: [0u8; 8] };

        for typ in &self.types {
            let idx = typ.id as usize / 8;
            let offs = typ.id % 8;
            if idx >= 8 {
                continue;
            }
            resp.types[idx] |= 1 << offs;
        }

        let len = resp.to_slice(&mut self.buf)?;
        let resp = req.response_borrowed(&self.buf[0..len]);
        Ok(resp)
    }

    fn cmd_get_commands(
        &mut self,
        req: &PldmRequest,
    ) -> PldmCommandResult<PldmResponse<'_>> {
        let data = &req.data;
        let (_rest, creq) = control::GetPLDMCommandsReq::from_bytes((data, 0))?;

        let typ = self
            .types
            .iter()
            .find(|t| t.id == creq.pldm_type)
            .ok_or(control_ccode::INVALID_PLDM_TYPE_IN_REQUEST_DATA)?;

        if typ.version != creq.version {
            return Err(
                control_ccode::INVALID_PLDM_VERSION_IN_REQUEST_DATA.into()
            );
        }

        let resp = control::GetPLDMCommandsResp {
            commands: typ.commands,
        };

        let len = resp.to_slice(&mut self.buf)?;
        let resp = req.response_borrowed(&self.buf[0..len]);
        Ok(resp)
    }

    fn cmd_negotiate_transfer_parameters(
        &mut self,
        req: &PldmRequest,
        eid: Eid,
    ) -> PldmCommandResult<PldmResponse<'_>> {
        let data = &req.data;
        let (_rest, nreq) =
            control::NegotiateTransferParametersReq::from_bytes((data, 0))?;

        let req_size = nreq.part_size;
        if !req_size.is_power_of_two() || req_size < 256 {
            Err(CCode::ERROR_INVALID_DATA)?;
        }

        let req_size = req_size.ilog2() as u8;
        let mut neg_size = req_size;

        let req_types = u64::from_le_bytes(nreq.protocols);
        let mut neg_types = 0u64;

        for t in &self.types {
            if t.id >= 64 {
                continue;
            }
            let mask = 1 << t.id;
            if req_types & mask == 0 {
                continue;
            }
            if let Some(sz) = t.multipart_size {
                neg_types |= mask;
                neg_size = neg_size.min(sz);
            }
        }

        let negotiation = self.negotiations.iter_mut().find(|n| n.eid == eid);

        match negotiation {
            Some(n) => n.size = neg_size,
            None => {
                let n = NegotiatedTransfer {
                    eid,
                    size: neg_size,
                };
                self.negotiations.push(n).map_err(|_| CCode::ERROR)?;
            }
        }

        let resp = control::NegotiateTransferParametersResp {
            part_size: 1u16 << req_size,
            protocols: neg_types.to_le_bytes(),
        };

        let len = resp.to_slice(&mut self.buf)?;
        let resp = req.response_borrowed(&self.buf[0..len]);
        Ok(resp)
    }
}

impl<const N: usize> Default for Responder<N> {
    fn default() -> Self {
        Self::new()
    }
}
