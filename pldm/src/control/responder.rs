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
use mctp::AsyncRespChannel;

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
    commands: [u8; 32],
}

impl TypeData {
    fn new(id: u8, version: u32, commands: &[u8]) -> Self {
        let mut t = Self {
            id,
            version,
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

/// Responder object for PLDM Messaging Control and Discovery (type 0) commands.
///
/// The N const represents the number of PLDM subtype slots that we support.
/// The type-0 handler itself consumes one slot.
pub struct Responder<const N: usize> {
    tid: u8,
    types: Vec<TypeData, N>,
    // we can get our base PLDM responses into a single MCTP BTU
    buf: [u8; 64],
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
        };
        let t = TypeData::new(
            0,
            0xf1f1f000,
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
        commands: &[u8],
    ) -> Result<()> {
        let typ = TypeData::new(id, version, commands);
        self.types.push(typ).map_err(|_| PldmError::NoSpace)?;
        Ok(())
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

        let res = match Cmd::try_from(req.cmd) {
            Ok(Cmd::SetTID) => self.cmd_set_tid(req),
            Ok(Cmd::GetTID) => self.cmd_get_tid(req),
            Ok(Cmd::GetPLDMVersion) => self.cmd_get_version(req),
            Ok(Cmd::GetPLDMTypes) => self.cmd_get_types(req),
            Ok(Cmd::GetPLDMCommands) => self.cmd_get_commands(req),
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
        let (_rest, sreq) = control::SetTIDReq::from_bytes((data, data.len()))?;
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
        let (_rest, vreq) =
            control::GetPLDMVersionReq::from_bytes((data, data.len()))?;

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
        let (_rest, creq) =
            control::GetPLDMCommandsReq::from_bytes((data, data.len()))?;

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
}

impl<const N: usize> Default for Responder<N> {
    fn default() -> Self {
        Self::new()
    }
}
