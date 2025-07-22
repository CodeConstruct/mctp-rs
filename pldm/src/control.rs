// SPDX-License-Identifier: MIT OR Apache-2.0
/*
 * PLDM Messaging Control and Discovery ("PLDM Control") definitions.
 *
 * Copyright (c) 2025 Code Construct
 */

//! PLDM Messaging Control and Discovery ("PLDM Control" / type 0) messaging
//! support.
//!
//! This module provides definitions for PLDM control requests and responses.

use deku::{DekuRead, DekuWrite};

use crate::{proto_error, PldmError, Result};

pub mod requester;
pub mod responder;

/// PLDM Messaging Control and Discovery type
pub const PLDM_TYPE_CONTROL: u8 = 0;

/// PLDM Control command codes
#[allow(missing_docs)]
#[repr(u8)]
#[non_exhaustive]
pub enum Cmd {
    SetTID = 0x01,
    GetTID = 0x02,
    GetPLDMVersion = 0x03,
    GetPLDMTypes = 0x04,
    GetPLDMCommands = 0x05,
    SelectPLDMVersion = 0x06,
    NegotiateTransferParameters = 0x07,
    MultipartSend = 0x08,
    MultipartReceive = 0x09,
}

/// Completion codes for the PLDM Base (subtype 0) commands
#[allow(missing_docs)]
pub mod control_ccode {
    pub const INVALID_DATA_TRANSFER_HANDLE: u8 = 0x80;
    pub const INVALID_TRANSFER_OPERATION_FLAG: u8 = 0x81;
    pub const INVALID_PLDM_TYPE_IN_REQUEST_DATA: u8 = 0x83;
    pub const INVALID_PLDM_VERSION_IN_REQUEST_DATA: u8 = 0x84;
    pub const NEGOTIATION_INCOMPLETE: u8 = 0x83;
}

/// Multipart transfer operation values
#[allow(missing_docs)]
#[allow(non_camel_case_types)]
pub mod xfer_op {
    pub const FIRST_PART: u8 = 0;
    pub const NEXT_PART: u8 = 1;
    pub const ABORT: u8 = 2;
    pub const COMPLETE: u8 = 3;
    pub const CURRENT_PART: u8 = 4;
}

/// Transfer flag values
#[allow(missing_docs)]
#[allow(non_camel_case_types)]
pub mod xfer_flag {
    pub const START: u8 = 1;
    pub const MIDDLE: u8 = 2;
    pub const END: u8 = 4;
    // Provided by the spec....
    pub const START_AND_END: u8 = START | END;
    pub const ACKNOWLEDGE_COMPLETION: u8 = 8;
}

impl TryFrom<u8> for Cmd {
    type Error = PldmError;

    fn try_from(value: u8) -> Result<Self> {
        let c = match value {
            0x01 => Self::SetTID,
            0x02 => Self::GetTID,
            0x03 => Self::GetPLDMVersion,
            0x04 => Self::GetPLDMTypes,
            0x05 => Self::GetPLDMCommands,
            0x06 => Self::SelectPLDMVersion,
            0x07 => Self::NegotiateTransferParameters,
            0x08 => Self::MultipartSend,
            0x09 => Self::MultipartReceive,
            v => {
                let _ = v;
                return Err(proto_error!(
                    "Unknown PLDM base command",
                    "{v:02x}"
                ));
            }
        };
        Ok(c)
    }
}

/// Set TID request
#[derive(DekuRead, DekuWrite)]
pub struct SetTIDReq {
    /// TID
    pub tid: u8,
}

/// Get TID response
#[derive(DekuRead, DekuWrite)]
pub struct GetTIDResp {
    /// TID
    pub tid: u8,
}

/// Get PLDM Version request
#[derive(DekuRead, DekuWrite)]
#[deku(endian = "little")]
pub struct GetPLDMVersionReq {
    /// DataTransferHandle
    pub xfer_handle: u32,
    /// TransferOperationFlag
    pub xfer_op: u8,
    /// PLDMType
    pub pldm_type: u8,
}

/// Get PLDM Version response
#[derive(DekuRead, DekuWrite)]
#[deku(endian = "little")]
pub struct GetPLDMVersionResp {
    /// NextDataTransferHandle
    pub next_handle: u32,
    /// TransferFlag
    pub xfer_flag: u8,
    /// Version. We only support one version in our responses at present.
    pub version: u32,
    /// Checksum, over the version data.
    pub crc: u32,
}

/// Get PLDM Types response
#[derive(DekuRead, DekuWrite)]
pub struct GetPLDMTypesResp {
    /// PLDM Types bitmask
    pub types: [u8; 8],
}

/// Get PLDM Commands request
#[derive(DekuRead, DekuWrite)]
#[deku(endian = "little")]
pub struct GetPLDMCommandsReq {
    /// PLDMType
    pub pldm_type: u8,
    /// Version
    pub version: u32,
}

/// Get PLDM Commands response
#[derive(DekuRead, DekuWrite)]
pub struct GetPLDMCommandsResp {
    /// PLDM Types bitmask
    pub commands: [u8; 32],
}

/// Negotiate Transfer Parameters request
#[derive(DekuRead, DekuWrite)]
#[deku(endian = "little")]
pub struct NegotiateTransferParametersReq {
    /// RequesterPartSize.
    ///
    /// Maximum transfer size supported by the requester
    pub part_size: u16,

    /// Requester Protocol Support
    ///
    /// Bitmask of PLDM protocols implementing multipart transfer
    pub protocols: [u8; 8],
}

/// Negotiate Transfer Parameters response
#[derive(DekuRead, DekuWrite)]
#[deku(endian = "little")]
pub struct NegotiateTransferParametersResp {
    /// ResponderPartSize.
    ///
    /// Negotiated transfer size
    pub part_size: u16,

    /// Responder Protocol Support
    ///
    /// Bitmask of negotiated PLDM protocols implementing multipart transfer
    pub protocols: [u8; 8],
}

/// Multipart Receive request
#[derive(DekuRead, DekuWrite)]
#[deku(endian = "little")]
pub struct MultipartReceiveReq {
    /// PLDM type
    pub pldm_type: u8,
    /// Transfer operation
    pub xfer_op: u8,
    /// Transfer context identifier
    pub xfer_context: u32,
    /// Transfer handle for this receive request
    pub xfer_handle: u32,
    /// Requested offset
    pub req_offset: u32,
    /// Requested length
    pub req_length: u32,
}

/// Multipart Receive response
#[derive(DekuRead, DekuWrite)]
#[deku(endian = "little")]
pub struct MultipartReceiveResp {
    /// Transfer flag
    pub xfer_flag: u8,
    /// Next transfer handle
    pub next_handle: u32,
    /// Data length
    pub len: u32,
}
