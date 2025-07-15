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

use crate::{proto_error, PldmError, Result};

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
