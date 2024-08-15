// SPDX-License-Identifier: Apache-2.0
/*
 * PLDM firmware update utility.
 *
 * Copyright (c) 2023 Code Construct
 */

//! PLDM Firmware Device
//!
//! This is suitable for microcontroller targets, and supports `no_std`.
use log::{debug, error};

use nom::{
    combinator::{all_consuming, complete, map},
    multi::length_value,
    number::complete::le_u32,
    sequence::tuple,
    IResult,
};

use pldm::PldmError;

struct FirmwareDevice {


}

impl FirmwareDevice {
    // fn handle_mctp(eid: Eid, tag: Tag, payload: &[u8]

}

