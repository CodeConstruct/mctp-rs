// SPDX-License-Identifier: MIT OR Apache-2.0
/*
 * PLDM base responder implementation.
 *
 * Copyright (c) 2025 Code Construct
 */

//! PLDM base protocol requester support
#[allow(unused_imports)]
use log::{debug, error, info, trace, warn};

use mctp::AsyncReqChannel;

use deku::prelude::*;

use crate::{
    ccode_result, control, pldm_xfer_buf_async, proto_error, util::SliceWriter,
    PldmError, PldmRequest, PldmResult,
};

use super::xfer_flag;

/// Perform a Set TID request.
pub async fn set_tid(
    comm: &mut impl AsyncReqChannel,
    tid: u8,
) -> PldmResult<()> {
    let mut buf = [0u8; 1];
    let msg = control::SetTIDReq { tid };
    let l = msg.to_slice(&mut buf)?;
    let req = PldmRequest::new_borrowed(
        control::PLDM_TYPE_CONTROL,
        control::Cmd::SetTID as u8,
        &buf[..l],
    );

    let mut rx_buf = [0u8; 4];
    let resp = pldm_xfer_buf_async(comm, req, &mut rx_buf).await?;

    ccode_result(resp.cc)
}

/// Perform a Get TID request.
pub async fn get_tid(comm: &mut impl AsyncReqChannel) -> PldmResult<u8> {
    let req = PldmRequest::new_borrowed(
        control::PLDM_TYPE_CONTROL,
        control::Cmd::GetTID as u8,
        &[],
    );

    let mut rx_buf = [0u8; 5];
    let resp = pldm_xfer_buf_async(comm, req, &mut rx_buf).await?;

    ccode_result(resp.cc)?;

    let ((rest, _), tidrsp) = control::GetTIDResp::from_bytes((&resp.data, 0))?;

    if !rest.is_empty() {
        // TODO
        warn!("Extra get TID response");
    }

    Ok(tidrsp.tid)
}

/// Perform a Get PLDM Version request.
pub async fn get_pldm_version<'f>(
    comm: &mut impl AsyncReqChannel,
    pldm_type: u8,
    ret_buf: &'f mut [u32],
) -> PldmResult<&'f [u32]> {
    let mut buf = [0u8; 6];
    let msg = control::GetPLDMVersionReq {
        xfer_handle: 0,
        // Get first part
        xfer_op: 1,
        pldm_type,
    };
    let l = msg.to_slice(&mut buf)?;
    let req = PldmRequest::new_borrowed(
        control::PLDM_TYPE_CONTROL,
        control::Cmd::GetPLDMVersion as u8,
        &buf[..l],
    );

    let mut rx_buf = [0u8; 50];
    let resp = pldm_xfer_buf_async(comm, req, &mut rx_buf).await?;

    ccode_result(resp.cc)?;

    let ((rest, _), vrsp) =
        control::GetPLDMVersionResp::from_bytes((&resp.data, 0))?;

    if !rest.is_empty() {
        // TODO
        warn!("Extra get version response");
    }

    // Require StartAndEnd
    if vrsp.xfer_flag != xfer_flag::START_AND_END {
        // TODO
        return Err(proto_error!("Can't handle parts"));
    }

    let Some(r) = ret_buf.get_mut(..1) else {
        return Err(proto_error!("Short ret_buf"));
    };
    r[0] = vrsp.version;
    Ok(r)
}

/// Perform a Get PLDM Types request.
pub async fn get_pldm_types<'f>(
    comm: &mut impl AsyncReqChannel,
    ret_buf: &'f mut [u8],
) -> PldmResult<&'f [u8]> {
    let req = PldmRequest::new_borrowed(
        control::PLDM_TYPE_CONTROL,
        control::Cmd::GetPLDMTypes as u8,
        &[],
    );

    let mut rx_buf = [0u8; 70];
    let resp = pldm_xfer_buf_async(comm, req, &mut rx_buf).await?;

    ccode_result(resp.cc)?;

    let ((rest, _), vty) =
        control::GetPLDMTypesResp::from_bytes((&resp.data, 0))?;

    if !rest.is_empty() {
        // TODO
        warn!("Extra get types response");
    }

    let mut ret = SliceWriter::new(ret_buf);
    for t in 0..64 {
        if vty.types[t / 8] & (1 << (t % 8)) != 0 {
            ret.push_le(t as u8).ok_or(PldmError::NoSpace)?;
        }
    }

    Ok(ret.done())
}

/// Perform a Get PLDM Commands request.
pub async fn get_pldm_commands<'f>(
    comm: &mut impl AsyncReqChannel,
    pldm_type: u8,
    version: u32,
    ret_buf: &'f mut [u8],
) -> PldmResult<&'f [u8]> {
    let mut buf = [0u8; 5];
    let msg = control::GetPLDMCommandsReq { pldm_type, version };
    let l = msg.to_slice(&mut buf)?;
    let req = PldmRequest::new_borrowed(
        control::PLDM_TYPE_CONTROL,
        control::Cmd::GetPLDMCommands as u8,
        &buf[..l],
    );

    let mut rx_buf = [0u8; 36];
    let resp = pldm_xfer_buf_async(comm, req, &mut rx_buf).await?;

    ccode_result(resp.cc)?;

    let ((rest, _), cmdrsp) =
        control::GetPLDMCommandsResp::from_bytes((&resp.data, 0))?;

    if !rest.is_empty() {
        // TODO
        warn!("Extra get commands response");
    }

    let mut ret = SliceWriter::new(ret_buf);
    for t in 0..256 {
        if cmdrsp.commands[t / 8] & (1 << (t % 8)) != 0 {
            ret.push_le(t as u8).ok_or(PldmError::NoSpace)?;
        }
    }

    Ok(ret.done())
}

/// Negotiate Transfer Parameters.
///
/// This sends a Negotiate Transfer Parameters command with the given PLDM
/// type set and requested size. Returns the negotiated size and type set
/// from the responder.
pub async fn negotiate_transfer_parameters<'f>(
    comm: &mut impl AsyncReqChannel,
    req_types: &[u8],
    neg_types_buf: &'f mut [u8],
    part_size: u16,
) -> PldmResult<(u16, &'f [u8])> {
    let mut buf = [0u8; 10];

    let req_types = req_types.iter().fold(0u64, |x, typ| x | 1 << typ);

    if !part_size.is_power_of_two() || part_size < 256 {
        debug!("Bad part_size {}", part_size);
        return Err(PldmError::InvalidArgument);
    }

    let req = control::NegotiateTransferParametersReq {
        part_size,
        protocols: req_types.to_le_bytes(),
    };

    let len = req.to_slice(&mut buf)?;
    let req = PldmRequest::new_borrowed(
        control::PLDM_TYPE_CONTROL,
        control::Cmd::NegotiateTransferParameters as u8,
        &buf[..len],
    );

    let mut rx_buf = [0u8; 16];
    let resp = pldm_xfer_buf_async(comm, req, &mut rx_buf).await?;

    ccode_result(resp.cc)?;

    let ((rest, _), cmdrsp) =
        control::NegotiateTransferParametersReq::from_bytes((&resp.data, 0))?;

    if !rest.is_empty() {
        warn!("Extra negotiate transfer parameters response");
    }

    let neg_types = u64::from_le_bytes(cmdrsp.protocols);
    let mut neg_types_ret = SliceWriter::new(neg_types_buf);
    for t in 0..64 {
        let mask = 1u64 << t;
        if neg_types & mask != 0 {
            neg_types_ret.push_le(t as u8).ok_or(PldmError::NoSpace)?;
        }
    }

    Ok((cmdrsp.part_size, neg_types_ret.done()))
}
