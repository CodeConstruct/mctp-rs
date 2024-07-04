// SPDX-License-Identifier: Apache-2.0
/*
 * PLDM firmware update utility.
 *
 * Copyright (c) 2023 Code Construct
 */

//! PLDM Firmware Device
//!
//! This is suitable for microcontroller targets, and supports `no_std`.

#[allow(unused)]
use log::{debug, error, info, trace, warn};

#[allow(unused)]
use nom::{
    combinator::{all_consuming, complete, map},
    multi::length_value,
    number::complete::le_u32,
    sequence::tuple,
    IResult,
};

use num_traits::FromPrimitive;

use mctp::{Eid, Endpoint, Tag};
use pldm::{pldm_tx_resp, CCode, PldmError, PldmRequest, PldmResponse};

use crate::{
    Cmd, Component, ComponentId, Descriptor, DeviceIdentifiers, FwCode, PldmFDState,
    RequestUpdateRequest, PLDM_FW_BASELINE_TRANSFER, FirmwareParameters, DescriptorString,
};

// TODO, borrow from somewhere.
const SENDBUF: usize = 1024;

type Result<T> = core::result::Result<T, PldmError>;

#[derive(Debug)]
enum PldmFDError {
    Pldm(pldm::PldmError),
    Invalid,
    NoSpace,
}

impl From<pldm::PldmError> for PldmFDError {
    fn from(e: pldm::PldmError) -> Self {
        Self::Pldm(e)
    }
}

pub struct Responder {
    ua_eid: Option<Eid>,
    state: PldmFDState,

    send_buf: heapless::Vec<u8, SENDBUF>,
    max_transfer: usize,
}

impl Responder {
    pub fn new() -> Self {
        Self {
            ua_eid: None,
            state: PldmFDState::Idle,
            send_buf: heapless::Vec::new(),
            max_transfer: PLDM_FW_BASELINE_TRANSFER,
        }
    }

    /// Handle an incoming PLDM FW message
    ///
    /// Returns `Ok` if a reply is sent to the UA, including for error responses.
    pub fn request_in(
        &mut self,
        eid: Eid,
        tag: Tag,
        payload: &[u8],
        ep: &mut impl Endpoint,
        d: &mut impl Device,
    ) -> Result<()> {
        if !tag.is_owner() {
            trace!("request_in for response");
            return Err(PldmError::InvalidArgument);
        }
        let req = PldmRequest::from_buf_borrowed(Some(tag), payload)?;

        let Some(cmd) = Cmd::from_u8(req.cmd) else {
            self.reply_error(&req, ep, CCode::ERROR_UNSUPPORTED_PLDM_CMD as u8);
            return Ok(());
        };

        if Some(eid) != self.ua_eid {
            if self.ua_eid.is_some() {
                // TODO: maybe disallow if not Idle or a Cancelupdate?
                trace!("Varying UA EID");
            }
            // Cache most recent. TODO might need other handling?
            self.ua_eid = Some(eid);
        }

        // Handlers will return Ok if they have replied
        let r = match cmd {
            Cmd::QueryDeviceIdentifiers => self.cmd_qdi(&req, ep, d),
            Cmd::GetFirmwareParameters => self.cmd_fwparams(&req, ep, d),
            Cmd::RequestUpdate => self.cmd_update(&req, ep, d),
            _ => {
                trace!("unhandled command {cmd:?}");
                self.reply_error(
                    &req,
                    ep,
                    CCode::ERROR_UNSUPPORTED_PLDM_CMD as u8,
                );
                Ok(())
            }
        };

        if let Err(e) = &r {
            debug!("Error handling {cmd:?}: {e:?}");
            self.reply_error(&req, ep, CCode::ERROR as u8);
        }
        Ok(())
    }

    fn reply_error(
        &self,
        req: &PldmRequest,
        ep: &mut impl Endpoint,
        cc: u8,
    ) {
        let mut resp = req.response_borrowed(&[]).unwrap();
        resp.cc = cc as u8;
        let _ = pldm_tx_resp(ep, &resp)
            .inspect_err(|e| trace!("Error sending failure response. {e:?}"));
    }

    /// Query Device Identifiers
    fn cmd_qdi(
        &mut self,
        req: &PldmRequest,
        ep: &mut impl Endpoint,
        d: &mut impl Device,
    ) -> Result<()> {
        // Valid in any state, doesn't change state
        let _ = self.send_buf.resize_default(self.send_buf.capacity());

        let l = d.dev_identifiers().write_buf(&mut self.send_buf).ok_or(PldmError::NoSpace)?;
        self.send_buf.truncate(l);
        let resp = req.response_borrowed(&self.send_buf)?;

        pldm_tx_resp(ep, &resp)
    }

    /// Get Firmware Parameters
    fn cmd_fwparams(
        &mut self,
        req: &PldmRequest,
        ep: &mut impl Endpoint,
        d: &mut impl Device,
    ) -> Result<()> {
        // Valid in any state, doesn't change state

        let fwp = FirmwareParameters {
            caps: Default::default(),
            components: d.components().into(),
            active: d.active_image_set_version(),
            pending: d.pending_image_set_version(),
        };

        let _ = self.send_buf.resize_default(self.send_buf.capacity());
        let l = fwp.write_buf(&mut self.send_buf).ok_or(PldmError::NoSpace)?;
        self.send_buf.truncate(l);
        let resp = req.response_borrowed(&self.send_buf)?;

        pldm_tx_resp(ep, &resp)
    }


    fn cmd_update(
        &mut self,
        req: &PldmRequest,
        ep: &mut impl Endpoint,
        d: &mut impl Device,
    ) -> Result<()> {
        if self.state != PldmFDState::Idle {
            self.reply_error(req, ep, FwCode::ALREADY_IN_UPDATE_MODE as u8);
            return Ok(());
        }

        let Ok((_, ru)) = RequestUpdateRequest::parse(&req.data) else {
            self.reply_error(req, ep, CCode::ERROR_INVALID_DATA as u8);
            return Ok(());
        };
        self.max_transfer = ru.max_transfer as usize;

        let resp = req.response_borrowed(&self.send_buf)?;
        pldm_tx_resp(ep, &resp)
    }

    // fn cmd_update(
}

pub trait Device {
    fn dev_identifiers(&self) -> &DeviceIdentifiers;

    fn components(&self) -> &[Component];

    fn active_image_set_version(&self) -> DescriptorString;

    fn pending_image_set_version(&self) -> DescriptorString;

    // Runs at the start of UpdateComponent
    fn allow_update_component() -> bool;

    fn write(comp: ComponentId) -> Result<()>;
}

#[cfg(test)]
mod tests {

    use crate::*;
}
