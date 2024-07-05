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
    number::complete::{le_u16, le_u32, le_u8},
    sequence::tuple,
    IResult,
};

use num_traits::FromPrimitive;

use mctp::{Eid, Endpoint, Tag};
use pldm::{pldm_tx_resp, CCode, PldmError, PldmRequest};

use crate::*;

// TODO, borrow from somewhere.
const SENDBUF: usize = 1024;

type Result<T> = core::result::Result<T, PldmError>;

enum State {
    Idle,
    LearnComponents,
    ReadyXfer,
    Download {
        size: usize,
        offset: usize,
        last_req_fd_t2: u64,
        classification: ComponentClassification,
        identifier: u16,
        index: u8,
    },
    Verify,
    Apply,
    Activate,
}

impl From<&State> for PldmFDState {
    fn from(s: &State) -> PldmFDState {
        match s {
            State::Idle => PldmFDState::Idle,
            State::LearnComponents => PldmFDState::LearnComponents,
            State::ReadyXfer => PldmFDState::ReadyXfer,
            State::Download { .. } => PldmFDState::Download,
            State::Verify => PldmFDState::Verify,
            State::Apply => PldmFDState::Apply,
            State::Activate => PldmFDState::Activate,
        }
    }
}

pub struct Responder {
    ua_eid: Option<Eid>,
    state: State,

    send_buf: heapless::Vec<u8, SENDBUF>,
    max_transfer: usize,

    // Timestamp for FD T1 timeout, milliseconds
    update_timestamp_fd_t1: u64,
}

impl Responder {
    pub fn new() -> Self {
        Self {
            ua_eid: None,
            state: State::Idle,
            send_buf: heapless::Vec::new(),
            max_transfer: PLDM_FW_BASELINE_TRANSFER,
            update_timestamp_fd_t1: 0,
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
            Cmd::PassComponentTable => self.cmd_pass_components(&req, ep, d),
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

    fn reply_error(&self, req: &PldmRequest, ep: &mut impl Endpoint, cc: u8) {
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
        dev: &mut impl Device,
    ) -> Result<()> {
        // Valid in any state, doesn't change state
        let _ = self.send_buf.resize_default(self.send_buf.capacity());

        let l = dev
            .dev_identifiers()
            .write_buf(&mut self.send_buf)
            .ok_or(PldmError::NoSpace)?;
        self.send_buf.truncate(l);
        let resp = req.response_borrowed(&self.send_buf)?;

        pldm_tx_resp(ep, &resp)
    }

    /// Get Firmware Parameters
    fn cmd_fwparams(
        &mut self,
        req: &PldmRequest,
        ep: &mut impl Endpoint,
        dev: &mut impl Device,
    ) -> Result<()> {
        // Valid in any state, doesn't change state

        let fwp = FirmwareParameters {
            caps: Default::default(),
            components: dev.components().into(),
            active: dev.active_image_set_version(),
            pending: dev.pending_image_set_version(),
        };

        let _ = self.send_buf.resize_default(self.send_buf.capacity());
        let l = fwp
            .write_buf(&mut self.send_buf)
            .ok_or(PldmError::NoSpace)?;
        self.send_buf.truncate(l);
        let resp = req.response_borrowed(&self.send_buf)?;

        pldm_tx_resp(ep, &resp)
    }

    fn cmd_update(
        &mut self,
        req: &PldmRequest,
        ep: &mut impl Endpoint,
        dev: &mut impl Device,
    ) -> Result<()> {
        if !matches!(self.state, State::Idle) {
            self.reply_error(req, ep, FwCode::ALREADY_IN_UPDATE_MODE as u8);
            return Ok(());
        }

        let Ok((_, ru)) = RequestUpdateRequest::parse(&req.data) else {
            trace!("error parsing RequestUpdate");
            self.reply_error(req, ep, CCode::ERROR_INVALID_DATA as u8);
            return Ok(());
        };
        self.max_transfer = ru.max_transfer as usize;

        self.update_timestamp_fd_t1 = dev.now();

        let resp = req.response_borrowed(&self.send_buf)?;
        pldm_tx_resp(ep, &resp)?;
        self.state = State::LearnComponents;
        Ok(())
    }

    fn cmd_pass_components(
        &mut self,
        req: &PldmRequest,
        ep: &mut impl Endpoint,
        dev: &mut impl Device,
    ) -> Result<()> {
        if !matches!(self.state, State::LearnComponents) {
            self.reply_error(req, ep, FwCode::INVALID_STATE_FOR_COMMAND as u8);
            return Ok(());
        }

        let Ok((_, (transferflag, up))) =
            all_consuming(tuple((le_u8, UpdateComponent::parse_pass_component)))(&req.data)
        else {
            trace!("error parsing PassComponent");
            self.reply_error(req, ep, CCode::ERROR_INVALID_DATA as u8);
            return Ok(());
        };

        self.update_timestamp_fd_t1 = dev.now();

        let res = dev.update_component(false, &up);

        // byte 0: ComponentResponse, 0 for success, 1 otherwise?
        // byte 1: ComponentResponseCode
        let comp_resp = [(res != 0) as u8, res];
        let resp = req.response_borrowed(&comp_resp)?;
        pldm_tx_resp(ep, &resp)?;

        if transferflag & TransferFlag::End as u8 > 0 {
            self.state = State::ReadyXfer;
        }
        Ok(())
    }

    fn cmd_update_component(
        &mut self,
        req: &PldmRequest,
        ep: &mut impl Endpoint,
        dev: &mut impl Device,
    ) -> Result<()> {
        if !matches!(self.state, State::ReadyXfer) {
            self.reply_error(req, ep, FwCode::NOT_IN_UPDATE_MODE as u8);
            return Ok(());
        }

        let Ok((_, up)) =
            all_consuming(UpdateComponent::parse_update)(&req.data)
        else {
            trace!("error parsing UpdateComponent");
            self.reply_error(req, ep, CCode::ERROR_INVALID_DATA as u8);
            return Ok(());
        };

        self.update_timestamp_fd_t1 = dev.now();

        let res = dev.update_component(false, &up);

        let mut comp_resp = [0u8; 8];
        let mut b = SliceWriter::new(&mut comp_resp);
        // ComponentResponse, 0 for success, 1 otherwise?
        b.push_le8((res != 0) as u8).ok_or(PldmError::NoSpace)?;
        // ComponentResponseCode
        b.push_le8(res).ok_or(PldmError::NoSpace)?;
        // UpdateOptionFlagsEnabled, mask to only "Force Update"
        b.push_le32(up.flags.unwrap() & 0x1).ok_or(PldmError::NoSpace)?;
        // Estimated time until update, seconds
        b.push_le16(0).ok_or(PldmError::NoSpace)?;

        let resp = req.response_borrowed(&comp_resp)?;
        pldm_tx_resp(ep, &resp)?;

        self.state = State::Download {
            // OK unwrap, size is always set for parse_update()
            size: up.size.unwrap() as usize,
            offset: 0,
            last_req_fd_t2: dev.now(),
            classification: up.classification,
            identifier: up.identifier,
            index: up.classificationindex,
        };
        Ok(())
    }
}

pub trait Device {
    fn dev_identifiers(&mut self) -> &DeviceIdentifiers;

    fn components(&self) -> &[Component];

    fn active_image_set_version(&self) -> DescriptorString;

    fn pending_image_set_version(&self) -> DescriptorString;

    /// Pass a component at the start of update mode
    ///
    /// Will be called with `update = false` initially for
    /// Pass Component, and then later called with `update = true`
    /// when the actual update is starting.
    ///
    /// The `Device` implementation should return `0x0` on allowed,
    /// or a ComponentResponseCode otherwise (see PLDM FW specification).
    /// When `update == false` a response may indicate conditional success,
    /// such as requiring update flags to be set.
    fn update_component(&mut self, update: bool, comp: &UpdateComponent) -> u8;

    fn write(comp: ComponentId) -> Result<()>;

    /// Returns a monotonic timestamp in milliseconds.
    fn now(&mut self) -> u64;
}

#[cfg(test)]
mod tests {

    use crate::*;
}
