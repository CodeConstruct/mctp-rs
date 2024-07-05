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
use pldm::{pldm_tx_req, pldm_tx_resp, CCode, PldmError, PldmRequest};

use crate::*;

// TODO, borrow from somewhere.
const MSGBUF: usize = 1024;

type Result<T> = core::result::Result<T, PldmError>;

enum State {
    Idle { reason: PldmIdleReason },
    LearnComponents,
    ReadyXfer,
    Download {
        // limited to u32 on construction
        size: usize,
        offset: usize,
        // whether we are waiting for a response from the UA.
        // when this is true, it is valid to send a new request
        // for the current offset.
        // `offset` is incremented on the `requested` true->false transition.
        requested: bool,
        req_time: u64,
        classification: ComponentClassification,
        identifier: u16,
        index: u8,
        update_flags: u32,
    },
    Verify,
    Apply,
    Activate,
}

impl From<&State> for PldmFDState {
    fn from(s: &State) -> PldmFDState {
        match s {
            State::Idle { .. } => PldmFDState::Idle,
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
    /// state should be modified via set_state()
    state: State,
    prev_state: PldmFDState,

    msg_buf: [u8; MSGBUF],
    // Maximum size allowed by the UA
    max_transfer: usize,

    // Timestamp for FD T1 timeout, milliseconds
    update_timestamp_fd_t1: u64,
}

impl Responder {
    /// Update mode idle timeout, 120 seconds
    pub const FD_T1_TIMEOUT: u64 = 120_000;

    /// Retry req firmware time, 2 seconds
    pub const REQ_FW_RETRY_TIME: u64 = 1_000;

    /// Specification baseline request size
    pub const BASELINE_MTU: usize = 32;

    pub fn new() -> Self {
        Self {
            ua_eid: None,
            state: State::Idle { reason: PldmIdleReason::Init },
            prev_state: PldmFDState::Idle,
            msg_buf: [0; MSGBUF],
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
            Cmd::UpdateComponent => self.cmd_update_component(&req, ep, d),
            Cmd::GetStatus => self.cmd_get_status(&req, ep, d),
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
        resp.cc = cc;
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
        if !req.data.is_empty() {
            self.reply_error(req, ep, CCode::ERROR_INVALID_DATA as u8);
            return Ok(());
        }

        let l = dev.dev_identifiers().write_buf(&mut self.msg_buf).space()?;
        let resp = req.response_borrowed(&self.msg_buf[..l])?;

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
        if !req.data.is_empty() {
            self.reply_error(req, ep, CCode::ERROR_INVALID_DATA as u8);
            return Ok(());
        }

        let fwp = FirmwareParameters {
            caps: Default::default(),
            components: dev.components().into(),
            active: dev.active_image_set_version(),
            pending: dev.pending_image_set_version(),
        };

        let l = fwp.write_buf(&mut self.msg_buf).space()?;
        let resp = req.response_borrowed(&self.msg_buf[..l])?;

        pldm_tx_resp(ep, &resp)
    }

    // Request Update
    fn cmd_update(
        &mut self,
        req: &PldmRequest,
        ep: &mut impl Endpoint,
        dev: &mut impl Device,
    ) -> Result<()> {
        if !matches!(self.state, State::Idle { .. }) {
            self.reply_error(req, ep, FwCode::ALREADY_IN_UPDATE_MODE as u8);
            return Ok(());
        }

        let Ok((_, ru)) = all_consuming(RequestUpdateRequest::parse)(&req.data) else {
            trace!("error parsing RequestUpdate");
            self.reply_error(req, ep, CCode::ERROR_INVALID_DATA as u8);
            return Ok(());
        };

        // Don't let it be 0
        self.max_transfer =
            (ru.max_transfer as usize).max(PLDM_FW_BASELINE_TRANSFER);

        self.update_timestamp_fd_t1 = dev.now();

        let l = RequestUpdateResponse {
            fd_metadata_len: 0,
            fd_will_sent_gpd: 0,
        }.write_buf(&mut self.msg_buf).space()?;

        let resp = req.response_borrowed(&self.msg_buf[..l])?;
        pldm_tx_resp(ep, &resp)?;
        self.set_state(State::LearnComponents);
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
            self.set_state(State::ReadyXfer);
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

        // mask to only "Force Update"
        let res = dev.update_component(false, &up);

        let update_flags = up.flags.unwrap() & 0x1;

        let mut comp_resp = [0u8; 8];
        let mut b = SliceWriter::new(&mut comp_resp);
        // ComponentResponse, 0 for success, 1 otherwise?
        // ComponentResponseCode
        // UpdateOptionFlagsEnabled
        // Estimated time until update, seconds
        b.push_le8((res != 0) as u8).space()?;
        b.push_le8(res).space()?;
        b.push_le32(update_flags).space()?;
        b.push_le16(0).space()?;

        let resp = req.response_borrowed(&comp_resp)?;
        pldm_tx_resp(ep, &resp)?;

        self.set_state(State::Download {
            // OK unwrap, size is always set by parse_update()
            size: up.size.unwrap() as usize,
            offset: 0,
            requested: false,
            req_time: 0,
            classification: up.classification,
            identifier: up.identifier,
            index: up.classificationindex,
            update_flags,
        });
        Ok(())
    }

    fn cmd_get_status(
        &mut self,
        req: &PldmRequest,
        ep: &mut impl Endpoint,
        _dev: &mut impl Device,
    ) -> Result<()> {
        if !req.data.is_empty() {
            self.reply_error(req, ep, CCode::ERROR_INVALID_DATA as u8);
            return Ok(());
        }

        let l = self.get_status().write_buf(&mut self.msg_buf).space()?;
        let resp = req.response_borrowed(&self.msg_buf[..l])?;
        pldm_tx_resp(ep, &resp)
    }

    fn get_status(&self) -> GetStatusResponse {
        // Defaults for unspecified states
        let mut st = GetStatusResponse {
            current_state: (&self.state).into(),
            previous_state: self.prev_state,
            aux_state: 0,
            aux_state_status: 0,
            progress_percent: 101,
            reason_code: PldmIdleReason::Init as u8,
            update_option_flags_enabled: 0,
        };

        match &self.state {
            State::Idle { reason } => {
                st.reason_code = *reason as u8;
                st.aux_state = 3;
            }
            | State::LearnComponents
            | State::ReadyXfer
            => {
                st.aux_state = 3;
            }
            State::Download { size, offset, update_flags, .. } => {
                st.progress_percent = (size / offset * 100) as u8;
                st.update_option_flags_enabled = *update_flags;
                // TODO auxstate
            }
            State::Verify => {
                // TODO auxstate
            }
            State::Apply => {
                // TODO auxstate
            }
            State::Activate => {
                // TODO auxstate
            }
        }

        st

    }

    pub fn progress(&mut self, ep: &mut impl Endpoint, dev: &mut impl Device) {
        if !matches!(self.state, State::Idle { .. })
            && dev.now() - self.update_timestamp_fd_t1 > Self::FD_T1_TIMEOUT
        {
            // TODO cancel any updates in Device?
            self.set_state_idle_timeout();
        }

        if let State::Download { .. } = self.state {
            self.progress_download(ep, dev)
        }
    }

    /// The size of a request at a given offset
    fn req_size(&self, size: usize, offset: usize) -> usize {
        size.saturating_sub(offset)
            .min(self.max_transfer)
            .min(self.max_request())
    }

    fn progress_download(
        &mut self,
        ep: &mut impl Endpoint,
        dev: &mut impl Device,
    ) {
        let State::Download {
            size,
            offset,
            requested,
            req_time,
            ref classification,
            identifier,
            index,
            update_flags,
        } = self.state
        else {
            return;
        };

        if requested && dev.now() - req_time < Self::REQ_FW_RETRY_TIME {
            // waiting for a response, no action
            return;
        }

        // send a new request
        let mut buf = [0u8; 8];
        let mut b = SliceWriter::new(&mut buf);
        let _ = b.push_le32(offset as u32);
        let _ = b.push_le32(self.req_size(size, offset) as u32);
        debug_assert_eq!(b.written(), 8);

        let req = PldmRequest::new_borrowed(
            PLDM_TYPE_FW,
            Cmd::RequestFirmwareData as u8,
            &buf,
        );

        // reborrow mut
        let State::Download {
            requested,
            req_time,
            ..
        } = &mut self.state
        else {
            return;
        };

        *req_time = dev.now();

        if let Err(e) = pldm_tx_req(ep, &req) {
            trace!("Error tx request: {e:?}");
            return;
        }

        *requested = true;
    }

    fn set_state(&mut self, new_state: State) {
        self.prev_state = (&self.state).into();
        self.state = new_state;
    }

    fn set_idle(&mut self, reason: PldmIdleReason) {
        self.prev_state = (&self.state).into();
        self.state = State::Idle { reason };
    }

    fn set_state_idle_timeout(&mut self) {
        let reason = match self.state {
            State::Idle { .. } => return,
            State::LearnComponents => PldmIdleReason::TimeoutLearn,
            State::ReadyXfer => PldmIdleReason::TimeoutReadyXfer,
            State::Download { .. } => PldmIdleReason::TimeoutDownload,
            State::Verify => PldmIdleReason::TimeoutVerify,
            State::Apply => PldmIdleReason::TimeoutApply,
            // not a timeout
            State::Activate => PldmIdleReason::Activate,
        };
        self.set_idle(reason);
    }

    fn max_request(&self) -> usize {
        self.msg_buf.len()
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
