// SPDX-License-Identifier: Apache-2.0
/*
 * PLDM firmware device responder
 *
 * Copyright (c) 2024 Code Construct
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

use pldm::{pldm_tx_req, pldm_tx_resp, CCode, PldmError, PldmRequest, PldmResponse, PldmMessage,
proto_error};
use mctp::Eid;

use crate::*;

// Buffer for transmit. Must be sufficiently sized for sending
// components and device identifiers. TODO borrow this from somewhere?
const MSGBUF: usize = 1024 + 3;

type Result<T> = core::result::Result<T, PldmError>;

enum State {
    Idle {
        reason: PldmIdleReason,
    },
    LearnComponents,
    ReadyXfer,
    Download {
        offset: usize,
        // Set once when ready to exit from Download mode, will return
        // this value for TransferComplete request.
        transfer_result: Option<u8>,
        // Details of the last request.
        // `offset` is incremented on the `request` Sent->Ready transition.
        request: FDReq,

        update_flags: u32,

        // Details of the component currently being updated
        details: ComponentDetails,
    },
    Verify {
        // Set after retrieving the verify status from the [`Device`] callback.
        verify_result: Option<VerifyResult>,
        // details of the last request, and whether to retry
        request: FDReq,

        // Details of the component currently being updated, for the callback.
        details: ComponentDetails,
    },
    Apply {
        // Set after `apply()` from the [`Device`] callback.
        apply_result: Option<(ApplyResult, ActivationMethods)>,
        // details of the last request
        request: FDReq,

        // Details of the component currently being updated, for the callback.
        details: ComponentDetails,
    },
    Activate,
}

impl From<&State> for PldmFDState {
    fn from(s: &State) -> PldmFDState {
        match s {
            State::Idle { .. } => PldmFDState::Idle,
            State::LearnComponents => PldmFDState::LearnComponents,
            State::ReadyXfer => PldmFDState::ReadyXfer,
            State::Download { .. } => PldmFDState::Download,
            State::Verify { .. } => PldmFDState::Verify,
            State::Apply { .. } => PldmFDState::Apply,
            State::Activate => PldmFDState::Activate,
        }
    }
}

pub struct Responder {
    /// state should be modified via set_state()
    state: State,
    prev_state: PldmFDState,

    /// EID of the current EID. This is set on the RequestUpdate message
    /// and cleared when returning to Idle state.
    /// Non-informational commands from other EIDs will be rejected while ua_eid is set.
    /// CancelUpdate is allowed from any EID.
    ua_eid: Option<Eid>,

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

    /// Specification baseline request size
    pub const BASELINE_MTU: usize = 32;

    pub fn new() -> Self {
        Self {
            ua_eid: None,
            state: State::Idle {
                reason: PldmIdleReason::Init,
            },
            prev_state: PldmFDState::Idle,
            msg_buf: [0; MSGBUF],
            max_transfer: PLDM_FW_BASELINE_TRANSFER,
            update_timestamp_fd_t1: 0,
        }
    }

    /// Handle an incoming PLDM FW message
    ///
    /// Errors returned from this function are not expected to be handled
    /// apart from logging.
    /// `resp_ep` will be used to send responses, and must be associated with
    /// address `eid`.
    pub fn message_in(
        &mut self,
        eid: Eid,
        msg: &PldmMessage,
        resp_ep: &mut impl mctp::Endpoint,
        d: &mut impl Device,
    ) -> Result<()> {
        match msg {
            PldmMessage::Request(req) => self.request_in(eid, req, resp_ep, d),
            PldmMessage::Response(rsp) => self.response_in(eid, rsp, d),
        }
    }

    /// Handle an incoming PLDM FW request
    ///
    /// Returns `Ok` if a reply is sent to the UA, including for error responses.
    fn request_in(
        &mut self,
        eid: Eid,
        req: &PldmRequest,
        ep: &mut impl mctp::Endpoint,
        d: &mut impl Device,
    ) -> Result<()> {

        if req.typ != PLDM_TYPE_FW {
            trace!("pldm-fw non-pldm-fw request {req:?}");
            return Err(proto_error!("Unexpected pldm-fw request"));
        }

        let Some(cmd) = Cmd::from_u8(req.cmd) else {
            self.reply_error(&req, ep, CCode::ERROR_UNSUPPORTED_PLDM_CMD as u8);
            return Ok(());
        };

        // Check for consistent EID
        match cmd {
            // informational commands or Cancel always allowed
            | Cmd::QueryDeviceIdentifiers
            | Cmd::GetFirmwareParameters
            | Cmd::GetStatus
            | Cmd::CancelUpdate
            // RequestUpdate will check itself
            | Cmd::RequestUpdate
            => (),
            _ => {
                if self.ua_eid != Some(eid) {
                    debug!("Ignoring {cmd:?} from mismatching EID {eid}, expected {:?}", self.ua_eid);
                    self.reply_error(&req, ep,
                        CCode::ERROR_NOT_READY as u8,
                    );
                }
            }
        }

        debug_assert_eq!(self.ua_eid.is_none(), matches!(self.state, State::Idle {..}),
            "UA EID should be set in states apart from IDLE");

        trace!("pldm-fw cmd {cmd:?}");

        // Handlers will return Ok if they have replied
        let r = match cmd {
            Cmd::QueryDeviceIdentifiers => self.cmd_qdi(&req, ep, d),
            Cmd::GetFirmwareParameters => self.cmd_fwparams(&req, ep, d),
            Cmd::RequestUpdate => self.cmd_update(&req, eid, ep, d),
            Cmd::PassComponentTable => self.cmd_pass_components(&req, ep, d),
            Cmd::UpdateComponent => self.cmd_update_component(&req, ep, d),
            Cmd::CancelUpdate => self.cmd_cancel_update(&req, ep, d),
            Cmd::CancelUpdateComponent => self.cmd_cancel_update_component(&req, ep, d),
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

    /// Handle an incoming PLDM FW response
    ///
    /// These are responses to
    /// RequestFirmwareData, TransferComplete, VerifyComplete, ApplyComplete
    fn response_in(
        &mut self,
        eid: Eid,
        rsp: &PldmResponse,
        d: &mut impl Device,) -> Result<()> {

        if self.ua_eid != Some(eid) {
            // Either this is a response prior to a RequestUpdate,
            // or a response from a different EID to the RequestUpdate.
            return Err(proto_error!("Response from unexpected EID"));
        }

        match Cmd::from_u8(rsp.cmd) {
            Some(Cmd::RequestFirmwareData) => self.download_response(rsp, d),
            | Some(Cmd::TransferComplete)
            | Some(Cmd::VerifyComplete)
            | Some(Cmd::ApplyComplete)
            // Ignore replies to these requests.
            // We may have already moved on to a later state
            // and don't have any useful retry for them.
            => Ok(()),
            _ => Err(proto_error!("Unsupported PLDM response"))
        }
    }

    fn reply_error(&self, req: &PldmRequest, ep: &mut impl mctp::Endpoint, cc: u8) {
        let mut resp = req.response_borrowed(&[]).unwrap();
        resp.cc = cc;
        let _ = pldm_tx_resp(ep, &resp)
            .inspect_err(|e| trace!("Error sending failure response. {e:?}"));
    }

    /// Query Device Identifiers
    fn cmd_qdi(
        &mut self,
        req: &PldmRequest,
        ep: &mut impl mctp::Endpoint,
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
        ep: &mut impl mctp::Endpoint,
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
        eid: Eid,
        ep: &mut impl mctp::Endpoint,
        dev: &mut impl Device,
    ) -> Result<()> {
        if !matches!(self.state, State::Idle { .. }) {
            self.reply_error(req, ep, FwCode::ALREADY_IN_UPDATE_MODE as u8);
            return Ok(());
        }

        debug_assert!(self.ua_eid.is_none());
        self.ua_eid = Some(eid);

        let Ok((_, ru)) = all_consuming(RequestUpdateRequest::parse)(&req.data)
        else {
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
        }
        .write_buf(&mut self.msg_buf)
        .space()?;

        let resp = req.response_borrowed(&self.msg_buf[..l])?;
        pldm_tx_resp(ep, &resp)?;
        self.set_state(State::LearnComponents);
        Ok(())
    }

    fn cmd_pass_components(
        &mut self,
        req: &PldmRequest,
        ep: &mut impl mctp::Endpoint,
        dev: &mut impl Device,
    ) -> Result<()> {
        if !matches!(self.state, State::LearnComponents) {
            self.reply_error(req, ep, FwCode::INVALID_STATE_FOR_COMMAND as u8);
            return Ok(());
        }

        let Ok((_, (transferflag, up))) = all_consuming(tuple((
            le_u8,
            UpdateComponent::parse_pass_component,
        )))(&req.data) else {
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
        ep: &mut impl mctp::Endpoint,
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
        let res = dev.update_component(true, &up);

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

        let details = ComponentDetails {
            // OK unwrap, size is always set by parse_update()
            size: up.size.unwrap() as usize,
            classification: up.classification,
            identifier: up.identifier,
            index: up.classificationindex,
        };

        self.set_state(State::Download {
            offset: 0,
            transfer_result: None,
            request: FDReq::Ready,
            update_flags,
            details,
        });
        Ok(())
    }

    fn cmd_cancel_update(
        &mut self,
        req: &PldmRequest,
        ep: &mut impl mctp::Endpoint,
        dev: &mut impl Device,
    ) -> Result<()> {
        let details = match &self.state {
            | State::Download { details, .. }
            | State::Verify { details, .. }
            | State::Apply { details, .. }
            => Some(details),
            State::Idle { .. }=> {
                self.reply_error(req, ep, FwCode::NOT_IN_UPDATE_MODE as u8);
                return Ok(());
            }
            State::Activate => {
                self.reply_error(req, ep, FwCode::INVALID_STATE_FOR_COMMAND as u8);
                return Ok(());
            }
            _ => None,
        };

        if !req.data.is_empty() {
            trace!("error parsing CancelUpdate");
            self.reply_error(req, ep, CCode::ERROR_INVALID_DATA as u8);
            return Ok(())
        }

        let mut resp = req.response_borrowed(&[])?;
        resp.cc = CCode::SUCCESS as u8;
        pldm_tx_resp(ep, &resp)?;

        details.map(|d| dev.cancel_component(d));
        self.set_idle(PldmIdleReason::Cancel);

        Ok(())
    }

    fn cmd_cancel_update_component(
        &mut self,
        req: &PldmRequest,
        ep: &mut impl mctp::Endpoint,
        dev: &mut impl Device,
    ) -> Result<()> {
        let details = match &self.state {
            | State::Download { details, .. }
            | State::Verify { details, .. }
            | State::Apply { details, .. }
            => details,
            State::Idle { .. } => {
                self.reply_error(req, ep, FwCode::NOT_IN_UPDATE_MODE as u8);
                return Ok(());
            }
            _ => {
                self.reply_error(req, ep, FwCode::INVALID_STATE_FOR_COMMAND as u8);
                return Ok(());
            }
        };

        if !req.data.is_empty() {
            trace!("error parsing CancelUpdateComponent");
            self.reply_error(req, ep, CCode::ERROR_INVALID_DATA as u8);
            return Ok(())
        }

        let mut resp = req.response_borrowed(&[])?;
        resp.cc = CCode::SUCCESS as u8;
        pldm_tx_resp(ep, &resp)?;

        dev.cancel_component(&details);
        self.set_state(State::ReadyXfer);

        Ok(())
    }

    fn cmd_get_status(
        &mut self,
        req: &PldmRequest,
        ep: &mut impl mctp::Endpoint,
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
            State::LearnComponents | State::ReadyXfer => {
                st.aux_state = 3;
            }
            State::Download {
                details,
                offset,
                update_flags,
                request,
                ..
            } => {
                st.progress_percent =
                    ((*offset as u64) * 100 / (details.size as u64)) as u8;
                st.update_option_flags_enabled = *update_flags;
                (st.aux_state, st.aux_state_status) = request.aux_state();
            }
            State::Verify { request, .. } => {
                (st.aux_state, st.aux_state_status) = request.aux_state();
            }
            State::Apply { request, .. } => {
                (st.aux_state, st.aux_state_status) = request.aux_state();
            }
            State::Activate => {
                // TODO auxstate
            }
        }

        st
    }

    pub fn progress(&mut self, ep: &mut impl mctp::Endpoint, dev: &mut impl Device) {
        if !matches!(self.state, State::Idle { .. })
            && dev.now() - self.update_timestamp_fd_t1 > Self::FD_T1_TIMEOUT
        {
            // TODO cancel any updates in Device?
            self.set_state_idle_timeout();
        }

        if let State::Download { .. } = self.state {
            self.progress_download(ep, dev)
        }

        if let State::Verify { .. } = self.state {
            self.progress_verify(ep, dev)
        }

        if let State::Apply { .. } = self.state {
            self.progress_apply(ep, dev)
        }
    }

    /// The size of a request at a given offset.
    ///
    /// Must only be called in Download state
    fn req_size(&self) -> usize {
        let State::Download { ref details, offset, .. } = self.state else {
            debug_assert!(false);
            return 0;
        };

        details.size.saturating_sub(offset)
            .min(self.max_transfer)
            .min(self.max_request())
    }

    // Download state progress
    fn progress_download(
        &mut self,
        ep: &mut impl mctp::Endpoint,
        dev: &mut impl Device,
    ) {
        let State::Download {
            offset,
            ref request,
            transfer_result,
            ..
        } = self.state
        else {
            return;
        };

        if !request.should_send(dev) {
            return;
        }

        let mut b = [0u8; 8];
        let mut b = SliceWriter::new(&mut b);

        let mut req = if let Some(transfer_result) = transfer_result {
            let _ = b.push_le8(transfer_result);
            // Send a new TransferComplete
            PldmRequest::new_borrowed(
                PLDM_TYPE_FW,
                Cmd::TransferComplete as u8,
                b.done(),
            )
        } else {
            // send a new RequestFirmwareData
            let _ = b.push_le32(offset as u32);
            let _ = b.push_le32(self.req_size() as u32);
            debug_assert_eq!(b.written(), 8);

            PldmRequest::new_borrowed(
                PLDM_TYPE_FW,
                Cmd::RequestFirmwareData as u8,
                b.done(),
            )
        };

        if let Err(e) = pldm_tx_req(ep, &mut req) {
            trace!("Error tx request: {e:?}");
            // let the retry timer handle it.
            return;
        }

        // reborrow mut
        if let State::Download { request, transfer_result, details, .. } = &mut self.state {
            if let Some(tr) = transfer_result {
                // transfer complete sent
                if *tr == TransferResult::Success as u8 {
                    let details = details.clone();
                    self.set_state(State::Verify { verify_result: None,
                        request: FDReq::Ready,
                        details });
                } else {
                    // idle in Download state until the UA cancels
                    *request = FDReq::Failed(*tr)
                }
            } else {
                // update retry timer for for the firmware data request
                *request = FDReq::Sent { time: dev.now(), iid: req.iid, cmd: req.cmd }
            }
        }
    }

    // Verify state progress
    fn progress_verify(
        &mut self,
        ep: &mut impl mctp::Endpoint,
        dev: &mut impl Device,
    ) {
        let State::Verify {
            verify_result,
            request,
            details,
        } = &mut self.state
        else {
            return;
        };

        if !request.should_send(dev) {
            return;
        }

        let vr = verify_result.get_or_insert_with(|| {
            // Perform the device-specific verify
            dev.verify(details).unwrap_or_else(|_e| {
                trace!("Error from Device::verify().");
                VerifyResult::Failure
            })
        });

        // Send a new VerifyComplete
        let buf = [u8::from(*vr)];
        let mut req = PldmRequest::new_borrowed(
            PLDM_TYPE_FW,
            Cmd::VerifyComplete as u8,
            &buf,
        );

        if let Err(e) = pldm_tx_req(ep, &mut req) {
            trace!("Error tx request: {e:?}");
            // let the retry timer handle it
            return;
        }

        if *vr == VerifyResult::Success {
            let details = details.clone();
            self.set_state(State::Apply { apply_result: None, request: FDReq::Ready,
                details });
        } else {
            // on verify failure remain in State::Verify, wait for cancel
            *request = FDReq::Failed(u8::from(*vr))
        }
    }

    // Apply state progress
    fn progress_apply(
        &mut self,
        ep: &mut impl mctp::Endpoint,
        dev: &mut impl Device,
    ) {
        let State::Apply {
            apply_result,
            request,
            details,
        } = &mut self.state
        else {
            return;
        };

        if !request.should_send(dev) {
            return;
        }

        let (ar, methods) = apply_result.get_or_insert_with(|| {
            // Perform the device-specific apply
            dev.apply(details).unwrap_or_else(|_e| {
                trace!("Error from Device::apply().");
                (ApplyResult::GenericError, Default::default())
            })
        });

        // Create the response
        let mut r = [0u8; 3];
        let mut b = SliceWriter::new(&mut r);
        let _ = b.push_le8(u8::from(*ar));
        let _ = b.push_le16(methods.as_u16());

        // Send a new ApplyComplete
        let mut req = PldmRequest::new_borrowed(
            PLDM_TYPE_FW,
            Cmd::ApplyComplete as u8,
            &r,
        );

        if let Err(e) = pldm_tx_req(ep, &mut req) {
            trace!("Error tx request: {e:?}");
            // let retry timer handle it
            return;
        }

        if *ar == ApplyResult::Success {
            self.set_state(State::ReadyXfer);
        } else {
            // on failure remain in State::Apply, wait for cancel
            *request = FDReq::Failed(u8::from(*ar));
        }
    }

    fn download_response(
        &mut self,
        rsp: &PldmResponse,
        dev: &mut impl Device,) -> Result<()> {

        let State::Download {
            offset,
            ref request,
            transfer_result,
            ref details,
            ..
        } = self.state
        else {
            debug!("RequestFirmwareData response but not in Download state");
            return Ok(())
        };

        if transfer_result.is_some() {
            debug!("firmware data after result");
            return Ok(())
        }

        request.validate_response(rsp)?;

        let expect_size = self.req_size();
        if rsp.data.len() != expect_size {
            trace!(
                "Offset {offset} requested {expect_size} got {}",
                rsp.data.len()
            );
            // Let the timeout handle a retry
            return Ok(())
        }

        if let Err(e) = dev.firmware_data(offset, &rsp.data, details) {
            trace!("Error from firmware_data callback. {e:?}");
            // TODO let the Device cancel the transfer with a
            // TransferResult failure.
            // Let the timeout handle a retry.
            return Ok(())
        }

        // Success, move to next offset.
        // Next offset, progress() will send the next request.
        if let State::Download {
            offset, request, details, transfer_result, ..
        } = &mut self.state {
            *request = FDReq::Ready;
            *offset += rsp.data.len();

            if *offset == details.size {
                debug_assert!(transfer_result.is_none());
                // Transfer is complete.
                // TODO: At present we only exit Download state on success.
                *transfer_result = Some(TransferResult::Success as u8);
            }
        }

        Ok(())
    }

    fn set_state(&mut self, new_state: State) {
        debug_assert!(!matches!(new_state, State::Idle { .. }),
            "Idle state should use set_idle() instead");
        debug_assert!(self.ua_eid.is_some());

        self.prev_state = (&self.state).into();
        self.state = new_state;
    }

    fn set_idle(&mut self, reason: PldmIdleReason) {
        self.prev_state = (&self.state).into();
        self.state = State::Idle { reason };
        self.ua_eid = None;
    }

    fn set_state_idle_timeout(&mut self) {
        let reason = match self.state {
            State::Idle { .. } => return,
            State::LearnComponents => PldmIdleReason::TimeoutLearn,
            State::ReadyXfer => PldmIdleReason::TimeoutReadyXfer,
            State::Download { .. } => PldmIdleReason::TimeoutDownload,
            State::Verify { .. } => PldmIdleReason::TimeoutVerify,
            State::Apply { .. } => PldmIdleReason::TimeoutApply,
            // not a timeout
            State::Activate => PldmIdleReason::Activate,
        };
        self.set_idle(reason);
    }

    fn max_request(&self) -> usize {
        // allow space for pldm header
        self.msg_buf.len() - 3
    }
}

/// Handles request/response for Download/Verify/Apply states.
#[derive(Debug)]
enum FDReq {
    /// Ready to send a request
    Ready,
    /// Waiting for a response
    Sent {
        // iid of the request
        iid: u8,
        cmd: u8,
        // time the request was sent
        time: u64,
        // TODO: maybe add a current retry count?
    },
    /// Completed and failed, will not send more requests.
    /// Waiting for the UA to send a Cancel to move out of the current State
    /// The u8 value is the failure code, reported via GetStatus AuxState
    Failed(u8),
}

impl FDReq {
    pub const RETRY_TIME: u64 = 1_000;

    /// Checks whether a response matches a sent request.
    ///
    /// This checks matching cmd, iid.
    /// Consumes `request` by value since it will be cleared by callers
    /// after receiving it.
    fn validate_response(&self, rsp: &PldmResponse) -> Result<()> {
        let Self::Sent { iid, cmd, .. } = self else {
            trace!("unexpected pldm-fw response {rsp:?}");
            return Err(proto_error!("Unexpected pldm-fw response"));
        };

        if rsp.typ != PLDM_TYPE_FW {
            trace!("pldm-fw non-pldm-fw response {rsp:?}");
            return Err(proto_error!("Unexpected pldm-fw response"));
        }

        if rsp.iid != *iid {
            trace!("pldm-fw iid mismatch req {self:?} response {rsp:?}");
            return Err(proto_error!("Unexpected pldm-fw response"));
        }

        if rsp.cmd != *cmd {
            trace!("pldm-fw cmd mismatch req {self:?} response {rsp:?}");
            return Err(proto_error!("Unexpected pldm-fw response"));
        }

        Ok(())
    }

    fn should_send(&self, dev: &mut impl Device) -> bool {
        match self {
            Self::Ready => true,
            Self::Sent { time, .. } => {
                // send if retry time has elapsed
                dev.now() - time > Self::RETRY_TIME
            },
            // no retries, waiting for a cancel from the UA
            Self::Failed(_) => false,
        }
    }

    // Returns (AuxState, AuxStateStatus)
    fn aux_state(&self) -> (u8, u8) {
        match self {
            | Self::Ready
            | Self::Sent { .. }
             => (0, 0),
            Self::Failed(e) => (2, *e)
        }
    }
}

/// Details of a particular component image
#[derive(Debug, Clone)]
pub struct ComponentDetails {
    /// Size in bytes of the component image
    size: usize,
    /// Component classification
    classification: ComponentClassification,
    /// Component identifier
    identifier: u16,
    /// Component classification index
    index: u8,
}


/// Implementation details for a particular Firmware Device
///
/// Applications define the PLDM Firmware Update behaviour
/// by implementing this trait.
pub trait Device {
    fn dev_identifiers(&mut self) -> &DeviceIdentifiers;

    fn components(&self) -> &[Component];

    fn active_image_set_version(&self) -> DescriptorString;

    /// Provide the PendingComponentImageSet for GetFirmwareParameters
    ///
    /// The default implementation returns an empty entry.
    fn pending_image_set_version(&self) -> DescriptorString {
        DescriptorString::empty()
    }

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

    /// Provides a portion of a component image
    fn firmware_data(&mut self, offset: usize, data: &[u8],
        comp: &ComponentDetails,
        ) -> Result<()>;

    /// Verifies a component after transfer completion.
    ///
    /// This function should return a [`VerifyResult`] value (as a `u8`).
    // TODO: In future this may need a non-blocking variant
    // in order to report progress status of the verify.
    fn verify(&mut self, comp: &ComponentDetails) -> Result<VerifyResult>;

    /// Applies a component after verify success.
    fn apply(&mut self, comp: &ComponentDetails) -> Result<(ApplyResult, ActivationMethods)>;

    /// Cancel Update Component
    ///
    /// Called when a component update is cancelled prior to being applied.
    /// This function is called for both Cancel Update Component
    /// and Cancel Update (when a component is currently in progress).
    /// The default implementation does nothing.
    #[allow(unused)]
    fn cancel_component(&mut self, comp: &ComponentDetails) { }

    /// Returns a monotonic timestamp in milliseconds.
    ///
    /// This may have an arbitrary initial offset.
    /// Implementations must guarantee time doesn't go backwards.
    fn now(&mut self) -> u64;
}

#[cfg(test)]
mod tests {

    use crate::*;
}
