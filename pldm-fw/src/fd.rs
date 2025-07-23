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
    combinator::{all_consuming, map},
    multi::length_value,
    number::complete::{le_u16, le_u32, le_u8},
    sequence::tuple,
    IResult,
};

use num_traits::FromPrimitive;

use mctp::{Eid, ReqChannel, RespChannel};
use pldm::{
    pldm_tx_req, pldm_tx_resp, proto_error, CCode, PldmError, PldmRequest,
    PldmResponse,
};

use crate::*;

// Buffer for transmit. Must be sufficiently sized for sending
// components and device identifiers. TODO borrow this from somewhere?
const MSGBUF: usize = 1024 + 3;

type Result<T> = core::result::Result<T, PldmError>;

enum State<C: ReqChannel> {
    Idle {
        reason: PldmIdleReason,
    },
    LearnComponents,
    ReadyXfer,
    Download {
        offset: usize,
        // Set once when ready to exit from Download mode, will return
        // this value for TransferComplete request.
        transfer_result: Option<TransferResult>,
        // Details of the last request.
        // `offset` is incremented on the `request` Sent->Ready transition.
        request: FDReq,

        update_flags: u32,

        // Details of the component currently being updated
        details: ComponentDetails,

        // comm to send RequestFirmwareData to, and to await response from
        req_comm: C,
        // Whether a response is currently expected on req_comm.
        req_pending: bool,
    },
    Verify {
        // Set after retrieving the verify status from the [`Device`] callback.
        verify_result: Option<VerifyResult>,
        // details of the last request, and whether to retry
        request: FDReq,

        // Details of the component currently being updated, for the callback.
        details: ComponentDetails,

        req_comm: C,
        req_pending: bool,
    },
    Apply {
        // Set after `apply()` from the [`Device`] callback.
        apply_result: Option<(ApplyResult, ActivationMethods)>,
        // details of the last request
        request: FDReq,

        // Details of the component currently being updated, for the callback.
        details: ComponentDetails,

        req_comm: C,
        req_pending: bool,
    },
    Activate,
}

impl<C: ReqChannel> From<&State<C>> for PldmFDState {
    fn from(s: &State<C>) -> PldmFDState {
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

pub struct Responder<R: RespChannel> {
    /// state should be modified via set_state()
    state: State<R::ReqChannel>,
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

impl<R: RespChannel> Responder<R> {
    /// Update mode idle timeout, 120 seconds
    pub const FD_T1_TIMEOUT: u64 = 120_000;

    #[allow(clippy::new_without_default)]
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

    /// Handle an incoming PLDM FW request
    ///
    /// Returns `Ok` if a reply is sent to the UA, including for error responses.
    pub fn request_in(
        &mut self,
        mut comm: R,
        req: &PldmRequest,
        d: &mut impl Device,
    ) -> Result<()> {
        if req.typ != PLDM_TYPE_FW {
            trace!("pldm-fw non-pldm-fw request {req:?}");
            return Err(proto_error!("Unexpected pldm-fw request"));
        }

        let Some(cmd) = Cmd::from_u8(req.cmd) else {
            self.reply_error(
                req,
                &mut comm,
                CCode::ERROR_UNSUPPORTED_PLDM_CMD as u8,
            );
            return Ok(());
        };

        let eid = comm.remote_eid();
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
                    self.reply_error(req, &mut comm,
                        CCode::ERROR_NOT_READY as u8,
                    );
                }
            }
        }

        debug_assert_eq!(
            self.ua_eid.is_none(),
            matches!(self.state, State::Idle { .. }),
            "UA EID should be set in states apart from IDLE"
        );

        trace!("pldm-fw cmd {cmd:?}");

        // Handlers will return Ok if they have replied
        let r = match cmd {
            Cmd::QueryDeviceIdentifiers => self.cmd_qdi(req, &mut comm, d),
            Cmd::GetFirmwareParameters => self.cmd_fwparams(req, &mut comm, d),
            Cmd::RequestUpdate => self.cmd_update(req, eid, &mut comm, d),
            Cmd::PassComponentTable => {
                self.cmd_pass_components(req, &mut comm, d)
            }
            Cmd::UpdateComponent => {
                return self.cmd_update_component(req, comm, d)
            }
            Cmd::ActivateFirmware => self.cmd_activate(req, &mut comm, d),
            Cmd::CancelUpdate => self.cmd_cancel_update(req, &mut comm, d),
            Cmd::CancelUpdateComponent => {
                self.cmd_cancel_update_component(req, &mut comm, d)
            }
            Cmd::GetStatus => self.cmd_get_status(req, &mut comm, d),
            _ => {
                trace!("unhandled command {cmd:?}");
                self.reply_error(
                    req,
                    &mut comm,
                    CCode::ERROR_UNSUPPORTED_PLDM_CMD as u8,
                );
                Ok(())
            }
        };

        if let Err(e) = &r {
            debug!("Error handling {cmd:?}: {e:?}");
            self.reply_error(req, &mut comm, CCode::ERROR as u8);
        }
        Ok(())
    }

    pub fn pending_reply_ep(&mut self) -> Option<&mut R::ReqChannel> {
        let r = match &mut self.state {
            State::Download {
                req_comm,
                req_pending,
                ..
            }
            | State::Verify {
                req_comm,
                req_pending,
                ..
            }
            | State::Apply {
                req_comm,
                req_pending,
                ..
            } => req_pending.then(|| req_comm),
            _ => None,
        };
        trace!("pending reply {}", r.is_some());
        r
    }

    /// Handle an incoming PLDM FW response
    ///
    /// These are replies to
    /// RequestFirmwareData, TransferComplete, VerifyComplete, ApplyComplete
    pub fn reply_in(
        &mut self,
        eid: Eid,
        rsp: &PldmResponse,
        d: &mut impl Device,
    ) -> Result<()> {
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

    fn reply_error(&self, req: &PldmRequest, comm: &mut R, cc: u8) {
        let mut resp = req.response_borrowed(&[]);
        resp.cc = cc;
        let _ = pldm_tx_resp(comm, &resp)
            .inspect_err(|e| trace!("Error sending failure response. {e:?}"));
    }

    /// Query Device Identifiers
    fn cmd_qdi(
        &mut self,
        req: &PldmRequest,
        comm: &mut R,
        dev: &mut impl Device,
    ) -> Result<()> {
        // Valid in any state, doesn't change state
        if !req.data.is_empty() {
            self.reply_error(req, comm, CCode::ERROR_INVALID_DATA as u8);
            return Ok(());
        }

        let l = dev.dev_identifiers().write_buf(&mut self.msg_buf).space()?;
        let resp = req.response_borrowed(&self.msg_buf[..l]);

        pldm_tx_resp(comm, &resp)
    }

    /// Get Firmware Parameters
    fn cmd_fwparams(
        &mut self,
        req: &PldmRequest,
        comm: &mut R,
        dev: &mut impl Device,
    ) -> Result<()> {
        // Valid in any state, doesn't change state
        if !req.data.is_empty() {
            self.reply_error(req, comm, CCode::ERROR_INVALID_DATA as u8);
            return Ok(());
        }

        let fwp = FirmwareParameters {
            caps: Default::default(),
            components: dev.components().into(),
            active: dev.active_image_set_version(),
            pending: dev.pending_image_set_version(),
        };

        let l = fwp.write_buf(&mut self.msg_buf).space()?;
        let resp = req.response_borrowed(&self.msg_buf[..l]);

        pldm_tx_resp(comm, &resp)
    }

    // Request Update
    fn cmd_update(
        &mut self,
        req: &PldmRequest,
        eid: Eid,
        comm: &mut R,
        dev: &mut impl Device,
    ) -> Result<()> {
        if !matches!(self.state, State::Idle { .. }) {
            self.reply_error(req, comm, FwCode::ALREADY_IN_UPDATE_MODE as u8);
            return Ok(());
        }

        debug_assert!(self.ua_eid.is_none());
        self.ua_eid = Some(eid);

        let Ok((_, ru)) = all_consuming(RequestUpdateRequest::parse)(&req.data)
        else {
            trace!("error parsing RequestUpdate");
            self.reply_error(req, comm, CCode::ERROR_INVALID_DATA as u8);
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

        let resp = req.response_borrowed(&self.msg_buf[..l]);
        pldm_tx_resp(comm, &resp)?;
        self.set_state(State::LearnComponents);
        Ok(())
    }

    fn cmd_pass_components(
        &mut self,
        req: &PldmRequest,
        comm: &mut R,
        dev: &mut impl Device,
    ) -> Result<()> {
        if !matches!(self.state, State::LearnComponents) {
            self.reply_error(
                req,
                comm,
                FwCode::INVALID_STATE_FOR_COMMAND as u8,
            );
            return Ok(());
        }

        let Ok((_, (transferflag, up))) = all_consuming(tuple((
            le_u8,
            UpdateComponent::parse_pass_component,
        )))(&req.data) else {
            trace!("error parsing PassComponent");
            self.reply_error(req, comm, CCode::ERROR_INVALID_DATA as u8);
            return Ok(());
        };

        // only set for UpdateComponent
        debug_assert!(up.flags.is_none());
        debug_assert!(up.size.is_none());

        self.update_timestamp_fd_t1 = dev.now();

        let res = self.check_update_component(false, &up, dev);

        // byte 0: ComponentResponse, 0 for success, 1 otherwise?
        // byte 1: ComponentResponseCode
        let comp_resp = [(res != 0) as u8, res];
        let resp = req.response_borrowed(&comp_resp);
        pldm_tx_resp(comm, &resp)?;

        if transferflag & TransferFlag::End as u8 > 0 {
            self.set_state(State::ReadyXfer);
        }
        Ok(())
    }

    /// Wrapper around calls to dev.update_componenet() that first checks
    /// that the component is in the list returned from `dev`.
    fn check_update_component(
        &self,
        update: bool,
        up: &UpdateComponent,
        dev: &mut impl Device,
    ) -> u8 {
        // Check that the component is known in platform's list
        let found = dev.components().iter().any(|c| {
            c.classification == up.classification
                && c.identifier == up.identifier
                && c.classificationindex == up.classificationindex
        });

        if found {
            dev.update_component(update, up)
        } else {
            ComponentResponseCode::NotSupported as u8
        }
    }

    fn cmd_update_component(
        &mut self,
        req: &PldmRequest,
        mut comm: R,
        dev: &mut impl Device,
    ) -> Result<()> {
        if !matches!(self.state, State::ReadyXfer) {
            self.reply_error(req, &mut comm, FwCode::NOT_IN_UPDATE_MODE as u8);
            return Ok(());
        }

        let Ok((_, up)) =
            all_consuming(UpdateComponent::parse_update)(&req.data)
        else {
            trace!("error parsing UpdateComponent");
            self.reply_error(req, &mut comm, CCode::ERROR_INVALID_DATA as u8);
            return Ok(());
        };

        debug_assert!(up.flags.is_some());
        debug_assert!(up.size.is_some());

        self.update_timestamp_fd_t1 = dev.now();

        // mask to only "Force Update"
        let res = self.check_update_component(true, &up, dev);

        let update_flags = up.flags.unwrap_or(0) & 0x1;

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

        let resp = req.response_borrowed(&comp_resp);
        pldm_tx_resp(&mut comm, &resp)?;

        let details = ComponentDetails {
            size: up.size.unwrap_or(0) as usize,
            classification: up.classification,
            identifier: up.identifier,
            index: up.classificationindex,
        };

        // Special case for zero size component. It will immediately send TransferComplete
        // instead of RequestFirmwareData.
        let transfer_result =
            (details.size == 0).then_some(TransferResult::Success);

        let req_comm = comm.req_channel()?;

        self.set_state(State::Download {
            offset: 0,
            transfer_result,
            request: FDReq::Ready,
            update_flags,
            details,
            req_comm,
            req_pending: false,
        });
        Ok(())
    }

    fn cmd_activate(
        &mut self,
        req: &PldmRequest,
        comm: &mut R,
        dev: &mut impl Device,
    ) -> Result<()> {
        if req.data.len() != 1 {
            trace!("error parsing Activate");
            self.reply_error(req, comm, CCode::ERROR_INVALID_DATA as u8);
        }
        let self_contained = req.data[0] != 0;

        // check correct state
        match self.state {
            State::ReadyXfer => (),
            State::Idle { .. } => {
                self.reply_error(req, comm, FwCode::NOT_IN_UPDATE_MODE as u8);
                return Ok(());
            }
            _ => {
                self.reply_error(
                    req,
                    comm,
                    FwCode::INVALID_STATE_FOR_COMMAND as u8,
                );
                return Ok(());
            }
        }

        // The Device implementation is responsible for checking that
        // expected components have been updated.
        let status = dev.activate(self_contained) as u8;

        // No EstimatedTimeForSelfContainedActivation for now.
        let data = [0x00, 0x00];
        let mut resp = req.response_borrowed(&data);
        resp.cc = status;
        pldm_tx_resp(comm, &resp)?;

        // No progress is provided for self contained activation,
        // so we proceed ->Activate->Idle (which sets the previous state
        // correctly).
        self.set_state(State::Activate);
        self.set_idle(PldmIdleReason::Activate);
        Ok(())
    }

    fn cmd_cancel_update(
        &mut self,
        req: &PldmRequest,
        comm: &mut R,
        dev: &mut impl Device,
    ) -> Result<()> {
        let details = match &self.state {
            State::Download { details, .. }
            | State::Verify { details, .. }
            | State::Apply { details, .. } => Some(details),
            State::Idle { .. } => {
                self.reply_error(req, comm, FwCode::NOT_IN_UPDATE_MODE as u8);
                return Ok(());
            }
            State::Activate => {
                self.reply_error(
                    req,
                    comm,
                    FwCode::INVALID_STATE_FOR_COMMAND as u8,
                );
                return Ok(());
            }
            _ => None,
        };

        if !req.data.is_empty() {
            trace!("error parsing CancelUpdate");
            self.reply_error(req, comm, CCode::ERROR_INVALID_DATA as u8);
            return Ok(());
        }

        let mut resp = req.response_borrowed(&[]);
        resp.cc = CCode::SUCCESS as u8;
        pldm_tx_resp(comm, &resp)?;

        if let Some(details) = details {
            dev.cancel_component(details);
        }
        self.set_idle(PldmIdleReason::Cancel);

        Ok(())
    }

    fn cmd_cancel_update_component(
        &mut self,
        req: &PldmRequest,
        comm: &mut R,
        dev: &mut impl Device,
    ) -> Result<()> {
        let details = match &self.state {
            State::Download { details, .. }
            | State::Verify { details, .. }
            | State::Apply { details, .. } => details,
            State::Idle { .. } => {
                self.reply_error(req, comm, FwCode::NOT_IN_UPDATE_MODE as u8);
                return Ok(());
            }
            _ => {
                self.reply_error(
                    req,
                    comm,
                    FwCode::INVALID_STATE_FOR_COMMAND as u8,
                );
                return Ok(());
            }
        };

        if !req.data.is_empty() {
            trace!("error parsing CancelUpdateComponent");
            self.reply_error(req, comm, CCode::ERROR_INVALID_DATA as u8);
            return Ok(());
        }

        let mut resp = req.response_borrowed(&[]);
        resp.cc = CCode::SUCCESS as u8;
        pldm_tx_resp(comm, &resp)?;

        dev.cancel_component(details);
        self.set_state(State::ReadyXfer);

        Ok(())
    }

    fn cmd_get_status(
        &mut self,
        req: &PldmRequest,
        comm: &mut R,
        _dev: &mut impl Device,
    ) -> Result<()> {
        if !req.data.is_empty() {
            self.reply_error(req, comm, CCode::ERROR_INVALID_DATA as u8);
            return Ok(());
        }

        let l = self.get_status().write_buf(&mut self.msg_buf).space()?;
        let resp = req.response_borrowed(&self.msg_buf[..l]);
        pldm_tx_resp(comm, &resp)
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
                if details.size > 0 {
                    let one_percent = details.size.div_ceil(100);
                    // This won't usually reach 100% due to ceil, but that's OK since
                    // we transition out of Download state immediately on sending TransferComplete.
                    st.progress_percent = (*offset / one_percent) as u8;
                }
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

    pub fn progress(&mut self, dev: &mut impl Device) {
        trace!("pldm progress state {:?}", PldmFDState::from(&self.state));
        match self.state {
            State::Download { .. } => self.progress_download(dev),
            State::Verify { .. } => self.progress_verify(dev),
            State::Apply { .. } => self.progress_apply(dev),
            State::Idle { .. } => {
                if dev.now() - self.update_timestamp_fd_t1 > Self::FD_T1_TIMEOUT
                {
                    // TODO cancel any updates in Device?
                    self.set_state_idle_timeout();
                }
            }
            _ => (),
        }
    }

    /// The size of a request at a given offset.
    ///
    /// Must only be called in Download state
    fn req_size(&self) -> usize {
        let State::Download {
            offset,
            ref details,
            ..
        } = self.state
        else {
            debug_assert!(false);
            return 0;
        };

        details
            .size
            .saturating_sub(offset)
            .min(self.max_transfer)
            .min(self.max_request())
    }

    // Download state progress
    fn progress_download(&mut self, dev: &mut impl Device) {
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
            let _ = b.push_le8(transfer_result.into());
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

        // reborrow mut
        let State::Download {
            request,
            transfer_result,
            req_comm,
            req_pending,
            ..
        } = &mut self.state
        else {
            unreachable!();
        };

        if let Err(e) = pldm_tx_req(req_comm, &mut req) {
            trace!("Error tx request: {e:?}");
            // let the retry timer handle it.
            return;
        }
        *req_pending = true;

        if let Some(tr) = transfer_result {
            // transfer complete sent
            if *tr == TransferResult::Success {
                self.set_state_with(|prev| {
                    let State::Download {
                        details, req_comm, ..
                    } = prev
                    else {
                        unreachable!()
                    };
                    State::Verify {
                        verify_result: None,
                        request: FDReq::Ready,
                        details,
                        req_comm,
                        req_pending: false,
                    }
                });
            } else {
                // idle in Download state until the UA cancels
                *request = FDReq::Failed((*tr).into())
            }
        } else {
            // update retry timer for for the firmware data request
            *request = FDReq::Sent {
                time: dev.now(),
                iid: req.iid,
                cmd: req.cmd,
            }
        }
    }

    // Verify state progress
    fn progress_verify(&mut self, dev: &mut impl Device) {
        let State::Verify {
            verify_result,
            request,
            details,
            req_comm,
            req_pending,
            ..
        } = &mut self.state
        else {
            return;
        };

        if !request.should_send(dev) {
            return;
        }

        let vr = verify_result.get_or_insert_with(|| {
            // Perform the device-specific verify
            let r = dev.verify(details);
            if r != VerifyResult::Success {
                trace!("Error from Device::verify().");
            }
            r
        });

        // Send a new VerifyComplete
        let buf = [u8::from(*vr)];
        let mut req = PldmRequest::new_borrowed(
            PLDM_TYPE_FW,
            Cmd::VerifyComplete as u8,
            &buf,
        );

        if let Err(e) = pldm_tx_req(req_comm, &mut req) {
            trace!("Error tx request: {e:?}");
            // let the retry timer handle it
            return;
        }
        *req_pending = true;

        if *vr == VerifyResult::Success {
            self.set_state_with(|prev| {
                let State::Verify {
                    details, req_comm, ..
                } = prev
                else {
                    unreachable!()
                };
                State::Apply {
                    apply_result: None,
                    request: FDReq::Ready,
                    details,
                    req_comm,
                    req_pending: false,
                }
            });
        } else {
            // on verify failure remain in State::Verify, wait for cancel
            *request = FDReq::Failed(u8::from(*vr))
        }
    }

    // Apply state progress
    fn progress_apply(&mut self, dev: &mut impl Device) {
        let State::Apply {
            apply_result,
            request,
            details,
            req_comm,
            req_pending,
            ..
        } = &mut self.state
        else {
            return;
        };

        if !request.should_send(dev) {
            return;
        }

        let (ar, methods) = apply_result.get_or_insert_with(|| {
            // Perform the device-specific apply
            match dev.apply(details) {
                Ok(a) => (ApplyResult::Success, a),
                Err(e) => {
                    trace!("Error from Device::apply().");
                    (e, Default::default())
                }
            }
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

        if let Err(e) = pldm_tx_req(req_comm, &mut req) {
            trace!("Error tx request: {e:?}");
            // let retry timer handle it
            return;
        }
        *req_pending = true;

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
        dev: &mut impl Device,
    ) -> Result<()> {
        let State::Download {
            offset,
            ref request,
            transfer_result,
            ref details,
            ..
        } = self.state
        else {
            debug!("RequestFirmwareData response but not in Download state");
            return Ok(());
        };

        if transfer_result.is_some() {
            debug!("firmware data after result");
            return Ok(());
        }

        request.validate_response(rsp)?;

        let expect_size = self.req_size();
        if rsp.data.len() != expect_size {
            trace!(
                "Offset {offset} requested {expect_size} got {}",
                rsp.data.len()
            );
            // Let the timeout handle a retry
            return Ok(());
        }

        let fwdata_result = dev.firmware_data(offset, &rsp.data, details);

        // Move to next offset, or set transfer result
        // Progress() will send the next request.
        if let State::Download {
            offset,
            request,
            details,
            transfer_result,
            ..
        } = &mut self.state
        {
            *request = FDReq::Ready;
            if fwdata_result == TransferResult::Success {
                *offset += rsp.data.len();
                if *offset == details.size {
                    // Transfer is complete.
                    *transfer_result = Some(TransferResult::Success);
                }
            } else {
                // Return the failure from the callback as the total transfer result.
                trace!("Error from firmware_data callback. {fwdata_result:?}");
                *transfer_result = Some(fwdata_result);
            }
        }

        Ok(())
    }

    /// Updates the state with a closure
    ///
    /// The closure is provided with the previous state as an argument.
    /// This can be used to move members between State enum variants.
    fn set_state_with<F>(&mut self, update: F)
    where
        F: FnOnce(State<R::ReqChannel>) -> State<R::ReqChannel>,
    {
        self.prev_state = (&self.state).into();

        // Using ReadyXfer here as a placeholder without any contents,
        // any other simple variant could be used instead.
        let prev = core::mem::replace(&mut self.state, State::ReadyXfer);
        let new_state = update(prev);

        debug_assert!(
            !matches!(new_state, State::Idle { .. }),
            "Idle state should use set_idle() instead"
        );
        debug_assert!(self.ua_eid.is_some());

        self.state = new_state;
    }

    /// Set a new state
    fn set_state(&mut self, new_state: State<R::ReqChannel>) {
        debug_assert!(
            !matches!(new_state, State::Idle { .. }),
            "Idle state should use set_idle() instead"
        );
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
    /// Retry req firmware time, 1 second
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
            }
            // no retries, waiting for a cancel from the UA
            Self::Failed(_) => false,
        }
    }

    // Returns (AuxState, AuxStateStatus)
    fn aux_state(&self) -> (u8, u8) {
        match self {
            Self::Ready | Self::Sent { .. } => (0, 0),
            Self::Failed(e) => (2, *e),
        }
    }
}

/// Details of a particular component image
#[derive(Debug, Clone)]
pub struct ComponentDetails {
    /// Size in bytes of the component image
    pub size: usize,
    /// Component classification
    pub classification: ComponentClassification,
    /// Component identifier
    pub identifier: u16,
    /// Component classification index
    pub index: u8,
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
    /// Prior to calling `update_component` the `Responder` will check
    /// that the given `comp` matches an entry returned from `Device::components()`.
    ///
    /// Will be called with `update = false` initially for
    /// Pass Component, and then later called with `update = true`
    /// when the actual update is starting.
    ///
    /// The `Device` implementation should return `0x0` on allowed,
    /// or a ComponentResponseCode otherwise (see PLDM FW specification).
    /// When `update == false` a response may indicate conditional success,
    /// such as requiring update flags to be set.
    //
    // fd shouldn't call this directly, instead use check_update_component()
    // which checks that comp exists in the component list.
    fn update_component(&mut self, update: bool, comp: &UpdateComponent) -> u8;

    /// Provides a portion of a component image
    ///
    /// The `Responder` will provide all firmware blocks in sequence.
    ///
    /// If a failure `TransferResult` is returned, the component transfer is aborted
    /// and that result code sent to the Update Agent.
    fn firmware_data(
        &mut self,
        offset: usize,
        data: &[u8],
        comp: &ComponentDetails,
    ) -> TransferResult;

    /// Verifies a component after transfer completion.
    ///
    /// This function should return a [`VerifyResult`].
    // TODO: In future this may need a non-blocking variant
    // in order to report progress status of the verify.
    fn verify(&mut self, comp: &ComponentDetails) -> VerifyResult;

    /// Applies a component after verify success.
    fn apply(
        &mut self,
        comp: &ComponentDetails,
    ) -> core::result::Result<ActivationMethods, ApplyResult>;

    /// Activates new firmware
    ///
    /// The Device implementation is responsible for checking that
    /// expected components have been updated, returning `INCOMPLETE_UPDATE`
    /// if not.
    ///
    /// The default implementation returns `ACTIVATION_NOT_REQURED`.
    #[allow(unused)]
    fn activate(&mut self, self_contained: bool) -> ActivateResult {
        ActivateResult::ACTIVATION_NOT_REQUIRED
    }

    /// Cancel Update Component
    ///
    /// Called when a component update is cancelled prior to being applied.
    /// This function is called for both Cancel Update Component
    /// and Cancel Update (when a component is currently in progress).
    /// The default implementation does nothing.
    #[allow(unused)]
    fn cancel_component(&mut self, comp: &ComponentDetails);

    /// Returns a monotonic timestamp in milliseconds.
    ///
    /// This may have an arbitrary initial offset.
    /// Implementations must guarantee time doesn't go backwards.
    fn now(&mut self) -> u64;
}

/// Results that may be returned from an [`Device::activate`] callback.
#[repr(u8)]
#[allow(missing_docs)]
#[allow(non_camel_case_types)]
#[derive(Debug)]
pub enum ActivateResult {
    SUCCESS = CCode::SUCCESS as u8,
    ERROR = CCode::ERROR as u8,
    INCOMPLETE_UPDATE = FwCode::INCOMPLETE_UPDATE as u8,
    ACTIVATION_NOT_REQUIRED = FwCode::ACTIVATION_NOT_REQUIRED as u8,
    SELF_CONTAINED_ACTIVATION_NOT_PERMITTED =
        FwCode::SELF_CONTAINED_ACTIVATION_NOT_PERMITTED as u8,
}
