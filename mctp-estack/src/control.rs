// SPDX-License-Identifier: MIT OR Apache-2.0
/*
 * MCTP common types and traits.
 *
 * Copyright (c) 2024-2025 Code Construct
 */

//! MCTP Control Protocol implementation

use mctp::{AsyncRespChannel, Eid, Error, Listener, MsgType, RespChannel};
use libmctp::control_packet::CompletionCode;
use uuid::Uuid;
use crate::Router;

pub use libmctp::control_packet::CommandCode;

type Header = libmctp::control_packet::MCTPControlMessageHeader<[u8; 2]>;

/// A `Result` with a MCTP Control Completion Code as error
pub type ControlResult<T> = core::result::Result<T, libmctp::control_packet::CompletionCode>;

pub struct MctpControlMsg<'a> {
    pub header: Header,
    pub body: &'a [u8],
}

const MAX_MSG_SIZE: usize = 8;
const MAX_MSG_TYPES: usize = 8;

impl<'a> MctpControlMsg<'a> {
    pub fn from_buf(buf: &'a [u8]) -> ControlResult<Self> {
        if buf.len() < 2 {
            return Err(CompletionCode::ErrorInvalidLength);
        }
        let b: [u8; 2] = buf[..2].try_into().unwrap();
        let header = Header::new_from_buf(b);

        if header.d() != 0 {
            // Datagram bit is unhandled
            return Err(CompletionCode::ErrorInvalidData);
        }

        let body = &buf[2..];
        Ok(Self { header, body })
    }

    pub fn new_resp<'f>(&self, body: &'f [u8]) -> ControlResult<MctpControlMsg<'f>> {
        if self.header.rq() == 0 {
            return Err(CompletionCode::ErrorInvalidData);
        }

        let mut header = Header::new_from_buf(self.header.0);
        header.set_rq(0);

        Ok(MctpControlMsg { header, body })
    }

    pub fn slices(&self) -> [&[u8]; 2] {
        [&self.header.0, self.body]
    }

    pub fn command_code(&self) -> CommandCode {
        self.header.command_code().into()
    }
}

pub fn respond_get_eid<'a>(
    req: &MctpControlMsg,
    eid: Eid,
    medium_specific: u8,
    rsp_buf: &'a mut [u8],
) -> ControlResult<MctpControlMsg<'a>> {
    if req.command_code() != CommandCode::GetEndpointID {
        return Err(CompletionCode::Error);
    }
    if !req.body.is_empty() {
        return Err(CompletionCode::ErrorInvalidLength);
    }
    // simple endpoint, static EID supported
    let endpoint_type = 0b0000_0001;
    let body = [CompletionCode::Success as u8, eid.0, endpoint_type, medium_specific];

    let rsp_buf = &mut rsp_buf[0..body.len()];
    rsp_buf.clone_from_slice(&body);
    req.new_resp(rsp_buf)
}

#[derive(Debug)]
pub struct SetEndpointId {
    pub eid: Eid,
    pub force: bool,
    pub reset: bool,
}

pub fn parse_set_eid<'f>(req: &MctpControlMsg) -> ControlResult<SetEndpointId> {
    if req.command_code() != CommandCode::SetEndpointID {
        return Err(CompletionCode::Error)
    }
    if req.body.len() != 2 {
        return Err(CompletionCode::ErrorInvalidLength)
    }

    let eid = Eid::new_normal(req.body[1]).map_err(|_| CompletionCode::ErrorInvalidData)?;

    let mut ret = SetEndpointId { eid, force: false, reset: false };

    match req.body[0] & 0x03 {
        // Set
        0b00 => (),
        // Force
        0b01 => ret.force = true,
        // Reset
        0b10 => ret.reset = true,
        // Set Discovered
        0b11 => return Err(CompletionCode::ErrorInvalidData),
        _ => unreachable!(),
    }

    Ok(ret)
}

pub fn respond_set_eid<'a>(
    req: &MctpControlMsg,
    accepted: bool,
    current_eid: Eid,
    rsp_buf: &'a mut [u8],
) -> ControlResult<MctpControlMsg<'a>> {
    if req.command_code() != CommandCode::GetEndpointID {
        return Err(CompletionCode::Error)
    }
    if !req.body.is_empty() {
        return Err(CompletionCode::ErrorInvalidLength)
    }
    let status = if accepted {
        0b00000000
    } else {
        0b00010000
    };
    let body = [CompletionCode::Success as u8, status, current_eid.0, 0x00];
    let rsp_buf = &mut rsp_buf[0..body.len()];
    rsp_buf.clone_from_slice(&body);
    req.new_resp(rsp_buf)
}

pub fn respond_get_msg_types<'a>(
    req: &MctpControlMsg,
    msgtypes: &[u8],
    rsp_buf: &'a mut [u8],
) -> ControlResult<MctpControlMsg<'a>> {
    if req.command_code() != CommandCode::GetMessageTypeSupport {
        return Err(CompletionCode::Error)
    }
    if !req.body.is_empty() {
        return Err(CompletionCode::ErrorInvalidLength)
    }
    let n: u8 = msgtypes.len().try_into().map_err(|_| CompletionCode::Error)?;
    let body = [CompletionCode::Success as u8, n];
    let rsp_buf = &mut rsp_buf[0..body.len()];
    rsp_buf.clone_from_slice(&body);
    req.new_resp(rsp_buf)
}

pub fn respond_unimplemented<'a>(
    req: &MctpControlMsg,
    rsp_buf: &'a mut [u8],
) -> mctp::Result<MctpControlMsg<'a>> {
    respond_error(req, CompletionCode::ErrorUnsupportedCmd, rsp_buf)
}

/// Respond with an error completion code.
///
/// This returns a `mctp::Result` since failures can't be sent as a response.
pub fn respond_error<'a>(
    req: &MctpControlMsg,
    err: CompletionCode,
    rsp_buf: &'a mut [u8],
) -> mctp::Result<MctpControlMsg<'a>> {
    if err == CompletionCode::Success {
        return Err(Error::BadArgument)
    }
    let body = [err as u8];
    let rsp_buf = &mut rsp_buf[0..body.len()];
    rsp_buf.clone_from_slice(&body);
    req.new_resp(rsp_buf).map_err(|_| mctp::Error::InternalError)
}

pub fn mctp_control_rx_req<'f, 'l, L>(listener: &'l mut L, buf: &'f mut [u8])
    -> mctp::Result<(L::RespChannel<'l>, MctpControlMsg<'f>)> where L: Listener {

    let (buf, ch, _tag, _typ, ic) = listener.recv(buf)?;
    if ic {
        return Err(Error::InvalidInput);
    }

    let msg = MctpControlMsg::from_buf(buf).map_err(|_| Error::InvalidInput)?;
    Ok((ch, msg))
}

/// A Control Message handler.
pub struct MctpControl {
    rsp_buf: [u8; MAX_MSG_SIZE],
    types: heapless::Vec<MsgType, MAX_MSG_TYPES>,
}

impl MctpControl {
    pub fn new() -> Self {
        Self {
            rsp_buf: [0u8; MAX_MSG_SIZE],
            types: heapless::Vec::new(),
        }
    }

    pub async fn handle_async(&mut self, msg: &[u8], mut resp_chan: impl AsyncRespChannel)
    -> mctp::Result<()> {
        let req = MctpControlMsg::from_buf(msg)
            .map_err(|_| mctp::Error::InvalidInput)?;

        let resp = match self.handle_req(&req) {
            Err(e) => respond_error(&req, e, &mut self.rsp_buf),
            Ok(r) => Ok(r),
        }?;

        resp_chan.send_vectored(
            mctp::MCTP_TYPE_CONTROL,
            false,
            &resp.slices()
        ).await
    }

    pub fn handle(&mut self, _msg: &[u8], mut _resp_chan: impl RespChannel)
    -> mctp::Result<()> {
        unimplemented!();
    }

    pub fn set_message_types(&mut self, types: &[MsgType]) -> mctp::Result<()> {
        if types.len() > self.types.capacity() {
            return Err(mctp::Error::NoSpace);
        }
        self.types.clear();
        // We have already checked the length, so no Err here
        let _ = self.types.extend_from_slice(types);
        Ok(())
    }

    fn handle_req(&mut self, req: &MctpControlMsg) -> ControlResult<MctpControlMsg> {
        let cc = req.command_code();

        match cc {
            CommandCode::GetEndpointID => {
                // todo: fillers
                respond_get_eid(req, Eid(9), 0, &mut self.rsp_buf)
            }
            _ => {
                Err(CompletionCode::ErrorUnsupportedCmd)
            }
        }
    }
}
