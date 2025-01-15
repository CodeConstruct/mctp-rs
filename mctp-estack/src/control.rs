//! MCTP Control Protocol implementation

use mctp::{Eid, Error, RespChannel, MCTP_TYPE_CONTROL, Listener};
use libmctp::control_packet::CompletionCode;

pub use libmctp::control_packet::CommandCode;

type Header = libmctp::control_packet::MCTPControlMessageHeader<[u8; 2]>;

/// A `Result` with a MCTP Control Completion Code as error
pub type ControlResult<T> = core::result::Result<T, libmctp::control_packet::CompletionCode>;

pub struct MctpControlMsg<'a> {
    pub header: Header,
    pub body: &'a [u8],
}

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

pub fn respond_get_eid(
    ch: &mut impl RespChannel,
    req: &MctpControlMsg,
    eid: Eid,
    medium_specific: u8,
) -> ControlResult<()> {
    if req.command_code() != CommandCode::GetEndpointID {
        return Err(CompletionCode::Error);
    }
    if !req.body.is_empty() {
        return Err(CompletionCode::ErrorInvalidLength);
    }
    // simple endpoint, static EID supported
    let endpoint_type = 0b0000_0001;
    let body = [CompletionCode::Success as u8, eid.0, endpoint_type, medium_specific];
    let msg = req.new_resp(&body)?;
    ch.send_vectored(MCTP_TYPE_CONTROL, false, &msg.slices())
        .map_err(|_| CompletionCode::Error)
}

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


pub fn respond_set_eid(
    ch: &mut impl RespChannel,
    req: &MctpControlMsg,
    accepted: bool,
    current_eid: Eid,
) -> ControlResult<()> {
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
    let msg = req.new_resp(&body)?;
    ch.send_vectored(MCTP_TYPE_CONTROL, false, &msg.slices())
        .map_err(|_| CompletionCode::Error)
}

pub fn respond_get_msg_types(
    ch: &mut impl RespChannel,
    req: &MctpControlMsg,
    msgtypes: &[u8],
) -> ControlResult<()> {
    if req.command_code() != CommandCode::GetMessageTypeSupport {
        return Err(CompletionCode::Error)
    }
    if !req.body.is_empty() {
        return Err(CompletionCode::ErrorInvalidLength)
    }
    let n: u8 = msgtypes.len().try_into().map_err(|_| CompletionCode::Error)?;
    let body = [CompletionCode::Success as u8, n];
    let msg = req.new_resp(&body)?;

    let slices = [
        msg.slices()[0],
        msg.slices()[1],
        msgtypes,
    ];

    ch.send_vectored(MCTP_TYPE_CONTROL, false, &slices)
        .map_err(|_| CompletionCode::Error)
}

pub fn respond_unimplemented(
    ch: &mut impl RespChannel,
    req: &MctpControlMsg,
) -> ControlResult<()> {
    respond_error(ch, req, CompletionCode::ErrorUnsupportedCmd)
        .map_err(|_| CompletionCode::Error)
}

/// Respond with an error completion code.
///
/// This returns a `mctp::Result` since failures can't be sent as a response.
pub fn respond_error(
    ch: &mut impl RespChannel,
    req: &MctpControlMsg,
    err: CompletionCode,
) -> mctp::Result<()> {
    if err == CompletionCode::Success {
        return Err(Error::BadArgument)
    }
    let body = [err as u8];
    let msg = req.new_resp(&body).map_err(|_| Error::BadArgument)?;
    ch.send_vectored(MCTP_TYPE_CONTROL, false, &msg.slices())
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
