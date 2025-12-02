#![warn(missing_docs)]
// SPDX-License-Identifier: MIT OR Apache-2.0
/*
 * Copyright (c) 2024-2025 Code Construct
 */

//! MCTP Control Protocol implementation

use crate::fmt::*;
#[cfg(feature = "async")]
use crate::Router;
#[cfg(feature = "async")]
use mctp::{AsyncRespChannel, MsgIC};
use mctp::{Eid, Error, Listener, MsgType};
use uuid::Uuid;

/// A `Result` with a MCTP control completion code as error.
pub type ControlResult<T> = core::result::Result<T, CompletionCode>;

/// MCTP control message completion code.
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash, PartialOrd, Ord)]
#[allow(missing_docs)]
#[expect(non_camel_case_types)]
pub enum CompletionCode {
    SUCCESS,
    ERROR,
    ERROR_INVALID_DATA,
    ERROR_INVALID_LENGTH,
    ERROR_NOT_READY,
    ERROR_UNSUPPORTED_CMD,
    /// 0x80-0xff
    COMMAND_SPECIFIC(u8),
    OTHER(u8),
}

impl From<u8> for CompletionCode {
    fn from(value: u8) -> Self {
        use CompletionCode::*;
        match value {
            0x00 => SUCCESS,
            0x01 => ERROR,
            0x02 => ERROR_INVALID_DATA,
            0x03 => ERROR_INVALID_LENGTH,
            0x04 => ERROR_NOT_READY,
            0x05 => ERROR_UNSUPPORTED_CMD,
            0x80..=0xff => COMMAND_SPECIFIC(value),
            _ => OTHER(value),
        }
    }
}

impl From<CompletionCode> for u8 {
    fn from(cc: CompletionCode) -> Self {
        use CompletionCode::*;
        match cc {
            SUCCESS => 0x00,
            ERROR => 0x01,
            ERROR_INVALID_DATA => 0x02,
            ERROR_INVALID_LENGTH => 0x03,
            ERROR_NOT_READY => 0x04,
            ERROR_UNSUPPORTED_CMD => 0x05,
            COMMAND_SPECIFIC(v) | OTHER(v) => v,
        }
    }
}

/// MCTP control command code.
#[allow(missing_docs)]
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash, PartialOrd, Ord)]
pub enum CommandCode {
    SetEndpointID,
    GetEndpointID,
    GetEndpointUUID,
    GetMCTPVersionSupport,
    GetMessageTypeSupport,
    GetVendorDefinedMessageSupport,
    ResolveEndpointID,
    AllocateEndpointIDs,
    RoutingInformationUpdate,
    GetRoutingTableEntries,
    PrepareforEndpointDiscovery,
    DiscoveryNotify,
    QueryHop,
    ResolveUUID,
    QueryRateRimit,
    RequestTXRateLimit,
    UpdateRateLimit,
    QuerySupportedInterfaces,
    TransportSpecific(u8),
    Unknown(u8),
}

impl From<u8> for CommandCode {
    fn from(value: u8) -> Self {
        use CommandCode::*;
        match value {
            0x01 => SetEndpointID,
            0x02 => GetEndpointID,
            0x03 => GetEndpointUUID,
            0x04 => GetMCTPVersionSupport,
            0x05 => GetMessageTypeSupport,
            0x06 => GetVendorDefinedMessageSupport,
            0x07 => ResolveEndpointID,
            0x08 => AllocateEndpointIDs,
            0x09 => RoutingInformationUpdate,
            0x0A => GetRoutingTableEntries,
            0x0B => PrepareforEndpointDiscovery,
            0x0D => DiscoveryNotify,
            0x0F => QueryHop,
            0x10 => ResolveUUID,
            0x11 => QueryRateRimit,
            0x12 => RequestTXRateLimit,
            0x13 => UpdateRateLimit,
            0x14 => QuerySupportedInterfaces,
            0xf0..=0xff => TransportSpecific(value),
            _ => Unknown(value),
        }
    }
}

impl From<CommandCode> for u8 {
    fn from(cc: CommandCode) -> Self {
        use CommandCode::*;
        match cc {
            SetEndpointID => 0x01,
            GetEndpointID => 0x02,
            GetEndpointUUID => 0x03,
            GetMCTPVersionSupport => 0x04,
            GetMessageTypeSupport => 0x05,
            GetVendorDefinedMessageSupport => 0x06,
            ResolveEndpointID => 0x07,
            AllocateEndpointIDs => 0x08,
            RoutingInformationUpdate => 0x09,
            GetRoutingTableEntries => 0x0A,
            PrepareforEndpointDiscovery => 0x0B,
            DiscoveryNotify => 0x0D,
            QueryHop => 0x0F,
            ResolveUUID => 0x10,
            QueryRateRimit => 0x11,
            RequestTXRateLimit => 0x12,
            UpdateRateLimit => 0x13,
            QuerySupportedInterfaces => 0x14,
            TransportSpecific(v) | Unknown(v) => v,
        }
    }
}

/// MCTP control message header
#[derive(PartialEq, Eq, Clone, Hash, Debug)]
pub struct MctpControlHeader {
    /// Request bit.
    pub rq: bool,
    /// Datagram bit.
    pub datagram: bool,
    /// Instance ID.
    pub iid: u8,
    /// Command Code.
    pub command: CommandCode,
}

impl MctpControlHeader {
    /// Decode a header.
    pub fn decode(payload: &[u8]) -> mctp::Result<Self> {
        let header = payload.get(..2).ok_or(mctp::Error::BadArgument)?;
        let header: [u8; 2] = header.try_into().unwrap();

        Ok(Self {
            rq: header[0] & 0b1000_0000 != 0,
            datagram: header[0] & 0b0100_0000 != 0,
            iid: header[0] & 0b11111,
            command: header[1].into(),
        })
    }

    /// Encode a header.
    pub fn encode(&self) -> mctp::Result<[u8; 2]> {
        if self.iid > 0b11111 {
            return Err(mctp::Error::BadArgument);
        }
        Ok([
            (self.rq as u8) << 7 | (self.datagram as u8) << 6 | self.iid,
            self.command.into(),
        ])
    }
}

/// A MCTP control message
pub struct MctpControlMsg<'a> {
    /// Header
    pub header: MctpControlHeader,
    /// Message body
    pub body: &'a [u8],
    // buffer for serialising the header
    work: [u8; 2],
}

#[cfg(feature = "async")]
const MAX_MSG_SIZE: usize = 20; /* largest is Get Endpoint UUID */
#[cfg(feature = "async")]
const MAX_MSG_TYPES: usize = 8;

impl<'a> MctpControlMsg<'a> {
    /// Parse a control message from a message payload.
    pub fn from_buf(buf: &'a [u8]) -> ControlResult<Self> {
        let header = MctpControlHeader::decode(buf)
            .map_err(|_| CompletionCode::ERROR_INVALID_LENGTH)?;

        if header.datagram {
            // Datagram bit is unhandled
            return Err(CompletionCode::ERROR_INVALID_DATA);
        }

        let body = buf.get(2..).ok_or(CompletionCode::ERROR_INVALID_LENGTH)?;
        Ok(Self {
            header,
            body,
            work: Default::default(),
        })
    }

    /// Create a new response MCTP control message.
    pub fn new_resp<'f>(
        &self,
        body: &'f [u8],
    ) -> ControlResult<MctpControlMsg<'f>> {
        if !self.header.rq {
            return Err(CompletionCode::ERROR_INVALID_DATA);
        }

        let mut header = self.header.clone();
        header.rq = false;

        Ok(MctpControlMsg {
            header,
            body,
            work: Default::default(),
        })
    }

    /// Return contents of the message.
    pub fn slices(&mut self) -> [&[u8]; 2] {
        self.work = self.header.encode().unwrap();
        [self.work.as_slice(), self.body]
    }

    /// Return the MCTP control message command code.
    pub fn command_code(&self) -> CommandCode {
        self.header.command
    }
}

/// Create a Get Endpoint ID response.
pub fn respond_get_eid<'a>(
    req: &MctpControlMsg,
    eid: Eid,
    medium_specific: u8,
    rsp_buf: &'a mut [u8],
) -> ControlResult<MctpControlMsg<'a>> {
    if req.command_code() != CommandCode::GetEndpointID {
        return Err(CompletionCode::ERROR);
    }
    if !req.body.is_empty() {
        return Err(CompletionCode::ERROR_INVALID_LENGTH);
    }
    // simple endpoint, static EID supported
    let endpoint_type = 0b0000_0001;
    let body = [
        CompletionCode::SUCCESS.into(),
        eid.0,
        endpoint_type,
        medium_specific,
    ];

    let rsp_buf = &mut rsp_buf[0..body.len()];
    rsp_buf.clone_from_slice(&body);
    req.new_resp(rsp_buf)
}

/// A Set Endpoint ID request.
#[allow(missing_docs)]
#[derive(Debug)]
pub enum SetEndpointId {
    Set(Eid),
    Force(Eid),
    Reset,
    SetDiscovered,
}

/// Parse a Set Endpoint ID request.
pub fn parse_set_eid(req: &MctpControlMsg) -> ControlResult<SetEndpointId> {
    if req.command_code() != CommandCode::SetEndpointID {
        return Err(CompletionCode::ERROR);
    }
    if req.body.len() != 2 {
        return Err(CompletionCode::ERROR_INVALID_LENGTH);
    }

    let op = req.body[0] & 0x03;
    Ok(match op {
        // Set or Force
        0b00 | 0b01 => {
            let eid = Eid::new_normal(req.body[1]).map_err(|_| {
                warn!("Invalid Set EID {}", req.body[1]);
                CompletionCode::ERROR_INVALID_DATA
            })?;
            if op == 0b00 {
                SetEndpointId::Set(eid)
            } else {
                SetEndpointId::Force(eid)
            }
        }
        // Reset
        0b10 => SetEndpointId::Reset,
        // Set Discovered
        0b11 => SetEndpointId::SetDiscovered,
        _ => unreachable!(),
    })
}

/// Create a Set Endpoint ID response.
pub fn respond_set_eid<'a>(
    req: &MctpControlMsg,
    accepted: bool,
    current_eid: Eid,
    rsp_buf: &'a mut [u8],
) -> ControlResult<MctpControlMsg<'a>> {
    if req.command_code() != CommandCode::SetEndpointID {
        return Err(CompletionCode::ERROR);
    }
    let status = if accepted { 0b00000000 } else { 0b00010000 };
    let pool_size = 0;
    let body = [
        CompletionCode::SUCCESS.into(),
        status,
        current_eid.0,
        pool_size,
    ];
    let rsp_buf = &mut rsp_buf[0..body.len()];
    rsp_buf.clone_from_slice(&body);
    req.new_resp(rsp_buf)
}

/// Create a Get UUID response.
pub fn respond_get_uuid<'a>(
    req: &MctpControlMsg,
    uuid: Uuid,
    rsp_buf: &'a mut [u8],
) -> ControlResult<MctpControlMsg<'a>> {
    if req.command_code() != CommandCode::GetEndpointUUID {
        return Err(CompletionCode::ERROR);
    }

    let mut body = [0u8; 1 + 16];
    body[0] = CompletionCode::SUCCESS.into();
    body[1..].clone_from_slice(uuid.as_bytes());

    let rsp_buf = &mut rsp_buf[0..body.len()];
    rsp_buf.clone_from_slice(&body);
    req.new_resp(rsp_buf)
}

/// Create a Get Message Types response.
pub fn respond_get_msg_types<'a>(
    req: &MctpControlMsg,
    msgtypes: &[MsgType],
    rsp_buf: &'a mut [u8],
) -> ControlResult<MctpControlMsg<'a>> {
    if req.command_code() != CommandCode::GetMessageTypeSupport {
        return Err(CompletionCode::ERROR);
    }
    if !req.body.is_empty() {
        return Err(CompletionCode::ERROR_INVALID_LENGTH);
    }
    let n = msgtypes.len();
    let body = rsp_buf.get_mut(..n + 2).ok_or(CompletionCode::ERROR)?;
    body[0] = CompletionCode::SUCCESS.into();
    body[1] = n as u8;
    for (i, t) in msgtypes.iter().enumerate() {
        body[i + 2] = t.0;
    }
    req.new_resp(body)
}

/// Create an Unsupported Command response.
pub fn respond_unimplemented<'a>(
    req: &MctpControlMsg,
    rsp_buf: &'a mut [u8],
) -> mctp::Result<MctpControlMsg<'a>> {
    respond_error(req, CompletionCode::ERROR_UNSUPPORTED_CMD, rsp_buf)
}

/// Create an error completion code response.
///
/// This returns a `mctp::Result` since failures can't be sent as a response.
pub fn respond_error<'a>(
    req: &MctpControlMsg,
    err: CompletionCode,
    rsp_buf: &'a mut [u8],
) -> mctp::Result<MctpControlMsg<'a>> {
    if err == CompletionCode::SUCCESS {
        return Err(Error::BadArgument);
    }
    let body = [err.into()];
    let rsp_buf = &mut rsp_buf[0..body.len()];
    rsp_buf.clone_from_slice(&body);
    req.new_resp(rsp_buf)
        .map_err(|_| mctp::Error::InternalError)
}

/// Receive a control request from a listener.
pub fn mctp_control_rx_req<'f, 'l, L>(
    listener: &'l mut L,
    buf: &'f mut [u8],
) -> mctp::Result<(MctpControlMsg<'f>, L::RespChannel<'l>)>
where
    L: Listener,
{
    let (typ, ic, buf, ch) = listener.recv(buf)?;
    if ic.0 {
        return Err(Error::InvalidInput);
    }
    if typ != mctp::MCTP_TYPE_CONTROL {
        // Listener was bound to the wrong type?
        return Err(Error::BadArgument);
    }

    let msg = MctpControlMsg::from_buf(buf).map_err(|_| Error::InvalidInput)?;
    Ok((msg, ch))
}

/// A Control Message handler.
#[cfg(feature = "async")]
pub struct MctpControl<'g, 'r> {
    rsp_buf: [u8; MAX_MSG_SIZE],
    types: heapless::Vec<MsgType, MAX_MSG_TYPES>,
    uuid: Option<Uuid>,
    router: &'g Router<'r>,
}

#[cfg(feature = "async")]
impl<'g, 'r> MctpControl<'g, 'r> {
    /// Create a new instance.
    pub fn new(router: &'g Router<'r>) -> Self {
        Self {
            rsp_buf: [0u8; MAX_MSG_SIZE],
            types: heapless::Vec::new(),
            uuid: None,
            router,
        }
    }

    /// Handle an incoming message and send a response.
    ///
    /// May return `Err` if a message cannot be handled (no response sent),
    /// for example incorrect header.
    /// Will return `Ok` if an error completion code response was sent.
    pub async fn handle_async(
        &mut self,
        msg: &[u8],
        mut resp_chan: impl AsyncRespChannel,
    ) -> mctp::Result<Option<ControlEvent>> {
        let req = MctpControlMsg::from_buf(msg).map_err(|e| {
            // Can't send a response since request couldn't be parsed
            debug!("Bad control input {:?}", e);
            mctp::Error::InvalidInput
        })?;

        let (mut resp, ev) =
            match self.handle_req(&req, resp_chan.remote_eid()).await {
                Err(e) => {
                    debug!("Control error response {:?}", e);
                    respond_error(&req, e, &mut self.rsp_buf).map(|r| (r, None))
                }
                Ok(r) => Ok(r),
            }?;

        resp_chan
            .send_vectored(MsgIC(false), &resp.slices())
            .await?;
        Ok(ev)
    }

    /// Set MCTP message types to be reported by the handler.
    pub fn set_message_types(&mut self, types: &[MsgType]) -> mctp::Result<()> {
        if types.len() > self.types.capacity() {
            return Err(mctp::Error::NoSpace);
        }
        self.types.clear();
        // We have already checked the length, so no Err here
        let _ = self.types.extend_from_slice(types);
        Ok(())
    }

    /// Set the UUID of the endpoint.
    pub fn set_uuid(&mut self, uuid: &Uuid) {
        let _ = self.uuid.insert(*uuid);
    }

    async fn handle_req(
        &mut self,
        req: &'_ MctpControlMsg<'_>,
        source_eid: Eid,
    ) -> ControlResult<(MctpControlMsg<'_>, Option<ControlEvent>)> {
        let cc = req.command_code();

        let mut event = None;
        #[cfg(feature = "log")]
        debug!("Control request {:?}", cc);
        match cc {
            CommandCode::GetEndpointID => {
                let eid = self.router.get_eid().await;
                respond_get_eid(req, eid, 0, &mut self.rsp_buf)
            }
            CommandCode::SetEndpointID => {
                let (SetEndpointId::Set(eid) | SetEndpointId::Force(eid)) =
                    parse_set_eid(req)?
                else {
                    // Don't support Reset or SetDiscovered
                    return Err(CompletionCode::ERROR_INVALID_DATA);
                };
                let old = self.router.get_eid().await;
                let res = self.router.set_eid(eid).await;
                let present_eid = self.router.get_eid().await;

                if res.is_ok() {
                    event = Some(ControlEvent::SetEndpointId {
                        old,
                        new: present_eid,
                        bus_owner: source_eid,
                    });
                }

                respond_set_eid(
                    req,
                    res.is_ok(),
                    present_eid,
                    &mut self.rsp_buf,
                )
            }
            CommandCode::GetEndpointUUID => {
                if let Some(uuid) = self.uuid {
                    respond_get_uuid(req, uuid, &mut self.rsp_buf)
                } else {
                    Err(CompletionCode::ERROR_UNSUPPORTED_CMD)
                }
            }
            CommandCode::GetMessageTypeSupport => respond_get_msg_types(
                req,
                self.types.as_slice(),
                &mut self.rsp_buf,
            ),
            _ => Err(CompletionCode::ERROR_UNSUPPORTED_CMD),
        }
        .map(|r| (r, event))
    }
}

/// An MCTP control handler event
pub enum ControlEvent {
    /// Set Endpoint ID received.
    ///
    /// Note that the EID may be unchanged.
    SetEndpointId {
        /// Previous EID.
        ///
        old: Eid,
        /// New EID
        new: Eid,
        /// Bus Owner that set the EID
        bus_owner: Eid,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_header() {
        for b2 in 0..=0xff {
            for cmd in 0..=0xff {
                // mask out reserved bit
                let b2 = b2 & !0b00100000;
                let hdr = [b2, cmd];
                let m = MctpControlHeader::decode(&hdr).unwrap();
                let h2 = m.encode().unwrap();
                assert_eq!(hdr, h2);
            }
        }
    }
}
