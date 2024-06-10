// SPDX-License-Identifier: GPL-3.0-or-later
/*
 * PLDM base message definitions.
 *
 * Copyright (c) 2023 Code Construct
 */

use thiserror::Error;

use mctp::{MctpEndpoint, MctpError, Tag};

pub const PLDM_MAX_MSGSIZE: usize = 1024;

#[derive(Error, Debug)]
pub enum PldmError {
    // #[error("IO error: {0}")]
    // Io(#[from] std::io::Error),
    #[error("PLDM protocol error: {0}")]
    Protocol(String),
    #[error("MCTP error")]
    // TODO figure how to keep it
    Mctp,
}

impl PldmError {
    pub fn new_proto(s: String) -> Self {
        Self::Protocol(s)
    }
}

impl<E> From<E> for PldmError where E: MctpError {
    fn from(_e: E) -> PldmError {
        PldmError::Mctp
    }
}

pub type Result<T> = std::result::Result<T, PldmError>;

#[derive(Debug)]
pub struct PldmRequest {
    pub mctp_tag: Tag,
    pub iid: u8,
    pub typ: u8,
    pub cmd: u8,
    pub data: Vec<u8>,
}

impl PldmRequest {
    pub fn new(typ: u8, cmd: u8) -> Self {
        Self {
            mctp_tag: Tag::OwnedAuto,
            iid: 0,
            typ,
            cmd,
            data: Vec::new(),
        }
    }

    pub fn from_buf(tag: Tag, data: &[u8]) -> Result<Self> {
        if data.len() < 3 {
            panic!("request too short");
        }

        let iid = data[0] & 0x1f;
        let typ = data[1] & 0x3f;
        let cmd = data[2];

        Ok(PldmRequest {
            mctp_tag: tag,
            iid,
            typ,
            cmd,
            data: data[3..].to_vec(),
        })
    }

    pub fn set_data(&mut self, data: Vec<u8>) {
        self.data = data;
    }

    pub fn response(&self) -> Result<PldmResponse> {
        let tag = self.mctp_tag.tag()
            .ok_or(PldmError::Protocol("OwnedAuto tag".into()))?;
        let resp_tag = Tag::Unowned(tag);
        Ok(PldmResponse {
            mctp_tag: resp_tag,
            iid: self.iid,
            typ: self.typ,
            cmd: self.cmd,
            cc: 0,
            data: Vec::new(),
        })
    }
}

#[derive(Debug)]
pub struct PldmResponse {
    pub mctp_tag: Tag,
    pub iid: u8,
    pub typ: u8,
    pub cmd: u8,
    pub cc: u8,
    pub data: Vec<u8>,
}

pub fn pldm_xfer(ep: &mut impl MctpEndpoint, req: PldmRequest) -> Result<PldmResponse> {
    const REQ_IID: u8 = 0;
    let mut tx_buf = Vec::with_capacity(req.data.len() + 2);
    tx_buf.push(1 << 7 | REQ_IID);
    tx_buf.push(req.typ & 0x3f);
    tx_buf.push(req.cmd);
    tx_buf.extend_from_slice(&req.data);

    ep.send(mctp::MCTP_TYPE_PLDM, req.mctp_tag, &tx_buf)?;

    let mut rx_buf = [0u8; PLDM_MAX_MSGSIZE]; // todo: set size? peek?
    let (rx_buf, _eid, tag) = ep.recv(&mut rx_buf)?;

    if rx_buf.len() < 4 {
        return Err(PldmError::new_proto(format!("short response, {} bytes", rx_buf.len())));
    }

    // TODO: should check eid, but against what? Or should MctpEndpoint impl check it?

    let iid = rx_buf[0] & 0x1f;
    let typ = rx_buf[1] & 0x3f;
    let cmd = rx_buf[2];
    let cc = rx_buf[3];

    if iid != REQ_IID {
        return Err(PldmError::new_proto(format!(
            "Incorrect instance ID in reply. Expected 0x{REQ_IID:02x} got 0x{iid:02x}")));
    }

    if typ != req.typ {
        return Err(PldmError::new_proto(format!(
            "Incorrect PLDM type in reply. Expected 0x{:02x} got 0x{:02x}",
            req.typ, typ)));
    }

    if cmd != req.cmd {
        return Err(PldmError::new_proto(format!(
            "Incorrect PLDM command in reply. Expected 0x{:02x} got 0x{:02x}",
            req.cmd, cmd)));
    }

    let rsp = PldmResponse {
        mctp_tag: tag,
        iid,
        typ,
        cmd,
        cc,
        data: rx_buf[4..].to_vec(),
    };

    Ok(rsp)
}

pub fn pldm_rx_req(ep: &mut impl MctpEndpoint) -> Result<PldmRequest> {
    let mut rx_buf = [0u8; PLDM_MAX_MSGSIZE]; // todo: set size? peek?
    let (rx_buf, _eid, tag) = ep.recv(&mut rx_buf)?;

    let req = PldmRequest::from_buf(tag, rx_buf)?;

    Ok(req)
}

pub fn pldm_tx_resp(ep: &mut impl MctpEndpoint, resp: &PldmResponse) -> Result<()> {
    let mut tx_buf = Vec::with_capacity(resp.data.len() + 4);
    tx_buf.push(resp.iid);
    tx_buf.push(resp.typ);
    tx_buf.push(resp.cmd);
    tx_buf.push(resp.cc);
    tx_buf.extend_from_slice(&resp.data);

    ep.send(mctp::MCTP_TYPE_PLDM, resp.mctp_tag, &tx_buf)?;

    Ok(())
}
