// SPDX-License-Identifier: GPL-3.0-or-later
/*
 * PLDM base message definitions.
 *
 * Copyright (c) 2023 Code Construct
 */

use mctp_linux::{self as mctp, MctpEndpoint};
use thiserror::Error;

pub const MCTP_TYPE_PLDM: u8 = 0x01;
pub const PLDM_MAX_MSGSIZE: usize = 1024;

#[derive(Error, Debug)]
pub enum PldmError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("PLDM protocol error: {0}")]
    Protocol(String),
}

impl PldmError {
    pub fn new_proto(s: String) -> Self {
        Self::Protocol(s)
    }
}

pub type Result<T> = std::result::Result<T, PldmError>;

#[derive(Debug)]
pub struct PldmRequest {
    pub mctp_tag: u8,
    pub iid: u8,
    pub typ: u8,
    pub cmd: u8,
    pub data: Vec<u8>,
}

impl PldmRequest {
    pub fn new(typ: u8, cmd: u8) -> Self {
        Self {
            mctp_tag: mctp::MCTP_TAG_OWNER,
            iid: 0,
            typ,
            cmd,
            data: Vec::new(),
        }
    }

    pub fn from_buf(data: &[u8]) -> Result<Self> {
        if data.len() < 3 {
            panic!("request too short");
        }

        let iid = data[0] & 0x1f;
        let typ = data[1] & 0x3f;
        let cmd = data[2];

        Ok(PldmRequest {
            mctp_tag: 0,
            iid,
            typ,
            cmd,
            data: data[3..].to_vec(),
        })
    }

    pub fn set_data(&mut self, data: Vec<u8>) {
        self.data = data;
    }

    pub fn response(&self) -> PldmResponse {
        PldmResponse {
            mctp_tag: self.mctp_tag & !mctp::MCTP_TAG_OWNER,
            iid: self.iid,
            typ: self.typ,
            cmd: self.cmd,
            cc: 0,
            data: Vec::new(),
        }
    }
}

#[derive(Debug)]
pub struct PldmResponse {
    pub mctp_tag: u8,
    pub iid: u8,
    pub typ: u8,
    pub cmd: u8,
    pub cc: u8,
    pub data: Vec<u8>,
}

pub fn pldm_xfer(ep: &MctpEndpoint, req: PldmRequest) -> Result<PldmResponse> {
    const REQ_IID: u8 = 0;
    let mut tx_buf = Vec::with_capacity(req.data.len() + 2);
    tx_buf.push(1 << 7 | REQ_IID);
    tx_buf.push(req.typ & 0x3f);
    tx_buf.push(req.cmd);
    tx_buf.extend_from_slice(&req.data);

    ep.send(MCTP_TYPE_PLDM, req.mctp_tag, &tx_buf)?;

    let mut rx_buf = [0u8; PLDM_MAX_MSGSIZE]; // todo: set size? peek?
    let (sz, tag) = ep.recv(&mut rx_buf)?;

    if sz < 4 {
        return Err(PldmError::new_proto(format!("short response, {} bytes", sz)));
    }

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
        data: rx_buf[4..sz].to_vec(),
    };

    Ok(rsp)
}

pub fn pldm_rx_req(ep: &MctpEndpoint) -> Result<PldmRequest> {
    let mut rx_buf = [0u8; PLDM_MAX_MSGSIZE]; // todo: set size? peek?
    let (sz, tag) = ep.recv(&mut rx_buf)?;

    let mut resp = PldmRequest::from_buf(&rx_buf[0..sz])?;
    resp.mctp_tag = tag;

    Ok(resp)
}

pub fn pldm_tx_resp(ep: &MctpEndpoint, resp: &PldmResponse) -> Result<()> {
    let mut tx_buf = Vec::with_capacity(resp.data.len() + 4);
    tx_buf.push(resp.iid);
    tx_buf.push(resp.typ);
    tx_buf.push(resp.cmd);
    tx_buf.push(resp.cc);
    tx_buf.extend_from_slice(&resp.data);

    ep.send(MCTP_TYPE_PLDM, resp.mctp_tag, &tx_buf)?;

    Ok(())
}
