// SPDX-License-Identifier: GPL-3.0-or-later
/*
 * PLDM base message definitions.
 *
 * Copyright (c) 2023 Code Construct
 */

use mctp_linux::{self as mctp, MctpEndpoint};

pub const MCTP_TYPE_PLDM: u8 = 0x01;
pub const PLDM_MAX_MSGSIZE: usize = 1024;

#[derive(Debug)]
pub enum PldmError {
    Io(std::io::Error),
    Protocol(String),
    Command(u8, String),
}

impl PldmError {
    pub fn cmd_err(cc: u8, s: &str) -> Self {
        Self::Command(cc, s.into())
    }

    pub fn proto_err(s: &str) -> Self {
        Self::Protocol(s.into())
    }
}

impl From<std::io::Error> for PldmError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl std::error::Error for PldmError {}

impl std::fmt::Display for PldmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "IO error: {e}"),
            Self::Protocol(e) => write!(f, "PLDM protocol error: {e}"),
            Self::Command(cc, e) => write!(f, "PLDM command failure ({cc}): {e}"),
        }
    }
}

pub(crate) type Result<T> = std::result::Result<T, PldmError>;

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
    let mut tx_buf = Vec::with_capacity(req.data.len() + 2);
    tx_buf.push(1 << 7);
    tx_buf.push(req.typ & 0x3f);
    tx_buf.push(req.cmd);
    tx_buf.extend_from_slice(&req.data);

    ep.send(MCTP_TYPE_PLDM, req.mctp_tag, &tx_buf)?;

    let mut rx_buf = [0u8; PLDM_MAX_MSGSIZE]; // todo: set size? peek?
    let (sz, tag) = ep.recv(&mut rx_buf)?;

    if sz < 4 {
        todo!();
    }

    let rsp = PldmResponse {
        mctp_tag: tag,
        iid: rx_buf[0] & 0x1f,
        typ: rx_buf[1] & 0x3f,
        cmd: rx_buf[2],
        cc: rx_buf[3],
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
