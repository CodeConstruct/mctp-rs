// SPDX-License-Identifier: MIT OR Apache-2.0

use deku::{DekuContainerRead, DekuContainerWrite, DekuError};
use log::{debug, trace};
use mctp::{AsyncRespChannel, Eid};
use num_traits::FromPrimitive;
use pldm::{
    self, pldm_tx_resp_async, proto_error, CCode, PldmError, PldmRequest,
    PldmResponse,
};

use crate::proto::file_ccode;
use crate::proto::*;
use crate::PLDM_TYPE_FILE_TRANSFER;

const FILE_ID: FileIdentifier = FileIdentifier(0);

const MAX_PART_SIZE: u16 = 1024;

pub trait Host {
    /// Returns number of bytes read
    // just a single-file implementation
    fn read(&self, buf: &mut [u8], offset: usize) -> std::io::Result<usize>;
}

// Created at the first stage (XFER_FIRST_PART) of a MultpartReceive,
// where we have the offset and size.
struct FileTransferContext {
    // File starting offset
    start: usize,
    len: usize,
    // Current transfer 0..len
    offset: usize,
}

// Created on DfOpen
struct FileContext {
    xfer_ctx: Option<FileTransferContext>,
}

pub struct Responder<const N: usize> {
    files: [Option<FileContext>; N],
}

#[derive(Debug)]
struct PldmFileError(u8);

impl From<CCode> for PldmFileError {
    fn from(cc: CCode) -> Self {
        Self(cc as u8)
    }
}

impl From<u8> for PldmFileError {
    fn from(cc: u8) -> Self {
        Self(cc)
    }
}

impl From<DekuError> for PldmFileError {
    fn from(_: DekuError) -> Self {
        CCode::ERROR_INVALID_DATA.into()
    }
}

impl From<PldmError> for PldmFileError {
    fn from(_: PldmError) -> Self {
        CCode::ERROR.into()
    }
}

impl From<PldmFileError> for u8 {
    fn from(err: PldmFileError) -> Self {
        err.0
    }
}
impl std::fmt::Display for PldmFileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CC: {}", self.0)
    }
}

const CRC32: crc::Crc<u32, crc::Table<16>> =
    crc::Crc::<u32, crc::Table<16>>::new(&crc::CRC_32_ISO_HDLC);

type Result<T> = std::result::Result<T, PldmFileError>;

impl<const N: usize> Responder<N> {
    pub fn new() -> Self {
        Self {
            files: [const { None }; N],
        }
    }

    pub fn register<const T: usize>(
        pldm: &mut pldm::control::responder::Responder<T>,
    ) -> pldm::Result<()> {
        pldm.register_type(
            PLDM_TYPE_FILE_TRANSFER,
            0xf1f0f000,
            Some(MAX_PART_SIZE),
            &[
                Cmd::DfProperties as u8,
                Cmd::DfOpen as u8,
                Cmd::DfClose as u8,
                Cmd::DfRead as u8,
            ],
        )
    }

    pub async fn request_in<R: AsyncRespChannel>(
        &mut self,
        mut comm: R,
        req: &PldmRequest<'_>,
        _host: &mut impl Host,
    ) -> pldm::Result<()> {
        if req.typ != PLDM_TYPE_FILE_TRANSFER {
            trace!("pldm-fw non-pldm-fw request {req:?}");
            return Err(proto_error!("Unexpected pldm-fw request"));
        }

        let Some(cmd) = Cmd::from_u8(req.cmd) else {
            let _ = self
                .reply_error(
                    req,
                    &mut comm,
                    CCode::ERROR_UNSUPPORTED_PLDM_CMD as u8,
                )
                .await;
            return Ok(());
        };

        let r = match cmd {
            Cmd::DfProperties => self.cmd_dfproperties(req),
            Cmd::DfOpen => self.cmd_dfopen(req),
            Cmd::DfClose => self.cmd_dfclose(req),
            _ => {
                trace!("unhandled command {cmd:?}");
                Err(CCode::ERROR_UNSUPPORTED_PLDM_CMD.into())
            }
        };

        let res = match r {
            Ok(resp) => pldm_tx_resp_async(&mut comm, &resp)
                .await
                .map_err(|e| ("command", e)),
            Err(e) => {
                debug!("Error handling {cmd:?}: {e:?}");
                self.reply_error(req, &mut comm, e.into())
                    .await
                    .map_err(|e| ("failure", e))
            }
        };

        if let Err((typ, e)) = res {
            debug!("error sending {typ} response. {e:?}");
            return Err(e);
        }
        Ok(())
    }

    // We may want to move this to the general request_in() path?
    pub async fn multipart_request_in<const T: usize, R: AsyncRespChannel>(
        &mut self,
        mut comm: R,
        req: &PldmRequest<'_>,
        pldm_ctrl: &pldm::control::responder::Responder<T>,
        host: &mut impl Host,
    ) -> pldm::Result<()> {
        let Ok(cmd) = pldm::control::Cmd::try_from(req.cmd) else {
            return self
                .reply_error(
                    req,
                    &mut comm,
                    CCode::ERROR_UNSUPPORTED_PLDM_CMD as u8,
                )
                .await;
        };

        let res = match cmd {
            pldm::control::Cmd::MultipartReceive => self.cmd_multipart_receive(
                req,
                comm.remote_eid(),
                pldm_ctrl,
                host,
            ),
            _ => {
                trace!("unhandled multipart request");
                Err(CCode::ERROR_UNSUPPORTED_PLDM_CMD.into())
            }
        };

        match res {
            Ok(resp) => pldm_tx_resp_async(&mut comm, &resp).await,
            Err(e) => {
                debug!("Error handling multipart command: {e:?}");
                self.reply_error(req, &mut comm, e.into()).await
            }
        }
    }

    async fn reply_error<R: AsyncRespChannel>(
        &self,
        req: &PldmRequest<'_>,
        comm: &mut R,
        cc: u8,
    ) -> std::result::Result<(), PldmError> {
        let mut resp = req.response();
        resp.cc = cc;
        pldm_tx_resp_async(comm, &resp).await
    }

    fn cmd_dfproperties<'a>(
        &mut self,
        req: &'a PldmRequest<'a>,
    ) -> Result<PldmResponse<'a>> {
        let (rest, dfp) = DfPropertiesReq::from_bytes((&req.data, 0))?;

        if !rest.0.is_empty() {
            Err(CCode::ERROR_INVALID_DATA)?;
        }

        let prop = DfProperty::try_from(dfp.property)
            .map_err(|_| file_ccode::INVALID_DF_ATTRIBUTE)?;

        // fixed properties at present...
        let value = match prop {
            DfProperty::MaxConcurrentMedium => 1u32,
            DfProperty::MaxFileDescriptors => 1u32,
        };

        let prop_resp = DfPropertiesResp { value };
        let mut resp = req.response();
        resp.set_data(prop_resp.to_bytes()?);

        Ok(resp)
    }

    fn cmd_dfopen<'a>(
        &mut self,
        req: &'a PldmRequest<'a>,
    ) -> Result<PldmResponse<'a>> {
        let (rest, dfo) = DfOpenReq::from_bytes((&req.data, 0))?;

        if !rest.0.is_empty() {
            Err(CCode::ERROR_INVALID_LENGTH)?;
        }

        if dfo.file_identifier != FILE_ID.0 {
            Err(file_ccode::INVALID_FILE_IDENTIFIER)?;
        }

        // todo: attributes

        // single file implementation, requires no file-specific context
        let file_ctx = FileContext { xfer_ctx: None };

        let id = self
            .files
            .iter()
            .position(|e| e.is_none())
            .ok_or(file_ccode::MAX_NUM_FDS_EXCEEDED)?;

        self.files[id].replace(file_ctx);

        let dfo_resp = DfOpenResp {
            file_descriptor: id as u16,
        };

        let mut resp = req.response();
        resp.set_data(dfo_resp.to_bytes()?);

        Ok(resp)
    }

    fn cmd_dfclose<'a>(
        &mut self,
        req: &'a PldmRequest<'a>,
    ) -> Result<PldmResponse<'a>> {
        let (rest, dfc) = DfCloseReq::from_bytes((&req.data, 0))?;

        if !rest.0.is_empty() {
            Err(CCode::ERROR_INVALID_LENGTH)?;
        }

        if dfc.attributes != 0 {
            Err(file_ccode::ZEROLENGTH_NOT_ALLOWED)?;
        }

        self.files
            .get_mut(dfc.file_descriptor as usize)
            .ok_or(file_ccode::INVALID_FILE_DESCRIPTOR)? // valid?
            .take()
            .ok_or(file_ccode::INVALID_FILE_DESCRIPTOR)?; // open?

        Ok(req.response())
    }

    fn cmd_multipart_receive<'a, const T: usize>(
        &mut self,
        req: &'a PldmRequest<'a>,
        eid: Eid,
        ctrl: &pldm::control::responder::Responder<T>,
        host: &mut impl Host,
    ) -> Result<PldmResponse<'a>> {
        let (rest, cmd) = pldm::control::MultipartReceiveReq::from_bytes((
            req.data.as_ref(),
            0,
        ))?;

        if !rest.0.is_empty() {
            Err(CCode::ERROR_INVALID_LENGTH)?;
        }

        // MultipartRead context is 32bits, but file descriptors are 16...
        if cmd.xfer_context > u16::MAX as u32 {
            Err(CCode::ERROR_INVALID_TRANSFER_CONTEXT)?;
        }

        let part_size = ctrl
            .negotiated_xfer_size(eid, PLDM_TYPE_FILE_TRANSFER)
            .ok_or(pldm::control::control_ccode::NEGOTIATION_INCOMPLETE)?
            as usize;

        let fd = FileDescriptor(cmd.xfer_context as u16);

        let file_ctx = self
            .files
            .get_mut(fd.0 as usize)
            .ok_or(CCode::ERROR_INVALID_TRANSFER_CONTEXT)? // valid?
            .as_mut()
            .ok_or(CCode::ERROR_INVALID_TRANSFER_CONTEXT)?; // open?

        // handle termination
        if cmd.xfer_op == pldm::control::xfer_op::ABORT
            || cmd.xfer_op == pldm::control::xfer_op::COMPLETE
        {
            file_ctx.xfer_ctx.take();
            let dfread_resp = pldm::control::MultipartReceiveResp {
                xfer_flag: pldm::control::xfer_flag::ACKNOWLEDGE_COMPLETION,
                next_handle: 0,
                len: 0,
            };
            let mut resp = req.response();
            resp.set_data(dfread_resp.to_bytes()?);
            return Ok(resp);
        }

        // Set new transfer context
        if cmd.xfer_op == pldm::control::xfer_op::FIRST_PART {
            if let Some(ctx) = file_ctx.xfer_ctx.as_mut() {
                ctx.offset = 0;
            } else {
                let new_ctx = Self::init_read(&cmd)?;
                // a repeated FIRST_PART is valid, and restarts the transfer
                file_ctx.xfer_ctx.replace(new_ctx);
            };
        }

        let xfer_ctx = file_ctx.xfer_ctx.as_mut().ok_or(CCode::ERROR)?;
        let full_len = xfer_ctx.len;

        let offset = match cmd.xfer_op {
            pldm::control::xfer_op::FIRST_PART
            | pldm::control::xfer_op::CURRENT_PART => xfer_ctx.offset,
            pldm::control::xfer_op::NEXT_PART => xfer_ctx.offset + part_size,
            _ => Err(CCode::ERROR_INVALID_DATA)?,
        };

        if offset >= xfer_ctx.len {
            Err(CCode::ERROR_INVALID_DATA)?;
        }

        let start = offset == 0;
        let (len, end) = if offset + part_size >= full_len {
            (full_len - offset, true)
        } else {
            (part_size, false)
        };

        let mut flags = 0;
        if start {
            flags |= pldm::control::xfer_flag::START
        }
        if end {
            flags |= pldm::control::xfer_flag::END
        }
        // spec defines useless flags :(
        if flags == 0 {
            flags |= pldm::control::xfer_flag::MIDDLE
        }

        let mut resp = req.response();
        let dfread_resp = pldm::control::MultipartReceiveResp {
            xfer_flag: flags,
            next_handle: 0,
            len: len as u32,
        };

        let mut resp_data = Vec::new();
        resp_data.extend_from_slice(&dfread_resp.to_bytes()?);

        let l = resp_data.len();
        resp_data.resize(resp_data.len() + len, 0);
        let data = &mut resp_data[l..];
        host.read(data, xfer_ctx.start + offset)
            .map_err(|_| CCode::ERROR)?;

        let cs = CRC32.checksum(data);
        resp_data.extend_from_slice(&cs.to_le_bytes());

        xfer_ctx.offset = offset;
        resp.set_data(resp_data);

        Ok(resp)
    }

    fn init_read(
        req: &pldm::control::MultipartReceiveReq,
    ) -> Result<FileTransferContext> {
        trace!("init_read {req:?}");
        let start = req.req_offset as usize;
        let len = req.req_length as usize;
        Ok(FileTransferContext {
            start,
            len,
            offset: 0,
        })
    }
}

impl<const N: usize> Default for Responder<N> {
    fn default() -> Self {
        Self::new()
    }
}
