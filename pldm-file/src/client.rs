use deku::{DekuContainerRead, DekuContainerWrite};
use log::trace;
use pldm::control::{MultipartReceiveReq, MultipartReceiveResp};
use pldm::{
    pldm_xfer_buf_async, proto_error, PldmError, PldmRequest, PldmResult,
    Result,
};

use crate::proto::*;
use crate::PLDM_TYPE_FILE_TRANSFER;

pub async fn df_properties(
    comm: &mut impl mctp::AsyncReqChannel,
    property: DfProperty,
) -> Result<u32> {
    let req = DfPropertiesReq {
        property: property as u32,
    };

    let mut buf = [0; 10];
    let l = req.to_slice(&mut buf).map_err(|_| PldmError::NoSpace)?;
    let buf = &buf[..l];

    let req = PldmRequest::new_borrowed(
        PLDM_TYPE_FILE_TRANSFER,
        Cmd::DfProperties as u8,
        buf,
    );

    let mut rx = [0; 30];
    let resp = pldm_xfer_buf_async(comm, req, &mut rx).await?;

    let ((rest, _), ret) = DfPropertiesResp::from_bytes((&resp.data, 0))
        .map_err(|e| {
            trace!("DfProperties parse error {e}");
            proto_error!("Bad DfProperties response")
        })?;

    if !rest.is_empty() {
        return Err(proto_error!("Extra response"));
    }

    Ok(ret.value)
}

pub async fn df_open(
    comm: &mut impl mctp::AsyncReqChannel,
    id: FileIdentifier,
    attributes: DfOpenAttributes,
) -> Result<FileDescriptor> {
    let req = DfOpenReq {
        file_identifier: id.0,
        attributes: attributes.as_u16(),
    };

    let mut buf = [0; 10];
    let l = req.to_slice(&mut buf).map_err(|_| PldmError::NoSpace)?;
    let buf = &buf[..l];

    let req = PldmRequest::new_borrowed(
        PLDM_TYPE_FILE_TRANSFER,
        Cmd::DfOpen as u8,
        buf,
    );

    let mut rx = [0; 10];
    let resp = pldm_xfer_buf_async(comm, req, &mut rx).await?;

    let ((rest, _), ret) =
        DfOpenResp::from_bytes((&resp.data, 0)).map_err(|e| {
            trace!("DfOpen parse error {e}");
            proto_error!("Bad DfOpen response")
        })?;

    if !rest.is_empty() {
        return Err(proto_error!("Extra response"));
    }

    Ok(FileDescriptor(ret.file_descriptor))
}

const PART_SIZE: usize = 1024;

/// Read a file from the host.
///
/// The total file size read is returned.
pub async fn df_read(
    comm: &mut impl mctp::AsyncReqChannel,
    file: FileDescriptor,
    offset: usize,
    buf: &mut [u8],
) -> Result<usize> {
    let len = buf.len();
    let mut v = pldm::util::SliceWriter::new(buf);

    df_read_with(comm, file, offset, len, |b| {
        let r = v.extend(b);
        debug_assert!(r.is_some(), "provided data should be <= len");
        Ok(())
    })
    .await
}

/// Read a file into a provided closure.
///
/// The `out` closure will be called repeatedly with sequential buffer chunks
/// sent from the host. Any error returned by `out` will be returned from `df_read_with`.
pub async fn df_read_with<F>(
    comm: &mut impl mctp::AsyncReqChannel,
    file: FileDescriptor,
    offset: usize,
    len: usize,
    mut out: F,
) -> Result<usize>
where
    F: FnMut(&[u8]) -> PldmResult<()>,
{
    let req_offset = u32::try_from(offset).map_err(|_| {
        trace!("invalid offset");
        PldmError::InvalidArgument
    })?;
    let req_length = u32::try_from(len).map_err(|_| {
        trace!("invalid len");
        PldmError::InvalidArgument
    })?;
    req_length.checked_add(req_offset).ok_or_else(|| {
        trace!("invalid len");
        PldmError::InvalidArgument
    })?;

    let mut part_offset = 0usize;
    let mut req = MultipartReceiveReq {
        pldm_type: PLDM_TYPE_FILE_TRANSFER,
        xfer_op: pldm::control::xfer_op::FIRST_PART,
        xfer_context: file.0 as u32,
        xfer_handle: 0,
        req_offset,
        req_length,
    };
    loop {
        let mut tx_buf = [0; 18];
        let l = req.to_slice(&mut tx_buf).map_err(|_| PldmError::NoSpace)?;
        let tx_buf = &tx_buf[..l];

        let pldm_req = PldmRequest::new_borrowed(
            pldm::control::PLDM_TYPE_CONTROL,
            pldm::control::Cmd::MultipartReceive as u8,
            tx_buf,
        );

        // todo: negotiated length
        let mut rx_buf = [0u8; 14 + PART_SIZE + 4];
        let resp = pldm_xfer_buf_async(comm, pldm_req, &mut rx_buf).await?;

        let ((rest, _), read_resp) =
            MultipartReceiveResp::from_bytes((&resp.data, 0)).map_err(|e| {
                trace!("DfRead parse error {e}");
                proto_error!("Bad DfOpen response")
            })?;

        let resp_data_len = read_resp.len as usize;

        if rest.len() != resp_data_len + 4 {
            return Err(proto_error!("invalid resonse data length"));
        }

        let (resp_data, resp_cs) = rest.split_at(resp_data_len);

        let crc32 = crc::Crc::<u32>::new(&crc::CRC_32_ISO_HDLC);
        let calc_cs = crc32.checksum(resp_data);
        // unwrap: we have asserted the lengths above
        let cs = u32::from_le_bytes(resp_cs.try_into().unwrap());

        if calc_cs != cs {
            return Err(proto_error!("data checksum mismatch"));
        }

        // Ensure the host doesn't send more data than requested
        let total_len = part_offset
            .checked_add(resp_data_len)
            .filter(|l| *l <= (req_length as usize))
            .ok_or(proto_error!("excess data received"))?;

        // provide data to the callback
        out(resp_data)?;

        if read_resp.xfer_flag & pldm::control::xfer_flag::END != 0 {
            break Ok(total_len);
        }

        part_offset = total_len;
        req.xfer_op = pldm::control::xfer_op::NEXT_PART;
        req.xfer_context = 0;
        req.xfer_handle = read_resp.next_handle;
        req.req_offset = 0;
        req.req_length = 0;
    }
}
