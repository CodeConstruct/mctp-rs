use deku::{DekuContainerRead, DekuContainerWrite};
use log::trace;
use pldm::{pldm_xfer_buf_async, proto_error, PldmError, PldmRequest, Result};

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
