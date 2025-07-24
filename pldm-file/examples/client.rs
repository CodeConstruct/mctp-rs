use anyhow::{Context, Result};
use mctp::Eid;
use mctp_linux::MctpLinuxAsyncReq;
use pldm::{control::requester::negotiate_transfer_parameters, PldmError};
use pldm_file::{
    client::{df_close, df_open, df_properties, df_read_with},
    proto::{DfCloseAttributes, DfOpenAttributes, DfProperty, FileIdentifier},
};

const EID: Eid = Eid(8);

fn main() -> Result<()> {
    let mut req = MctpLinuxAsyncReq::new(EID, None)?;

    smol::block_on(async {
        let mcm_prop =
            df_properties(&mut req, DfProperty::MaxConcurrentMedium).await;
        let fds_prop =
            df_properties(&mut req, DfProperty::MaxFileDescriptors).await;
        println!("Max Concurrent Medium: {mcm_prop:?}, Max FDs: {fds_prop:?}");

        let req_types = [pldm_file::PLDM_TYPE_FILE_TRANSFER];
        let mut buf = [0u8];

        let (size, neg_types) =
            negotiate_transfer_parameters(&mut req, &req_types, &mut buf, 512)
                .await?;

        println!("Negotiated multipart size {size} for types {neg_types:?}");

        let id = FileIdentifier(0);
        let attrs = DfOpenAttributes::empty();
        let fd = df_open(&mut req, id, attrs)
            .await
            .context("DfOpen failed")?;

        println!("Open: {fd:?}");

        let mut buf = Vec::new();
        let req_len = 4096;

        println!("Reading...");
        let res = df_read_with(&mut req, fd, 0, req_len, |part| {
            println!("  {} bytes", part.len());
            if buf.len() + part.len() > req_len {
                println!("  data overflow!");
                Err(PldmError::NoSpace)
            } else {
                buf.extend_from_slice(part);
                Ok(())
            }
        })
        .await;

        println!("Read: {res:?}");

        let attrs = DfCloseAttributes::empty();
        let res = df_close(&mut req, fd, attrs).await;

        println!("Close: {res:?}");

        Ok(())
    })
}
