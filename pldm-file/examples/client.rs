use anyhow::{Context, Result};
use mctp::Eid;
use mctp_linux::MctpLinuxAsyncReq;
use pldm_file::{
    client::{df_open, df_properties, df_read},
    proto::{DfOpenAttributes, DfProperty, FileIdentifier},
};

const EID: Eid = Eid(8);

fn main() -> Result<()> {
    let mut req = MctpLinuxAsyncReq::new(EID, None)?;

    let (mcm_prop, fds_prop) = smol::block_on(async {
        (
            df_properties(&mut req, DfProperty::MaxConcurrentMedium).await,
            df_properties(&mut req, DfProperty::MaxFileDescriptors).await,
        )
    });

    println!("Max Concurrent Medium: {mcm_prop:?}, Max FDs: {fds_prop:?}");

    smol::block_on(async {
        let id = FileIdentifier(0);
        let attrs = DfOpenAttributes::empty();
        let fd = df_open(&mut req, id, attrs)
            .await
            .context("DfOpen failed")?;

        println!("Open: {fd:?}");

        let mut buf = vec![0; 4096];
        let res = df_read(&mut req, fd, 0, &mut buf).await;

        println!("Read: {res:?}");

        Ok(())
    })
}
