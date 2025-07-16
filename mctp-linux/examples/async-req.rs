// SPDX-License-Identifier: MIT OR Apache-2.0
/*
 * Simple MCTP example using Linux sockets in async mode.
 *
 * Copyright (c) 2025 Code Construct
 */

use mctp::{AsyncReqChannel, Eid, MCTP_TYPE_CONTROL};
use mctp_linux::MctpLinuxAsyncReq;

fn main() -> std::io::Result<()> {
    const EID: Eid = Eid(8);

    let mut ep = MctpLinuxAsyncReq::new(EID, None)?;

    let tx_buf = vec![0x02u8];
    let mut rx_buf = vec![0u8; 16];

    let (typ, ic, rx_buf) = smol::block_on(async {
        ep.send(MCTP_TYPE_CONTROL, &tx_buf).await?;
        ep.recv(&mut rx_buf).await
    })?;

    println!("response type {typ}, ic {ic:?}: {rx_buf:x?}");

    Ok(())
}
