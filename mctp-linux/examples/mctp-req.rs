// SPDX-License-Identifier: Apache-2.0
/*
 * Simple MCTP example using Linux sockets: Get Endpoint ID requester.
 *
 * Copyright (c) 2024 Code Construct
 */

use mctp_linux::MctpLinuxReq;
use mctp::{Eid, ReqChannel, MCTP_TYPE_CONTROL};

fn main() -> std::io::Result<()> {
    const EID : Eid = Eid(8);

    // Create a new endpoint using the linux socket support
    let mut ep = MctpLinuxReq::new(EID, None)?;

    // for subsequent use of `ep`, we're just interacting with the
    // mctp::Comm trait, which is independent of the socket support

    // Get Endpoint ID message: command 0x02, no data. Allow the MCTP stack
    // to allocate an owned tag.
    let tx_buf = vec![0x02u8];
    ep.send(MCTP_TYPE_CONTROL, &tx_buf)?;

    // Receive a response. We create a 16-byte vec to read into; ep.recv()
    // will return the sub-slice containing just the response data.
    let mut rx_buf = vec![0u8; 16];
    let (rx_buf, eid, tag, ic) = ep.recv(&mut rx_buf)?;

    println!("response from {}, tag {}, ic {:?}: {:x?}", eid, tag, ic, rx_buf);

    Ok(())
}
