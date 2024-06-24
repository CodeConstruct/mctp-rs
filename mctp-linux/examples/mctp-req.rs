// SPDX-License-Identifier: Apache-2.0
/*
 * Simple MCTP example using Linux sockets: Get Endpoint ID requester.
 *
 * Copyright (c) 2024 Code Construct
 */

use mctp_linux::{MctpLinuxEp, MCTP_NET_ANY};
use mctp::{Endpoint, MCTP_TYPE_CONTROL, Tag};

fn main() -> std::io::Result<()> {
    const EID : u8 = 8;

    // Create a new endpoint using the linux socket support
    let mut ep = MctpLinuxEp::new(EID, MCTP_NET_ANY)?;

    // for subsequent use of `ep`, we're just interacting with the
    // mctp::Endpoint trait, which are independent of the socket support

    // Get Endpoint ID message: command 0x02, no data. Allow the MCTP stack
    // to allocate an owned tag.
    let tx_buf = vec![0x02u8];
    ep.send(MCTP_TYPE_CONTROL, Tag::OwnedAuto, &tx_buf)?;

    // Receive a response. We create a 16-byte vec to read into; ep.recv()
    // will return the sub-slice containing just the response data.
    let mut rx_buf = vec![0u8; 16];
    let (rx_buf, eid, tag) = ep.recv(&mut rx_buf)?;

    println!("response from {}, tag {}: {:x?}", eid, tag, rx_buf);

    Ok(())
}
