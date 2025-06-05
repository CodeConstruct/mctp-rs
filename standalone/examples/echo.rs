// SPDX-License-Identifier: MIT OR Apache-2.0
/*
 * Copyright (c) 2024 Code Construct
 */

//! MCTP echo demo
//!
//! Can be tested with pty pairs an socat:
//! ```
//! socat -v -x -d -d pty,raw,echo=0 pty,raw,echo=0
//! ```
//! Run a `echo` on one PTY (printed in output), a `req` on the other.

#[allow(unused)]
use log::{debug, error, info, trace, warn};

use anyhow::Result;
use log::LevelFilter;

use mctp::{Eid, Listener, MsgType, RespChannel};
use mctp_standalone::MctpSerialListener;

/** mctp serial echo
 */
#[derive(argh::FromArgs)]
struct Args {
    #[argh(switch, short = 'v')]
    /// verbose
    verbose: bool,

    #[argh(switch)]
    /// trace, extra verbose
    trace: bool,

    #[argh(positional)]
    serial: String,
}

const REQ_MSG_TYPE: MsgType = mctp::MCTP_TYPE_VENDOR_PCIE;
const VENDOR_SUBTYPE_ECHO: [u8; 3] = [0xcc, 0xde, 0xf0];

fn main() -> Result<()> {
    let args: Args = argh::from_env();

    let level = if args.trace {
        LevelFilter::Trace
    } else if args.verbose {
        LevelFilter::Debug
    } else {
        LevelFilter::Info
    };

    let conf = simplelog::ConfigBuilder::new().build();
    simplelog::SimpleLogger::init(level, conf)?;

    let s = std::fs::OpenOptions::new()
        .write(true)
        .read(true)
        .open(args.serial)?;
    let s = smol::Async::new(s)?;
    let s = embedded_io_adapters::futures_03::FromFutures::new(s);

    let eid = Eid(13);
    let typ = REQ_MSG_TYPE;
    let mut l = MctpSerialListener::new(eid, typ, s);

    let mut buf = [0u8; 2000];

    loop {
        let r = l.recv(&mut buf);

        match r {
            Ok((typ, _ic, buf, mut resp)) => {
                assert!(typ == REQ_MSG_TYPE);
                if !buf.starts_with(&VENDOR_SUBTYPE_ECHO) {
                    warn!(
                        "Bad vendor prefix: {:02x?}",
                        &buf[..VENDOR_SUBTYPE_ECHO.len()]
                    );
                }

                info!("Received OK {buf:02x?}");
                let r = resp.send(buf);
                if let Err(e) = r {
                    warn!("send error {e:?}");
                }
            }
            Err(e) => {
                warn!("Received err {e:?}");
            }
        }
    }
}
