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

use mctp::{Listener, Eid, MsgType, RespChannel};
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


fn main() -> Result<()> {

    let args: Args = argh::from_env();

    let level = if args.trace {
        LevelFilter::Trace
    } else if args.verbose {
        LevelFilter::Debug
    } else {
        LevelFilter::Info
    };

    let conf = simplelog::ConfigBuilder::new()
        .build();
    simplelog::SimpleLogger::init(level, conf)?;


    let s = std::fs::OpenOptions::new().write(true).read(true).open(args.serial)?;
    let s = smol::Async::new(s)?;
    let s = embedded_io_adapters::futures_03::FromFutures::new(s);

    let eid = Eid(13);
    let typ = MsgType(1);
    let mut l = MctpSerialListener::new(eid, typ, s);

    let mut buf = [0u8; 2000];

    loop {
        let r = l.recv(&mut buf);
        match r {
            Ok((buf, mut resp, tag, _ic)) => {
                info!("Received OK {buf:02x?} tag {tag}");
                let r = resp.send(typ, buf);
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
