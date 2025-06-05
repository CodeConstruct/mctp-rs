// SPDX-License-Identifier: MIT OR Apache-2.0
/*
 * Copyright (c) 2024 Code Construct
 */

#[allow(unused)]
use log::{debug, error, info, trace, warn};

use anyhow::{bail, Context, Result};
use log::LevelFilter;

use mctp::{Eid, MsgType, ReqChannel};
use mctp_standalone::MctpSerialReq;

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

    #[argh(switch)]
    /// run corner cases
    serial_corner: bool,

    #[argh(switch)]
    /// exit on error or mismatch
    fatal: bool,

    #[argh(positional)]
    eid: u8,

    #[argh(positional)]
    serial: String,
}

const REQ_MSG_TYPE: MsgType = MsgType(1);

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

    let own_eid = Eid::new_normal(93).unwrap();
    let remote_eid = Eid::new_normal(args.eid).context("Bad remote eid")?;
    let mut ch = MctpSerialReq::new(own_eid, remote_eid, s);
    ch.set_timeout(core::time::Duration::from_millis(3000));

    if args.serial_corner {
        serial_corner_cases(&mut ch)?;
        return Ok(());
    }

    let mut payload = [0u8; 257];
    loop {
        getrandom::getrandom(&mut payload).unwrap();
        let mut l = 0u8;
        getrandom::getrandom(core::slice::from_mut(&mut l)).unwrap();
        let l = (l as usize) % 24;
        let payload = &payload[..l];

        if let Err(e) = req(&mut ch, REQ_MSG_TYPE, &payload, args.fatal) {
            warn!("Error {e:?}");
            if args.fatal {
                bail!("Response error.")
            }
        }
    }
}

fn req(
    ch: &mut impl ReqChannel,
    typ: MsgType,
    payload: &[u8],
    fatal: bool,
) -> Result<()> {
    ch.send(typ, &payload).context("Error sending")?;

    info!("Sent OK");

    let mut buf = [0u8; 2000];
    let (rep, rep_typ, _ic) = ch.recv(&mut buf)?;

    info!("Reply {rep:02x?}");

    if fatal {
        if rep != payload || typ != rep_typ {
            info!("rep_typ 0x{rep_typ:x?}");
            bail!("Response mismatch)")
        }
    }
    assert!(rep == payload);
    Ok(())
}

/// Test roundtrip of payloads with escape bytes
fn serial_corner_cases(ch: &mut impl ReqChannel) -> Result<()> {
    const MTU: usize = 64;
    const ESCAPE: u8 = 0x7d;

    for n in 0..=MTU {
        // Create a buffer with no special bytes
        let mut b = Vec::new();
        let mut c = 5u8;
        let limit = 0x40;
        for _ in 0..n {
            c = (c + 1) % limit;
            b.push(c);
        }

        // Unmodified
        req(ch, REQ_MSG_TYPE, &b, true)?;

        let mut addescape = |n| {
            if let Some(c) = b.get_mut(n) {
                *c = ESCAPE;
                req(ch, REQ_MSG_TYPE, &b, true)?;
            }
            anyhow::Result::<_>::Ok(())
        };

        // Beginning
        addescape(0)?;
        addescape(1)?;
        addescape(2)?;

        // Middle
        addescape(7)?;
        addescape(8)?;
        addescape(9)?;

        // End
        addescape(n.saturating_sub(1))?;
        addescape(n.saturating_sub(3))?;
        addescape(n.saturating_sub(2))?;
        addescape(n.saturating_sub(5))?;
        addescape(n.saturating_sub(6))?;
    }
    Ok(())
}
