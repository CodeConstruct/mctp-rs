// SPDX-License-Identifier: MIT OR Apache-2.0
/*
 * Copyright (c) 2024 Code Construct
 */

//! A MCTP serial transport binding, DSP0253

#[allow(unused)]
use crate::fmt::{debug, error, info, trace, warn};
use mctp::{Error, Result};

use crc::Crc;
use heapless::Vec;

use embedded_io_async::{Read, Write};

const MCTP_SERIAL_REVISION: u8 = 0x01;

// Limited by u8 bytecount field, minus MCTP headers
pub const MTU_MAX: usize = 0xff - 4;

// Received frame after unescaping. Bytes 1-N+1 in Figure 1 (serial protocol
// revision to frame check seq lsb)
const RXBUF_FRAMING: usize = 4;
const MAX_RX: usize = 0xff + RXBUF_FRAMING;

const FRAMING_FLAG: u8 = 0x7e;
const FRAMING_ESCAPE: u8 = 0x7d;
const FLAG_ESCAPED: u8 = 0x5e;
const ESCAPE_ESCAPED: u8 = 0x5d;

// Rx byte position in DSP0253 Table 1
// Indicates the expected position of the next read byte.
#[derive(Debug, PartialEq)]
enum Pos {
    // Searching for Framing Flag
    FrameSearch,
    SerialRevision,
    ByteCount,
    Data,
    // Byte following a 0x7d
    DataEscaped,
    Check,
    FrameEnd,
}

#[derive(Debug)]
pub struct MctpSerialHandler {
    rxpos: Pos,
    rxbuf: Vec<u8, MAX_RX>,
    // Last-seen byte count field
    rxcount: usize,
}

// https://www.rfc-editor.org/rfc/rfc1662
// checksum is complement of the output
const CRC_FCS: Crc<u16> = Crc::<u16>::new(&crc::CRC_16_IBM_SDLC);

impl MctpSerialHandler {
    pub fn new() -> Self {
        Self {
            rxpos: Pos::FrameSearch,
            rxcount: 0,
            rxbuf: Vec::new(),
        }
    }

    /// Read a frame.
    ///
    /// This is async cancel-safe.
    pub async fn recv_async(&mut self, input: &mut impl Read) -> Result<&[u8]> {
        // TODO: This reads one byte a time, might need a buffering wrapper
        // for performance. Will require more thought about cancel-safety

        loop {
            let mut b = 0u8;
            // Read from serial
            match input.read(core::slice::from_mut(&mut b)).await {
                Ok(1) => (),
                Ok(0) => {
                    trace!("Serial EOF");
                    return Err(Error::RxFailure);
                }
                Ok(2..) => unreachable!(),
                Err(_e) => {
                    trace!("Serial read error");
                    // TODO or do we want a RxFailure?
                    return Err(Error::RxFailure);
                }
            }
            if let Some(_p) = self.feed_frame(b) {
                // bleh polonius
                // return Ok(p)
                return Ok(&self.rxbuf[2..][..self.rxcount]);
            }
        }
    }

    fn feed_frame(&mut self, b: u8) -> Option<&[u8]> {
        trace!("serial read {:02x}", b);

        match self.rxpos {
            Pos::FrameSearch => {
                if b == FRAMING_FLAG {
                    self.rxpos = Pos::SerialRevision
                }
            }
            Pos::SerialRevision => {
                self.rxpos = match b {
                    MCTP_SERIAL_REVISION => Pos::ByteCount,
                    FRAMING_FLAG => Pos::SerialRevision,
                    _ => Pos::FrameSearch,
                };
                self.rxbuf.clear();
                self.rxcount = 0;
                self.rxbuf.push(b).unwrap();
            }
            Pos::ByteCount => {
                self.rxcount = b as usize;
                self.rxbuf.push(b).unwrap();
                self.rxpos = Pos::Data;
            }
            Pos::Data => {
                match b {
                    // Unexpected framing, restart
                    FRAMING_FLAG => self.rxpos = Pos::SerialRevision,
                    FRAMING_ESCAPE => self.rxpos = Pos::DataEscaped,
                    _ => {
                        self.rxbuf.push(b).unwrap();
                        if self.rxbuf.len() == self.rxcount + 2 {
                            self.rxpos = Pos::Check;
                        }
                    }
                }
            }
            Pos::DataEscaped => {
                match b {
                    FLAG_ESCAPED => {
                        self.rxbuf.push(FRAMING_FLAG).unwrap();
                        self.rxpos = Pos::Data;
                    }
                    ESCAPE_ESCAPED => {
                        self.rxbuf.push(FRAMING_ESCAPE).unwrap();
                        self.rxpos = Pos::Data;
                    }
                    // Unexpected escape, restart
                    _ => self.rxpos = Pos::FrameSearch,
                }
                if self.rxbuf.len() == self.rxcount + 2 {
                    self.rxpos = Pos::Check;
                }
            }
            Pos::Check => {
                self.rxbuf.push(b).unwrap();
                if self.rxbuf.len() == self.rxcount + RXBUF_FRAMING {
                    self.rxpos = Pos::FrameEnd;
                }
            }
            Pos::FrameEnd => {
                if b == FRAMING_FLAG {
                    // Ready for next frame
                    self.rxpos = Pos::FrameSearch;
                    // Compare checksum
                    let (csdata, cs) = self.rxbuf.split_at(self.rxcount + 2);
                    let cs: [u8; 2] = cs.try_into().unwrap();
                    let cs = u16::from_be_bytes(cs);
                    let cs_calc = !CRC_FCS.checksum(csdata);
                    if cs_calc == cs {
                        // Complete frame
                        let packet = &self.rxbuf[2..][..self.rxcount];
                        return Some(packet);
                    } else {
                        warn!(
                            "Bad checksum got {:04x} calc {:04x}",
                            cs, cs_calc
                        );
                    }
                } else {
                    // restart
                    self.rxpos = Pos::SerialRevision;
                }
            }
        }
        // Frame is incomplete
        None
    }

    pub async fn send_async(
        &mut self,
        pkt: &[u8],
        output: &mut impl Write,
    ) -> Result<()> {
        Self::frame_to_serial(pkt, output)
            .await
            .map_err(|_e| Error::TxFailure)
    }

    async fn frame_to_serial<W>(
        p: &[u8],
        output: &mut W,
    ) -> core::result::Result<(), W::Error>
    where
        W: Write,
    {
        debug_assert!(p.len() <= u8::MAX.into());
        debug_assert!(p.len() > 4);

        let start = [FRAMING_FLAG, MCTP_SERIAL_REVISION, p.len() as u8];
        let mut cs = CRC_FCS.digest();
        cs.update(&start[1..]);
        cs.update(p);
        let cs = !cs.finalize();

        output.write_all(&start).await?;
        Self::write_escaped(p, output).await?;
        output.write_all(&cs.to_be_bytes()).await?;
        output.write_all(&[FRAMING_FLAG]).await?;
        Ok(())
    }

    async fn write_escaped<W>(
        p: &[u8],
        output: &mut W,
    ) -> core::result::Result<(), W::Error>
    where
        W: Write,
    {
        for c in
            p.split_inclusive(|&b| b == FRAMING_FLAG || b == FRAMING_ESCAPE)
        {
            let (last, rest) = c.split_last().unwrap();
            match *last {
                FRAMING_FLAG => {
                    output.write_all(rest).await?;
                    output.write_all(&[FRAMING_ESCAPE, FLAG_ESCAPED]).await?;
                }
                FRAMING_ESCAPE => {
                    output.write_all(rest).await?;
                    output.write_all(&[FRAMING_ESCAPE, ESCAPE_ESCAPED]).await?;
                }
                _ => output.write_all(c).await?,
            }
        }
        Ok(())
    }
}

impl Default for MctpSerialHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use crate::serial::*;
    use crate::*;
    use embedded_io_adapters::futures_03::FromFutures;
    use proptest::prelude::*;

    fn start_log() {
        let _ = env_logger::Builder::new()
            .filter(None, log::LevelFilter::Trace)
            .is_test(true)
            .try_init();
    }

    async fn do_roundtrip(payload: &[u8]) {
        let mut esc = vec![];
        let mut s = FromFutures::new(&mut esc);
        MctpSerialHandler::frame_to_serial(payload, &mut s)
            .await
            .unwrap();
        debug!("{:02x?}", payload);
        debug!("{:02x?}", esc);

        let mut h = MctpSerialHandler::new();
        let mut s = FromFutures::new(esc.as_slice());
        let packet = h.recv_async(&mut s).await.unwrap();
        debug_assert_eq!(payload, packet);
    }

    #[test]
    fn roundtrip_cases() {
        // Fixed testcases
        start_log();
        smol::block_on(async {
            for payload in
                [&[0x01, 0x5d, 0x0d, 0xf4, 0x01, 0x93, 0x7d, 0xcd, 0x36]]
            {
                do_roundtrip(payload).await
            }
        })
    }

    proptest! {
        #[test]
        fn roundtrip_escape(payload in proptest::collection::vec(0..255u8, 5..20)) {
            start_log();

            smol::block_on(do_roundtrip(&payload))

        }
    }
}
