//! A MCTP serial transport binding, DSP0253

#[allow(unused)]
use crate::fmt::{debug, error, info, trace, warn};

use crate::{
    AppCookie, MctpMessage, ReceiveHandle, SendOutput, Stack,
};
use mctp::{Eid, Error, MsgType, Result, Tag};

use crc::Crc;
use heapless::Vec;

use embedded_io_async::{Read, Write};

const MCTP_SERIAL_REVISION: u8 = 0x01;

// Limited by u8 bytecount field, minus MCTP headers
const MCTP_SERIAL_MAXMTU: usize = 0xff - 4;

// Received frame after unescaping. Bytes 1-N+1 in Figure 1 (serial protocol
// revision to frame check seq lsb)
const RXBUF_FRAMING: usize = 4;
const MAX_RX: usize = 0xff + RXBUF_FRAMING;

const FRAMING_FLAG: u8 = 0x7e;
const FRAMING_ESCAPE: u8 = 0x7d;
const FLAG_ESCAPED: u8 = 0x5e;
const ESCAPE_ESCAPED: u8 = 0x5d;

const TXMSGBUF: usize = 1024;
// 6 serial header/footer bytes, 0xff MCTP packet bytes
const TXFRAGBUF: usize = 6 + 0xff;

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

    send_message: Vec<u8, TXMSGBUF>,
    send_fragment: [u8; TXFRAGBUF]
}

// https://www.rfc-editor.org/rfc/rfc1662
// checksum is complement of the output
const CRC_FCS: Crc::<u16> = Crc::<u16>::new(&crc::CRC_16_IBM_SDLC);

impl MctpSerialHandler {
    pub fn new() -> Self {
        Self {
            rxpos: Pos::FrameSearch,
            rxcount: 0,
            rxbuf: Vec::new(),

            send_message: Vec::new(),
            send_fragment: [0u8; TXFRAGBUF],
        }
    }

    /// Receive with a timeout.
    pub async fn receive_async<'f>(&mut self, input: &mut impl Read, mctp: &'f mut Stack)
    -> Result<Option<(MctpMessage<'f>, ReceiveHandle)>> {
        let packet = self.read_frame_async(input).await?;
        mctp.receive(packet)
    }

    /// Read a frame.
    ///
    /// This is async cancel-safe.
    async fn read_frame_async(&mut self, input: &mut impl Read) -> Result<&[u8]> {
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
                        warn!("Bad checksum got {:04x} calc {:04x}", cs, cs_calc);
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

    // Returns SendOutput::Complete or SendOutput::Error
    pub async fn send_fill<F>(&mut self, eid: Eid, typ: MsgType, tag: Option<Tag>,
        ic: bool, cookie: Option<AppCookie>, output: &mut impl Write, mctp: &mut Stack, fill_msg: F) -> SendOutput
    where F: FnOnce(&mut Vec<u8, TXMSGBUF>) -> Option<()>,
    {
        // Fetch the message from input
        self.send_message.clear();
        if fill_msg(&mut self.send_message).is_none() {
            return SendOutput::Error {
                err: Error::Other,
                cookie: None,
            }
        }

        let mut fragmenter = match mctp.start_send(eid, typ, tag, true, ic, Some(MCTP_SERIAL_MAXMTU), cookie) {
            Ok(f) => f,
            Err(err) => {
                return SendOutput::Error {
                    err,
                    cookie: None,
                }
            }
        };

        loop {
            let r = fragmenter.fragment(&self.send_message, &mut self.send_fragment);
            match r {
                SendOutput::Packet(p) => {
                    trace!("packet len {} msg {}", p.len(), self.send_message.len());
                    // Write to serial
                    if let Err(_e) = Self::frame_to_serial(p, output).await {
                        trace!("Serial write error");
                        return SendOutput::Error {
                            err: Error::TxFailure,
                            cookie: None,
                        }
                    }
                }
                _ => return r.unborrowed().unwrap()
            }
        }
    }

    async fn frame_to_serial<W>(p: &[u8], output: &mut W) -> core::result::Result<(), W::Error> 
    where W: Write {
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

    async fn write_escaped<W>(p: &[u8], output: &mut W) -> core::result::Result<(), W::Error>
    where W: Write {
        for c in p.split_inclusive(|&b| b == FRAMING_FLAG || b == FRAMING_ESCAPE) {

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


#[cfg(test)]
mod tests {

    use crate::*;
    use crate::serial::*;
    use proptest::prelude::*;
    use embedded_io_adapters::futures_03::FromFutures;

    fn start_log() {
        let _ = env_logger::Builder::new()
        .filter(None, log::LevelFilter::Trace)
        .is_test(true).try_init();
    }

    async fn do_roundtrip(payload: &[u8]) {
        let mut esc = vec![];
        let mut s = FromFutures::new(&mut esc);
        MctpSerialHandler::frame_to_serial(&payload, &mut s).await.unwrap();
        debug!("{:02x?}", payload);
        debug!("{:02x?}", esc);

        let mut h = MctpSerialHandler::new();
        let mut s = FromFutures::new(esc.as_slice());
        let packet = h.read_frame_async(&mut s).await.unwrap();
        debug_assert_eq!(payload, packet);
    }

    #[test]
    fn roundtrip_cases() {
        // Fixed testcases
        start_log();
        smol::block_on(async {
            for payload in [
                &[0x01, 0x5d, 0x0d, 0xf4, 0x01, 0x93, 0x7d, 0xcd, 0x36],
            ] {
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
