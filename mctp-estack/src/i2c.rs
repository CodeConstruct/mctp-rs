// SPDX-License-Identifier: MIT OR Apache-2.0
/*
 * Copyright (c) 2024 Code Construct
 */

//! MCTP over I2C transport binding

#[allow(unused)]
use crate::fmt::{debug, error, info, trace, warn};

use crate::{
    AppCookie, Fragmenter, MctpMessage, MsgIC, SendOutput, Stack, MAX_PAYLOAD,
};
use mctp::{Eid, Error, MsgType, Result, Tag};

use heapless::Vec;

pub const MCTP_I2C_COMMAND_CODE: u8 = 0x0f;

const MCTP_I2C_HEADER: usize = 4;
// bytecount is limited to u8, includes MCTP payload + 1 byte i2c source
pub const MCTP_I2C_MAXMTU: usize = u8::MAX as usize - 1;

pub struct MctpI2cHeader {
    pub dest: u8,
    pub source: u8,
    pub byte_count: usize,
}

impl MctpI2cHeader {
    fn encode(&self) -> Result<[u8; 4]> {
        if self.dest > 0x7f || self.source > 0x7f {
            return Err(Error::BadArgument);
        }
        if self.byte_count > u8::MAX as usize {
            return Err(Error::BadArgument);
        }
        Ok([
            self.dest << 1,
            MCTP_I2C_COMMAND_CODE,
            self.byte_count as u8,
            self.source << 1 | 1,
        ])
    }

    /// Decode a 4-byte I2C header
    ///
    /// Checks and decodes destination and source address,
    /// command code, and byte count.
    fn decode(header: &[u8]) -> Result<Self> {
        let [dest, cmd, byte_count, source] =
            header.try_into().map_err(|_| Error::BadArgument)?;
        if dest & 1 != 0 {
            trace!("Bad i2c dest write bit");
            return Err(Error::InvalidInput);
        }
        if cmd != MCTP_I2C_COMMAND_CODE {
            trace!("Bad i2c command code");
            return Err(Error::InvalidInput);
        }
        if source & 1 != 1 {
            trace!("Bad i2c source read bit");
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            dest: dest >> 1,
            source: source >> 1,
            byte_count: byte_count as usize,
        })
    }
}

/// Simple packet processing to add/remove the 4 byte MCTP-I2C header.
#[derive(Debug, Clone)]
pub struct MctpI2cEncap {
    own_addr: u8,
}

impl MctpI2cEncap {
    pub fn new(own_addr: u8) -> Self {
        Self { own_addr }
    }

    pub fn own_addr(&self) -> u8 {
        self.own_addr
    }

    pub fn decode<'f>(
        &self,
        mut packet: &'f [u8],
        pec: bool,
    ) -> Result<(&'f [u8], MctpI2cHeader)> {
        if packet.is_empty() {
            return Err(Error::InvalidInput);
        }
        if pec {
            // Remove the pec byte, check it.
            let packet_pec;
            (packet_pec, packet) = packet.split_last().unwrap();
            let calc_pec = smbus_pec::pec(packet);
            if calc_pec != *packet_pec {
                trace!("Incorrect PEC");
                return Err(Error::InvalidInput);
            }
        }

        let header =
            MctpI2cHeader::decode(packet.get(..4).ok_or(Error::InvalidInput)?)?;
        // total packet len == byte_count + 3 (destination, command code, byte count)
        // pec is not included
        if header.byte_count + 3 != packet.len() {
            trace!("Packet byte count mismatch");
            return Err(Error::InvalidInput);
        }

        Ok((&packet[MCTP_I2C_HEADER..], header))
    }

    /// Handles a MCTP fragment with the PEC already validated
    ///
    /// `packet` should omit the PEC byte.
    /// Returns the MCTP message and the i2c header.
    pub fn receive_done_pec<'f>(
        &self,
        packet: &[u8],
        mctp: &'f mut Stack,
    ) -> Result<Option<(MctpMessage<'f>, MctpI2cHeader)>> {
        let (mctp_packet, i2c_header) = self.decode(packet, false)?;

        // Pass to MCTP stack
        let m = mctp.receive(mctp_packet)?;

        // Return a (message, i2c_header) tuple on completion
        Ok(m.map(|msg| (msg, i2c_header)))
    }

    /// `out` must be sized to hold 8+mctp_mtu, to allow for MCTP and I2C headers
    ///
    /// TODO: optionally add PEC.
    pub fn send<'f>(
        &self,
        i2c_dest: u8,
        payload: &[u8],
        out: &'f mut [u8],
        fragmenter: &mut Fragmenter,
    ) -> SendOutput<'f> {
        if out.len() < MCTP_I2C_HEADER {
            return SendOutput::failure(Error::InvalidInput, fragmenter);
        }

        let (i2chead, packet) = out.split_at_mut(MCTP_I2C_HEADER);

        // Get a packet from the fragmenter
        let r = fragmenter.fragment(payload, packet);
        let packet = match r {
            SendOutput::Packet(packet) => packet,
            // Just return on Complete or Error
            SendOutput::Complete { .. } | SendOutput::Error { .. } => {
                return r.unborrowed().unwrap()
            }
        };

        debug_assert!(packet.len() <= MCTP_I2C_MAXMTU);
        // Write the i2c header and return the whole packet
        let header = MctpI2cHeader {
            source: self.own_addr,
            dest: i2c_dest,
            byte_count: packet.len() + 1,
        };

        match header.encode() {
            Ok(h) => i2chead.copy_from_slice(&h),
            Err(e) => return SendOutput::failure(e, fragmenter),
        }

        let out_len = MCTP_I2C_HEADER + packet.len();
        let out = &mut out[..out_len];
        SendOutput::Packet(out)
    }

    pub fn encode<'f>(
        &self,
        i2c_dest: u8,
        inp: &[u8],
        out: &'f mut [u8],
        pec: bool,
    ) -> Result<&'f mut [u8]> {
        let pec_extra = pec as usize;
        let out_len = MCTP_I2C_HEADER + inp.len() + pec_extra;
        if out.len() < out_len {
            return Err(Error::BadArgument);
        }
        if inp.len() > MCTP_I2C_MAXMTU {
            return Err(Error::BadArgument);
        }

        let (i2chead, packet) = out.split_at_mut(MCTP_I2C_HEADER);
        // Write the i2c header and return the whole packet
        let header = MctpI2cHeader {
            source: self.own_addr,
            dest: i2c_dest,
            // Include i2c source address byte in bytecount. No PEC.
            byte_count: inp.len() + 1,
        };
        i2chead.copy_from_slice(&header.encode()?);
        packet[..inp.len()].copy_from_slice(inp);

        if pec {
            let pec_content = &out[..MCTP_I2C_HEADER + inp.len()];
            out[MCTP_I2C_HEADER + inp.len()] = smbus_pec::pec(pec_content);
        }
        Ok(&mut out[..out_len])
    }
}

/// A handler for I2C MCTP
///
/// One instance should exist for each I2C bus with a MCTP transport.
pub struct MctpI2cHandler {
    encap: MctpI2cEncap,

    send_message: &'static mut Vec<u8, MAX_PAYLOAD>,
    send_state: HandlerSendState,
}

impl core::fmt::Debug for MctpI2cHandler {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MctpI2cHandler")
            .field("send_state", &self.send_state)
            .finish_non_exhaustive()
    }
}

impl MctpI2cHandler {
    /// Constructs a new `MctpI2cHandler`.
    ///
    /// Note that the `heapless::Vec` for `fill_msg` is the version
    /// specified by `mctp-estack` crate. The re-export
    /// [`mctp_estack::Vec`](crate::Vec) can be used for API compatibility.
    pub fn new(
        own_addr: u8,
        send_message: &'static mut Vec<u8, MAX_PAYLOAD>,
    ) -> Self {
        Self {
            encap: MctpI2cEncap::new(own_addr),
            send_message,
            send_state: HandlerSendState::Idle,
        }
    }

    /// Handles receiving an I2C target write
    ///
    /// Expects to be passed a `packet` starting from the MCTP I2C header
    /// (first byte is destination address).
    /// `buf` should have the PEC byte removed, already checked by callers.
    ///
    /// *TODO:* provide separate software PEC check function?
    pub fn receive<'f>(
        &mut self,
        packet: &[u8],
        mctp: &'f mut Stack,
    ) -> Result<Option<(MctpMessage<'f>, MctpI2cHeader)>> {
        self.encap.receive_done_pec(packet, mctp)
    }

    /// Indicates whether data is pending to send
    pub fn is_send_ready(&self) -> bool {
        matches!(self.send_state, HandlerSendState::Sending { .. })
    }

    /// Indicates whether the send queue is idle, ready for an application to enqueue a new message
    pub fn is_send_idle(&self) -> bool {
        matches!(self.send_state, HandlerSendState::Idle)
    }

    /// Fill a buffer with a packet to send over the i2c bus.
    ///
    /// The `send_complete` closure is called when an entire message completes sending.
    /// It is called with `Some(Tag)` on success (with the tag that was sent)
    /// or `None` on failure. The cookie is the one provided to [`send_enqueue`](Self::send_enqueue).
    pub fn send_fill<'f>(&mut self, buf: &'f mut [u8]) -> SendOutput<'f> {
        let HandlerSendState::Sending {
            fragmenter,
            i2c_dest,
        } = &mut self.send_state
        else {
            debug_assert!(false, "called when not !is_send_ready()");
            return SendOutput::bare_failure(Error::Other);
        };

        let r = self
            .encap
            .send(*i2c_dest, self.send_message, buf, fragmenter);
        match r {
            SendOutput::Complete { .. } | SendOutput::Error { .. } => {
                self.send_message.clear();
                self.send_state = HandlerSendState::Idle;
            }
            SendOutput::Packet(_) => (),
        };
        r
    }

    pub fn cancel_send(&mut self) -> Option<AppCookie> {
        let mut cookie = None;
        if let HandlerSendState::Sending { fragmenter, .. } =
            &mut self.send_state
        {
            cookie = fragmenter.cookie();
        }
        self.send_message.clear();
        self.send_state = HandlerSendState::Idle;
        cookie
    }

    /// Provides a MCTP message to send.
    ///
    /// The provided closure will fill out the message buffer, returning
    /// `Some(())` on success. If the closure fails it returns `None`, and
    /// `send_enqueue()` will return `mctp::Error::InvalidInput`.
    ///
    /// `send_enqueue()` must only be called when `is_send_idle()` is true.
    /// TODO `fill_msg` will take something that isn't a Vec.
    ///
    /// Note that the `heapless::Vec` for `fill_msg` is the version
    /// specified by `mctp-estack` crate. The re-export
    /// [`mctp_estack::Vec`](crate::Vec) can be used for API compatibility.
    pub fn send_enqueue<F>(
        &mut self,
        eid: Eid,
        typ: MsgType,
        tag: Option<Tag>,
        ic: MsgIC,
        i2c_dest: u8,
        cookie: Option<AppCookie>,
        mctp: &mut Stack,
        fill_msg: F,
    ) -> Result<()>
    where
        F: FnOnce(&mut Vec<u8, MAX_PAYLOAD>) -> Option<()>,
    {
        if !self.is_send_idle() {
            return Err(Error::Other);
        }
        // debug_assert!(self.send_message.is_empty());
        if !self.send_message.is_empty() {
            trace!("sendmsg not empty");
        }

        // Retrieve data from the app. This may be a simple copy, or
        // going through a kernel to fetch the message.
        fill_msg(self.send_message).ok_or(Error::InvalidInput)?;

        let fragmenter = mctp.start_send(
            eid,
            typ,
            tag,
            true,
            ic,
            Some(MCTP_I2C_MAXMTU),
            cookie,
        )?;
        self.send_state = HandlerSendState::Sending {
            fragmenter,
            i2c_dest,
        };
        Ok(())
    }
}

#[derive(Debug)]
enum HandlerSendState {
    Idle,
    Sending {
        fragmenter: Fragmenter,
        i2c_dest: u8,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn i2c_codec_roundtrip() {
        let codec = MctpI2cEncap::new(0x0A);
        const PACKET: &[u8] =
            &[0x01, 0x00, 0x09, 0xc8, 0x00, 0x8a, 0x01, 0x00, 0x0a];

        let mut buf = [0; 128];
        let i2c_packet = codec.encode(0x0B, PACKET, &mut buf, false).unwrap();

        assert_eq!(&i2c_packet[..4], [0x16, 0x0f, 0x0a, 0x15]);

        let codec = MctpI2cEncap::new(0x0B);
        let (decoded_packet, header) = codec.decode(i2c_packet, false).unwrap();
        assert_eq!(decoded_packet, PACKET);
        assert_eq!(header.source, 0x0a);
        assert_eq!(header.dest, 0x0b);
    }

    #[test]
    fn test_partial_packet_decode() {
        let codec = MctpI2cEncap::new(0x0A);

        // Test that empty packets are handled correctly
        let res = codec.decode(&[], false);
        assert!(res.is_err());
        let res = codec.decode(&[], true);
        assert!(res.is_err());
        // Test that packets with only partial header are handled correctly
        let res = codec.decode(&[0x16, 0x0f], false);
        assert!(res.is_err());
        let res = codec.decode(&[0x16, 0x0f], true);
        assert!(res.is_err());
    }

    #[test]
    fn test_decode_byte_count_mismatch() {
        let codec = MctpI2cEncap::new(0x0A);

        // Try to decode a packet with a `byte count` of 0x0a followed by only 3 bytes
        let res = codec.decode(&[0x16, 0x0f, 0x0a, 0x15, 0x01, 0x02], false);
        assert!(res.is_err_and(|e| matches!(e, Error::InvalidInput)));
    }
}
