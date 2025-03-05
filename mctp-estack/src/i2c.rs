// SPDX-License-Identifier: MIT OR Apache-2.0
/*
 * Copyright (c) 2024 Code Construct
 */

//! MCTP over I2C transport binding

#[allow(unused)]
use crate::fmt::{debug, error, info, trace, warn};

use crate::{
    AppCookie, Fragmenter, MctpMessage, ReceiveHandle, SendOutput, Stack,
};
use mctp::{Eid, Error, MsgType, Result, Tag};

use heapless::Vec;

pub const MCTP_I2C_COMMAND_CODE: u8 = 0x0f;

const MCTP_I2C_HEADER: usize = 4;
// bytecount is limited to u8, includes MCTP payload + 1 byte i2c source
pub const MCTP_I2C_MAXMTU: usize = u8::MAX as usize - 1;

/// Size of fixed transmit buffer. This is the maximum size of a MCTP message.
///
/// *TODO:* This will be replaced with a dynamically sized `send_message` buffer
/// passed in.
///
/// Requires finding a replacement for `Vec` in `fill_msg` for `send_enqueue()`.
/// Maybe heapless::VecView once it's in a release.
pub const SENDBUF: usize = 1024;

type MctpI2cHeader =
    libmctp::smbus_proto::MCTPSMBusHeader<[u8; MCTP_I2C_HEADER]>;

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

    pub fn decode<'f>(&self, mut packet: &'f [u8], pec: bool)
    -> Result<(&'f [u8], u8)> {
        if pec {
            // Remove the pec byte, check it.
            if packet.is_empty() {
                return Err(Error::InvalidInput);
            }
            let packet_pec;
            (packet_pec, packet) = packet.split_last().unwrap();
            let calc_pec = smbus_pec::pec(packet);
            if calc_pec != *packet_pec {
                trace!("Incorrect PEC");
                return Err(Error::InvalidInput);
            }
        }

        if packet.len() < MCTP_I2C_HEADER {
            return Err(Error::InvalidInput);
        }

        let (i2c, packet) = packet.split_at(MCTP_I2C_HEADER);
        // OK unwrap, size matches
        let header = MctpI2cHeader::new_from_buf(i2c.try_into().unwrap());
        // +1 for i2c source address field
        if header.byte_count() as usize != packet.len() + 1 {
            return Err(Error::InvalidInput);
        }

        if header.command_code() != MCTP_I2C_COMMAND_CODE {
            return Err(Error::InvalidInput);
        }
        Ok((packet, header.source_slave_addr()))
    }

    /// Handles a MCTP fragment with the PEC already validated
    ///
    /// `packet` should omit the PEC byte.
    /// Returns the MCTP message and the i2c source address.
    pub fn receive_done_pec<'f>(
        &self,
        packet: &[u8],
        mctp: &'f mut Stack,
    ) -> Result<Option<(MctpMessage<'f>, u8, ReceiveHandle)>> {

        let (mctp_packet, i2c_src) = self.decode(packet, false)?;

        // Pass to MCTP stack
        let m = mctp.receive(mctp_packet)?;

        // Return a (message, i2c_source) tuple on completion
        Ok(m.map(|(msg, handle)| (msg, i2c_src, handle)))
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
            | SendOutput::Complete { .. }
            | SendOutput::Error { .. }
            => return r.unborrowed().unwrap(),
        };

        // Write the i2c header and return the whole packet
        let mut header = MctpI2cHeader::new();
        header.set_dest_slave_addr(i2c_dest);
        header.set_source_slave_addr(self.own_addr);
        header.set_source_read_write(1);
        header.set_command_code(MCTP_I2C_COMMAND_CODE);
        debug_assert!(packet.len() <= MCTP_I2C_MAXMTU);
        header.set_byte_count((packet.len() + 1) as u8);

        i2chead.copy_from_slice(&header.0);

        let out_len = MCTP_I2C_HEADER + packet.len();
        let out = &mut out[..out_len];
        SendOutput::Packet(out)
    }

    pub fn encode<'f>(&self, i2c_dest: u8, inp: &[u8], out: &'f mut [u8], pec: bool)
        -> Result<&'f mut [u8]> {

        let pec_extra = pec as usize;
        let out_len = MCTP_I2C_HEADER + inp.len() + pec_extra;
        if out.len() < out_len {
            return Err(Error::BadArgument);
        }
        if inp.len() > MCTP_I2C_MAXMTU {
            return Err(Error::BadArgument);
        }

        let (i2chead, packet) = out.split_at_mut(MCTP_I2C_HEADER);
        let mut header = MctpI2cHeader::new();
        header.set_dest_slave_addr(i2c_dest);
        header.set_source_slave_addr(self.own_addr);
        header.set_source_read_write(1);
        header.set_command_code(MCTP_I2C_COMMAND_CODE);
        // Include i2c source address byte in bytecount. No PEC.
        header.set_byte_count((1 + inp.len()) as u8);
        i2chead.copy_from_slice(&header.0);
        packet[..inp.len()].copy_from_slice(inp);

        if pec {
            let pec_content = &out[..MCTP_I2C_HEADER+inp.len()];
            out[MCTP_I2C_HEADER+inp.len()] = smbus_pec::pec(pec_content);
        }
        Ok(&mut out[..out_len])
    }
}

/// A handler for I2C MCTP
///
/// One instance should exist for each I2C bus with a MCTP transport.
pub struct MctpI2cHandler {
    encap: MctpI2cEncap,

    // TODO: replace with a &[u8] or similar so that we can avoid
    // the const SENDBUF.
    send_message: &'static mut Vec<u8, SENDBUF>,
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
        send_message: &'static mut Vec<u8, SENDBUF>,
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
    ) -> Result<Option<(MctpMessage<'f>, u8, ReceiveHandle)>> {
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
        ic: bool,
        i2c_dest: u8,
        cookie: Option<AppCookie>,
        mctp: &mut Stack,
        fill_msg: F,
    ) -> Result<()>
    where
        F: FnOnce(&mut Vec<u8, SENDBUF>) -> Option<()>,
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

        let fragmenter =
            mctp.start_send(eid, typ, tag, true, ic, Some(MCTP_I2C_MAXMTU), cookie)?;
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
