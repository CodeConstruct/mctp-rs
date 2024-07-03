#[allow(unused)]
use log::{debug, error, info, trace, warn};

use crate::{
    AppCookie, Fragmenter, MctpMessage, ReceiveHandle, Stack,
};
use mctp::{Eid, Error, MsgType, Result, Tag};

use heapless::Vec;

pub const MCTP_I2C_COMMAND_CODE: u8 = 0x0f;

const MCTP_I2C_HEADER: usize = 4;
// bytecount is limited to u8, includes MCTP payload + 1 byte i2c source
const MCTP_I2C_MAXMTU: usize = u8::MAX as usize - 1;

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
#[derive(Debug)]
pub struct MctpI2cEncap {
    own_addr: u8,
}

impl MctpI2cEncap {
    pub fn new(own_addr: u8) -> Self {
        Self { own_addr }
    }

    /// Handles a MCTP fragment with the PEC already validated
    ///
    /// `packet` should omit the PEC byte.
    /// Returns the MCTP message and the i2c source address.
    pub fn receive_done_pec<'f>(
        &mut self,
        packet: &[u8],
        mctp: &'f mut Stack,
    ) -> Result<Option<(MctpMessage<'f>, u8, ReceiveHandle)>> {
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

        // Pass to MCTP stack
        let m = mctp.receive(packet)?;

        // Return a (message, i2c_source) tuple on completion
        Ok(m.map(|(msg, handle)| (msg, header.source_slave_addr(), handle)))
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
    ) -> Result<Option<&'f mut [u8]>> {
        if out.len() < MCTP_I2C_HEADER {
            return Err(Error::InvalidInput);
        }

        let (i2chead, packet) = out.split_at_mut(MCTP_I2C_HEADER);

        let packet = fragmenter.fragment(payload, packet)?;
        let Some(packet) = packet else {
            return Ok(None);
        };

        let mut header = MctpI2cHeader::new();
        header.set_dest_slave_addr(i2c_dest);
        header.set_source_slave_addr(self.own_addr);
        header.set_command_code(MCTP_I2C_COMMAND_CODE);
        debug_assert!(packet.len() <= MCTP_I2C_MAXMTU);
        header.set_byte_count((packet.len() + 1) as u8);

        i2chead.copy_from_slice(&header.0);

        let out_len = MCTP_I2C_HEADER + packet.len();
        let out = &mut out[..out_len];
        Ok(Some(out))
    }
}

/// A hardware abstracted handler for I2C MCTP
///
/// For a single MCTP stack on a single i2c bus.
pub struct MctpI2cHandler {
    /// I2C bus identifier. TODO: This may be better extended to usize (or a newtype)
    port: u8,

    encap: MctpI2cEncap,

    // TODO: replace with a &[u8] or similar so that we can avoid
    // the const SENDBUF.
    send_message: &'static mut Vec<u8, SENDBUF>,
    send_state: HandlerSendState,
}

impl core::fmt::Debug for MctpI2cHandler {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MctpI2cHandler")
            .field("port", &self.port)
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
        port: u8,
        own_addr: u8,
        send_message: &'static mut Vec<u8, SENDBUF>,
    ) -> Self {
        Self {
            port,
            encap: MctpI2cEncap::new(own_addr),
            send_message,
            send_state: HandlerSendState::Idle,
        }
    }

    pub fn port(&self) -> u8 {
        self.port
    }

    /// Handles receiving an I2C target write
    ///
    /// Expects to be passed a `packet` starting from the MCTP I2C header
    /// (first byte is destination address).
    /// `buf` should have the PEC byte removed, already checked by callers.
    ///
    /// *TODO:* provide separate software PEC check function?
    pub fn receive_write<'f>(
        &mut self,
        packet: &[u8],
        mctp: &'f mut Stack,
    ) -> Result<Option<(MctpMessage<'f>, u8, ReceiveHandle)>> {
        self.encap.receive_done_pec(packet, mctp)
    }

    /// Indicates whether data is ready to send over i2c
    pub fn send_ready(&self) -> bool {
        matches!(self.send_state, HandlerSendState::Sending { .. })
    }

    /// Fill a buffer with a packet to send over the i2c bus.
    ///
    /// The `send_complete` closure is called when a message completes sending.
    /// It is called with `Some(Tag)` on success (with the tag that was sent)
    /// or `None` on failure. The cookie is the one provided to [`send_enqueue`](Self::send_enqueue).
    pub fn send_fill<F>(
        &mut self,
        buf: &mut [u8],
        send_complete: F,
    ) -> Result<usize>
    where
        F: FnOnce(Option<Tag>, Option<AppCookie>),
    {
        let HandlerSendState::Sending {
            fragmenter,
            i2c_dest,
        } = &mut self.send_state
        else {
            return Err(Error::Other);
        };

        let r = self
            .encap
            .send(*i2c_dest, self.send_message, buf, fragmenter);
        match r {
            Ok(Some(b)) => Ok(b.len()),
            Ok(None) => {
                // Finished
                send_complete(Some(fragmenter.tag()), fragmenter.cookie());
                self.send_message.clear();
                self.send_state = HandlerSendState::Idle;
                Ok(0)
            }
            Err(e) => {
                debug!("Error fragmenting {e:?}");
                send_complete(None, fragmenter.cookie());
                self.send_state = HandlerSendState::Idle;
                self.send_message.clear();
                Err(e)
            }
        }
    }

    /// Indicates whether the send queue is idle, ready for an application to enqueue a new message
    pub fn send_idle(&self) -> bool {
        matches!(self.send_state, HandlerSendState::Idle)
    }

    /// Provides a MCTP message to send.
    ///
    /// The provided closure will fill out the message buffer, returning
    /// `Some(())` on success. If the closure fails it returns `None`, and
    /// `send_enqueue()` will return `mctp::Error::InvalidInput`.
    ///
    /// `send_enqueue()` must only be called when `send_idle()` is true.
    /// TODO `fill_msg` will take something that isn't a Vec.
    ///
    /// Note that the `heapless::Vec` for `fill_msg` is the version
    /// specified by `mctp-estack` crate. The re-export
    /// [`mctp_estack::Vec`](crate::Vec) can be used for API compatibility.
    pub fn send_enqueue<F>(
        &mut self,
        eid: Eid,
        typ: MsgType,
        tag: Tag,
        i2c_dest: u8,
        cookie: Option<AppCookie>,
        mctp: &mut Stack,
        fill_msg: F,
    ) -> Result<()>
    where
        F: FnOnce(&mut Vec<u8, SENDBUF>) -> Option<()>,
    {
        if !self.send_idle() {
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
            mctp.start_send(eid, typ, tag, Some(MCTP_I2C_MAXMTU), cookie)?;
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
