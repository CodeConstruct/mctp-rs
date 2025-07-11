// SPDX-License-Identifier: MIT OR Apache-2.0
/*
 * MCTP common types and traits.
 *
 * Copyright (c) 2024 Code Construct
 */

//! MCTP over USB transport binding
//!
//! This implements DSP0283 1.0.1

#![allow(unused)]

use crate::{AppCookie, MctpMessage, SendOutput, Stack, MAX_PAYLOAD};
use heapless::Vec;
use mctp::{Eid, Error, MsgIC, MsgType, Result, Tag};

#[cfg(feature = "defmt")]
#[allow(unused)]
use defmt::{debug, error, info, trace, warn};

#[cfg(feature = "log")]
#[allow(unused)]
use log::{debug, error, info, trace, warn};

const HDR_LEN: usize = 4;
const MCTP_USB_MTU_MAX: usize = u8::MAX as usize - HDR_LEN;
const TX_XFER_SIZE: usize = 512;

pub struct MctpUsbHandler {
    tx_msg: Vec<u8, MAX_PAYLOAD>,
    tx_xfer: [u8; TX_XFER_SIZE],
}

pub trait MctpUsbXfer {
    fn send_xfer(&mut self, buf: &[u8]) -> Result<()>;
}

impl MctpUsbHandler {
    pub fn new() -> Self {
        Self {
            tx_msg: Vec::new(),
            tx_xfer: [0u8; TX_XFER_SIZE],
        }
    }

    /// Returns (mctp_packet, remainder).
    ///
    /// `xfer` an input buffer, starting at a MCTP over USB header
    /// and containing at least one MCTP packet.
    /// `mctp_packet` is the portion after the MCTP over USB header.
    /// `remainder` is the remaining portion of xfer (which can be
    /// passed to a subsequent `decode()` call).
    pub fn decode(xfer: &[u8]) -> Result<(&[u8], &[u8])> {
        let (hdr, data) =
            xfer.split_at_checked(HDR_LEN).ok_or(Error::RxFailure)?;

        if hdr[0..2] != [0x1a, 0xb4] {
            debug!("mismatch: {:x} {:x}", hdr[0], hdr[1]);
            return Err(Error::RxFailure);
        }

        let Some(len) = (hdr[3] as usize).checked_sub(HDR_LEN) else {
            trace!("Mismatch mctp usb len");
            return Err(Error::RxFailure);
        };

        let Some(data) = data.split_at_checked(len) else {
            trace!("Short mctp usb packet");
            return Err(Error::RxFailure);
        };
        Ok(data)
    }

    pub fn receive<'f>(
        xfer: &[u8],
        mctp: &'f mut Stack,
    ) -> Result<Option<MctpMessage<'f>>> {
        // debug!("xfer: {xfer:02x?}");
        // TODO remainder in case of multiple MCTP per USB packet
        let (data, _rem) = Self::decode(xfer)?;
        mctp.receive(data)
    }

    pub fn send_fill<F>(
        &mut self,
        eid: Eid,
        typ: MsgType,
        tag: Option<Tag>,
        ic: MsgIC,
        cookie: Option<AppCookie>,
        xfer: &mut impl MctpUsbXfer,
        mctp: &mut Stack,
        fill_msg: F,
    ) -> SendOutput<'_>
    where
        F: FnOnce(&mut Vec<u8, MAX_PAYLOAD>) -> Option<()>,
    {
        self.tx_msg.clear();
        if fill_msg(&mut self.tx_msg).is_none() {
            return SendOutput::Error {
                err: Error::Other,
                cookie: None,
            };
        }

        let res = mctp.start_send(
            eid,
            typ,
            tag,
            true,
            ic,
            Some(MCTP_USB_MTU_MAX),
            cookie,
        );
        let mut fragmenter = match res {
            Ok(f) => f,
            Err(err) => return SendOutput::Error { err, cookie: None },
        };

        loop {
            let (mut hdr, mut data) = self.tx_xfer.split_at_mut(HDR_LEN);
            let r = fragmenter.fragment(&self.tx_msg, data);
            let len = match r {
                SendOutput::Packet(p) => p.len(),
                SendOutput::Complete { .. } | SendOutput::Error { .. } => {
                    return r.unborrowed().unwrap()
                }
            };
            if Self::header(len, hdr).is_err() {
                return SendOutput::Error {
                    err: Error::InternalError,
                    cookie: None,
                };
            }
            let slice = &self.tx_xfer[0..len + 4];
            let res = xfer.send_xfer(slice);
            if let Err(_e) = res {
                trace!("USB transfer error");
                return SendOutput::Error {
                    err: Error::TxFailure,
                    cookie: None,
                };
            }
        }
    }

    /// Creates a MCTP over USB Header.
    ///
    /// `mctplen` is the length of the remaining MCTP packet
    /// after the header.
    /// `hdr` must be a 4 byte slice.
    pub fn header(mctp_len: usize, hdr: &mut [u8]) -> Result<()> {
        if hdr.len() != 4 {
            return Err(Error::BadArgument);
        }

        let usb_len: u8 = mctp_len
            .checked_add(4)
            .ok_or(Error::BadArgument)?
            .try_into()
            .map_err(|_| Error::BadArgument)?;

        hdr[0] = 0x1a;
        hdr[1] = 0xb4;
        hdr[2] = 0;
        hdr[3] = usb_len;
        Ok(())
    }
}

impl Default for MctpUsbHandler {
    fn default() -> Self {
        Self::new()
    }
}
