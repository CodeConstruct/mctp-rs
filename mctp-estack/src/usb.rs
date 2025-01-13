
#![allow(unused)]

use heapless::Vec;
use crate::{
    AppCookie, MctpMessage, ReceiveHandle, SendOutput, Stack,
};
use mctp::{Eid, MsgType, Tag, Error, Result};
use log::{debug, trace};

const TX_MSG_SIZE: usize = 1024;
const TX_XFER_SIZE: usize = 512;
const MCTP_USB_MTU_MAX: usize = u8::max_value() as usize;

pub struct MctpUsbHandler {
    tx_msg: Vec<u8, TX_MSG_SIZE>,
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

    pub fn receive<'f>(&mut self, xfer: &[u8], mctp: &'f mut Stack)
    -> Result<Option<(MctpMessage<'f>, ReceiveHandle)>> {
        if xfer.len() < 4 {
            return Err(Error::RxFailure);
        }

        if xfer[0..2] != [0xb4, 0x1a] {
            debug!("mismatch: {:?}", &xfer[0..2]);
            return Err(Error::RxFailure);
        }

        let len = xfer[3];
        if len as usize > xfer.len() {
            return Err(Error::RxFailure);
        }

        debug!("xfer: {xfer:02x?}");
        mctp.receive(&xfer[4..])
    }

    pub fn send_fill<F>(
        &mut self,
        eid: Eid,
        typ: MsgType,
        tag: Option<Tag>,
        ic: bool,
        cookie: Option<AppCookie>,
        xfer: &mut impl MctpUsbXfer,
        mctp: &mut Stack,
        fill_msg: F,
    ) -> SendOutput
        where F: FnOnce(&mut Vec<u8, TX_MSG_SIZE>) -> Option<()>,
    {
        self.tx_msg.clear();
        if fill_msg(&mut self.tx_msg).is_none() {
            return SendOutput::Error {
                err: Error::Other,
                cookie: None,
            }
        }

        let res = mctp.start_send(
            eid,
            typ,
            tag,
            ic,
            Some(MCTP_USB_MTU_MAX),
            cookie
        );
        let mut fragmenter = match res {
            Ok(f) => f,
            Err(err) => {
                return SendOutput::Error {
                    err,
                    cookie: None,
                }
            }
        };

        loop {
            let (mut hdr, mut data) = self.tx_xfer.split_at_mut(4);
            let r = fragmenter.fragment(&self.tx_msg, data);
            let len = match r {
                SendOutput::Packet(p) => p.len(),
                _
                | SendOutput::Complete { .. }
                | SendOutput::Error { .. }
                => return r.unborrowed().unwrap(),
            };
            hdr[0] = 0xb4;
            hdr[1] = 0x1a;
            hdr[2] = 0;
            hdr[3] = len as u8;
            let slice = &self.tx_xfer[0..len+4];
            let res = xfer.send_xfer(slice);
            if let Err(e) = res {
                trace!("USB transfer error {e:?}");
                return SendOutput::Error {
                    err: Error::TxFailure,
                    cookie: None,
                }
            }
        }
    }
}
