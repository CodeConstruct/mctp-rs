// SPDX-License-Identifier: MIT OR Apache-2.0
/*
 * Copyright (c) 2024 Code Construct
 */

#[allow(unused)]
use log::{debug, error, info, trace, warn};

use core::time::Duration;
use std::time::Instant;

use embedded_io_async::{Read, Write};
use smol::future::FutureExt;
use smol::Timer;

use mctp::{Eid, Error, MsgIC, MsgType, Result, Tag, TagValue};
use mctp_estack::{
    fragment::SendOutput, serial::MctpSerialHandler, AppCookie, MctpMessage,
    Stack,
};

struct Inner<S: Read + Write> {
    mctp: Stack,
    mctpserial: MctpSerialHandler,
    serial: S,

    start_time: Instant,
}

impl<S: Read + Write> Inner<S> {
    fn new(own_eid: Eid, serial: S) -> Self {
        let start_time = Instant::now();
        let mctp = Stack::new(own_eid, 0);
        let mctpserial = MctpSerialHandler::new();
        Self {
            mctp,
            mctpserial,
            serial,
            start_time,
        }
    }

    fn now(&self) -> u64 {
        self.start_time.elapsed().as_millis() as u64
    }

    fn send_vectored(
        &mut self,
        eid: Eid,
        typ: MsgType,
        tag: Option<Tag>,
        integrity_check: MsgIC,
        bufs: &[&[u8]],
    ) -> Result<Tag> {
        let _ = self.mctp.update(self.now());
        let cookie = None;
        let mut fragmenter = self.mctp.start_send(
            eid,
            typ,
            tag,
            true,
            integrity_check,
            Some(mctp_estack::serial::MTU_MAX),
            cookie,
        )?;

        let mut tx_msg = Vec::new();
        for buf in bufs {
            tx_msg.extend_from_slice(buf);
        }

        loop {
            let mut tx_pkt = [0u8; mctp_estack::serial::MTU_MAX];
            let r = fragmenter.fragment(&tx_msg, &mut tx_pkt);
            match r {
                SendOutput::Packet(p) => {
                    let fut = self.mctpserial.send_async(p, &mut self.serial);
                    smol::block_on(fut)?;
                }
                SendOutput::Complete { tag, .. } => break Ok(tag),
                SendOutput::Error { err, .. } => break Err(err),
            };
        }
    }

    /// Return a whole MCTP message reassembled
    ///
    /// Deadline is milliseconds, relative to `self.now()`
    fn receive(&mut self, deadline: Option<u64>) -> Result<MctpMessage<'_>> {
        let now = self.now();

        let deadline = if let Some(d) = deadline {
            // deadline must be >= now
            let t = d.checked_sub(now).ok_or(mctp::Error::BadArgument)?;
            // smol::Timer is relative to Instant
            Some(Instant::now() + Duration::from_millis(t))
        } else {
            None
        };

        const LIFETIME_COOKIE: AppCookie = AppCookie(0x123123);

        loop {
            let _ = self.mctp.update(self.now());

            let r = self.mctpserial.recv_async(&mut self.serial).or(async {
                if let Some(deadline) = deadline {
                    Timer::at(deadline)
                } else {
                    Timer::never()
                }
                .await;
                Err(mctp::Error::TimedOut)
            });

            let pkt = smol::block_on(r)?;

            let r = self.mctp.receive(pkt)?;

            if let Some(mut msg) = r {
                // Tricks here for loops+lifetimes.
                // Could return `msg` directly once Rust polonius merged.
                assert!(
                    msg.cookie().is_none(),
                    "standalone isn't setting cookies on send"
                );
                msg.set_cookie(Some(LIFETIME_COOKIE));
                msg.retain();
                break;
            }
        }

        // loop only exits after receiving a message
        Ok(self
            .mctp
            .get_deferred_bycookie(&[LIFETIME_COOKIE])
            .expect("cookie was just set"))
    }
}

pub struct MctpSerialReq<S: Read + Write> {
    inner: Inner<S>,
    eid: Eid,
    sent_tv: Option<TagValue>,
    timeout: Option<Duration>,
}

impl<S: Read + Write> MctpSerialReq<S> {
    pub fn new(own_eid: Eid, remote_eid: Eid, serial: S) -> Self {
        let inner = Inner::new(own_eid, serial);
        Self {
            inner,
            eid: remote_eid,
            sent_tv: None,
            timeout: None,
        }
    }

    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = Some(timeout);
    }

    pub fn clear_timeout(&mut self) {
        self.timeout = None;
    }
}

impl<S: Read + Write> mctp::ReqChannel for MctpSerialReq<S> {
    fn send_vectored(
        &mut self,
        typ: MsgType,
        integrity_check: MsgIC,
        bufs: &[&[u8]],
    ) -> Result<()> {
        let req_tag = None;
        let tag = self.inner.send_vectored(
            self.eid,
            typ,
            req_tag,
            integrity_check,
            bufs,
        )?;
        self.sent_tv = Some(tag.tag());
        Ok(())
    }

    fn recv<'f>(
        &mut self,
        buf: &'f mut [u8],
    ) -> Result<(MsgType, MsgIC, &'f mut [u8])> {
        let tv = self.sent_tv.ok_or(Error::BadArgument)?;
        let match_tag = Tag::Unowned(tv);

        // timeout deadline for reading from serial
        let deadline = self
            .timeout
            .map(|t| t.as_millis() as u64 + self.inner.now());

        loop {
            let msg = match self.inner.receive(deadline) {
                Ok(r) => r,
                Err(Error::TimedOut) => {
                    // TODO
                    // if let Err(e) = self.inner.mctp.cancel_flow(self.eid, tv) {
                    //     debug!("Error cancelling flow: {e:?}");
                    // }
                    return Err(Error::TimedOut);
                }
                Err(e) => {
                    return Err(e);
                }
            };
            if msg.tag == match_tag && msg.source == self.eid {
                let ic = msg.ic;
                let typ = msg.typ;
                let b =
                    buf.get_mut(..msg.payload.len()).ok_or(Error::NoSpace)?;
                b.copy_from_slice(msg.payload);
                return Ok((typ, ic, b));
            } else {
                warn!("Dropped unexpected MCTP message {msg:?}");
            }
        }
    }

    /// Return the remote Endpoint ID
    fn remote_eid(&self) -> Eid {
        self.eid
    }
}

pub struct MctpSerialResp<'a, S: Read + Write> {
    eid: Eid,
    tv: TagValue,
    inner: &'a mut Inner<S>,
    typ: MsgType,
}

impl<S: Read + Write> mctp::RespChannel for MctpSerialResp<'_, S> {
    type ReqChannel = MctpSerialReq<S>;

    fn send_vectored(
        &mut self,
        integrity_check: MsgIC,
        bufs: &[&[u8]],
    ) -> Result<()> {
        let tag = Some(Tag::Unowned(self.tv));
        self.inner.send_vectored(
            self.eid,
            self.typ,
            tag,
            integrity_check,
            bufs,
        )?;
        Ok(())
    }

    /// Return the remote Endpoint ID
    fn remote_eid(&self) -> Eid {
        self.eid
    }

    fn req_channel(&self) -> Result<Self::ReqChannel> {
        Err(Error::Unsupported)
    }
}

pub struct MctpSerialListener<S: Read + Write> {
    typ: MsgType,

    inner: Inner<S>,
}

impl<S: Read + Write> MctpSerialListener<S> {
    pub fn new(own_eid: Eid, typ: MsgType, serial: S) -> Self {
        let inner = Inner::new(own_eid, serial);
        Self { typ, inner }
    }
}

impl<S: Read + Write> mctp::Listener for MctpSerialListener<S> {
    type RespChannel<'a>
        = MctpSerialResp<'a, S>
    where
        Self: 'a;

    fn recv<'f>(
        &mut self,
        buf: &'f mut [u8],
    ) -> Result<(MsgType, MsgIC, &'f mut [u8], Self::RespChannel<'_>)> {
        loop {
            // Receive a whole message
            let msg = self.inner.receive(None)?;

            // Return a matching packet
            if msg.typ == self.typ && msg.tag.is_owner() {
                let tag = msg.tag;
                let ic = msg.ic;
                let typ = msg.typ;
                let b =
                    buf.get_mut(..msg.payload.len()).ok_or(Error::NoSpace)?;
                b.copy_from_slice(msg.payload);
                let eid = msg.source;
                drop(msg);
                let resp = MctpSerialResp {
                    eid,
                    tv: tag.tag(),
                    inner: &mut self.inner,
                    typ,
                };
                return Ok((typ, ic, b, resp));
            } else {
                trace!("Discarding unmatched message {msg:?}");
            }
        }
    }
}
