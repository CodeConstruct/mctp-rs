#[allow(unused)]
use log::{debug, error, info, trace, warn};

use std::time::Instant;
use core::time::Duration;

// use embedded_io::Write;
use embedded_io_async::{Read, Write};
use smol::future::FutureExt;
use smol::Timer;

use mctp::{Error, Result, Eid, MsgType, Tag, TagValue};
use mctp_estack::{
    Stack,
    SendOutput,
    ReceiveHandle,
    MctpMessage,
    serial::MctpSerialHandler,
};

struct Inner<S: Read+Write> {
    mctp: Stack,
    mctpserial: MctpSerialHandler,
    serial: S,

    start_time: Instant,
}

impl<S: Read+Write> Inner<S> {
    fn new(own_eid: Eid, serial: S) -> Self {
        let start_time = Instant::now();
        let todo_mtu = 64;
        let mctp = Stack::new(own_eid, todo_mtu, 0);
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
        integrity_check: bool,
        bufs: &[&[u8]],
    ) -> Result<Tag> {
        let _ = self.mctp.update(self.now());
        let cookie = None;
        let r = self.mctpserial.send_fill(eid, typ,
            tag, integrity_check, cookie,
            &mut self.serial, &mut self.mctp,
            |v| {
                for b in bufs {
                    v.extend_from_slice(b).ok()?
                }
                trace!("v len {}", v.len());
                Some(())
            });

        let r = smol::block_on(r);

        match r {
            SendOutput::Packet(_) => unreachable!(),
            SendOutput::Complete { tag, .. } => Ok(tag),
            SendOutput::Error { err, .. } => Err(err),
        }
    }

    /// Return a whole MCTP message reassembled
    ///
    /// Deadline is milliseconds, relative to `self.now()`
    fn receive(&mut self, deadline: Option<u64>) -> Result<(MctpMessage, ReceiveHandle)> {
        let now = self.now();

        let deadline = if let Some(d) = deadline {
            // deadline must be >= now
            let t = d.checked_sub(now).ok_or(mctp::Error::BadArgument)?;
            // smol::Timer is relative to Instant
            Some(Instant::now() + Duration::from_millis(t))
        } else {
            None
        };

        loop {
            let _ = self.mctp.update(self.now());

            let r = self.mctpserial.receive_async(&mut self.serial, &mut self.mctp)
                .or(async {
                    if let Some(deadline) = deadline {
                        Timer::at(deadline)
                    } else {
                        Timer::never()
                    }.await;
                    Err(mctp::Error::TimedOut)
                });

            let r = smol::block_on(r)?;

            if let Some((_msg, handle)) = r {
                // Tricks here for loops+lifetimes.
                // Could return (msg, handle) directly once Rust polonius merged.
                let msg = self.mctp.fetch_message(&handle).unwrap();
                return Ok((msg, handle))
            }
        }
    }
}

pub struct MctpSerialReq<S: Read+Write> {
    inner: Inner<S>,
    eid: Eid,
    sent_tv: Option<TagValue>,
    timeout: Option<Duration>,
}

impl<S: Read+Write> MctpSerialReq<S> {
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

impl<S: Read+Write> mctp::ReqChannel for MctpSerialReq<S> {
    fn send_vectored(
        &mut self,
        typ: MsgType,
        integrity_check: bool,
        bufs: &[&[u8]],
    ) -> Result<()> {
        let req_tag = None;
        let tag = self.inner.send_vectored(self.eid, typ, req_tag, integrity_check, bufs)?;
        self.sent_tv = Some(tag.tag());
        Ok(())
    }

    fn recv<'f>(
        &mut self,
        buf: &'f mut [u8],
    ) -> Result<(&'f mut [u8], MsgType, Tag, bool)> {
        let tv = self.sent_tv.ok_or(Error::BadArgument)?;
        let match_tag = Tag::Unowned(tv);

        // timeout deadline for reading from serial
        let deadline = self.timeout.map(|t| t.as_millis() as u64+ self.inner.now());

        loop {
            let (msg, handle) = match self.inner.receive(deadline) {
                Ok(r) => r,
                Err(Error::TimedOut) => {
                    if let Err(e) = self.inner.mctp.cancel_flow(self.eid, tv) {
                        debug!("Error cancelling flow: {e:?}");
                    }
                    return Err(Error::TimedOut);
                }
                Err(e) => {
                    return Err(e);
                }
            };
            if msg.tag == match_tag && msg.source == self.eid {
                let ic = msg.ic;
                let typ = msg.typ;
                let b = buf.get_mut(..msg.payload.len()).ok_or(Error::NoSpace)?;
                b.copy_from_slice(msg.payload);
                self.inner.mctp.finished_receive(handle);
                return Ok((b, typ, match_tag, ic));
            } else {
                warn!("Dropped unexpected MCTP message {msg:?}");
                self.inner.mctp.finished_receive(handle);
            }
        }
    }

    /// Return the remote Endpoint ID
    fn remote_eid(&self) -> Eid {
        self.eid
    }
}

pub struct MctpSerialResp<'a, S: Read+Write> {
    eid: Eid,
    tv: TagValue,
    inner: &'a mut Inner<S>,
}

impl<S: Read+Write> mctp::RespChannel for MctpSerialResp<'_, S> {
    type ReqChannel = MctpSerialReq<S>;

    fn send_vectored(
        &mut self,
        typ: MsgType,
        integrity_check: bool,
        bufs: &[&[u8]],
    ) -> Result<()> {
        let tag = Some(Tag::Unowned(self.tv));
        self.inner.send_vectored(self.eid, typ, tag, integrity_check, bufs)?;
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

pub struct MctpSerialListener<S: Read+Write> {
    typ: MsgType,

    inner: Inner<S>,
}

impl<S: Read+Write> MctpSerialListener<S> {
    pub fn new(own_eid: Eid, typ: MsgType, serial: S) -> Self {
        let inner = Inner::new(own_eid, serial);
        Self {
            typ,
            inner,
        }
    }
}

impl<S: Read+Write> mctp::Listener for MctpSerialListener<S> {
    type RespChannel<'a> = MctpSerialResp<'a, S> where Self: 'a;

    fn recv<'f>(&mut self, buf: &'f mut [u8])
     -> Result<(&'f mut [u8], Self::RespChannel<'_>, Tag, bool)>
    {
        loop {
            // Receive a whole message
            let (msg, handle) = self.inner.receive(None)?;

            // Return a matching packet
            if msg.typ == self.typ && msg.tag.is_owner() {
                let tag = msg.tag;
                let ic = msg.ic;
                let b = buf.get_mut(..msg.payload.len()).ok_or(Error::NoSpace)?;
                b.copy_from_slice(msg.payload);
                let eid = msg.source;
                self.inner.mctp.finished_receive(handle);
                let resp = MctpSerialResp {
                    eid,
                    tv: tag.tag(),
                    inner: &mut self.inner,
                };
                return Ok((b, resp, tag, ic));
            } else {
                trace!("Discarding unmatched message {msg:?}");
                self.inner.mctp.finished_receive(handle);
            }
        }
    }

    fn mctp_type(&self) -> MsgType {
        self.typ
    }
}
