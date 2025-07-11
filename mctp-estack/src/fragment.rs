// SPDX-License-Identifier: MIT OR Apache-2.0
/*
 * Copyright (c) 2024 Code Construct
 */

//! Packet Fragmentation

#[allow(unused)]
use crate::fmt::{debug, error, info, trace, warn};

use mctp::{Eid, Error, MsgIC, MsgType, Result, Tag, MCTP_HEADER_VERSION_1};

use crate::{AppCookie, Header, HEADER_LEN, MAX_MTU};

/// Fragments a MCTP message.
///
/// This is constructed from [`Stack::start_send()`](crate::Stack::start_send)
#[derive(Debug)]
pub struct Fragmenter {
    src: Eid,
    dest: Eid,
    typ: MsgType,
    tag: Tag,
    ic: MsgIC,
    seq: u8,
    mtu: usize,

    first: bool,
    done: bool,
    cookie: Option<AppCookie>,

    // A count of how many bytes have already been sent.
    payload_used: usize,
}

impl Fragmenter {
    pub(crate) fn new(
        typ: MsgType,
        src: Eid,
        dest: Eid,
        tag: Tag,
        mtu: usize,
        cookie: Option<AppCookie>,
        ic: MsgIC,
        initial_seq: u8,
    ) -> Result<Self> {
        if tag.tag().0 > mctp::MCTP_TAG_MAX {
            return Err(Error::InvalidInput);
        }
        debug_assert!(typ.0 & 0x80 == 0, "IC bit's set in typ");
        debug_assert!(initial_seq & !mctp::MCTP_SEQ_MASK == 0);
        if mtu < HEADER_LEN + 1 {
            debug!("mtu too small");
            return Err(Error::BadArgument);
        }
        if mtu > MAX_MTU {
            debug!("mtu too large");
            return Err(Error::BadArgument);
        }
        // TODO other validity checks

        Ok(Self {
            payload_used: 0,
            src,
            dest,
            typ,
            mtu,
            first: true,
            done: false,
            seq: initial_seq,
            tag,
            cookie,
            ic,
        })
    }

    pub fn tag(&self) -> Tag {
        self.tag
    }

    pub fn dest(&self) -> Eid {
        self.dest
    }

    pub fn cookie(&self) -> Option<AppCookie> {
        self.cookie
    }

    pub fn is_done(&self) -> bool {
        self.done
    }

    fn header(&self) -> Header {
        let mut header = Header::new(MCTP_HEADER_VERSION_1);
        header.set_dest_endpoint_id(self.dest.0);
        header.set_source_endpoint_id(self.src.0);
        header.set_pkt_seq(self.seq);
        if self.first {
            header.set_som(self.first as u8);
        }
        header.set_msg_tag(self.tag.tag().0);
        header.set_to(self.tag.is_owner() as u8);
        header
    }

    /// Returns fragments for the MCTP payload
    ///
    /// The same input message `payload` should be passed to each `fragment()` call.
    /// In `SendOutput::Packet(buf)`, `out` is borrowed as the returned fragment, filled with packet contents.
    pub fn fragment<'f>(
        &mut self,
        payload: &[u8],
        out: &'f mut [u8],
    ) -> SendOutput<'f> {
        if self.done {
            return SendOutput::success(self);
        }

        // first fragment needs type byte
        let min = HEADER_LEN + self.first as usize;

        if out.len() < min {
            return SendOutput::failure(Error::NoSpace, self);
        }

        // Reserve header space, the remaining buffer keeps being
        // updated in `rest`
        let max_total = out.len().min(self.mtu);
        // let out = &mut out[..max_total];
        let (h, mut rest) = out[..max_total].split_at_mut(HEADER_LEN);

        // Append type byte
        if self.first {
            rest[0] = mctp::encode_type_ic(self.typ, self.ic);
            rest = &mut rest[1..];
        }

        if payload.len() < self.payload_used {
            // Caller is passing varying payload buffers
            return SendOutput::failure(Error::BadArgument, self);
        }

        // Copy as much as is available in input or output
        let p = &payload[self.payload_used..];
        let l = p.len().min(rest.len());
        let (d, rest) = rest.split_at_mut(l);
        self.payload_used += l;
        d.copy_from_slice(&p[..l]);

        // Add the header
        let mut header = self.header();
        if self.payload_used == payload.len() {
            header.set_eom(1);
            self.done = true;
        }
        h.copy_from_slice(&header.0);

        self.first = false;
        self.seq = (self.seq + 1) & mctp::MCTP_SEQ_MASK;

        let used = max_total - rest.len();
        SendOutput::Packet(&mut out[..used])
    }
}

pub enum SendOutput<'p> {
    Packet(&'p mut [u8]),
    Complete {
        tag: Tag,
        cookie: Option<AppCookie>,
    },
    Error {
        err: Error,
        cookie: Option<AppCookie>,
    },
}

impl SendOutput<'_> {
    /// Returns an unborrowed copy for Complete or Error variants.
    ///
    /// Panics if called with a Packet variant (borrowed).
    /// For avoiding borrow problems. Can be removed once Rust polonius merges.
    pub(crate) fn unborrowed<'x>(self) -> Option<SendOutput<'x>> {
        match self {
            Self::Packet(_) => unreachable!(),
            Self::Complete { tag, cookie } => {
                Some(SendOutput::Complete { tag, cookie })
            }
            Self::Error { err, cookie } => {
                Some(SendOutput::Error { err, cookie })
            }
        }
    }

    pub(crate) fn success(f: &Fragmenter) -> Self {
        Self::Complete {
            tag: f.tag,
            cookie: f.cookie,
        }
    }

    pub(crate) fn failure(err: Error, f: &Fragmenter) -> Self {
        Self::Error {
            err,
            cookie: f.cookie,
        }
    }

    /// Just an error, no fragmenter required
    pub(crate) fn bare_failure(err: Error) -> Self {
        Self::Error { err, cookie: None }
    }
}
