// SPDX-License-Identifier: MIT OR Apache-2.0
/*
 * Copyright (c) 2024 Code Construct
 */

//! Packet Fragmentation

#[allow(unused)]
use crate::fmt::{debug, error, info, trace, warn};

use mctp::{Eid, Error, MsgIC, MsgType, Result, Tag};

use crate::{util::VectorReader, AppCookie, MctpHeader};

/// Fragments a MCTP message.
///
/// This is constructed from [`Stack::start_send()`](crate::Stack::start_send)
#[derive(Debug)]
pub struct Fragmenter {
    header: MctpHeader,
    typ: MsgType,
    ic: MsgIC,
    mtu: usize,

    cookie: Option<AppCookie>,

    // A reader to read from the payload vector
    reader: VectorReader,
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
        if mtu < mctp::MCTP_MIN_MTU {
            debug!("mtu too small");
            return Err(Error::BadArgument);
        }

        let header = MctpHeader {
            dest,
            src,
            seq: initial_seq,
            som: true,
            eom: false,
            tag,
        };

        Ok(Self {
            reader: VectorReader::new(),
            header,
            typ,
            mtu,
            cookie,
            ic,
        })
    }

    pub fn tag(&self) -> Tag {
        self.header.tag
    }

    pub fn dest(&self) -> Eid {
        self.header.dest
    }

    pub fn cookie(&self) -> Option<AppCookie> {
        self.cookie
    }

    pub fn is_done(&self) -> bool {
        self.header.eom
    }

    /// Returns fragments for the MCTP payload
    ///
    /// The same input message `payload` should be passed to each `fragment()` call.
    /// In `SendOutput::Packet(buf)`, `out` is borrowed as the returned fragment, filled with
    /// packet contents.
    ///
    /// Calls to `fragment_vectored()` and `fragment()` should not be mixed.
    /// (If you do, the vector has to hold exactly one buffer that is
    /// equal to the one passed to `fragment()`.)
    ///
    /// `out` must be at least as large as the specified `mtu`.
    pub fn fragment<'f>(
        &mut self,
        payload: &[u8],
        out: &'f mut [u8],
    ) -> SendOutput<'f> {
        self.fragment_vectored(&[payload], out)
    }

    /// Returns fragments for the MCTP payload
    ///
    /// The same input message `payload` should be passed to each `fragment_vectored()` call.
    /// In `SendOutput::Packet(buf)`, `out` is borrowed as the returned fragment, filled with
    /// packet contents.
    ///
    /// Calls to `fragment_vectored()` and `fragment()` should not be mixed.
    /// (If you do, the vector has to hold exactly one buffer that is
    /// equal to the one passed to `fragment()`.)
    ///
    /// `out` must be at least as large as the specified `mtu`.
    pub fn fragment_vectored<'f>(
        &mut self,
        payload: &[&[u8]],
        out: &'f mut [u8],
    ) -> SendOutput<'f> {
        if self.header.eom {
            return SendOutput::success(self);
        }

        if self.reader.is_exhausted(payload).is_err() {
            // Caller is passing varying payload buffers
            debug!("varying payload");
            return SendOutput::failure(Error::BadArgument, self);
        }

        // Require at least MTU buffer size, to ensure that all non-end
        // fragments are the same size per the spec.
        if out.len() < self.mtu {
            debug!("small out buffer");
            return SendOutput::failure(Error::BadArgument, self);
        }

        // Reserve header space, the remaining buffer keeps being
        // updated in `rest`
        let max_total = out.len().min(self.mtu);
        let (h, mut rest) = out[..max_total].split_at_mut(MctpHeader::LEN);

        // Append type byte
        if self.header.som {
            rest[0] = mctp::encode_type_ic(self.typ, self.ic);
            rest = &mut rest[1..];
        }

        let Ok(n) = self.reader.read(payload, &mut rest) else {
            return SendOutput::failure(Error::BadArgument, self);
        };
        let rest = &rest[n..];

        // Add the header
        if self.reader.is_exhausted(payload).unwrap() {
            self.header.eom = true;
        }
        // OK unwrap: seq and tag are valid.
        h.copy_from_slice(&self.header.encode().unwrap());

        self.header.som = false;
        self.header.seq = (self.header.seq + 1) & mctp::MCTP_SEQ_MASK;

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
            tag: f.header.tag,
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
