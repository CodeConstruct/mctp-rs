// SPDX-License-Identifier: MIT OR Apache-2.0
/*
 * Copyright (c) 2024 Code Construct
 */

//! Packet Fragmentation

#[allow(unused)]
use crate::fmt::{debug, error, info, trace, warn};

use mctp::{Eid, Error, MsgIC, MsgType, Result, Tag};

use crate::{AppCookie, MctpHeader};

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
            payload_used: 0,
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
    /// `out` must be at least as large as the specified `mtu`.
    pub fn fragment<'f>(
        &mut self,
        payload: &[u8],
        out: &'f mut [u8],
    ) -> SendOutput<'f> {
        if self.header.eom {
            return SendOutput::success(self);
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

        if payload.len() < self.payload_used {
            // Caller is passing varying payload buffers
            debug!("varying payload");
            return SendOutput::failure(Error::BadArgument, self);
        }

        // Copy as much as is available in input or output
        let p = &payload[self.payload_used..];
        let l = p.len().min(rest.len());
        let (d, rest) = rest.split_at_mut(l);
        self.payload_used += l;
        d.copy_from_slice(&p[..l]);

        // Add the header
        if self.payload_used == payload.len() {
            self.header.eom = true;
        }
        // OK unwrap: seq and tag are valid.
        h.copy_from_slice(&self.header.encode().unwrap());

        self.header.som = false;
        self.header.seq = (self.header.seq + 1) & mctp::MCTP_SEQ_MASK;

        let used = max_total - rest.len();
        SendOutput::Packet(&mut out[..used])
    }

    pub fn fragment_vectored<'f>(
        &mut self,
        payload: &[&[u8]],
        out: &'f mut [u8],
    ) -> SendOutput<'f> {
        let total_payload_len =
            payload.iter().fold(0, |acc, part| acc + part.len());
        if total_payload_len < self.payload_used {
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

        let remaining_payload_len = total_payload_len - self.payload_used;
        let l = remaining_payload_len.min(rest.len());
        let (d, rest) = rest.split_at_mut(l);
        copy_vectored(payload, self.payload_used, d);
        self.payload_used += l;

        // Add the header
        if self.payload_used == total_payload_len {
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

/// Copy data from a vectored src to dest
///
/// Copies `dest.len()` bytes from payload to dest,
/// starting after `offset` bytes.
///
/// ## Panics
///
/// This function will panic when not enough bytes are available to fill dest.
/// Total size of `payload` has to be `atleast dest.len()` + `offset`.
fn copy_vectored(src: &[&[u8]], offset: usize, dest: &mut [u8]) {
    let mut i = 0;

    while i < dest.len() {
        let payload_index = i + offset;
        let next = get_sub_slice(src, payload_index);
        let remaining = dest.len() - i;
        if remaining > next.len() {
            dest[i..(i + next.len())].copy_from_slice(next);
            i += next.len();
        } else {
            dest[i..].copy_from_slice(&next[..remaining]);
            return;
        }
    }
}

/// Get a slice of `vector` indexed by `offset`
///
/// The `offset` is the absolute byte index.
/// The returned slice is the remaining sub slice starting at `offset`.
///
/// ## Panics
///
/// Will panic when offset is larger than the size of `vector`.
///
/// ## Example
/// ```ignore
/// # use mctp_estack::fragment::get_slice;
/// let vector: &[&[u8]] = &[&[1, 2, 3], &[4, 5, 6]];
///
/// let slice = get_slice(vector, 4);
///
/// assert_eq!(slice, &[5, 6]);
/// ```
fn get_sub_slice<'a>(vector: &'a [&[u8]], offset: usize) -> &'a [u8] {
    let mut i = offset;
    for slice in vector {
        if i >= slice.len() {
            i -= slice.len();
        } else {
            return &slice[i..];
        }
    }
    panic!("offset for vector out of bounds");
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

#[cfg(test)]
mod tests {
    #[test]
    fn test_get_slice() {
        use super::get_sub_slice;
        let vector: &[&[u8]] = &[&[1, 2, 3], &[4, 5, 6], &[7, 8, 9]];
        let slice = get_sub_slice(vector, 4);
        assert_eq!(slice, &[5, 6]);
        let slice = get_sub_slice(vector, 0);
        assert_eq!(slice, &[1, 2, 3]);
        let slice = get_sub_slice(vector, 3);
        assert_eq!(slice, &[4, 5, 6]);
    }
    #[test]
    fn test_copy_vectored() {
        use super::copy_vectored;
        let vector: &[&[u8]] = &[&[1, 2, 3], &[4, 5], &[6, 7, 8, 9]];

        let mut dest = [0; 6];
        copy_vectored(vector, 1, &mut dest);
        assert_eq!(&dest, &[2, 3, 4, 5, 6, 7]);

        let mut dest = [0; 5];
        copy_vectored(vector, 4, &mut dest);
        assert_eq!(&dest, &[5, 6, 7, 8, 9]);

        let mut dest = [0; 9];
        copy_vectored(vector, 0, &mut dest);
        assert_eq!(&dest, &[1, 2, 3, 4, 5, 6, 7, 8, 9]);

        let vector: &[&[u8]] = &[&[1, 2, 3]];

        let mut dest = [0; 1];
        copy_vectored(vector, 2, &mut dest);
        assert_eq!(&dest, &[3]);
    }
}
