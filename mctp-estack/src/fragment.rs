use mctp::{Eid, MsgType, Tag, MCTP_HEADER_VERSION_1, Error, Result};

use crate::{AppCookie, Header, HEADER_LEN};

#[derive(Debug)]
pub struct Fragmenter {
    src: Eid,
    dest: Eid,
    typ: MsgType,
    tag: Tag,
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
    ) -> Result<Self> {
        // tag must be allocated and valid
        match tag.tag() {
            Some(t) if t.0 <= mctp::MCTP_TAG_MAX => (),
            _ => return Err(Error::InvalidInput),
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
            seq: 0,
            tag,
            cookie,
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

    fn header(&self) -> Header {
        let mut header = Header::new(MCTP_HEADER_VERSION_1);
        header.set_dest_endpoint_id(self.dest.0);
        header.set_source_endpoint_id(self.src.0);
        header.set_pkt_seq(self.seq);
        if self.first {
            header.set_som(self.first as u8);
        }
        // OK unwrap, checked in new()
        header.set_msg_tag(self.tag.tag().unwrap().0);
        header.set_to(self.tag.is_owner() as u8);
        header
    }

    /// Returns fragments for the MCTP payload, like an iterator.
    ///
    /// `None` is returned after all fragments have been returned.
    /// `out` buffer is borrowed as the returned fragment, filled with packet contents
    pub fn fragment<'f>(
        &mut self,
        payload: &[u8],
        out: &'f mut [u8],
    ) -> Result<Option<&'f mut [u8]>> {
        if self.done {
            return Ok(None);
        }

        // first fragment needs type byte
        let min = HEADER_LEN + self.first as usize;

        if out.len() < min {
            return Err(Error::NoSpace);
        }

        // Reserve header space, the remaining buffer keeps being
        // updated in `rest`
        let (h, mut rest) = out.split_at_mut(HEADER_LEN);

        if rest.len() > self.mtu {
            rest = &mut rest[..self.mtu];
        }

        // Append type byte
        if self.first {
            rest[0] = self.typ.0;
            rest = &mut rest[1..];
        }

        if payload.len() < self.payload_used {
            // Caller is passing varying payload buffers
            return Err(Error::InvalidInput)
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

        let spare = rest.len();
        let used = out.len() - spare;

        Ok(Some(&mut out[..used]))
    }
}
