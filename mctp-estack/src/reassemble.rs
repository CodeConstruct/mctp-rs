#[allow(unused)]
use log::{debug, error, info, trace, warn};

use heapless::Vec;

use mctp::{Eid, MsgType, Tag, MCTP_HEADER_VERSION_1, Error, Result, TagValue};

use crate::{Header, MctpMessage, HEADER_LEN, AppCookie, ReceiveHandle};

#[derive(Debug)]
enum State {
    New,
    Active { typ: MsgType, next_seq: u8 },
    Done { typ: MsgType },
    Bad,
}

#[derive(Debug)]
pub(crate) struct Reassembler {
    pub own_eid: Eid,
    pub peer: Eid,
    pub tag: Tag,
    pub cookie: Option<AppCookie>,
    state: State,
    // set true when the ReceiveHandle to this reassembler exists.
    handle_taken: bool,
    pub completion_stamp: u64,
}

impl Reassembler {
    // Must be called with a SOM packet
    pub fn new(own_eid: Eid, packet: &[u8]) -> Result<Self> {
        let header = Self::header(packet)?;
        // TODO: validation

        // TODO NULL or broadcast EID
        if own_eid != Eid(header.dest_endpoint_id()) {
            return Err(Error::InvalidInput);
        }

        let tag = if header.to() == 1 {
            Tag::Owned(TagValue(header.msg_tag()))
        } else {
            Tag::Unowned(TagValue(header.msg_tag()))
        };

        Ok(Self {
            own_eid,
            peer: Eid(header.source_endpoint_id()),
            tag,

            state: State::New,
            cookie: None,
            handle_taken: false,
            completion_stamp: u64::MAX,
        })
    }

    /// Receive a message
    ///
    /// Returns `Ok(Some(_))` when a full message is reassembled.
    /// Returns `Ok(None)` on success when the message is incomplete.
    pub fn receive<'f, const N: usize>(
        &mut self,
        packet: &[u8],
        message: &'f mut Vec<u8, N>,
    ) -> Result<Option<MctpMessage<'f>>> {
        if !self.matches_packet(packet) {
            // Callers should have already checked matches_packet().
            // This should be a cheap check (or optimised away?) but
            // could become a debug assertion if needed.
            return Err(Error::InvalidInput);
        }

        let header = Self::header(packet)?;
        let som = header.som() == 1;
        let eom = header.eom() == 1;
        let min = HEADER_LEN + som as usize;
        if packet.len() < min {
            // TODO counters
            debug!("Short packet");
            return Err(Error::InvalidInput);
        }
        let payload = &packet[min..];

        if som {
            let typ = MsgType(packet[HEADER_LEN]);
            let next_seq = header.pkt_seq();

            self.state = State::Active { next_seq, typ };

            // New SOM packet restarts reassembly
            if !message.is_empty() {
                // TODO counters
                debug!("Duplicate SOM");
            }
            message.clear();
        }

        let State::Active {
            typ,
            ref mut next_seq,
        } = self.state
        else {
            // TODO counters
            debug!("Unexpected packet state");
            return Err(Error::InvalidInput);
        };

        if header.pkt_seq() == *next_seq {
            *next_seq = (*next_seq + 1) & mctp::MCTP_SEQ_MASK;
        } else {
            // Bad sequence halts reassembly
            // TODO counters
            debug!("Bad seq got {} expect {}", header.pkt_seq(), next_seq);
            self.state = State::Bad;
            message.clear();
            return Err(Error::InvalidInput);
        }

        trace!("message extend {} {:x?}", message.len(), payload);
        message.extend_from_slice(payload).map_err(|_| {
            self.state = State::Bad;
            Error::NoSpace
        })?;

        if eom {
            self.state = State::Done { typ };
            trace!("message reassembly complete {:x?}", message);
            return Ok(Some(self.message(message)?));
        }

        Ok(None)
    }

    /// Must be called in Done state
    pub fn message<'f, const N: usize>(
        &self,
        message: &'f mut Vec<u8, N>,
    ) -> Result<MctpMessage<'f>> {
        let State::Done { typ } = self.state else {
            return Err(Error::InvalidInput);
        };

        Ok(MctpMessage {
            source: self.peer,
            dest: self.own_eid,
            tag: self.tag,

            typ,
            payload: message.as_slice(),
            cookie: self.cookie,
        })
    }

    pub fn matches_packet(&self, packet: &[u8]) -> bool {
        if self.is_done() {
            return false;
        }

        let Ok(header) = Self::header(packet) else {
            return false;
        };

        self.peer == Eid(header.source_endpoint_id())
            && self.own_eid == Eid(header.dest_endpoint_id())
            && self.tag.tag() == Some(TagValue(header.msg_tag()))
            && self.tag.is_owner() == (header.to() == 1)
    }

    fn header(packet: &[u8]) -> Result<Header> {
        if packet.len() < HEADER_LEN {
            warn!("bad len {:?}", packet);
            return Err(Error::InvalidInput)
        }

        // OK unwrap, size is fixed
        let hd = packet[..HEADER_LEN].try_into().unwrap();
        let header = Header::new_from_buf(hd, 1).map_err(|e| {
            warn!("bad header {e:?}");
            Error::InvalidInput
        })?;

        if header.hdr_version() != MCTP_HEADER_VERSION_1 {
            warn!("wrong version 0x{:02x}", header.hdr_version());
            return Err(Error::InvalidInput)
        }

        Ok(header)
    }

    pub(crate) fn set_cookie(&mut self, cookie: Option<AppCookie>) {
        if self.cookie.is_some() {
            trace!("replacing reassember cookie")
        }
        self.cookie = cookie;
    }

    pub(crate) fn is_done(&self) -> bool {
        matches!(self.state, State::Done { .. } )
    }

    /// Track whether an assember is in use or not
    ///
    /// Must only be called when in `Done` state, and only one handle
    /// may be in use at a time.
    pub(crate) fn take_handle(&mut self, i: usize) -> ReceiveHandle {
        debug_assert!(!self.handle_taken);
        debug_assert!(self.is_done());
        self.handle_taken = true;
        ReceiveHandle(i)
    }

    pub(crate) fn return_handle(&mut self, _r: ReceiveHandle) {
        debug_assert!(self.handle_taken);
        self.handle_taken = false;
    }

    pub(crate) fn set_completion_order(&mut self, stamp: u64) {
        self.completion_stamp = stamp
    }
}

impl Drop for Reassembler {
    fn drop(&mut self) {
        debug_assert!(!self.handle_taken)
    }
}
