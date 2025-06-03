// SPDX-License-Identifier: MIT OR Apache-2.0
/*
 * Copyright (c) 2024-2025 Code Construct
 */

//! MCTP packet reassembly
#[allow(unused)]
use crate::fmt::{debug, error, info, trace, warn};

use mctp::MCTP_HEADER_VERSION_1;

use crate::*;

#[derive(Debug)]
enum State {
    New,
    Active {
        typ: MsgType,
        ic: MsgIC,
        next_seq: u8,
    },
    Done {
        typ: MsgType,
        ic: MsgIC,
    },
    /// An error must be returned whenver Bad state is set,
    /// and the caller will dispose of the Reassembler.
    Bad,
    /// Reassembler is not used at all.
    Unused,
}

#[derive(Debug)]
pub(crate) struct Reassembler {
    // Destination EID of currently reassembled packets.
    // Either Stack's own_eid, or MCTP_ADDR_NULL.
    pub dest_eid: Eid,

    pub peer: Eid,
    pub tag: Tag,
    pub cookie: Option<AppCookie>,
    state: State,
    // Time of SOM received for Active state, or time of EOM for Done state.
    pub stamp: EventStamp,
}

impl Reassembler {
    pub fn new_unused() -> Self {
        Self {
            state: State::Unused,
            peer: Eid(0),
            tag: Tag::Unowned(TagValue(0)),
            dest_eid: Eid(0),
            stamp: EventStamp::default(),
            cookie: None,
        }
    }

    pub fn new(own_eid: Eid, packet: &[u8], stamp: EventStamp) -> Result<Self> {
        let header = Self::header(packet)?;

        if !Self::is_local_dest(own_eid, packet) {
            return Err(Error::InvalidInput);
        }

        let dest_eid = Eid(header.dest_endpoint_id());
        let peer = Eid(header.source_endpoint_id());
        if peer == mctp::MCTP_ADDR_ANY {
            return Err(Error::InvalidInput);
        }

        let tag = if header.to() == 1 {
            Tag::Owned(TagValue(header.msg_tag()))
        } else {
            Tag::Unowned(TagValue(header.msg_tag()))
        };

        if header.som() != 1 {
            // A reassembler always starts with a SOM
            return Err(Error::InvalidInput);
        }

        Ok(Self {
            dest_eid,
            peer,
            tag,

            state: State::New,
            cookie: None,
            stamp,
        })
    }

    pub fn is_local_dest(own_eid: Eid, packet: &[u8]) -> bool {
        let Ok(header) = Self::header(packet) else {
            return false;
        };

        let dest_eid = Eid(header.dest_endpoint_id());
        // Allow NULL EID for physical addressing
        if !(dest_eid == own_eid || dest_eid == mctp::MCTP_ADDR_NULL) {
            return false;
        }

        true
    }

    /// Receive a packet, returning a message when complete.
    ///
    /// Returns `Ok(Some(_))` when a full message is reassembled.
    /// Returns `Ok(None)` on success when the message is incomplete.
    pub fn receive<'f, const N: usize>(
        &'f mut self,
        packet: &[u8],
        message: &'f mut Vec<u8, N>,
        stamp: EventStamp,
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
            let (typ, ic) = mctp::decode_type_ic(packet[HEADER_LEN]);
            let next_seq = header.pkt_seq();

            self.state = State::Active { next_seq, typ, ic };

            // New SOM packet restarts reassembly
            if !message.is_empty() {
                // TODO counters
                debug!("Duplicate SOM");
            }
            message.clear();
            self.stamp = stamp;
        }

        let State::Active {
            typ,
            ic,
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

        message.extend_from_slice(payload).map_err(|_| {
            self.state = State::Bad;
            trace!("nospace message too long");
            Error::NoSpace
        })?;

        if eom {
            self.state = State::Done { typ, ic };
            self.stamp = stamp;
            trace!("message reassembly complete, len {}", message.len());
            return Ok(Some(self.message(message)?));
        }

        Ok(None)
    }

    /// Must be called in Done state
    pub fn message<'f, const N: usize>(
        &'f mut self,
        message: &'f mut Vec<u8, N>,
    ) -> Result<MctpMessage<'f>> {
        let State::Done { typ, ic } = self.state else {
            return Err(Error::BadArgument);
        };

        Ok(MctpMessage {
            source: self.peer,
            dest: self.dest_eid,
            tag: self.tag,

            typ,
            ic,
            payload: message.as_slice(),
            reassembler: self,
            retain: false,
        })
    }

    pub fn matches_packet(&self, packet: &[u8]) -> bool {
        match self.state {
            State::Done { .. } | State::Unused => return false,
            State::Bad => {
                debug_assert!(false, "Using reassembler after failure");
                return false;
            }
            State::New | State::Active { .. } => (),
        }

        let Ok(header) = Self::header(packet) else {
            return false;
        };

        self.peer == Eid(header.source_endpoint_id())
            && self.dest_eid == Eid(header.dest_endpoint_id())
            && self.tag.tag() == TagValue(header.msg_tag())
            && self.tag.is_owner() == (header.to() == 1)
    }

    /// Check timeouts
    ///
    /// Returns `None` if timed out, `Some(remaining)` otherwise.
    pub fn check_expired(
        &self,
        now: &EventStamp,
        reassemble_timeout: u32,
        done_timeout: u32,
    ) -> Option<u32> {
        let timeout = match self.state {
            State::Active { .. } => reassemble_timeout,
            State::Done { .. } => done_timeout,
            State::New | State::Bad => {
                // Bad ones should have been cleaned up, New ones should
                // have moved to Active prior to check_expired().
                debug_assert!(false, "Bad or new reassembler");
                return None;
            }
            State::Unused => return None,
        };
        self.stamp.check_timeout(now, timeout)
    }

    pub(crate) fn header(packet: &[u8]) -> Result<Header> {
        if packet.len() < HEADER_LEN {
            warn!("bad len {:?}", packet);
            return Err(Error::InvalidInput);
        }

        // OK unwrap, size is fixed
        let hd = packet[..HEADER_LEN].try_into().unwrap();
        let header = Header::new_from_buf(hd, 1).map_err(|_e| {
            warn!("bad header");
            Error::InvalidInput
        })?;

        if header.hdr_version() != MCTP_HEADER_VERSION_1 {
            warn!("wrong version 0x{:02x}", header.hdr_version());
            return Err(Error::InvalidInput);
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
        matches!(self.state, State::Done { .. })
    }

    pub fn set_unused(&mut self) {
        self.state = State::Unused
    }

    pub fn is_unused(&self) -> bool {
        matches!(self.state, State::Unused)
    }
}
