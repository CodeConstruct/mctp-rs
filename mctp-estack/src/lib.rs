// SPDX-License-Identifier: MIT OR Apache-2.0
/*
 * Copyright (c) 2024-2025 Code Construct
 */

//! MCTP Stack
//!
//! This crate provides a MCTP stack that can be embedded in other programs
//! or devices. A [`Stack`] handles MCTP message formatting and parsing, independent
//! of any particular MCTP transport binding.

#![cfg_attr(not(any(feature = "std", test)), no_std)]
#![forbid(unsafe_code)]

#[allow(unused)]
use log::{debug, error, info, trace, warn};

/// Re-exported so that callers can use the same `heapless` version.
///
/// TODO: will be replaced with something else, maybe `heapless::VecView` once
/// released.
pub use heapless::Vec;

use heapless::LinearMap;

use mctp::{Eid, MsgType, TagValue, Tag, Error, Result};

mod fragment;
mod reassemble;
pub mod i2c;
pub mod serial;
pub mod usb;
pub mod control;

pub use fragment::{Fragmenter, SendOutput};
use reassemble::Reassembler;

const FLOWS: usize = 8;

const NUM_RECEIVE: usize = 4;
const RECV_PAYLOAD: usize = 1032;

/// Timeout for message reassembly.
///
/// In milliseconds.
const REASSEMBLY_EXPIRY_TIMEOUT: u32 = 6000;

/// Timeout for [`get_deferred()`](Stack::get_deferred).
///
/// Reassembled messages will remain available for this length of time
/// unless `finished_receive` etc is called.
/// In milliseconds.
pub const DEFERRED_TIMEOUT: u32 = 6000;

#[derive(Debug)]
struct Flow {
    stamp: EventStamp,
    cookie: Option<AppCookie>,
}

/// An opaque identifier that applications can use to associate responses.
#[derive(Debug, Eq, PartialEq, Clone, Copy, Hash)]
pub struct AppCookie(pub usize);

pub(crate) const HEADER_LEN: usize = 4;
type Header = libmctp::base_packet::MCTPTransportHeader<[u8; HEADER_LEN]>;

/// A handle to a received message.
///
/// Must be returned to the stack with [`finished_receive`](Stack::finished_receive)
/// or [`fetch_message_with`](Stack::fetch_message_with)
/// otherwise the reassembly slot will not be released for further messages.
#[must_use]
// This is an opaque index into `Stack.reassemblers`. Is deliberately not `Copy`,
// so that it can't be held longer than the reassembler is valid.
#[derive(Debug)]
pub struct ReceiveHandle(usize);

#[derive(Debug)]
pub struct Stack {
    own_eid: Eid,

    // flows where we own the tag
    flows: LinearMap<(Eid, TagValue), Flow, FLOWS>,

    // The buffer is kept outside of the Reassembler, in case it is borrowed
    // from other storage locations in future.
    // This is [Option<>] rather than Vec so that indices remain stable
    // for the ReceiveHandle. Could use a LinearMap instead?
    reassemblers: [Option<(Reassembler, Vec<u8, RECV_PAYLOAD>)>; NUM_RECEIVE],

    /// monotonic time and counter.
    now: EventStamp,

    mtu: usize,

    // Arbitrary counter to make tag allocation more variable.
    next_tag: u8,

    // Arbitrary next sequence number to start a fragmenter
    next_seq: u8,
}

impl Stack {
    /// Create a new `Stack`.
    ///
    /// `own_eid` is the EID for this stack. It may be 0 (`MCTP_ADDR_NULL`).
    ///
    /// `now_millis` is the current timestamp, the same style as would be
    /// passed to `update_clock()`.
    ///
    /// `mtu` is the default MTU of the stack. Specific [`start_send()`](Self::start_send)
    /// calls may use a smaller MTU if needed (for example a per-link or per-EID MTU).
    /// `new()` will panic if a MTU smaller than 5 is given (minimum MCTP header and type byte).
    pub fn new(own_eid: Eid, mtu: usize, now_millis: u64) -> Self {
        let now = EventStamp { clock: now_millis, counter: 0 };
        assert!(mtu >= HEADER_LEN+1);
        Self {
            own_eid,
            now,
            mtu,
            flows: LinearMap::new(),
            reassemblers: Default::default(),
            next_tag: 0,
            next_seq: 0,
        }
    }

    /// Update the internal timestamp of the stack.
    ///
    /// This is used for expiring flows and reassembly.
    ///
    /// Returns [`Error::InvalidInput`] if time goes backwards.
    fn update_clock(&mut self, now_millis: u64) -> Result<()> {
        if now_millis < self.now.clock {
            Err(Error::InvalidInput)
        } else {
            if now_millis > self.now.clock {
                self.now.clock = now_millis;
                self.now.counter = 0;
            } else {
                // update_clock was called with the same millisecond as previously.
                // Don't do anything.
            }
            Ok(())
        }
    }

    /// Updates timeouts and returns the next timeout in milliseconds
    ///
    /// `u32::MAX` will be returned if no timeouts are pending.
    /// Returns [`Error::InvalidInput`] if time goes backwards.
    pub fn update(&mut self, now_millis: u64) -> Result<u32> {
        self.update_clock(now_millis)?;

        let mut timeout = u32::MAX;

        // Check reassembler expiry for incomplete packets
        for r in self.reassemblers.iter_mut() {
            if let Some((re, _buf)) = r {
                match re.check_expired(&self.now,
                    REASSEMBLY_EXPIRY_TIMEOUT,
                    DEFERRED_TIMEOUT) {
                    None => {
                        trace!("Expired {re:?}");
                        *r = None;
                    }
                    // Not expired, update the timeout
                    Some(t) => timeout = timeout.min(t),
                }
            }
        }

        // Expire reply-packet flows
        let mut to_remove = Vec::<(Eid, TagValue), FLOWS>::new();
        for (k, flow) in &self.flows {
            match flow.stamp.check_timeout(&self.now, REASSEMBLY_EXPIRY_TIMEOUT) {
                None => to_remove.push(*k).unwrap(),
                Some(t) => timeout = timeout.min(t),
            }
        }
        for (peer, tv) in to_remove {
            self.remove_flow(peer, tv);
        }


        Ok(timeout)
    }

    /// Initiates a MCTP message send.
    ///
    /// Returns a [`Fragmenter`] that will packetize the message.
    ///
    /// `mtu` is an optional override, will be the min of the stack MTU and the argument.
    ///
    /// The provided cookie will be returned when `send_fill()` completes.
    ///
    /// When sending a with `tag.is_owner() == true`,
    /// the cookie will be stored with the flow, and the reply [`MctpMessage`] `cookie`
    /// field will be set.
    pub fn start_send(
        &mut self,
        dest: Eid,
        typ: MsgType,
        tag: Option<Tag>,
        ic: bool,
        mtu: Option<usize>,
        cookie: Option<AppCookie>,
    ) -> Result<Fragmenter> {

        // Add an entry to the flow table for owned tags
        let tag = match tag {
            None => {
                // allocate a tag
                Tag::Owned(self.set_flow(dest, None, cookie)?)
            }
            Some(Tag::Owned(_tv)) => {
                // Preallocated tags are not yet supported. Flow cleanup handling
                // doesn't yet handle preallocated tags, and it's untested.
                return Err(mctp::Error::Unsupported)
                // self.set_flow(dest, Some(tv), cookie)?;
                // Tag::Owned(tv)
            }
            Some(Tag::Unowned(tv)) => Tag::Unowned(tv),
        };

        let mut frag_mtu = self.mtu;
        if let Some(m) = mtu {
            frag_mtu = frag_mtu.min(m);
        }

        // Vary the starting seq
        self.next_seq = (self.next_seq + 1) & mctp::MCTP_SEQ_MASK;

        Fragmenter::new(
            typ,
            self.own_eid,
            dest,
            tag,
            frag_mtu,
            cookie,
            ic,
            self.next_seq,
        )
    }

    /// Receive a packet.
    ///
    /// Returns `Ok(Some(_))` when a full message is reassembled.
    /// Returns `Ok(None)` on success when the message is incomplete.
    /// Callers must call [`finished_receive`](Stack::finished_receive)
    /// or [`fetch_message_with`](Stack::fetch_message_with)
    /// for any returned [`ReceiveHandle`].
    pub fn receive(&mut self, packet: &[u8]) -> Result<Option<(MctpMessage, ReceiveHandle)>> {
        // Get or insert a reassembler for this packet
        let idx = self.get_reassembler(packet)?;
        let (re, buf) = if let Some(r) = &mut self.reassemblers[idx] {
            r
        } else {
            // Create a new one
            let mut re = Reassembler::new(self.own_eid, packet, self.now.increment())?;

            if !re.tag.is_owner() {
                // Only allow it if we had an existing flow
                if let Some(f) = self.lookup_flow(re.peer, re.tag.tag()) {
                    re.set_cookie(f.cookie);
                } else {
                    return Err(Error::Unreachable);
                }
            }
            self.reassemblers[idx].insert((re, Vec::new()))

        };

        // Feed the packet to the reassembler
        match re.receive(packet, buf, self.now.increment()) {
            // Received a complete message
            Ok(Some(_msg)) => {
                // Have received a "response", flow is finished.
                // TODO preallocated tags won't remove the flow.
                if !re.tag.is_owner() {
                    let (peer, tv) = (re.peer, re.tag.tag());
                    self.remove_flow(peer, tv);
                }

                // Required to reborrow `re` and `buf`. Otherwise
                // we hit lifetime problems setting `= None` in the Err case.
                // These two lines can be removed once Rust "polonius" borrow
                // checker is added.
                let (re, buf) = self.reassemblers[idx].as_mut().unwrap();
                let msg = re.message(buf)?;

                let handle = re.take_handle(idx);
                Ok(Some((msg, handle)))
            }
            // Message isn't complete, no error
            Ok(None) => Ok(None),
            // Error
            Err(e) => {
                // Something went wrong, release the reassembler.
                self.reassemblers[idx] = None;
                Err(e)
            }
        }
    }

    /// Retrieves a MCTP message for a receive handle.
    ///
    /// The message is provided to a closure.
    /// This allows using a closure that takes ownership of non-copyable objects.
    pub fn fetch_message_with<F>(&mut self, handle: ReceiveHandle, f: F)
        where F: FnOnce(MctpMessage)
    {
        let m = self.fetch_message(&handle);
        f(m);

        // Always call finished_receive() regardless of errors
        self.finished_receive(handle);
    }

    /// Provides a message previously returned from [`receive`](Self::receive)
    pub fn fetch_message(&mut self, handle: &ReceiveHandle) -> MctpMessage {
        let Some(Some((re, buf))) = self.reassemblers.get_mut(handle.0) else {
            // ReceiveHandle can only be constructed when
            // a completed message exists, so this should be impossible.
            unreachable!("Bad ReceiveHandle");
        };

        let Ok(msg) = re.message(buf) else {
            unreachable!("Bad ReceiveHandle");
        };
        msg
    }

    /// Returns a handle to the `Stack` and complete the message
    pub fn finished_receive(&mut self, handle: ReceiveHandle) {
        if let Some(r) = self.reassemblers.get_mut(handle.0) {
            if let Some((re, _buf)) = r {
                re.return_handle(handle);
                *r = None;
                return;
            }
        }
        unreachable!("Bad ReceiveHandle");
    }

    /// Returns a handle to the `Stack`, the message will be kept (until timeouts)
    pub fn return_handle(&mut self, handle: ReceiveHandle) {
        // OK unwrap: handle can't be invalid
        let (re, _buf) = self.reassemblers[handle.0].as_mut().unwrap();
        re.return_handle(handle);
    }

    /// Retrieves a message deferred from a previous [`receive`](Self::receive) callback.
    ///
    /// Messages are selected by `(source_eid, tag)`.
    /// If multiple match the earliest is returned.
    ///
    /// Messages are only available for [`DEFERRED_TIMEOUT`], after
    /// that time they will be discarded and the message slot/tag may
    /// be reused.
    pub fn get_deferred(&mut self, source: Eid, tag: Tag) -> Option<ReceiveHandle> {
        // Find the earliest matching entry
        self.done_reassemblers().filter(|(_i, re)| {
            re.tag == tag && re.peer == source
        })
        .min_by_key(|(_i, re)| re.stamp)
        .map(|(i, re)| re.take_handle(i))
    }

    /// Retrieves a message deferred from a previous [`receive`](Self::receive) callback.
    ///
    /// If multiple match the earliest is returned.
    /// Multiple cookies to match may be provided.
    ///
    /// Messages are only available for [`DEFERRED_TIMEOUT`], after
    /// that time they will be discarded and the message slot may
    /// be reused.
    pub fn get_deferred_bycookie(&mut self, cookies: &[AppCookie]) -> Option<ReceiveHandle> {
        // Find the earliest matching entry
        self.done_reassemblers().filter(|(_i, re)| {
            if let Some(c) = re.cookie {
                if cookies.contains(&c) {
                    return true
                }
            }
            false
        })
        .min_by_key(|(_i, re)| re.stamp)
        .map(|(i, re)| re.take_handle(i))
    }

    pub fn cancel_flow(&mut self, source: Eid, tv: TagValue) -> Result<()> {
        trace!("cancel flow {source:?} {tv:?}");
        let tag = Tag::Unowned(tv);
        let mut removed = false;
        for r in self.reassemblers.iter_mut() {
            if let Some((re, _buf)) = r.as_mut() {
                if re.tag == tag && re.peer == source {
                    if re.handle_taken() {
                        trace!("Outstanding handle");
                        return Err(Error::BadArgument);
                    } else {
                        *r = None;
                        removed = true;
                    }
                }
            }
        }

        trace!("removed flow");
        let r = self.flows.remove(&(source, tv));
        if removed {
            debug_assert!(r.is_some());
        }
        Ok(())
    }

    /// Returns an iterator over completed reassemblers.
    ///
    /// The Item is (enumerate_index, reassembler)
    fn done_reassemblers(&mut self) -> impl Iterator<Item = (usize, &mut Reassembler)> {
        self.reassemblers.iter_mut().enumerate().filter_map(|(i, r)| {
            // re must be Some and is_done
            r.as_mut().and_then(|(re, _buf)| re.is_done().then(|| (i, re)))
        })
    }

    pub fn set_cookie(&mut self, handle: &ReceiveHandle, cookie: Option<AppCookie>) {
        // OK unwrap: handle can't be invalid
        let (re, _buf) = self.reassemblers[handle.0].as_mut().unwrap();
        re.set_cookie(cookie)
    }

    /// Sets the local Endpoint ID.
    pub fn set_eid(&mut self, eid: u8) -> Result<()> {
        self.own_eid = Eid::new_normal(eid)?;
        Ok(())
    }

    /// Retrieves  the local Endpoint ID.
    pub fn eid(&self) -> Eid {
        self.own_eid
    }

    /// Returns an index in to the `reassemblers` array
    fn get_reassembler(&mut self, packet: &[u8]) -> Result<usize> {
        // Look for an existing match
        let pos = self.reassemblers.iter().position(|r|
            r.as_ref().is_some_and(|(re, _buf)| re.matches_packet(packet))
        );
        if let Some(pos) = pos {
            return Ok(pos);
        }

        // Find a spare slot
        let pos = self.reassemblers.iter().position(|r| r.is_none());
        if let Some(pos) = pos {
            return Ok(pos)
        }

        trace!("out of reassemblers");
        Err(Error::NoSpace)
    }

    fn alloc_tag(&mut self, peer: Eid) -> Option<TagValue> {
        // Find used tags as a bitmask
        let mut used = 0u8;
        for (_fpeer, tag) in self.flows.keys().filter(|(fpeer, _tag)| *fpeer == peer) {
            debug_assert!(tag.0 <= mctp::MCTP_TAG_MAX);
            let bit = 1u8 << tag.0;
            debug_assert!(used & bit == 0);
            used |= bit;
        }

        let mut tag = None;

        // Find an unset bit
        self.next_tag = (self.next_tag + 1) & mctp::MCTP_TAG_MAX;
        let end = self.next_tag + mctp::MCTP_TAG_MAX;
        for t in self.next_tag..=end {
            let t = t & mctp::MCTP_TAG_MAX;
            let tagmask = 1 << t;
            if used & tagmask == 0 {
                tag = Some(TagValue(t));
                break;
            }
        }

        tag
    }

    /// Inserts a new flow. Called when we are the tag owner.
    ///
    /// A tag will be allocated if fixedtag = None
    /// Returns [`Error::TagUnavailable`] if all tags or flows are used.
    fn new_flow(&mut self, peer: Eid, fixedtag: Option<TagValue>, cookie: Option<AppCookie>) -> Result<TagValue> {

        let tag = fixedtag.or_else(|| self.alloc_tag(peer));
        trace!("new flow tag {tag:?}");

        let Some(tag) = tag else {
            return Err(Error::TagUnavailable);
        };

        let f = Flow {
            stamp: self.now.increment(),
            cookie,
        };
        let r = self.flows.insert((peer, tag), f)
        .map_err(|_| Error::TagUnavailable)?;
        debug_assert!(r.is_none(), "Duplicate flow insertion");
        trace!("new flow {peer:?} {tag:?}");
        Ok(tag)
    }

    /// Adds a flow tag, or updates the timestamp if it already exists
    fn set_flow(&mut self, peer: Eid, tag: Option<TagValue>, cookie: Option<AppCookie>) -> Result<TagValue> {
        trace!("set flow {peer:?}");
        if let Some(tv) = tag {
            if let Some(f) = self.flows.get_mut(&(peer, tv)) {
                f.stamp = self.now.increment();
                if f.cookie != cookie {
                    trace!("varying app for flow {f:?}");
                }
                f.cookie = cookie;
                return Ok(tv);
            }
        }

        self.new_flow(peer, tag, cookie)
    }

    fn lookup_flow(&self, peer: Eid, tv: TagValue) -> Option<&Flow> {
        self.flows.get(&(peer, tv))
        .inspect(|r| trace!("lookup flow {peer:?} {tv:?} got {r:?}"))
    }

    fn remove_flow(&mut self, peer: Eid, tv: TagValue) {
        trace!("remove flow {peer:?} {tv:?}");
        let r = self.flows.remove(&(peer, tv));

        debug_assert!(r.is_some(), "non-existent remove_flow");
    }
}

// For received reassembled messages
pub struct MctpMessage<'a> {
    pub source: Eid,
    pub dest: Eid,
    pub tag: Tag,

    pub typ: MsgType,
    pub ic: bool,
    pub payload: &'a [u8],

    /// Set for response messages when the request had `cookie` set in the [`Stack::start_send`] call.
    /// "Response" message refers having `TO` bit unset.
    pub cookie: Option<AppCookie>,
}

impl<'a> core::fmt::Debug for MctpMessage<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Mctpmessage")
            .field("source", &self.source)
            .field("dest", &self.dest)
            .field("tag", &self.tag)
            .field("typ", &self.typ)
            .field("ic", &self.ic)
            .field("cookie", &self.cookie)
            .field("payload length", &self.payload.len())
            .finish_non_exhaustive()
    }
}

#[derive(Default, Debug, Ord, PartialOrd, PartialEq, Eq, Copy, Clone)]
pub(crate) struct EventStamp {
    // Ordering of members matters here for `Ord` derive

    /// Monotonic real clock in milliseconds
    pub clock: u64,
    /// A counter to order events having the same realclock value
    pub counter: u32,
}

impl EventStamp {
    // Performs a pre-increment on the `counter`. `clock` is unmodified.
    fn increment(&mut self) -> Self {
        self.counter += 1;
        Self {
            clock: self.clock,
            counter: self.counter,
        }
    }

    /// Check timeout
    ///
    /// Returns `None` if expired, or `Some(time_remaining)`.
    /// Times are in milliseconds.
    pub fn check_timeout(&self, now: &EventStamp, timeout: u32) -> Option<u32> {
        let Some(elapsed) = now.clock.checked_sub(self.clock) else {
            debug_assert!(false, "Timestamp backwards");
            return None;
        };
        let Ok(elapsed) = u32::try_from(elapsed) else {
            // Longer than 49 days elapsed. It's expired.
            return None;
        };

        timeout.checked_sub(elapsed)
    }
}

#[cfg(test)]
mod tests {

    // TODO:
    // back to back fragmenter/reassembler

    // back to back stacks?
}
