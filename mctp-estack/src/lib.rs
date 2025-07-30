// SPDX-License-Identifier: MIT OR Apache-2.0
/*
 * Copyright (c) 2024-2025 Code Construct
 */

//! # MCTP Stack
//!
//! This crate provides a MCTP stack that can be embedded in other programs
//! or devices.
//!
//! A [`Router`] object lets programs use a [`Stack`] with
//! MCTP transport binding links. Each *Port* handles transmitting and receiving
//! packets independently. Messages destined for the stack's own EID will
//! be passed to applications.
//!
//! Applications can create [`router::RouterAsyncListener`] and [`router::RouterAsyncReqChannel`]
//! instances to communicate over MCTP. Those implement the standard [`mctp` crate](mctp)
//! async traits.
//!
//! The IO-less [`Stack`] handles MCTP message formatting and parsing, independent
//! of any particular MCTP transport binding.
//!
//! ## Configuration
//!
//! `mctp-estack` uses fixed sizes to be suitable on no-alloc platforms.
//! These can be configured at build time, see [`config`]

#![cfg_attr(not(feature = "std"), no_std)]
// Temporarily relaxed for zerocopy_channel vendored code.
#![deny(unsafe_code)]
// #![forbid(unsafe_code)]
#![allow(clippy::int_plus_one)]
#![allow(clippy::too_many_arguments)]
// defmt does not currently allow inline format arguments, so we don't want
// those reworked when using the log crate either.
#![allow(clippy::uninlined_format_args)]

#[cfg(test)]
#[macro_use]
extern crate std;

/// Re-exported so that callers can use the same `heapless` version.
///
/// `heapless::Vec` is currently an argument of `send_fill()` in transports.
///
/// TODO: will be replaced with something else, maybe `heapless::VecView` once
/// released.
pub use heapless::Vec;

use heapless::{Entry, FnvIndexMap};

use mctp::{Eid, Error, MsgIC, MsgType, Result, Tag, TagValue};

#[cfg(not(any(feature = "log", feature = "defmt")))]
compile_error!("Either log or defmt feature must be enabled");
#[cfg(all(feature = "log", feature = "defmt"))]
compile_error!("log and defmt features are mutually exclusive");

pub mod control;
pub mod fragment;
pub mod i2c;
mod reassemble;
pub mod router;
pub mod serial;
pub mod usb;
#[macro_use]
mod util;
mod proto;

#[rustfmt::skip]
#[allow(clippy::needless_lifetimes)]
mod zerocopy_channel;

use fragment::{Fragmenter, SendOutput};
use reassemble::Reassembler;
pub use router::Router;

use crate::fmt::*;
pub(crate) use config::*;

pub(crate) use proto::MctpHeader;

/// Timeout for message reassembly.
///
/// In milliseconds.
const REASSEMBLY_EXPIRY_TIMEOUT: u32 = 6000;

/// Timeout for calling [`get_deferred()`](Stack::get_deferred).
///
/// See documentation for [`MctpMessage`].
pub const DEFERRED_TIMEOUT: u32 = 6000;

/// Timeout granularity.
///
/// Timeouts will be checked no more often than this interval (in milliseconds).
/// See [`Stack::update()`].
pub const TIMEOUT_INTERVAL: u32 = 100;

/// Build-time configuration and defaults
///
/// To set a non-default value, set the `MCTP_ESTACK_...` environment variable
/// during the build. Those variables can be set in the `[env]`
/// section of `.cargo/config.toml`.
pub mod config {
    /// Maximum size of a MCTP message payload in bytes, default 1032
    ///
    /// This does not include the MCTP type byte.
    ///
    /// Customise with `MCTP_ESTACK_MAX_MESSAGE` environment variable.
    pub const MAX_PAYLOAD: usize =
        get_build_var!("MCTP_ESTACK_MAX_MESSAGE", 1032);

    /// Number of concurrent receive messages, default 4
    ///
    /// The number of in-progress message reassemblies is limited to `NUM_RECEIVE`.
    /// Total memory used for reassembly buffers is roughly
    /// `MAX_PAYLOAD` * `NUM_RECEIVE` bytes.
    ///
    /// Customise with `MCTP_ESTACK_NUM_RECEIVE` environment variable.
    /// Number of outstanding waiting responses, default 64
    pub const NUM_RECEIVE: usize = get_build_var!("MCTP_ESTACK_NUM_RECEIVE", 4);

    /// Maximum number of incoming flows, default 64.
    ///
    /// After a message is sent with Tag Owner (TO) bit set, the stack will accept
    /// response messages with the same tag and TO _unset_. `FLOWS` defines
    /// the number of slots available for pending responses.
    ///
    /// Customise with `MCTP_ESTACK_FLOWS` environment variable.
    /// Must be a power of two.
    pub const FLOWS: usize = get_build_var!("MCTP_ESTACK_FLOWS", 64);

    /// Maximum allowed MTU, default 255
    ///
    /// The largest MTU allowed for any link.
    ///
    /// Customise with `MCTP_ESTACK_MAX_MTU` environment variable.
    pub const MAX_MTU: usize = get_build_var!("MCTP_ESTACK_MAX_MTU", 255);
    const _: () =
        assert!(MAX_MTU >= crate::MctpHeader::LEN + 1, "MAX_MTU too small");

    /// Per-port transmit queue length, default 4.
    ///
    /// This applies to [`Router`](crate::Router).
    /// Each port will use `PORT_TXQUEUE` * `MAX_MTU` buffer space.
    ///
    /// Customise with `MCTP_ESTACK_PORT_TXQUEUE` environment variable.
    pub const PORT_TXQUEUE: usize =
        get_build_var!("MCTP_ESTACK_PORT_TXQUEUE", 4);

    /// Maximum number of ports for [`Router`](crate::Router), default 1.
    ///
    /// Customise with `MCTP_ESTACK_MAX_PORTS` environment variable.
    pub const MAX_PORTS: usize = get_build_var!("MCTP_ESTACK_MAX_PORTS", 2);
}

#[derive(Debug)]
struct Flow {
    // preallocated flows have None expiry
    expiry_stamp: Option<EventStamp>,
    cookie: Option<AppCookie>,
}

/// An opaque identifier that applications can use to associate responses.
#[derive(Debug, Eq, PartialEq, Clone, Copy, Hash, PartialOrd, Ord)]
pub struct AppCookie(pub usize);

/// Low level MCTP stack.
///
/// This is an IO-less MCTP stack, independent of any particular transport.
#[derive(Debug)]
pub struct Stack {
    own_eid: Eid,

    // flows where we own the tag
    flows: FnvIndexMap<(Eid, TagValue), Flow, FLOWS>,

    // The buffer is kept outside of the Reassembler, in case it is borrowed
    // from other storage locations in future.
    //
    // Unused reassemblers set Reassembler::is_unused()
    reassemblers: [(Reassembler, Vec<u8, MAX_PAYLOAD>); NUM_RECEIVE],

    /// monotonic time and counter.
    now: EventStamp,
    /// cached next expiry time from update()
    next_timeout: u64,

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
    pub fn new(own_eid: Eid, now_millis: u64) -> Self {
        let now = EventStamp {
            clock: now_millis,
            counter: 0,
        };
        Self {
            own_eid,
            now,
            next_timeout: 0,
            flows: Default::default(),
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

    /// Return the current internal timestamp.
    ///
    /// This is the time last set with `update_clock()`.
    pub fn now(&self) -> u64 {
        self.now.clock
    }

    /// Updates timeouts and returns the next timeout in milliseconds
    ///
    /// Must be called regularly to update the current clock value.
    /// Returns [`Error::InvalidInput`] if time goes backwards.
    ///
    /// Returns `(next_timeout, any_expired)`.
    /// `next_timeout` is a suitable interval (milliseconds) for the next
    /// call to `update()`, currently a maximum of 100 ms.
    ///
    /// `any_expired` is set true if any message receive timeouts expired with this call.
    pub fn update(&mut self, now_millis: u64) -> Result<(u64, bool)> {
        self.update_clock(now_millis)?;

        if let Some(remain) = self.next_timeout.checked_sub(now_millis) {
            if remain > 0 {
                // Skip timeout checks if within previous interval
                return Ok((remain, false));
            }
        }

        let mut timeout = TIMEOUT_INTERVAL;
        let mut any_expired = false;

        // Check reassembler expiry for incomplete packets
        for (re, _buf) in self.reassemblers.iter_mut() {
            if !re.is_unused() {
                match re.check_expired(
                    &self.now,
                    REASSEMBLY_EXPIRY_TIMEOUT,
                    DEFERRED_TIMEOUT,
                ) {
                    None => {
                        trace!("Expired");
                        any_expired = true;
                        re.set_unused();
                    }
                    // Not expired, update the timeout
                    Some(t) => timeout = timeout.min(t),
                }
            }
        }

        // Expire reply-packet flows
        self.flows.retain(|_k, flow| {
            match flow.expiry_stamp {
                // no expiry
                None => true,
                Some(stamp) => {
                    match stamp
                        .check_timeout(&self.now, REASSEMBLY_EXPIRY_TIMEOUT)
                    {
                        // expired, remove it
                        None => {
                            any_expired = true;
                            false
                        }
                        Some(t) => {
                            // still time left
                            timeout = timeout.min(t);
                            true
                        }
                    }
                }
            }
        });

        self.next_timeout = timeout as u64 + now_millis;

        Ok((timeout as u64, any_expired))
    }

    /// Initiates a MCTP message send.
    ///
    /// Returns a [`Fragmenter`] that will packetize the message.
    ///
    /// `mtu` is optional, the default and minimum is 64 (MCTP protocol minimum).
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
        tag_expires: bool,
        ic: MsgIC,
        mtu: Option<usize>,
        cookie: Option<AppCookie>,
    ) -> Result<Fragmenter> {
        // Add an entry to the flow table for owned tags
        let tag = match tag {
            None => {
                // allocate a tag
                Tag::Owned(self.set_flow(dest, None, tag_expires, cookie)?)
            }
            Some(Tag::Owned(tv)) => {
                let check =
                    self.set_flow(dest, Some(tv), tag_expires, cookie)?;
                debug_assert!(check == tv);
                Tag::Owned(tv)
            }
            Some(Tag::Unowned(tv)) => Tag::Unowned(tv),
        };

        let frag_mtu = mtu.unwrap_or(mctp::MCTP_MIN_MTU);
        // mtu size checked by Fragmenter::new()

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
    /// Returns `Ok(Some(MctpMessage))` when a full message is reassembled.
    /// Returns `Ok(None)` on success when the message is incomplete.
    pub fn receive(
        &mut self,
        packet: &[u8],
    ) -> Result<Option<MctpMessage<'_>>> {
        // Get or insert a reassembler for this packet
        let idx = self.get_reassembler(packet)?;
        let (re, buf) = &mut self.reassemblers[idx];
        if re.is_unused() {
            // Create a new one
            let mut newre =
                Reassembler::new(self.own_eid, packet, self.now.increment())?;
            buf.clear();

            if !newre.tag.is_owner() {
                // Only allow it if we had an existing flow
                if let Some(f) = self.lookup_flow(newre.peer, newre.tag.tag()) {
                    newre.set_cookie(f.cookie);
                } else {
                    return Err(Error::Unreachable);
                }
            }
            self.reassemblers[idx].0 = newre;
        };

        // TODO polonius get-or-insert above
        let (re, buf) = &mut self.reassemblers[idx];

        // Feed the packet to the reassembler
        match re.receive(packet, buf, self.now.increment()) {
            // Received a complete message
            Ok(Some(mut msg)) => {
                // Have received a "response", flow may be finished.
                let re = &mut msg.reassembler;
                if !re.tag.is_owner() {
                    let e = self.flows.entry((re.peer, re.tag.tag()));
                    match e {
                        Entry::Occupied(e) => {
                            if e.get().expiry_stamp.is_some() {
                                trace!("remove flow");
                                e.remove();
                            }
                        }
                        Entry::Vacant(_) => {
                            debug_assert!(false, "non-existent remove_flow")
                        }
                    }
                }

                Ok(Some(msg))
            }
            // Message isn't complete, no error
            Ok(None) => Ok(None),
            // Error
            Err(e) => Err(e),
        }
    }

    /// Retrieves a message previously retained.
    ///
    /// This will return messages from a previous [`MctpMessage::retain()`].
    ///
    /// Messages are selected by `(source_eid, tag)`.
    /// If multiple match the earliest is returned.
    ///
    /// Messages are only available for [`DEFERRED_TIMEOUT`], after
    /// that time they will be discarded and the message slot/tag may
    /// be reused.
    pub fn get_deferred(
        &mut self,
        source: Eid,
        tag: Tag,
    ) -> Option<MctpMessage<'_>> {
        // Find the earliest matching entry
        self.done_reassemblers()
            .filter(|(re, _buf)| re.tag == tag && re.peer == source)
            .min_by_key(|(re, _buf)| re.stamp)
            .map(|(re, buf)| re.message(buf))
            .transpose()
            .unwrap_or_else(|_| {
                debug_assert!(false, "Done reassembler failed");
                None
            })
    }

    /// Retrieves a message previously retained, matching by cookie.
    ///
    /// This will return messages from a previous [`MctpMessage::retain()`].
    /// The cookie can either have been set by [`MctpMessage::set_cookie()`],
    /// or will be set on a matching response from a [`Stack::start_send()`].
    ///
    /// If multiple match the earliest is returned.
    /// Multiple cookies to match may be provided.
    ///
    /// Messages are only available for [`DEFERRED_TIMEOUT`], after
    /// that time they will be discarded and the message slot may
    /// be reused.
    pub fn get_deferred_bycookie(
        &mut self,
        cookies: &[AppCookie],
    ) -> Option<MctpMessage<'_>> {
        // Find the earliest matching entry
        self.done_reassemblers()
            .filter(|(re, _buf)| {
                re.cookie.is_some_and(|c| cookies.contains(&c))
            })
            .min_by_key(|(re, _buf)| re.stamp)
            .map(|(re, buf)| re.message(buf))
            .transpose()
            .unwrap_or_else(|_| {
                debug_assert!(false, "Done reassembler failed");
                None
            })
    }

    /// Returns an iterator over completed reassemblers.
    ///
    /// The Item is (enumerate_index, reassembler)
    fn done_reassemblers(
        &mut self,
    ) -> impl Iterator<Item = &mut (Reassembler, Vec<u8, MAX_PAYLOAD>)> {
        self.reassemblers
            .iter_mut()
            .filter(|(re, _buf)| re.is_done())
    }

    /// Sets the local Endpoint ID.
    pub fn set_eid(&mut self, eid: u8) -> Result<()> {
        self.own_eid = Eid::new_normal(eid)
            .inspect_err(|_e| warn!("Invalid Set EID {}", eid))?;
        info!("Set EID to {}", eid);
        Ok(())
    }

    /// Retrieves  the local Endpoint ID.
    pub fn eid(&self) -> Eid {
        self.own_eid
    }

    pub fn is_local_dest(&self, packet: &[u8]) -> bool {
        Reassembler::is_local_dest(self.own_eid, packet)
    }

    /// Returns an index in to the `reassemblers` array
    fn get_reassembler(&mut self, packet: &[u8]) -> Result<usize> {
        // Look for an existing match
        let pos = self
            .reassemblers
            .iter()
            .position(|(re, _buf)| re.matches_packet(packet));
        if let Some(pos) = pos {
            return Ok(pos);
        }

        // Find a spare slot
        let pos = self
            .reassemblers
            .iter()
            .position(|(re, _buf)| re.is_unused());
        if let Some(pos) = pos {
            return Ok(pos);
        }

        trace!("out of reassemblers");
        Err(Error::NoSpace)
    }

    fn alloc_tag(&mut self, peer: Eid) -> Option<TagValue> {
        // Find used tags as a bitmask
        let mut used = 0u8;
        for (_fpeer, tag) in
            self.flows.keys().filter(|(fpeer, _tag)| *fpeer == peer)
        {
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
    fn new_flow(
        &mut self,
        peer: Eid,
        fixedtag: Option<TagValue>,
        flow_expires: bool,
        cookie: Option<AppCookie>,
    ) -> Result<TagValue> {
        let tag = fixedtag.or_else(|| self.alloc_tag(peer));
        trace!("new flow tag {}", peer);

        let Some(tag) = tag else {
            return Err(Error::TagUnavailable);
        };

        let expiry_stamp = flow_expires.then(|| self.now.increment());

        let f = Flow {
            expiry_stamp,
            cookie,
        };
        let r = self
            .flows
            .insert((peer, tag), f)
            .map_err(|_| Error::TagUnavailable)?;
        debug_assert!(r.is_none(), "Duplicate flow insertion");
        trace!("new flow {}", peer);
        Ok(tag)
    }

    /// Creates a new tag, or ensures that an existing one matches.
    fn set_flow(
        &mut self,
        peer: Eid,
        tag: Option<TagValue>,
        flow_expires: bool,
        cookie: Option<AppCookie>,
    ) -> Result<TagValue> {
        trace!("set flow {}", peer);

        if let Some(tv) = tag {
            if flow_expires {
                trace!("Can't specify a tag with tag_expires");
                return Err(Error::BadArgument);
            }

            // Compare with any existing flow
            if let Some(f) = self.flows.get_mut(&(peer, tv)) {
                if flow_expires != f.expiry_stamp.is_some() {
                    trace!("varying slow_expires for flow");
                    return Err(Error::BadArgument);
                }

                if f.cookie != cookie {
                    trace!("varying cookie for flow");
                    return Err(Error::BadArgument);
                }
                return Ok(tv);
            }
        }

        self.new_flow(peer, tag, flow_expires, cookie)
    }

    fn lookup_flow(&self, peer: Eid, tv: TagValue) -> Option<&Flow> {
        self.flows.get(&(peer, tv))
    }

    pub fn cancel_flow(&mut self, source: Eid, tv: TagValue) -> Result<()> {
        trace!("cancel flow {}", source);
        let tag = Tag::Unowned(tv);
        let mut removed = false;
        for (re, _buf) in self.reassemblers.iter_mut() {
            if !re.is_unused() && re.tag == tag && re.peer == source {
                re.set_unused();
                removed = true;
            }
        }

        trace!("removed flow");
        let r = self.flows.remove(&(source, tv));
        if removed {
            debug_assert!(r.is_some());
        }
        Ok(())
    }
}

/// A received MCTP message.
///
/// This is a complete message received by the MCTP stack.
/// By default when it is dropped the MCTP stack will discard the internal message buffer.
///
/// If the the message is going to be retrieved again using
/// [`get_deferred()`](Stack::get_deferred) or
/// [`get_deferred_bycookie()`](Stack::get_deferred_bycookie), the caller must
/// call [`retain()`](Self::retain). In that case the MCTP stack will keep the message
/// buffer available until [`DEFERRED_TIMEOUT`] (measured from when the final packet
/// of the message was received).
pub struct MctpMessage<'a> {
    pub source: Eid,
    pub dest: Eid,
    pub tag: Tag,

    pub typ: MsgType,
    pub ic: MsgIC,
    pub payload: &'a [u8],

    /// Cookie is set for response messages when the request had `cookie` set in the [`Stack::start_send`] call.
    /// "Response" message refers having `TO` bit unset.
    reassembler: &'a mut Reassembler,

    // By default when a MctpMessage is dropped the reassembler will be
    // marked as Done.
    retain: bool,
}

impl<'a> MctpMessage<'a> {
    /// Retrieve the message's cookie.
    ///
    /// For response messages with `tag.is_owner() == false` this will be
    /// set to the `cookie` argument of [`start_send()`](Stack::start_send).
    pub fn cookie(&self) -> Option<AppCookie> {
        self.reassembler.cookie
    }

    /// Retrieve the message's cookie.
    ///
    /// This can be used to set a cookie to be used later with
    /// [`get_deferred_bycookie()`](Stack::get_deferred_bycookie).
    pub fn set_cookie(&mut self, cookie: Option<AppCookie>) {
        self.reassembler.set_cookie(cookie)
    }

    /// Retain the message in the MCTP stack.
    ///
    /// This must be called for every instance of a `MctpMessage` if
    /// it is going to be fetch with `get_deferred{_bycookie}()` - otherwise the
    /// message will be released by the MCTP stack.
    pub fn retain(&mut self) {
        self.retain = true;
    }
}

impl<'a> Drop for MctpMessage<'a> {
    fn drop(&mut self) {
        if !self.retain {
            self.reassembler.set_unused()
        }
    }
}

impl core::fmt::Debug for MctpMessage<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Mctpmessage")
            .field("source", &self.source)
            .field("dest", &self.dest)
            .field("tag", &self.tag)
            .field("typ", &self.typ)
            .field("ic", &self.ic)
            .field("payload length", &self.payload.len())
            .field("re.cookie", &self.cookie())
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

pub(crate) mod fmt {
    #[cfg(feature = "defmt")]
    pub use defmt::{debug, error, info, trace, warn};

    #[cfg(feature = "log")]
    pub use log::{debug, error, info, trace, warn};
}

#[cfg(test)]
mod tests {

    // TODO:
    // back to back fragmenter/reassembler

    // back to back stacks?
}
