#![no_std]
#![forbid(unsafe_code)]
// #![warn(missing_docs)]

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
mod i2c;
mod reassemble;

pub use crate::i2c::{MctpI2cEncap, MCTP_I2C_COMMAND_CODE, MctpI2cHandler};
pub use fragment::{Fragmenter, SendOutput};
use reassemble::Reassembler;

const FLOWS: usize = 8;

const NUM_RECEIVE: usize = 4;
const RECV_PAYLOAD: usize = 1032;

#[derive(Debug)]
struct Flow {
    // TODO
    timestamp: u64,
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

    /// monotonic time counter.
    now_millis: u64,

    mtu: usize,

    // counter used for ordering events. no relation to real time.
    ordering: u64,
}

impl Stack {
    pub fn new(own_eid: Eid, mtu: usize, now_millis: u64) -> Self {
        Self {
            own_eid,
            now_millis,
            mtu,
            flows: LinearMap::new(),
            reassemblers: Default::default(),
            ordering: 0,
        }
    }

    /// Returns [`Error::InvalidInput`] if time goes backwards.
    pub fn update_clock(&mut self, now_millis: u64) -> Result<()> {
        if now_millis < self.now_millis {
            Err(Error::InvalidInput)
        } else {
            self.now_millis = now_millis;
            Ok(())
        }
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
        mtu: Option<usize>,
        // TODO: should cookie be not-Option?
        cookie: Option<AppCookie>,
    ) -> Result<Fragmenter> {

        // Add an entry to the flow table for owned tags
        let flow_cookie = match tag {
            Some(t) if !t.is_owner() => None,
            _ => cookie,
        };

        let tag = match tag {
            None => {
                // allocate a tag
                Tag::Owned(self.set_flow(dest, None, flow_cookie)?)
            }
            Some(Tag::Owned(tv)) => {
                 // A pre-known owned tag isn't normally used.
                 // Useful for future preallocated tag API
                 self.set_flow(dest, Some(tv), flow_cookie)?;
                 Tag::Owned(tv)
            }
            Some(Tag::Unowned(tv)) => Tag::Unowned(tv),
        };

        let mut frag_mtu = self.mtu;
        if let Some(m) = mtu {
            frag_mtu = frag_mtu.min(m);
        }

        Fragmenter::new(
            typ,
            self.own_eid,
            dest,
            tag,
            frag_mtu,
            cookie,
        )
    }

    /// Receive a message
    ///
    /// Returns `Ok(Some(_))` when a full message is reassembled.
    /// Returns `Ok(None)` on success when the message is incomplete.
    /// Callers must call [`finished_receive`](Stack::finished_receive)
    /// or [`fetch_message_with`](Stack::fetch_message_with)
    /// for any returned [`ReceiveHandle`].
    pub fn receive(&mut self, packet: &[u8]) -> Result<Option<(MctpMessage, ReceiveHandle)>> {
        let idx = self.get_reassembler(packet)?;
        if self.reassemblers[idx].is_none() {
            // Create a new one
            let mut re = Reassembler::new(self.own_eid, packet)?;

            if !re.tag.is_owner() {
                // Only allow it if we had an existing flow
                if let Some(f) = self.lookup_flow(re.peer, re.tag.tag()) {
                    re.set_cookie(f.cookie);
                } else {
                    return Err(Error::Unreachable);
                }
                // TODO timestamp?
            }

            self.reassemblers[idx] = Some((re, Vec::new()));
        }

        // OK unwrap, we just set it.
        let (re, buf) = self.reassemblers[idx].as_mut().unwrap();
        match re.receive(packet, buf) {
            // Received a complete message
            Ok(Some(_msg)) => {
                // Have received a "response", flow is finished.
                if !re.tag.is_owner() {
                    let (peer, tv) = (re.peer, re.tag.tag());
                    self.remove_flow(peer, tv);
                }

                // Required to reborrow `re` and `buf`. Otherwise
                // we hit lifetime problems setting `= None` in the error case.
                // These two lines can be removed once Rust "polonius" borrow
                // checker is added.
                let (re, buf) = self.reassemblers[idx].as_mut().unwrap();

                // Have received a "response", flow is finished.
                if !re.tag.is_owner() {
                    self.remove_flow(re.peer, re.tag.tag())
                }

                let msg = re.message(buf)?;

                re.set_completion_order(self.ordering);
                self.ordering += 1;
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
    /// The message is provided to a closure. If an error occurs in
    // `fetch_message()` the error will be provided to the closure. This allows
    /// using a closure that takes ownership of non-copyable objects.
    pub fn fetch_message_with<F>(&mut self, handle: ReceiveHandle, f: F)
        where F: FnOnce(Result<MctpMessage>)
    {
        let m = self.fetch_message(&handle);
        f(m);

        // Always call finished_receive() regardless of errors
        self.finished_receive(handle);
    }

    /// Provides a message previously returned from [`receive`](Self::receive)
    pub fn fetch_message(&mut self, handle: &ReceiveHandle) -> Result<MctpMessage> {
        if let Some(Some((re, buf))) = self.reassemblers.get_mut(handle.0) {
            re.message(buf)
        } else {
            debug!("message() for bad handle {}", handle.0);
            debug_assert!(false);
            Err(Error::Other)
        }
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
        debug!("finished_receive for bad handle");
        debug_assert!(false);
    }

    /// Returns a handle to the `Stack`, the message will be kept (until timeouts)
    pub fn return_handle(&mut self, handle: ReceiveHandle) {
        // OK unwrap: handle can't be invalid
        let (re, _buf) = self.reassemblers[handle.0].as_mut().unwrap();
        re.return_handle(handle);
    }

    /// Retrieves a message deferred from a previous [`receive`] callback.
    ///
    /// If multiple match the earliest is returned
    pub fn get_deferred(&mut self, source: Eid, tag: Tag) -> Option<ReceiveHandle> {
        // Find the earliest matching entry
        self.done_reassemblers().filter(|(_i, re)| {
            re.tag == tag && re.peer == source
        })
        .min_by_key(|(_i, re)| re.completion_stamp)
        .map(|(i, re)| re.take_handle(i)) 
    }

    /// Retrieves a message deferred from a previous [`receive`] callback.
    ///
    /// If multiple match the earliest is returned.
    /// Multiple cookies to match may be provided.
    // TODO: maybe also give this a `source: Option<Eid>` filter argument.
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
        .min_by_key(|(_i, re)| re.completion_stamp)
        .map(|(i, re)| re.take_handle(i)) 
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

    fn alloc_tag(&self, peer: Eid) -> Option<TagValue> {
        // Find used tags as a bitmask
        let mut used = 0u8;
        for (_fpeer, tag) in self.flows.keys().filter(|(fpeer, _tag)| *fpeer == peer) {
            debug_assert!(tag.0 <= mctp::MCTP_TAG_MAX);
            let bit = 1u8 << tag.0;
            debug_assert!(used & bit == 0);
            used |= bit;
        }

        let mut tag = None;

        // Find the first bit unset
        for t in 0..mctp::MCTP_TAG_MAX {
            if used & 1 == 0 {
                tag = Some(TagValue(t));
                break;
            }
            used >>= 1;
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
            timestamp: self.now_millis,
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
                f.timestamp = self.now_millis;
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
        self.flows.remove(&(peer, tv));
    }
}

// For received reassembled messages
pub struct MctpMessage<'a> {
    pub source: Eid,
    pub dest: Eid,
    pub tag: Tag,

    pub typ: MsgType,
    pub payload: &'a [u8],

    /// Set for response messages when the request had `cookie` set in the [`Stack::send`] call.
    /// "Response" message refers having `TO` bit unset.
    pub cookie: Option<AppCookie>,
}


#[cfg(test)]
mod tests {

    use crate::*;

    // TODO:
    // back to back fragmenter/reassembler

    // back to back stacks?
}
