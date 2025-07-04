// SPDX-License-Identifier: MIT OR Apache-2.0
/*
 * Copyright (c) 2024-2025 Code Construct
 */

//! MCTP Routing

#[allow(unused)]
use crate::fmt::{debug, error, info, trace, warn};

use core::cell::RefCell;
use core::debug_assert;
use core::future::{poll_fn, Future};
use core::pin::pin;
use core::task::{Poll, Waker};

use crate::{
    AppCookie, Fragmenter, MctpHeader, MctpMessage, SendOutput, Stack, MAX_MTU,
    MAX_PAYLOAD,
};
use mctp::{Eid, Error, MsgIC, MsgType, Result, Tag, TagValue};

use embassy_sync::waitqueue::WakerRegistration;
use embassy_sync::zerocopy_channel::{Channel, Receiver, Sender};

use heapless::{Entry, FnvIndexMap, Vec};

/// Maximum number of listeners per `Router`.
// TODO sizing is a bit arbitrary. They don't take up much space.
pub const MAX_LISTENERS: usize = 20;

/// Maximum number of channels per `Router`.
///
/// This is the maximum count of instantiated `RouterListener`,
/// `RouterRespChannel`, `RouterReqChannel` at one time.
// Must be power of 2.
pub const MAX_CHANNELS: usize = 64;

// TODO: feature to configure mutex?
type RawMutex = embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
type AsyncMutex<T> = embassy_sync::mutex::Mutex<RawMutex, T>;
type BlockingMutex<T> = embassy_sync::blocking_mutex::Mutex<RawMutex, T>;

type PortRawMutex = embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
// type PortRawMutex = embassy_sync::blocking_mutex::raw::NoopRawMutex;

// Identifier for a Port
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PortId(pub u8);

/// A trait implemented by applications to determine the routing table.
pub trait PortLookup: Send {
    /// Returns the `PortId` for a destination EID.
    ///
    /// `PortId` is an index into the array of `ports` provided to [`Router::new`]
    ///
    /// Return `None` to drop the packet as unreachable. This lookup
    /// is only called for outbound packets - packets destined for the local EID
    /// will not be passed to this callback.
    ///
    /// `source_port` is the incoming interface of a forwarded packet,
    /// or `None` for locally generated packets.
    fn by_eid(
        &mut self,
        eid: Eid,
        source_port: Option<PortId>,
    ) -> Option<PortId>;
}

/// Used like `heapless::Vec`, but lets the mut buffer be written into
/// without zero-fill every time.
struct PktBuf {
    data: [u8; MAX_MTU],
    len: usize,
}

impl PktBuf {
    const fn new() -> Self {
        Self {
            data: [0u8; MAX_MTU],
            len: 0,
        }
    }

    fn set(&mut self, data: &[u8]) -> Result<()> {
        debug_assert!(MctpHeader::decode(data).is_ok());

        let dst = self.data.get_mut(..data.len()).ok_or(Error::NoSpace)?;
        dst.copy_from_slice(data);
        self.len = data.len();
        Ok(())
    }
}

impl core::ops::Deref for PktBuf {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.data[..self.len]
    }
}

/// The "producer" side of a queue of packets to send out a MCTP port/interface.
///
/// It will be used by `Routing` to enqueue packets to a port.
pub struct PortTop<'a> {
    /// Forwarded packet queue.
    /// The outer mutex will not be held over an await.
    packets: AsyncMutex<Sender<'a, PortRawMutex, PktBuf>>,

    mtu: usize,
}

impl PortTop<'_> {
    /// Enqueues a packet.
    ///
    /// Do not call with locks held.
    /// May block waiting for a port queue to flush.
    /// Packet must be a valid MCTP packet, may panic otherwise.
    async fn forward_packet(&self, pkt: &[u8]) -> Result<()> {
        debug_assert!(MctpHeader::decode(pkt).is_ok());

        let mut sender = self.packets.lock().await;
        // Note: must not await while holding `sender`

        // Check space first (can't rollback after try_send)
        if pkt.len() > self.mtu {
            debug!("Forward packet too large");
            return Err(Error::NoSpace);
        }

        // Get a slot to send
        let slot = sender.try_send().ok_or_else(|| {
            debug!("Dropped forward packet");
            Error::TxFailure
        })?;

        // Fill the buffer
        // OK unwrap: pkt.len() checked above.
        slot.set(pkt).unwrap();
        sender.send_done();
        Ok(())
    }

    /// Fragments and enqueues a message.
    ///
    /// Do not call with locks held.
    /// May block waiting for a port queue to flush.
    async fn send_message(
        &self,
        fragmenter: &mut Fragmenter,
        pkt: &[&[u8]],
        work_msg: &mut Vec<u8, MAX_PAYLOAD>,
    ) -> Result<Tag> {
        trace!("send_message");
        let payload = if pkt.len() == 1 {
            // Avoid the copy when sending a single slice
            pkt[0]
        } else {
            work_msg.clear();
            for p in pkt {
                work_msg.extend_from_slice(p).map_err(|_| {
                    debug!("Message too large");
                    Error::NoSpace
                })?;
            }
            work_msg
        };

        loop {
            let mut sender = self.packets.lock().await;

            let qpkt = sender.send().await;
            qpkt.len = 0;
            let r = fragmenter.fragment(payload, &mut qpkt.data);
            match r {
                SendOutput::Packet(p) => {
                    qpkt.len = p.len();
                    sender.send_done();
                }
                SendOutput::Error { err, .. } => {
                    debug!("Error packetising");
                    sender.send_done();
                    break Err(err);
                }
                SendOutput::Complete { tag, cookie: _ } => break Ok(tag),
            }
        }
    }
}

/// The "consumer" side of a queue of packets to send out a MCTP interface,
///
/// An MCTP transport implementation will read packets to send with
/// [`outbound()`](Self::outbound).
pub struct PortBottom<'a> {
    /// packet queue
    packets: Receiver<'a, PortRawMutex, PktBuf>,
}

impl PortBottom<'_> {
    /// Retrieve an outbound packet to send for this port.
    ///
    /// Should call [`outbound_done()`](Self::outbound_done) to consume the
    /// packet and advance the queue.
    /// `outbound()` may be called multiple times to peek at the same packet.
    /// Also returns the destination EID.
    pub async fn outbound(&mut self) -> (&[u8], Eid) {
        if self.packets.len() > 1 {
            trace!("packets avail {}", self.packets.len());
        }
        let pkt = self.packets.receive().await;
        // OK unwrap, checked by channel sender
        let dest = MctpHeader::decode(pkt).unwrap().dest;
        (pkt, dest)
    }

    /// Attempt to retrieve an outbound packet.
    ///
    /// This is the same as [`outbound()`](Self::outbound) but returns
    /// `None` immediately if not available.
    ///
    /// Should call [`outbound_done()`](Self::outbound_done) to consume the
    /// packet and advance the queue.
    /// `try_outbound()` may be called multiple times to peek at the same packet.
    pub fn try_outbound(&mut self) -> Option<(&[u8], Eid)> {
        trace!("packets avail {} try", self.packets.len());
        self.packets.try_receive().map(|pkt| {
            let dest = MctpHeader::decode(pkt).unwrap().dest;
            (&**pkt, dest)
        })
    }

    /// Consume the outbound packet and advance the queue.
    pub fn outbound_done(&mut self) {
        self.packets.receive_done()
    }
}

/// Storage for a Port, being a physical MCTP interface.
// TODO: instead of storing Vec<u8, N>, it could
// store `&'r []` and a length field, which would allow different ports
// have different MAX_MESSAGE/MAX_MTU. Does add another lifetime parameter.
pub struct PortStorage<const FORWARD_QUEUE: usize = 4> {
    /// forwarded packet queue
    packets: [PktBuf; FORWARD_QUEUE],
}

impl<const FORWARD_QUEUE: usize> PortStorage<FORWARD_QUEUE> {
    pub fn new() -> Self {
        Self {
            packets: [const { PktBuf::new() }; FORWARD_QUEUE],
        }
    }
}

impl<const FORWARD_QUEUE: usize> Default for PortStorage<FORWARD_QUEUE> {
    fn default() -> Self {
        Self::new()
    }
}

pub struct PortBuilder<'a> {
    /// forwarded packet queue
    packets: Channel<'a, PortRawMutex, PktBuf>,
}

impl<'a> PortBuilder<'a> {
    pub fn new<const FORWARD_QUEUE: usize>(
        storage: &'a mut PortStorage<FORWARD_QUEUE>,
    ) -> Self {
        // PortBuilder and PortStorage need to be separate structs, since
        // zerocopy_channel::Channel takes a slice.
        Self {
            packets: Channel::new(storage.packets.as_mut_slice()),
        }
    }

    pub fn build(
        &mut self,
        mtu: usize,
    ) -> Result<(PortTop<'_>, PortBottom<'_>)> {
        if mtu > MAX_MTU {
            debug!("port mtu {} > MAX_MTU {}", mtu, MAX_MTU);
            return Err(Error::BadArgument);
        }

        let (ps, pr) = self.packets.split();

        let t = PortTop {
            packets: AsyncMutex::new(ps),
            mtu,
        };
        let b = PortBottom { packets: pr };
        Ok((t, b))
    }
}

#[derive(Default)]
struct WakerPoolInner {
    pool: FnvIndexMap<AppCookie, WakerRegistration, MAX_CHANNELS>,
    next: usize,
}

struct WakerPool {
    inner: BlockingMutex<RefCell<WakerPoolInner>>,
}

impl Default for WakerPool {
    fn default() -> Self {
        Self {
            inner: BlockingMutex::new(RefCell::new(Default::default())),
        }
    }
}

impl WakerPool {
    fn wake(&self, cookie: AppCookie) {
        self.inner.lock(|i| i.borrow_mut().pool[&cookie].wake())
    }

    fn wake_all(&self) {
        self.inner.lock(|i| {
            for w in i.borrow_mut().pool.values_mut() {
                w.wake()
            }
        })
    }

    fn register(&self, cookie: AppCookie, waker: &Waker) {
        self.inner
            .lock(|i| i.borrow_mut().pool[&cookie].register(waker))
    }

    /// Returns `Error::NoSpace` if all slots are occupied.
    fn alloc(&self) -> Result<AppCookie> {
        self.inner.lock(|i| {
            let mut i = i.borrow_mut();

            loop {
                // Allocate an arbitrary AppCookie
                i.next = i.next.wrapping_add(1);
                let cookie = AppCookie(i.next);
                let Entry::Vacant(entry) = i.pool.entry(cookie) else {
                    // Cookie was already in the map.
                    // This is unlikely, a retry will soon succeed.
                    continue;
                };

                break if entry.insert(WakerRegistration::new()).is_err() {
                    // Map is full
                    Err(Error::NoSpace)
                } else {
                    Ok(cookie)
                };
            }
        })
    }

    fn remove(&self, cookie: AppCookie) {
        self.inner.lock(|i| {
            let e = i.borrow_mut().pool.remove(&cookie);
            debug_assert!(e.is_some());
        });
    }
}

/// An async MCTP stack with routing.
///
/// This interfaces between transport ports and MCTP using applications.
///
/// Applications can use [`req()`](Self::req) and [`listener()`](Self::listener)
/// to obtain instances of the [`mctp`] async traits.
///
/// Device-provided input handlers feed input MCTP packets to
/// [`inbound()`](Self::inbound).
///
/// For outbound packets each port has queue split into `PortTop` and `PortBottom`.
/// `Router` will feed packets for a port into the top, and device output handlers
/// will read from [`PortBottom`] and write out the specific MCTP transport.
///
/// [`update_time()`](Self::update_time) should be called periodically to
/// handle timeouts.
///
/// Packets not destined for the local EID will be forwarded out a port
/// determined by the user-provided [`PortLookup`] implementation.
pub struct Router<'r> {
    inner: AsyncMutex<RouterInner<'r>>,
    ports: &'r [PortTop<'r>],

    /// Listeners for different message types.
    // Has a separate non-async Mutex so it can be used by RouterAsyncListener::drop()
    // TODO filter by more than just MsgType
    app_listeners:
        BlockingMutex<RefCell<Vec<(MsgType, AppCookie), MAX_LISTENERS>>>,

    recv_wakers: WakerPool,

    /// Temporary storage to flatten vectorised local sent messages
    // prior to fragmentation and queueing.
    work_msg: AsyncMutex<Vec<u8, MAX_PAYLOAD>>,
}

pub struct RouterInner<'r> {
    /// Core MCTP stack
    stack: Stack,

    lookup: &'r mut dyn PortLookup,
}

impl<'r> Router<'r> {
    /// Create a new Router.
    ///
    /// The EID of the provided `stack` is used to match local destination packets.
    ///
    /// `ports` is a list of transport interfaces for the router. The indices
    /// of the `ports`  slice are used as `PortId` identifiers.
    ///
    /// `lookup` callbacks define the routing table for outbound packets.
    pub fn new(
        stack: Stack,
        ports: &'r [PortTop<'r>],
        lookup: &'r mut dyn PortLookup,
    ) -> Self {
        let inner = RouterInner { stack, lookup };

        let app_listeners = BlockingMutex::new(RefCell::new(Vec::new()));

        Self {
            inner: AsyncMutex::new(inner),
            app_listeners,
            recv_wakers: Default::default(),
            ports,
            work_msg: AsyncMutex::new(Vec::new()),
        }
    }

    /// Called periodically to update the clock and check timeouts.
    ///
    /// A suitable interval (milliseconds) for the next call to `update_time()` will
    /// be returned, currently a maximum of 100 ms.
    pub async fn update_time(&self, now_millis: u64) -> Result<u64> {
        let mut inner = self.inner.lock().await;
        let (next, expired) = inner.stack.update(now_millis)?;
        if expired {
            // Wake pending receivers in case one was waiting on a now-expired response.
            // TODO something more efficient, maybe Reassembler should hold a waker?
            self.recv_wakers.wake_all();
        }
        Ok(next)
    }

    /// Provide an incoming packet to the router.
    ///
    /// This expects a single MCTP packet, with no transport binding header.
    ///
    /// Returns the packet's MCTP source EID for any valid packet,
    /// regardless of whether the packet is handled, forwarded, or dropped.
    pub async fn inbound(&self, pkt: &[u8], port: PortId) -> Option<Eid> {
        let mut inner = self.inner.lock().await;

        let header = MctpHeader::decode(pkt).ok()?;
        // Source EID is returned even if packet routing fails
        let ret_src = Some(header.src);

        // Handle locally if possible
        if inner.stack.is_local_dest(pkt) {
            match inner.stack.receive(pkt) {
                // Complete message
                Ok(Some(msg)) => {
                    self.incoming_local(msg).await;
                    return ret_src;
                }
                // Fragment consumed, message is incomplete
                Ok(None) => {
                    return ret_src;
                }
                Err(e) => {
                    debug!("Dropped local recv packet. {}", e);
                    return ret_src;
                }
            }
        }

        // Look for a route to forward to
        let Some(p) = inner.lookup.by_eid(header.dest, Some(port)) else {
            debug!("No route for recv {}", header.dest);
            return ret_src;
        };
        drop(inner);

        let Some(top) = self.ports.get(p.0 as usize) else {
            debug!("Bad port ID from lookup");
            return ret_src;
        };

        let _ = top.forward_packet(pkt).await;
        ret_src
    }

    async fn incoming_local(&self, msg: MctpMessage<'_>) {
        trace!("incoming local, type {}", msg.typ.0);
        debug_assert!(
            msg.tag.is_owner() == msg.cookie().is_none(),
            "cookie set only for responses"
        );

        if msg.tag.is_owner() {
            self.incoming_listener(msg).await
        } else {
            self.incoming_response(msg).await
        }
    }

    async fn incoming_listener(&self, mut msg: MctpMessage<'_>) {
        // wake the packet listener
        self.app_listeners.lock(|a| {
            let mut a = a.borrow_mut();
            // Find the matching listener
            for (t, cookie) in a.iter_mut() {
                if *t == msg.typ {
                    // Mark the message for that listener
                    msg.set_cookie(Some(*cookie));
                    msg.retain();

                    self.recv_wakers.wake(*cookie);
                    trace!("listener match");
                    return;
                }
            }
            trace!("listener no match");
        });
    }

    async fn incoming_response(&self, mut msg: MctpMessage<'_>) {
        if let Some(cookie) = msg.cookie() {
            msg.retain();
            self.recv_wakers.wake(cookie);
        }
    }

    fn app_bind(&self, typ: MsgType) -> Result<AppCookie> {
        self.app_listeners.lock(|a| {
            let mut a = a.borrow_mut();

            // Check for existing binds with the same type
            if a.iter().any(|(t, _cookie)| *t == typ) {
                return Err(Error::AddrInUse);
            }

            // Find a free slot
            if a.is_full() {
                return Err(Error::NoSpace);
            }
            let cookie = self.recv_wakers.alloc()?;
            let _ = a.push((typ, cookie));
            Ok(cookie)
        })
    }

    fn app_unbind(&self, cookie: AppCookie) {
        self.app_listeners.lock(|a| {
            let mut a = a.borrow_mut();

            let orig = a.len();
            a.retain(|(_t, c)| *c != cookie);
            debug_assert_eq!(orig, a.len() + 1, "One entry removed");

            // No need to wake any waker, unbind only occurs
            // on RouterAsyncListener::drop.
            self.recv_wakers.remove(cookie);
        })
    }

    async fn app_recv<'f>(
        &self,
        cookie: AppCookie,
        buf: &'f mut [u8],
    ) -> Result<(&'f mut [u8], Eid, MsgType, Tag, MsgIC)> {
        // buf can only be taken once
        let mut buf = Some(buf);

        // Wait for the message to arrive
        poll_fn(|cx| {
            let l = pin!(self.inner.lock());
            let Poll::Ready(mut inner) = l.poll(cx) else {
                return Poll::Pending;
            };

            let Some(msg) = inner.stack.get_deferred_bycookie(&[cookie]) else {
                self.recv_wakers.register(cookie, cx.waker());
                return Poll::Pending;
            };

            let buf = buf.take().unwrap();
            let res = if msg.payload.len() > buf.len() {
                trace!("no space");
                Err(Error::NoSpace)
            } else {
                trace!("good len {}", msg.payload.len());
                let buf = &mut buf[..msg.payload.len()];
                buf.copy_from_slice(msg.payload);
                Ok((buf, msg.source, msg.typ, msg.tag, msg.ic))
            };

            Poll::Ready(res)
        })
        .await
    }

    /// Used by traits to send a message, see comment on .send_vectored() methods
    ///
    /// TODO should handle loopback if eid matches local stack's
    async fn app_send_message(
        &self,
        eid: Eid,
        typ: MsgType,
        tag: Option<Tag>,
        tag_expires: bool,
        integrity_check: MsgIC,
        buf: &[&[u8]],
        cookie: Option<AppCookie>,
    ) -> Result<Tag> {
        let mut inner = self.inner.lock().await;

        let Some(p) = inner.lookup.by_eid(eid, None) else {
            debug!("No route for recv {}", eid);
            return Err(Error::TxFailure);
        };

        let Some(top) = self.ports.get(p.0 as usize) else {
            debug!("Bad port ID from lookup");
            return Err(Error::TxFailure);
        };

        let mtu = top.mtu;
        let mut fragmenter = inner
            .stack
            .start_send(
                eid,
                typ,
                tag,
                tag_expires,
                integrity_check,
                Some(mtu),
                cookie,
            )
            .inspect_err(|e| trace!("error fragmenter {}", e))?;
        // release to allow other ports to continue work
        drop(inner);

        // lock the shared work buffer against other app_send_message()
        let mut work_msg = self.work_msg.lock().await;
        top.send_message(&mut fragmenter, buf, &mut work_msg).await
    }

    /// Only needs to be called for tags allocated with tag_expires=false
    ///
    /// Must only be called for owned tags.
    async fn app_release_tag(&self, eid: Eid, tag: Tag) {
        let Tag::Owned(tv) = tag else { unreachable!() };
        let mut inner = self.inner.lock().await;

        if let Err(e) = inner.stack.cancel_flow(eid, tv) {
            warn!("flow cancel failed {}", e);
        }
    }

    /// Create a `AsyncReqChannel` instance.
    pub fn req(&'r self, eid: Eid) -> RouterAsyncReqChannel<'r> {
        RouterAsyncReqChannel::new(eid, self)
    }

    /// Create a `AsyncListener` instance.
    ///
    /// Will receive incoming messages with the TO bit set for the given `typ`.
    pub fn listener(&'r self, typ: MsgType) -> Result<RouterAsyncListener<'r>> {
        let cookie = self.app_bind(typ)?;
        Ok(RouterAsyncListener {
            cookie,
            router: self,
        })
    }

    /// Retrieve the EID assigned to the local stack
    pub async fn get_eid(&self) -> Eid {
        let inner = self.inner.lock().await;
        inner.stack.own_eid
    }

    /// Set the EID assigned to the local stack
    pub async fn set_eid(&self, eid: Eid) -> mctp::Result<()> {
        let mut inner = self.inner.lock().await;
        inner.stack.set_eid(eid.0)
    }
}

/// A request channel.
pub struct RouterAsyncReqChannel<'r> {
    eid: Eid,
    sent_tag: Option<Tag>,
    router: &'r Router<'r>,
    tag_expires: bool,
    cookie: Option<AppCookie>,
}

impl<'r> RouterAsyncReqChannel<'r> {
    fn new(eid: Eid, router: &'r Router<'r>) -> Self {
        RouterAsyncReqChannel {
            eid,
            sent_tag: None,
            tag_expires: true,
            router,
            cookie: None,
        }
    }

    /// Set the tag to not expire. That allows multiple calls to `send()`.
    ///
    /// `async_drop` must be called prior to drop.
    pub fn tag_noexpire(&mut self) -> Result<()> {
        if self.sent_tag.is_some() {
            return Err(Error::BadArgument);
        }
        self.tag_expires = false;
        Ok(())
    }

    /// This must be called prior to drop whenever `tag_noexpire()` is used.
    ///
    /// A workaround until async drop is implemented in Rust itself.
    /// <https://github.com/rust-lang/rust/issues/126482>
    pub async fn async_drop(self) {
        if !self.tag_expires {
            if let Some(tag) = self.sent_tag {
                self.router.app_release_tag(self.eid, tag).await;
            }
        }
    }
}

impl Drop for RouterAsyncReqChannel<'_> {
    fn drop(&mut self) {
        if !self.tag_expires && self.sent_tag.is_some() {
            warn!("Didn't call async_drop()");
        }
        if let Some(c) = self.cookie {
            self.router.recv_wakers.remove(c);
        }
    }
}

/// A request channel
///
/// Created with [`Router::req()`](Router::req).
impl mctp::AsyncReqChannel for RouterAsyncReqChannel<'_> {
    /// Send a message.
    ///
    /// This will async block until the message has been enqueued to the physical port.
    /// Note that it will return failure immediately if the MCTP stack has no available tags,
    /// that behaviour may need changing in future.
    ///
    /// Subsequent calls will fail unless tag_noexpire() was performed.
    async fn send_vectored(
        &mut self,
        typ: MsgType,
        integrity_check: MsgIC,
        bufs: &[&[u8]],
    ) -> Result<()> {
        // For the first call, we pass a None tag, get an Owned one allocated.
        // Subsequent calls will fail unless tag_noexpire() was performed.
        let tag = self
            .router
            .app_send_message(
                self.eid,
                typ,
                self.sent_tag,
                self.tag_expires,
                integrity_check,
                bufs,
                None,
            )
            .await?;
        debug_assert!(matches!(tag, Tag::Owned(_)));
        self.sent_tag = Some(tag);
        if self.cookie.is_none() {
            self.cookie = Some(self.router.recv_wakers.alloc()?);
        }
        Ok(())
    }

    async fn recv<'f>(
        &mut self,
        buf: &'f mut [u8],
    ) -> Result<(MsgType, MsgIC, &'f mut [u8])> {
        let Some(Tag::Owned(tv)) = self.sent_tag else {
            debug!("recv without send");
            return Err(Error::BadArgument);
        };
        let Some(cookie) = self.cookie else {
            return Err(Error::BadArgument);
        };
        let recv_tag = Tag::Unowned(tv);
        let (buf, eid, typ, tag, ic) =
            self.router.app_recv(cookie, buf).await?;
        debug_assert_eq!(tag, recv_tag);
        debug_assert_eq!(eid, self.eid);
        Ok((typ, ic, buf))
    }

    fn remote_eid(&self) -> Eid {
        self.eid
    }
}

/// A response channel.
///
/// Returned by [`RouterAsyncListener::recv`](mctp::AsyncListener::recv).
pub struct RouterAsyncRespChannel<'r> {
    eid: Eid,
    tv: TagValue,
    router: &'r Router<'r>,
    typ: MsgType,
}

impl<'r> mctp::AsyncRespChannel for RouterAsyncRespChannel<'r> {
    type ReqChannel<'a>
        = RouterAsyncReqChannel<'r>
    where
        Self: 'a;

    /// Send a message.
    ///
    /// See description of `RouterAsyncReqChannel::send_vectored()`.
    async fn send_vectored(
        &mut self,
        integrity_check: MsgIC,
        bufs: &[&[u8]],
    ) -> Result<()> {
        let tag = Some(Tag::Unowned(self.tv));
        self.router
            .app_send_message(
                self.eid,
                self.typ,
                tag,
                false,
                integrity_check,
                bufs,
                None,
            )
            .await?;
        Ok(())
    }

    fn remote_eid(&self) -> Eid {
        self.eid
    }

    fn req_channel(&self) -> mctp::Result<Self::ReqChannel<'_>> {
        Ok(RouterAsyncReqChannel::new(self.eid, self.router))
    }
}

/// A listener.
///
/// Created with [`Router::listener()`](Router::listener).
pub struct RouterAsyncListener<'r> {
    router: &'r Router<'r>,
    cookie: AppCookie,
}

impl<'r> mctp::AsyncListener for RouterAsyncListener<'r> {
    // type RespChannel<'a> = RouterAsyncRespChannel<'a> where Self: 'a;
    type RespChannel<'a>
        = RouterAsyncRespChannel<'r>
    where
        Self: 'a;

    async fn recv<'f>(
        &mut self,
        buf: &'f mut [u8],
    ) -> mctp::Result<(MsgType, MsgIC, &'f mut [u8], Self::RespChannel<'_>)>
    {
        let (msg, eid, typ, tag, ic) =
            self.router.app_recv(self.cookie, buf).await?;

        let Tag::Owned(tv) = tag else {
            debug_assert!(false, "listeners only accept owned tags");
            return Err(Error::InternalError);
        };

        let resp = RouterAsyncRespChannel {
            eid,
            tv,
            router: self.router,
            typ,
        };
        Ok((typ, ic, msg, resp))
    }
}

impl Drop for RouterAsyncListener<'_> {
    fn drop(&mut self) {
        self.router.app_unbind(self.cookie)
    }
}
