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
use core::mem::take;
use core::pin::pin;
use core::task::{Poll, Waker};

use crate::{
    config, AppCookie, Fragmenter, MctpHeader, MctpMessage, SendOutput, Stack,
    MAX_MTU, MAX_PAYLOAD,
};
use mctp::{Eid, Error, MsgIC, MsgType, Result, Tag, TagValue};

use crate::zerocopy_channel::{FixedChannel, Receiver};
use embassy_sync::waitqueue::{AtomicWaker, WakerRegistration};

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
pub trait PortLookup: Sync + Send {
    /// Returns `(PortId, MTU)` for a destination EID.
    ///
    /// Return a `None` `PortId` to drop the packet as unreachable. This lookup
    /// is only called for outbound packets - packets destined for the local EID
    /// will not be passed to this callback.
    ///
    /// A MTU can optionally be returned, it will be applied to locally fragmented packets.
    /// This MTU is ignored for forwarded packets in a bridge (the transport implementation
    /// can drop packets if desired).
    /// If MTU is `None`, the MCTP minimum 64 is used.
    ///
    /// `source_port` is the incoming interface of a forwarded packet,
    /// or `None` for locally generated packets.
    fn by_eid(
        &self,
        eid: Eid,
        source_port: Option<PortId>,
    ) -> (Option<PortId>, Option<usize>);
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

impl Default for PktBuf {
    fn default() -> Self {
        Self::new()
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
pub struct PortTop {
    /// Forwarded packet queue.
    channel: FixedChannel<PortRawMutex, PktBuf, { config::PORT_TXQUEUE }>,
    // Callers should hold send_mutex when using channel.sender().
    // send_message() will wait on send_mutex being available using sender_waker.
    send_mutex: BlockingMutex<()>,
    sender_waker: AtomicWaker,
}

impl PortTop {
    pub fn new() -> Self {
        Self {
            channel: FixedChannel::new(),
            send_mutex: BlockingMutex::new(()),
            sender_waker: AtomicWaker::new(),
        }
    }

    /// Return the bottom half port for the channel.
    ///
    /// Applications call Router::port().
    /// Returns None if already borrowed. `id` is not checked, just passed through.
    fn bottom(&self, id: PortId) -> Option<Port<'_>> {
        self.channel.receiver().map(|packets| Port { packets, id })
    }

    /// Enqueues a packet.
    ///
    /// Do not call with locks held.
    /// May block waiting for a port queue to flush.
    /// Packet must be a valid MCTP packet, may panic otherwise.
    async fn forward_packet(&self, pkt: &[u8]) -> Result<()> {
        debug_assert!(MctpHeader::decode(pkt).is_ok());

        // With forwarded packets we don't want to block if
        // the queue is full (we drop packets instead).
        let r = self.send_mutex.lock(|_| {
            // OK unwrap, we have the send_mutex
            let mut sender = self.channel.sender().unwrap();

            // Get a slot to send
            let slot = sender.try_send().ok_or_else(|| {
                debug!("Dropped forward packet");
                Error::TxFailure
            })?;

            // Fill the buffer
            if slot.set(pkt).is_ok() {
                sender.send_done();
                Ok(())
            } else {
                debug!("Oversized forward packet");
                Err(Error::TxFailure)
            }
        });
        self.sender_waker.wake();
        r
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

        // send_message() needs to wait for packets to get enqueued to the PortTop channel.
        // It shouldn't hold the send_mutex() across an await, since that would block
        // forward_packet().
        poll_fn(|cx| {
            self.send_mutex.lock(|_| {
                // OK to unwrap, protected by send_mutex.lock()
                let mut sender = self.channel.sender().unwrap();

                // Send as much as we can in a loop without blocking.
                // If it blocks the next poll_fn iteration will continue
                // where it left off.
                loop {
                    let Poll::Ready(qpkt) = sender.poll_send(cx) else {
                        self.sender_waker.register(cx.waker());
                        break Poll::Pending;
                    };

                    qpkt.len = 0;
                    match fragmenter.fragment(payload, &mut qpkt.data) {
                        SendOutput::Packet(p) => {
                            qpkt.len = p.len();
                            sender.send_done();
                            if fragmenter.is_done() {
                                // Break here rather than using SendOutput::Complete,
                                // since we don't want to call channel.sender() an extra time.
                                break Poll::Ready(Ok(fragmenter.tag()));
                            }
                        }
                        SendOutput::Error { err, .. } => {
                            debug!("Error packetising");
                            debug_assert!(false, "fragment () shouldn't fail");
                            break Poll::Ready(Err(err));
                        }
                        SendOutput::Complete { .. } => unreachable!(),
                    }
                }
            })
        })
        .await
    }
}

impl Default for PortTop {
    fn default() -> Self {
        Self::new()
    }
}

/// The "consumer" side of a queue of packets to send out a MCTP interface,
///
/// An MCTP transport implementation will read packets to send with
/// [`outbound()`](Self::outbound).
pub struct Port<'a> {
    /// packet queue
    packets: Receiver<'a, PortRawMutex, PktBuf>,
    id: PortId,
}

impl Port<'_> {
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

    /// Retrieve the `PortId`.
    pub fn id(&self) -> PortId {
        self.id
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

#[derive(Default)]
struct WakerPoolInner {
    // Value is None for AppCookies that are pending deallocation.
    // Deallocation is deferred since it needs an async lock on the stack.
    pool: FnvIndexMap<AppCookie, Option<WakerRegistration>, MAX_CHANNELS>,

    /// Next AppCookie to allocate. Arbitrary, but incrementing
    /// values are nicer for debugging.
    next: usize,

    /// Set when remove() is called, lets cleanup() avoid scanning the
    /// whole pool if not necessary.
    need_cleanup: bool,
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
        self.inner.lock(|i| {
            let mut i = i.borrow_mut();
            if let Some(Some(w)) = i.pool.get_mut(&cookie) {
                w.wake()
            } else {
                // Some(None) case is when .remove() has removed the slot, but cleanup()
                // hasn't run yet.
                //
                // None case is when a ReqChannel is dropped but the core stack
                // subsequently receives a response message corresponding to that cookie,
                // prior to cleanup().
                //
                // In both cases we do nothing, a subsequent cleanup will handle it.
            }
        })
    }

    fn wake_all(&self) {
        self.inner.lock(|i| {
            for w in i.borrow_mut().pool.values_mut().flatten() {
                w.wake()
            }
        })
    }

    fn register(&self, cookie: AppCookie, waker: &Waker) {
        self.inner.lock(|i| {
            if let Some(w) = i.borrow_mut().pool[&cookie].as_mut() {
                w.register(waker);
            } else {
                debug_assert!(false, "register called after remove");
            }
        });
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

                break if entry.insert(Some(WakerRegistration::new())).is_err() {
                    // Map is full
                    Err(Error::NoSpace)
                } else {
                    Ok(cookie)
                };
            }
        })
    }

    // Marks the cookie as unused. It will later be fully cleared by a call
    // to cleanup(). They are split so that remove() can call from drop handlers
    // (no async lock possible), while cleanup() can run later holding an async lock.
    fn remove(&self, cookie: AppCookie) {
        self.inner.lock(|i| {
            let mut i = i.borrow_mut();
            if let Some(e) = i.pool.get_mut(&cookie) {
                debug_assert!(e.is_some(), "remove called twice");
                *e = None;
                i.need_cleanup = true;
            }
        });
    }

    // Finalises items previously remove()d, calling a closure with the cookie.
    //
    // Does nothing if no cleanup is necessary.
    fn cleanup<F>(&self, mut f: F)
    where
        F: FnMut(AppCookie),
    {
        self.inner.lock(|i| {
            let mut i = i.borrow_mut();
            if take(&mut i.need_cleanup) {
                i.pool.retain(|cookie, w| {
                    if w.is_none() {
                        f(*cookie);
                    }
                    w.is_some()
                })
            }
        })
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
/// [`update_time()`](Self::update_time) should be called periodically to
/// handle timeouts.
///
/// Packets not destined for the local EID will be forwarded out a port
/// determined by the user-provided [`PortLookup`] implementation.
///
/// Outbound packets are provided to a transport's `Port` instance,
/// returned by [`port()`](Self::port).
pub struct Router<'r> {
    inner: AsyncMutex<RouterInner<'r>>,
    ports: Vec<&'r mut PortTop, { config::MAX_PORTS }>,

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

    /// Minimum receive deadline. u64::MAX when cleared.
    recv_deadline: u64,

    lookup: &'r dyn PortLookup,
}

impl<'r> Router<'r> {
    /// Create a new Router.
    ///
    /// `own_eid` is the EID that will respond locally to messages, and
    /// is used as a source address.
    ///
    /// `lookup` callbacks define the routing table for outbound packets.
    ///
    /// `now_millis` is the current timestamp, as would be provided to
    /// [`update_time`](Self::update_time).
    pub fn new(
        own_eid: Eid,
        lookup: &'r dyn PortLookup,
        now_millis: u64,
    ) -> Self {
        let stack = Stack::new(own_eid, now_millis);
        let inner = RouterInner {
            stack,
            recv_deadline: u64::MAX,
            lookup,
        };

        let app_listeners = BlockingMutex::new(RefCell::new(Vec::new()));

        Self {
            inner: AsyncMutex::new(inner),
            app_listeners,
            ports: Vec::new(),
            recv_wakers: Default::default(),
            work_msg: AsyncMutex::new(Vec::new()),
        }
    }

    pub fn add_port(&mut self, top: &'r mut PortTop) -> Result<PortId> {
        self.ports.push(top).map_err(|_| Error::NoSpace)?;
        Ok(PortId((self.ports.len() - 1) as u8))
    }

    /// Return a port.
    ///
    /// A port may only be borrowed once (may be reborrowed after dropping).
    pub fn port(&self, id: PortId) -> Result<Port<'_>> {
        let port = self.ports.get(id.0 as usize).ok_or_else(|| {
            debug!("Bad port index");
            Error::BadArgument
        })?;
        port.bottom(id).ok_or_else(|| {
            debug!("Port already borrowed");
            Error::BadArgument
        })
    }

    /// Called periodically to update the clock and check timeouts.
    ///
    /// A suitable interval (milliseconds) for the next call to `update_time()` will
    /// be returned, currently a maximum of 100 ms.
    pub async fn update_time(&self, now_millis: u64) -> Result<u64> {
        let mut inner = self.inner.lock().await;
        let (next, mut expired) = inner.stack.update(now_millis)?;

        if inner.recv_deadline <= now_millis {
            expired = true;
            // app_recv() will update with next minimum deadline.
            inner.recv_deadline = u64::MAX;
        }

        if expired {
            // Wake pending receivers in case one was waiting on a now-expired response.
            // TODO something more efficient, maybe Reassembler should hold a waker?
            trace!("update_time expired");
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
            // Clean up any outstanding reassembly slots, to ensure
            // they don't prevent the new packet being received.
            // This is cheap.
            self.recv_wakers.cleanup(|cookie| {
                inner.stack.cancel_flow_bycookie(cookie);
                while inner.stack.get_deferred_bycookie(&[cookie]).is_some() {}
            });

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
        let (Some(p), _mtu) = inner.lookup.by_eid(header.dest, Some(port))
        else {
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
        timeout: Option<u64>,
    ) -> Result<(&'f mut [u8], Eid, MsgType, Tag, MsgIC)> {
        // buf can only be taken once
        let mut buf = Some(buf);

        let mut deadline = None;

        // Wait for the message to arrive
        poll_fn(|cx| {
            let l = pin!(self.inner.lock());
            let Poll::Ready(mut inner) = l.poll(cx) else {
                return Poll::Pending;
            };

            // Convert timeout to a deadline on the first iteration
            if deadline.is_none() {
                if let Some(timeout) = timeout {
                    deadline = Some(timeout + inner.stack.now())
                }
            }

            let expired =
                deadline.map(|d| inner.stack.now() >= d).unwrap_or(false);

            if let Some(deadline) = deadline {
                // Update the Router-wide deadline.
                if !expired {
                    inner.recv_deadline = inner.recv_deadline.min(deadline);
                }
            }

            let Some(msg) = inner.stack.get_deferred_bycookie(&[cookie]) else {
                trace!("no message");
                if expired {
                    return Poll::Ready(Err(mctp::Error::TimedOut));
                }
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

        let (port, mtu) = inner.lookup.by_eid(eid, None);
        let Some(p) = port else {
            debug!("No route for recv {}", eid);
            return Err(Error::TxFailure);
        };

        let Some(top) = self.ports.get(p.0 as usize) else {
            debug!("Bad port ID from lookup");
            return Err(Error::TxFailure);
        };

        let mut fragmenter = inner
            .stack
            .start_send(
                eid,
                typ,
                tag,
                tag_expires,
                integrity_check,
                mtu,
                cookie,
            )
            .inspect_err(|e| trace!("error fragmenter {}", e))?;
        // release to allow other ports to continue work
        drop(inner);

        // lock the shared work buffer against other app_send_message()
        let mut work_msg = self.work_msg.lock().await;
        top.send_message(&mut fragmenter, buf, &mut work_msg).await
    }

    /// Create a `AsyncReqChannel` instance.
    pub fn req(&self, eid: Eid) -> RouterAsyncReqChannel<'_, 'r> {
        RouterAsyncReqChannel::new(eid, self)
    }

    /// Create a `AsyncListener` instance.
    ///
    /// Will receive incoming messages with the TO bit set for the given `typ`.
    pub fn listener(
        &self,
        typ: MsgType,
    ) -> Result<RouterAsyncListener<'_, 'r>> {
        let cookie = self.app_bind(typ)?;
        Ok(RouterAsyncListener {
            cookie,
            router: self,
            timeout: None,
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

    /// Clears the EID assigned to the local stack
    pub async fn clear_eid(&self) {
        let mut inner = self.inner.lock().await;
        inner.stack.clear_eid();
    }
}

impl core::fmt::Debug for Router<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Router").finish_non_exhaustive()
    }
}

/// A request channel.
#[derive(Debug)]
pub struct RouterAsyncReqChannel<'g, 'r> {
    /// Destination EID
    eid: Eid,
    /// Tag from the last `send()`.
    ///
    /// Cleared upon receiving a response, except in the case of !tag_expires.
    last_tag: Option<Tag>,
    router: &'g Router<'r>,
    tag_expires: bool,
    cookie: Option<AppCookie>,
    timeout: Option<u64>,
}

impl<'g, 'r> RouterAsyncReqChannel<'g, 'r> {
    fn new(eid: Eid, router: &'g Router<'r>) -> Self {
        RouterAsyncReqChannel {
            eid,
            last_tag: None,
            tag_expires: true,
            router,
            cookie: None,
            timeout: None,
        }
    }

    /// Set the tag to not expire. That allows multiple calls to `send()`.
    ///
    /// Should be called prior to any `send()` and may only be called once
    /// for a `RouterAsyncReqChannel`.
    /// This can also be called after the `recv()` has completed.
    pub fn tag_noexpire(&mut self) -> Result<()> {
        if self.last_tag.is_some() {
            return Err(Error::BadArgument);
        }
        self.tag_expires = false;
        Ok(())
    }

    /// Set a timeout.
    ///
    /// Specified in milliseconds.
    pub fn set_timeout(&mut self, timeout: Option<u64>) {
        self.timeout = timeout;
    }
}

impl Drop for RouterAsyncReqChannel<'_, '_> {
    fn drop(&mut self) {
        if !self.tag_expires && self.last_tag.is_some() {
            // tag cleanup will require a cookie
            debug_assert!(self.cookie.is_some());
        }

        if let Some(c) = self.cookie {
            self.router.recv_wakers.remove(c);
        }
    }
}

/// A request channel
///
/// Created with [`Router::req()`](Router::req).
impl mctp::AsyncReqChannel for RouterAsyncReqChannel<'_, '_> {
    /// Send a message.
    ///
    /// This will async block until the message has been enqueued to the physical port.
    /// Note that it will return failure immediately if the MCTP stack has no available tags,
    /// that behaviour may need changing in future.
    ///
    /// A `RouterAsyncReqChannel` can only receive responses for its
    /// most recent `send()`, unless unless `tag_noexpire()` was set.
    async fn send_vectored(
        &mut self,
        typ: MsgType,
        integrity_check: MsgIC,
        bufs: &[&[u8]],
    ) -> Result<()> {
        let send_tag = if self.tag_expires {
            // Expiring (normal) case. Pass a None tag, and use a new cookie.
            // An allocated tag is returned from app_send_message().
            if let Some(c) = self.cookie.take() {
                self.router.recv_wakers.remove(c);
            }
            None
        } else {
            // Non-expiring case, allocate a tag and cookie the
            // first time then reuse it.
            self.last_tag
        };

        if self.cookie.is_none() {
            self.cookie = Some(self.router.recv_wakers.alloc()?);
        }

        let tag = self
            .router
            .app_send_message(
                self.eid,
                typ,
                send_tag,
                self.tag_expires,
                integrity_check,
                bufs,
                self.cookie,
            )
            .await?;
        debug_assert!(matches!(tag, Tag::Owned(_)));
        self.last_tag = Some(tag);
        Ok(())
    }

    /// Receive a message.
    ///
    /// In the normal case, this will only receive responses to the
    /// most recent `send()`. Responses to earlier `send()`s will be dropped.
    /// When `tag_noexpire()` is set, this can receive multiple responses.
    async fn recv<'f>(
        &mut self,
        buf: &'f mut [u8],
    ) -> Result<(MsgType, MsgIC, &'f mut [u8])> {
        let Some(Tag::Owned(tv)) = self.last_tag else {
            debug!("recv without send");
            return Err(Error::BadArgument);
        };
        let Some(cookie) = self.cookie else {
            return Err(Error::BadArgument);
        };
        let recv_tag = Tag::Unowned(tv);
        let (buf, eid, typ, tag, ic) =
            self.router.app_recv(cookie, buf, self.timeout).await?;
        debug_assert_eq!(tag, recv_tag);
        debug_assert_eq!(eid, self.eid);

        if self.tag_expires {
            self.last_tag = None;

            // Remove the cookie. It would get cleared up anyway
            // by drop() or a later send(), but this means it won't
            // be taking up a slot in the interim.
            if let Some(c) = self.cookie.take() {
                self.router.recv_wakers.remove(c);
            }
        }
        Ok((typ, ic, buf))
    }

    fn remote_eid(&self) -> Eid {
        self.eid
    }
}

/// A response channel.
///
/// Returned by [`RouterAsyncListener::recv`](mctp::AsyncListener::recv).
#[derive(Debug)]
pub struct RouterAsyncRespChannel<'g, 'r> {
    eid: Eid,
    tv: TagValue,
    router: &'g Router<'r>,
    typ: MsgType,
}

impl<'g, 'r> mctp::AsyncRespChannel for RouterAsyncRespChannel<'g, 'r> {
    type ReqChannel<'a>
        = RouterAsyncReqChannel<'g, 'r>
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

    fn req_channel(&self) -> mctp::Result<Self::ReqChannel<'g>> {
        Ok(RouterAsyncReqChannel::new(self.eid, self.router))
    }
}

/// A listener.
///
/// Created with [`Router::listener()`](Router::listener).
#[derive(Debug)]
pub struct RouterAsyncListener<'g, 'r> {
    router: &'g Router<'r>,
    cookie: AppCookie,
    timeout: Option<u64>,
}

impl RouterAsyncListener<'_, '_> {
    /// Set a receive timeout.
    ///
    /// Specified in milliseconds.
    pub fn set_timeout(&mut self, timeout: Option<u64>) {
        self.timeout = timeout;
    }
}

impl<'g, 'r> mctp::AsyncListener for RouterAsyncListener<'g, 'r> {
    type RespChannel<'a>
        = RouterAsyncRespChannel<'g, 'r>
    where
        Self: 'a;

    async fn recv<'f>(
        &mut self,
        buf: &'f mut [u8],
    ) -> mctp::Result<(MsgType, MsgIC, &'f mut [u8], Self::RespChannel<'_>)>
    {
        let (msg, eid, typ, tag, ic) =
            self.router.app_recv(self.cookie, buf, self.timeout).await?;

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

impl Drop for RouterAsyncListener<'_, '_> {
    fn drop(&mut self) {
        self.router.app_unbind(self.cookie)
    }
}
