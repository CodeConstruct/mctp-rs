use embassy_sync::waitqueue::{MultiWakerRegistration, WakerRegistration};

#[allow(unused)]
use crate::fmt::{debug, error, info, trace, warn};

use core::cell::RefCell;
use core::task::Poll;
use core::future::{poll_fn, Future};
use core::pin::pin;

use mctp::{Eid, Error, MsgType, Result, Tag, TagValue};
use crate::{AppCookie, Fragmenter, ReceiveHandle, SendOutput, Stack};
use crate::reassemble::Reassembler;

use embassy_sync::zerocopy_channel::{Channel, Sender, Receiver};

use heapless::Vec;

// TODO sizing is a bit arbitrary.
const MAX_LISTENERS: usize = 6;
const MAX_RECEIVERS: usize = 20;

// TODO sizing
const MAX_MTU: usize = 255-4;
const MAX_MESSAGE: usize = 1024;

// TODO: feature to configure mutex?
type RawMutex = embassy_sync::blocking_mutex::raw::NoopRawMutex;
type AsyncMutex<T> = embassy_sync::mutex::Mutex<RawMutex, T>;
type BlockingMutex<T> = embassy_sync::blocking_mutex::Mutex<RawMutex, RefCell<T>>;

type PortRawMutex = embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
// type PortRawMutex = embassy_sync::blocking_mutex::raw::NoopRawMutex;

/// A trait implemented by applications to determine the routing table.
pub trait PortLookup {
    /// Returns the port index for a destination EID.
    ///
    /// This is an index into the array of `ports` provided to [`Router::new`]
    ///
    /// Return `None` for unreachable.
    fn by_eid(&mut self, eid: Eid) -> Option<usize>;
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
        let dst = self.data.get_mut(..data.len()).ok_or(Error::NoSpace)?;
        dst.copy_from_slice(data);
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

    /// Temporary storage to flatten vectorised local sent messages
    // prior to fragmentation and queueing.
    message: AsyncMutex<Vec<u8, MAX_MESSAGE>>,

    mtu: usize,
}

impl<'a> PortTop<'a> {
    /// Enqueues a packet.
    ///
    /// Do not call with locks held.
    /// May block waiting for a port queue to flush.
    async fn forward_packet(&self, pkt: &[u8]) -> Result<()> {
        let mut sender = self.packets.lock().await;
        // Note: must not await while holding `sender`

        // Check space first (can't rollback after try_send)
        if pkt.len() > self.mtu {
            debug!("Forward packet too large");
            return Err(Error::NoSpace)
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
    async fn send_message(&self, fragmenter: &mut Fragmenter, pkt: &[&[u8]]) -> Result<Tag> {
        let mut msg;
        let payload = if pkt.len() == 1 {
            pkt[0]
        } else {
            msg = self.message.lock().await;
            msg.clear();
            for p in pkt {
                msg.extend_from_slice(p).map_err(|_| {
                    debug!("Message too large");
                    Error::NoSpace
                })?;
            }
            &msg
        };

        loop {
            let mut sender = self.packets.lock().await;
            let qpkt = sender.send().await;

            let r = fragmenter.fragment(payload, &mut qpkt.data);
            match r {
                SendOutput::Packet(p) => {
                    qpkt.len = p.len();
                    sender.send_done();
                    if fragmenter.is_done() {
                        break Ok(fragmenter.tag())
                    }
                }
                SendOutput::Error { err, .. } => {
                    debug!("Error packetising");
                    sender.send_done();
                    break Err(err)
                }
                SendOutput::Complete { .. } => unreachable!(),
            }
        }
    }
}

/// The "consumer" side of a queue of packets to send out a MCTP interface,
///
/// This is used by the interface implementation.
pub struct PortBottom<'a> {
    /// packet queue
    packets: Receiver<'a, PortRawMutex, PktBuf>,
}

impl<'a> PortBottom<'a> {
    /// Receive a packet to send for this port.
    ///
    /// Must call `receive_done()` after each `receive()` call.
    pub async fn receive(&mut self) -> &[u8]
    {
        self.packets.receive().await
    }

    pub fn receive_done(&mut self) {
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

impl< const FORWARD_QUEUE: usize > PortStorage<FORWARD_QUEUE> {
    pub fn new() -> Self {
        Self {
            packets: [const { PktBuf::new() }; FORWARD_QUEUE],
        }
    }
}

pub struct PortBuilder<'a> {
    /// forwarded packet queue
    packets: Channel<'a, PortRawMutex, PktBuf>,
}

impl<'a> PortBuilder<'a> {

    pub fn new<const FORWARD_QUEUE: usize>(storage: &'a mut PortStorage<FORWARD_QUEUE>)
    -> Self {
        // PortBuilder and PortStorage need to be separate structs, since
        // zerocopy_channel::Channel takes a slice.
        Self {
            packets: Channel::new(storage.packets.as_mut_slice()),
        }
    }

    pub fn build(&mut self, mtu: usize) -> Result<(PortTop, PortBottom)>
    {
        if mtu > MAX_MTU {
            debug!("port mtu {} > MAX_MTU {}", mtu, MAX_MTU);
            return Err(Error::BadArgument);
        }

        let (ps, pr) = self.packets.split();

        let t = PortTop {
            message: AsyncMutex::new(Vec::new()),
            packets: AsyncMutex::new(ps),
            mtu,
        };
        let b = PortBottom {
            packets: pr,
        };
        Ok((t, b))
    }
}

pub struct Router<'r> {
    inner: AsyncMutex<RouterInner<'r>>,
    ports: &'r [PortTop<'r>],

    /// Listeners for different message types.
    // Has a separate non-async Mutex so it can be used by RouterAsyncLister::drop()
    // TODO filter by more than just MsgType, maybe have a Map of some sort?
    app_listeners: BlockingMutex<[Option<(MsgType, WakerRegistration)>;
        MAX_LISTENERS]>,
}

pub struct RouterInner<'r> {
    /// Core MCTP stack
    stack: Stack,

    // Wakers for RouterAsyncReqChannel and RouterAsyncRespChannel
    app_receive_wakers: MultiWakerRegistration<MAX_RECEIVERS>,

    lookup: &'r mut dyn PortLookup,
}

impl<'r> Router<'r> {
    pub fn new(stack: Stack, ports: &'r [PortTop<'r>], lookup: &'r mut dyn PortLookup) -> Self {
        let inner = RouterInner {
            stack,
            app_receive_wakers: MultiWakerRegistration::new(),
            lookup,
        };

        Self {
            inner: AsyncMutex::new(inner),
            app_listeners: BlockingMutex::new(RefCell::new([const { None }; MAX_LISTENERS])),
            ports,
        }
    }

    pub async fn receive(&self, pkt: &[u8]) {
        let mut inner = self.inner.lock().await;

        trace!("receive");

        // Handle locally if possible
        if inner.stack.is_local_dest(pkt) {
            trace!("local dest");
            match inner.stack.receive(pkt) {
                // Complete message
                Ok(Some((msg, handle))) => {
                    let typ = msg.typ;
                    let tag = msg.tag;
                    drop(inner);
                    self.incoming_local(tag, typ, handle).await
                }
                // Fragment consumed, message is incomplete
                Ok(None) => {
                    trace!("fragment");
                }
                Err(e) => {
                    debug!("Dropped local recv packet. {}", e);
                }
            }
            return;
        }

        trace!("not local dest");
        // Look for a route to forward to
        let Ok(header) = Reassembler::header(pkt) else {
            debug!("bad header");
            return;
        };
        let dest_eid = Eid(header.dest_endpoint_id());

        let Some(p) = inner.lookup.by_eid(dest_eid) else {
            debug!("No route for recv {}", dest_eid);
            return;
        };
        drop(inner);

        let Some(top) = self.ports.get(p) else {
            debug!("Bad port ID from lookup");
            return;
        };

        let _ = top.forward_packet(pkt).await;
    }

    async fn incoming_local(&self, tag: Tag, typ: MsgType, handle: ReceiveHandle) {
        trace!("incoming local, type {}", typ.0);
        if tag.is_owner() {
            self.incoming_listener(typ, handle).await
        } else {
            self.incoming_response(tag, handle).await
        }
    }

    async fn incoming_listener(&self, typ: MsgType, handle: ReceiveHandle) {
        let mut inner = self.inner.lock().await;
        let mut handle = Some(handle);

        // wake the packet listener
        self.app_listeners.lock(|a| {
            let mut a = a.borrow_mut();
            // Find the matching listener
            for (cookie, entry) in a.iter_mut().enumerate() {
                if let Some((t, waker)) = entry {
                    trace!("entry. {} vs {}", t.0, typ.0);
                    if *t == typ {
                        // OK unwrap: only set once
                        let handle = handle.take().unwrap();
                        inner.stack.set_cookie(&handle, Some(AppCookie(cookie)));
                        inner.stack.return_handle(handle);
                        waker.wake();
                        trace!("listener match");
                        break;
                    }
                }
            }
        });

        if let Some(handle) = handle.take() {
            trace!("listener no match");
            inner.stack.finished_receive(handle);
        }
    }

    async fn incoming_response(&self, _tag: Tag, handle: ReceiveHandle) {
        let mut inner = self.inner.lock().await;
        inner.stack.return_handle(handle);
        // TODO: inefficient waking them all. should
        // probably wake only the useful one.
        inner.app_receive_wakers.wake();
    }

    fn app_bind(&self, typ: MsgType) -> Result<AppCookie> {
        self.app_listeners.lock(|a| {
            let mut a = a.borrow_mut();

            // Check for existing binds with the same type
            for bind in a.iter() {
                if bind.as_ref().is_some_and(|(t, _)| *t == typ) {
                    return Err(Error::AddrInUse);
                }
            }

            // Find a free slot
            if let Some((i, bind)) = a.iter_mut()
                .enumerate().find(|(_i, bind)| bind.is_none()) {
                *bind = Some((typ, WakerRegistration::new()));
                return Ok(AppCookie(i))
            }

            return Err(Error::NoSpace)
        })
    }

    fn app_unbind(&self, cookie: AppCookie) -> Result<()> {
        self.app_listeners.lock(|a| {
            let mut a = a.borrow_mut();
            let bind = a.get_mut(cookie.0).ok_or(Error::BadArgument)?;

            if bind.is_none() {
                return Err(Error::BadArgument)
            }

            // Clear the bind.
            *bind = None;
            // No need to wake any waker, unbind only occurs
            // on RouterAsyncListener::drop.
            Ok(())
        })
    }

    /// Receive a message.
    ///
    /// Listeners will pass the cookie returned from `[app_bind]`.
    /// Other receivers will pass `tag_eid`.
    async fn app_recv_message<'f>(
        &self,
        cookie: Option<AppCookie>,
        tag_eid: Option<(Tag, Eid)>,
        buf: &'f mut [u8],
    ) -> Result<(&'f mut [u8], Eid, MsgType, Tag, bool)> {
        // Allow single use inside poll_fn
        let mut buf = Some(buf);

        poll_fn(|cx| {
            // Lock it inside the poll_fn
            let l = self.inner.lock();
            let l = pin!(l);
            let mut inner = match l.poll(cx) {
                Poll::Ready(i) => i,
                Poll::Pending => return Poll::Pending,
            };

            trace!("poll recv message");

            // Find the message's handle
            // TODO: get_deferred is inefficient lookup, does it matter?
            let handle = match (cookie, tag_eid) {
                // lookup by cookie for Listener
                (Some(cookie), None) => inner.stack.get_deferred_bycookie(&[cookie]),
                // lookup by tag/eid for ReqChannel
                (None, Some((tag, eid))) => inner.stack.get_deferred(eid, tag),
                // one of them must have been set
                _ => unreachable!(),
            };

            let Some(handle) = handle else {
                // No message handle. Maybe it hasn't arrived yet, find the waker
                // to register.

                if let Some(cookie) = cookie {
                    // This is a Listener.
                    trace!("listener, cookie index {}", cookie.0);
                    self.app_listeners.lock(|a| {
                        let mut a = a.borrow_mut();
                        let Some(bind) = a.get_mut(cookie.0) else {
                            debug_assert!(false, "recv bad cookie");
                            return;
                        };
                        let Some((_typ, waker)) = bind else {
                            debug_assert!(false, "recv no listener");
                            return;
                        };
                        waker.register(cx.waker());
                    });
                } else {
                    // Other receivers.
                    trace!("other recv");
                    inner.app_receive_wakers.register(cx.waker());
                }
                trace!("pending");
                return Poll::Pending;
            };

            // A matching message was found. Fetch it, copy the contents to the caller,
            // and finish with it for the stack.
            trace!("got handle");

            let msg = inner.stack.fetch_message(&handle);

            // OK unwrap, set above and only hit once on Poll::Ready
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

            inner.stack.finished_receive(handle);
            Poll::Ready(res)
        }).await
    }

    // Used by traits to send a message, see comment on .send_vectored() methods
    async fn app_send_message(
        &self,
        eid: Eid,
        typ: MsgType,
        tag: Option<Tag>,
        integrity_check: bool,
        buf: &[&[u8]],
        cookie: Option<AppCookie>,
    ) -> Result<Tag> {
        let mut inner = self.inner.lock().await;

        let Some(p) = inner.lookup.by_eid(eid) else {
            debug!("No route for recv {}", eid);
            return Err(Error::TxFailure);
        };

        let Some(top) = self.ports.get(p) else {
            debug!("Bad port ID from lookup");
            return Err(Error::TxFailure);
        };

        let mtu = top.mtu;
        let mut fragmenter = inner.stack.start_send(eid, typ, tag, integrity_check,
                Some(mtu), cookie)?;
        // release to allow other ports to continue work
        drop(inner);

        top.send_message(&mut fragmenter, buf).await
    }

    /// Create a `AsyncReqChannel` instance
    pub fn req(&'r self, eid: Eid) -> RouterAsyncReqChannel<'r> {
        RouterAsyncReqChannel {
            eid,
            sent_tag: None,
            router: &self,
        }
    }

    /// Create a `AsyncListener` instance
    pub fn listener(&'r self, typ: MsgType) -> Result<RouterAsyncListener<'r>> {
        let cookie = self.app_bind(typ)?;
        Ok(RouterAsyncListener {
            cookie,
            router: &self,
        })
    }
}

pub struct RouterAsyncReqChannel<'r> {
    eid: Eid,
    sent_tag: Option<Tag>,
    router: &'r Router<'r>,
}

impl<'r> mctp::AsyncReqChannel for RouterAsyncReqChannel<'r> {
    /// Send a message.
    ///
    /// This will async block until the message has been enqueued to the physical port.
    /// Note that it will return failure immediately if the MCTP stack has no available tags,
    /// that behaviour may need changing in future.
    async fn send_vectored(
        &mut self,
        typ: MsgType,
        integrity_check: bool,
        bufs: &[&[u8]],
    ) -> Result<()> {
        // Pass a None tag, get an Owned one allocated.
        let tag = None;
        let tag = self.router.app_send_message(self.eid, typ, tag, integrity_check, bufs, None).await?;
        debug_assert!(matches!(tag, Tag::Owned(_)));
        self.sent_tag = Some(tag);
        Ok(())
    }

    async fn recv<'f>(
        &mut self,
        buf: &'f mut [u8],
    ) -> Result<(&'f mut [u8], MsgType, Tag, bool)> {
        let Some(Tag::Owned(tv)) = self.sent_tag else {
            debug!("recv without send");
            return Err(Error::BadArgument)
        };
        let recv_tag = Tag::Unowned(tv);
        let (buf, eid, typ, tag, ic ) =
            self.router.app_recv_message(None, Some((recv_tag, self.eid)), buf).await?;
        debug_assert_eq!(tag, recv_tag);
        debug_assert_eq!(eid, self.eid);
        Ok((buf, typ, tag, ic))
        // todo!()
    }

    fn remote_eid(&self) -> Eid {
        self.eid
    }
}

pub struct RouterAsyncRespChannel<'r> {
    eid: Eid,
    tv: TagValue,
    router: &'r Router<'r>,
}

impl<'r> mctp::AsyncRespChannel for RouterAsyncRespChannel<'r> {
    type ReqChannel<'a> = RouterAsyncReqChannel<'r> where Self: 'a;

    /// Send a message.
    ///
    /// See description of `RouterAsyncReqChannel::send_vectored()`.
    async fn send_vectored(
        &mut self,
        typ: MsgType,
        integrity_check: bool,
        bufs: &[&[u8]],
    ) -> Result<()> {
        let tag = Some(Tag::Unowned(self.tv));
        self.router.app_send_message(self.eid, typ, tag, integrity_check, bufs, None).await?;
        Ok(())
    }

    fn remote_eid(&self) -> Eid {
        self.eid
    }

    fn req_channel(&self) -> mctp::Result<Self::ReqChannel<'_>> {
        Ok(RouterAsyncReqChannel {
            eid: self.eid,
            sent_tag: None,
            router: self.router,
        })
    }
}

pub struct RouterAsyncListener<'r> {
    router: &'r Router<'r>,
    cookie: AppCookie,
}

impl<'r> mctp::AsyncListener for RouterAsyncListener<'r> {
    // type RespChannel<'a> = RouterAsyncRespChannel<'a> where Self: 'a;
    type RespChannel<'a> = RouterAsyncRespChannel<'r> where Self: 'a;

    async fn recv<'f>(
        &mut self,
        buf: &'f mut [u8])
    -> mctp::Result<(&'f mut [u8], Self::RespChannel<'_>, Tag, MsgType, bool)> {
        let (msg, eid, typ, tag, ic) = self.router.app_recv_message(Some(self.cookie), None, buf).await?;

        let Tag::Owned(tv) = tag else {
            debug_assert!(false, "listeners only accept owned tags");
            return Err(Error::InternalError);
        };

        let resp = RouterAsyncRespChannel {
            eid,
            tv,
            router: self.router,
        };
        Ok((msg, resp, tag, typ, ic))
    }
}

impl <'r> Drop for RouterAsyncListener<'r> {
    fn drop(&mut self) {
        if let Err(_) = self.router.app_unbind(self.cookie) {
            // should be infallible, cookie should be valid.
            debug_assert!(false, "bad unbind");
        }
    }
}
