// SPDX-License-Identifier: MIT OR Apache-2.0
/*
 * Copyright (c) 2025 Code Construct
 */
#[cfg(feature = "defmt")]
#[allow(unused)]
use defmt::{debug, error, info, trace, warn};

#[cfg(feature = "log")]
#[allow(unused)]
use log::{debug, error, info, trace, warn};

#[cfg(not(any(feature = "log", feature = "defmt")))]
compile_error!("Either log or defmt feature must be enabled");
#[cfg(all(feature = "log", feature = "defmt"))]
compile_error!("log and defmt features are mutually exclusive");

use core::ops::Range;

use embassy_futures::join::join;
use embassy_usb::descriptor::{SynchronizationType, UsageType};
use embassy_usb::Builder;
use embassy_usb_driver::{
    Driver, Endpoint, EndpointIn, EndpointOut, EndpointType,
};
use heapless::Vec;
use mctp_estack::{router::Port, router::PortId, usb::MctpUsbHandler, Router};

use crate::MCTP_USB_MAX_PACKET;

pub const USB_CLASS_MCTP: u8 = 0x14;
pub const MCTP_SUBCLASS_DEVICE: u8 = 0x0;
pub const MCTP_PROTOCOL_V1: u8 = 0x1;

/// The send half of a `MctpUsbClass`.
///
/// Returned from [`split()`](MctpUsbClass::split)
pub struct Sender<'d, D: Driver<'d>> {
    ep: D::EndpointIn,
    buf: Vec<u8, MCTP_USB_MAX_PACKET>,
}

impl<'d, D: Driver<'d>> Sender<'d, D> {
    /// Send a single packet.
    pub async fn send(&mut self, pkt: &[u8]) -> mctp::Result<()> {
        self.feed(pkt)?;
        self.flush().await
    }

    /// Enqueue a packet in the current USB payload.
    ///
    /// The payload will not be sent until `flush()` is called.
    /// May return [`mctp::Error::NoSpace`] if the packet won't
    /// fit in the current payload.
    pub fn feed(&mut self, pkt: &[u8]) -> mctp::Result<()> {
        let total = pkt.len().checked_add(4).ok_or(mctp::Error::NoSpace)?;
        let avail = self.buf.capacity() - self.buf.len();
        if avail < total {
            return Err(mctp::Error::NoSpace);
        }

        let mut hdr = [0u8; 4];
        MctpUsbHandler::header(pkt.len(), &mut hdr)?;
        let _ = self.buf.extend_from_slice(&hdr);
        let _ = self.buf.extend_from_slice(pkt);
        Ok(())
    }

    /// Send the current payload via USB.
    ///
    /// The payload must have been set with a previous `feed()`.
    pub async fn flush(&mut self) -> mctp::Result<()> {
        if self.buf.is_empty() {
            return Err(mctp::Error::BadArgument);
        }
        let r = self.ep.write(&self.buf).await;
        self.buf.clear();
        r.map_err(|_e| mctp::Error::TxFailure)
    }

    /// Wait for a host to connect.
    pub async fn wait_connection(&mut self) {
        self.ep.wait_enabled().await
    }

    /// Run with a `mctp::Router` stack.
    pub async fn run(mut self, mut port: Port<'_>) -> ! {
        // Outer loop for reattaching USB
        loop {
            debug!("mctp usb send waiting");
            self.wait_connection().await;
            debug!("mctp usb send attached");
            'sending: loop {
                // Wait for at least one MCTP packet enqueued
                let (pkt, _dest) = port.outbound().await;
                let r = self.feed(pkt);

                // Consume it
                port.outbound_done();
                if r.is_err() {
                    // MCTP packet too large for USB
                    continue 'sending;
                }

                'fill: loop {
                    let Some((pkt, _dest)) = port.try_outbound() else {
                        // No more packets
                        break 'fill;
                    };

                    // See if it fits in the payload
                    match self.feed(pkt) {
                        // Success, consume it
                        Ok(()) => port.outbound_done(),
                        // Won't fit, leave it until next 'sending iteration.
                        Err(_) => break 'fill,
                    }
                }

                if let Err(e) = self.flush().await {
                    debug!("usb send error {}", e);
                    break 'sending;
                }
            }
        }
    }
}

/// The receive half of a `MctpUsbClass`.
///
/// Returned from [`split()`](MctpUsbClass::split)
pub struct Receiver<'d, D: Driver<'d>> {
    ep: D::EndpointOut,
    buf: [u8; MCTP_USB_MAX_PACKET],
    // valid range remaining in buf
    remaining: Range<usize>,
}

impl<'d, D: Driver<'d>> Receiver<'d, D> {
    /// Receive a single MCTP packet.
    ///
    /// Returns `None` on USB disconnected.
    /// `Some(Err)` may be returned on an invalid packet.
    pub async fn receive(&mut self) -> Option<mctp::Result<&[u8]>> {
        if self.remaining.is_empty() {
            // Refill
            let l = match self.ep.read(&mut self.buf).await {
                Ok(l) => l,
                Err(_e) => return None,
            };
            self.remaining = Range { start: 0, end: l };
        }

        // TODO: would be nice to loop until a valid decode,
        // but lifetimes are difficult until polonius merges
        let rem = &self.buf[self.remaining.clone()];
        let (pkt, rem) = match MctpUsbHandler::decode(rem) {
            Ok(a) => a,
            Err(e) => return Some(Err(e)),
        };
        self.remaining.start = self.remaining.end - rem.len();
        Some(Ok(pkt))
    }

    /// Wait for a host to connect.
    pub async fn wait_connection(&mut self) {
        self.ep.wait_enabled().await
    }

    /// Run with a `mctp::Router` stack.
    pub async fn run(mut self, router: &Router<'_>, port: PortId) -> ! {
        // Outer loop for reattaching USB
        loop {
            debug!("mctp usb recv waiting");
            self.wait_connection().await;
            info!("mctp usb recv attached");

            // Inner loop receives packets and provides MCTP handling
            'receiving: loop {
                match self.receive().await {
                    Some(Ok(pkt)) => {
                        router.inbound(pkt, port).await;
                    }
                    Some(Err(e)) => {
                        debug!("mctp usb packet decode failure {}", e)
                    }
                    None => {
                        info!("mctp usb disconnected");
                        break 'receiving;
                    }
                }
            }
        }
    }
}

/// A MCTP-over-USB device.
///
/// This requires a USB high-speed device because the specification
/// requires a 512 byte maximum packet size.
pub struct MctpUsbClass<'d, D: Driver<'d>> {
    sender: Sender<'d, D>,
    receiver: Receiver<'d, D>,
}

impl<'d, D: Driver<'d>> MctpUsbClass<'d, D> {
    pub fn new(builder: &mut Builder<'d, D>) -> Self {
        let mut func = builder.function(
            USB_CLASS_MCTP,
            MCTP_SUBCLASS_DEVICE,
            MCTP_PROTOCOL_V1,
        );
        let mut iface = func.interface();
        // first alt iface is the default (and only)
        let mut alt = iface.alt_setting(
            USB_CLASS_MCTP,
            MCTP_SUBCLASS_DEVICE,
            MCTP_PROTOCOL_V1,
            None,
        );
        let interval = 1;
        let ep_out = alt.alloc_endpoint_out(
            EndpointType::Bulk,
            None,
            MCTP_USB_MAX_PACKET as u16,
            interval,
        );
        let ep_in = alt.alloc_endpoint_in(
            EndpointType::Bulk,
            None,
            MCTP_USB_MAX_PACKET as u16,
            interval,
        );

        alt.endpoint_descriptor(
            ep_out.info(),
            SynchronizationType::NoSynchronization,
            UsageType::DataEndpoint,
            &[],
        );
        alt.endpoint_descriptor(
            ep_in.info(),
            SynchronizationType::NoSynchronization,
            UsageType::DataEndpoint,
            &[],
        );

        let sender = Sender {
            ep: ep_in,
            buf: Vec::new(),
        };
        let receiver = Receiver {
            ep: ep_out,
            buf: [0; MCTP_USB_MAX_PACKET],
            remaining: Default::default(),
        };

        Self { sender, receiver }
    }

    /// Split into `Sender` and `Receiver`
    ///
    /// This allows manually sending and receiving MCTP over USB packets.
    pub fn split(self) -> (Sender<'d, D>, Receiver<'d, D>) {
        (self.sender, self.receiver)
    }

    /// Run with a `mctp::Router` stack.
    pub async fn run(self, router: &Router<'_>, port: Port<'_>) -> ! {
        let (s, r) = self.split();
        let id = port.id();
        let _ = join(s.run(port), r.run(router, id)).await;
        unreachable!()
    }
}
