// SPDX-License-Identifier: MIT OR Apache-2.0
/*
 * Copyright (c) 2025 Code Construct
 */
#![no_std]
#![forbid(unsafe_code)]
// defmt does not currently allow inline format arguments, so we don't want
// those reworked when using the log crate either.
#![allow(clippy::uninlined_format_args)]

//! # MCTP over USB transport for `embassy-usb`.
//!
//! Implements DMTF [DSP0283](https://www.dmtf.org/sites/default/files/standards/documents/DSP0283_1.0.1.pdf)
//! standard for a MCTP transport over USB.
//!
//! A `MctpUsbClass` instance is created with a `embassy-usb` `Builder`.
//!
//! That can be used directly with a [`mctp_estack::Router`] by calling
//! [`run()`](MctpUsbClass::run).
//!
//! A lower level interface can be used with [`Sender`] and [`Receiver`]
//! to send and receive MCTP-over-USB packets.

mod mctpusb;

pub use mctpusb::{MctpUsbClass, Receiver, Sender};

/// Maximum USB packet size for DSP0283 1.0.
///
/// This can be used to size `embassy-usb` endpoint buffers.
pub const MCTP_USB_MAX_PACKET: usize = 512;
