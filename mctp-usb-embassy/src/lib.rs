// SPDX-License-Identifier: MIT OR Apache-2.0
/*
 * Copyright (c) 2025 Code Construct
 */
#![no_std]
#![forbid(unsafe_code)]

mod mctpusb;

pub use mctpusb::{MctpUsbClass, Receiver, Sender};

/// Maximum packet for DSP0283 1.0.
pub const MCTP_USB_MAX_PACKET: usize = 512;
