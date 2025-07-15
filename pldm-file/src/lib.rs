#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub const PLDM_TYPE_FILE_TRANSFER: u8 = 7;

pub mod client;
#[cfg(feature = "std")]
pub mod host;
pub mod proto;
