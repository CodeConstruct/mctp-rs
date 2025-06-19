#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod proto;
pub mod requester;
pub mod state_sets;

pub const PLDM_TYPE_PLATFORM: u8 = 2;

/// Re-export of `heapless::Vec`
pub use heapless::Vec;
