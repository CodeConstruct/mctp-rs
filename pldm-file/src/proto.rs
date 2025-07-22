use num_derive::FromPrimitive;

use deku::{DekuRead, DekuWrite};
use enumset::{EnumSet, EnumSetType};

/// PLDM for File Transfer commands
#[allow(missing_docs)]
#[non_exhaustive]
#[derive(Debug, FromPrimitive)]
#[repr(u8)]
pub enum Cmd {
    DfOpen = 0x01,
    DfClose = 0x02,
    DfHeartbeat = 0x03,
    DfProperties = 0x10,
    DfGetFileAttribute = 0x11,
    DfSetFileAttribute = 0x12,
    // the following two are implemented as type-0 multipart commands, but
    // we need command identifiers for GetPLDMCommands.
    DfRead = 0x20,
    DfFifoSend = 0x21,
}

#[allow(missing_docs)]
pub mod file_ccode {
    pub const INVALID_FILE_DESCRIPTOR: u8 = 0x80;
    pub const INVALID_DF_ATTRIBUTE: u8 = 0x81;
    pub const ZEROLENGTH_NOT_ALLOWED: u8 = 0x82;
    pub const EXCLUSIVE_OWNERSHIP_NOT_ESTABLISHED: u8 = 0x83;
    pub const EXCLUSIVE_OWNERSHIP_NOT_ALLOWED: u8 = 0x84;
    pub const EXCLUSIVE_OWNERSHIP_NOT_AVAILABLE: u8 = 0x85;
    pub const INVALID_FILE_IDENTIFIER: u8 = 0x86;
    pub const DFOPEN_DIR_NOT_ALLOWED: u8 = 0x87;
    pub const MAX_NUM_FDS_EXCEEDED: u8 = 0x88;
    pub const FILE_OPEN: u8 = 0x89;
    pub const UNABLE_TO_OPEN_FILE: u8 = 0x8a;
}

#[derive(Debug)]
pub struct FileIdentifier(pub u16);

#[derive(Debug)]
pub struct FileDescriptor(pub u16);

// These are represented as their encoding in the DfProperties command;
// a bitmask, where only one value is permitted.
#[repr(u32)]
pub enum DfProperty {
    MaxConcurrentMedium = 0x01,
    MaxFileDescriptors = 0x02,
}

#[derive(EnumSetType, Debug)]
pub enum DfOpenAttribute {
    DfOpenWrite = 0,
    DfOpenExclusive = 1,
    DfOpenFifo = 2,
    DfOpenPushed = 3,
}

pub type DfOpenAttributes = EnumSet<DfOpenAttribute>;

impl TryFrom<u32> for DfProperty {
    type Error = ();

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::MaxConcurrentMedium),
            0x02 => Ok(Self::MaxFileDescriptors),
            _ => Err(()),
        }
    }
}

#[derive(DekuRead, DekuWrite)]
pub struct DfPropertiesReq {
    pub property: u32,
}

#[derive(DekuRead, DekuWrite)]
pub struct DfPropertiesResp {
    pub value: u32,
}

#[derive(DekuRead, DekuWrite)]
pub struct DfOpenReq {
    pub file_identifier: u16,
    pub attributes: u16,
}

#[derive(DekuRead, DekuWrite)]
pub struct DfOpenResp {
    pub file_descriptor: u16,
}
