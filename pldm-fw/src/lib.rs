// SPDX-License-Identifier: MIT OR Apache-2.0
/*
 * PLDM firmware update utility: PLDM type 5 messaging
 *
 * Copyright (c) 2023 Code Construct
 */
#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
// #![warn(missing_docs)]

use core::fmt;
use log::debug;

use chrono::Datelike;
use enumset::{EnumSet, EnumSetType};
use num_derive::FromPrimitive;

use nom::{
    branch::alt,
    bytes::complete::{tag, take},
    character::complete::u32 as c_u32,
    combinator::{
        all_consuming, flat_map, map, map_opt, map_parser, map_res, rest, value,
    },
    number::complete::{le_u16, le_u32, le_u8},
    sequence::tuple,
    IResult,
};

#[cfg(feature = "alloc")]
use nom::multi::{count, length_count};

#[cfg(feature = "alloc")]
extern crate alloc;

/// Firmware Device specific
pub mod fd;
/// PLDM firmware packaging
#[cfg(feature = "alloc")]
pub mod pkg;
/// Update Agent specific
#[cfg(feature = "std")]
pub mod ua;

use pldm::util::*;

// Firmware Update PLDM Type 5
pub const PLDM_TYPE_FW: u8 = 5;

// Baseline transfer size
pub const PLDM_FW_BASELINE_TRANSFER: usize = 32;

/// PLDM firmware specification requires 255 byte length.
///
/// Can be reduced when strings are a known length.
#[cfg(not(feature = "alloc"))]
const MAX_DESC_STRING: usize = 64;

/// Maximum length allowed for vendor data in no-alloc
///
/// PLDM firmware specification has no length limit.
/// Can be reduced if length is known.
#[cfg(not(feature = "alloc"))]
const MAX_VENDORDATA: usize = 64;

/// Component Identifier
#[derive(Debug, Eq, PartialEq, Hash)]
pub struct ComponentId(pub u16);

/// PLDM firmware device state definitions
#[derive(Debug, PartialEq, Copy, Clone)]
#[repr(u8)]
pub enum PldmFDState {
    Idle = 0,
    LearnComponents = 1,
    ReadyXfer = 2,
    Download = 3,
    Verify = 4,
    Apply = 5,
    Activate = 6,
}

impl TryFrom<u8> for PldmFDState {
    type Error = &'static str;
    fn try_from(value: u8) -> core::result::Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Idle),
            1 => Ok(Self::LearnComponents),
            2 => Ok(Self::ReadyXfer),
            3 => Ok(Self::Download),
            4 => Ok(Self::Verify),
            5 => Ok(Self::Apply),
            6 => Ok(Self::Activate),
            _ => Err("unknown state!"),
        }
    }
}

impl PldmFDState {
    /// Parse from a buffer
    pub fn parse(buf: &[u8]) -> VResult<&[u8], Self> {
        map_res(le_u8, TryInto::<PldmFDState>::try_into)(buf)
    }
}

/// Idle Reason Codes for Get Status response
#[allow(missing_docs)]
#[derive(FromPrimitive, Debug, PartialEq, Copy, Clone)]
#[repr(u8)]
pub enum PldmIdleReason {
    Init = 0,
    Activate = 1,
    Cancel = 2,
    TimeoutLearn = 3,
    TimeoutReadyXfer = 4,
    TimeoutDownload = 5,
    TimeoutVerify = 6,
    TimeoutApply = 7,
}

/// PLDM Firmware Commands
#[allow(missing_docs)]
#[derive(FromPrimitive, Debug, PartialEq)]
#[repr(u8)]
pub enum Cmd {
    QueryDeviceIdentifiers = 0x01,
    GetFirmwareParameters = 0x02,
    QueryDownstreamDevices = 0x03,
    QueryDownstreamIdentifiers = 0x04,
    GetDownstreamFirmwareParameters = 0x05,
    RequestUpdate = 0x10,
    GetPackageData = 0x11,
    GetDeviceMetaData = 0x12,
    PassComponentTable = 0x13,
    UpdateComponent = 0x14,
    RequestFirmwareData = 0x15,
    TransferComplete = 0x16,
    VerifyComplete = 0x17,
    ApplyComplete = 0x18,
    GetMetaData = 0x19,
    ActivateFirmware = 0x1A,
    GetStatus = 0x1B,
    CancelUpdateComponent = 0x1C,
    CancelUpdate = 0x1D,
    ActivatePendingComponentImageSet = 0x1E,
    ActivatePendingComponentImage = 0x1F,
    RequestDownstreamDeviceUpdate = 0x20,
}

impl Cmd {
    pub const fn is_ua(&self) -> bool {
        !self.is_fd()
    }

    pub const fn is_fd(&self) -> bool {
        matches!(
            self,
            Self::GetPackageData
                | Self::RequestFirmwareData
                | Self::TransferComplete
                | Self::VerifyComplete
                | Self::ApplyComplete
                | Self::GetMetaData
        )
    }
}

/// PLDM firmware response codes
#[allow(missing_docs)]
#[repr(u8)]
#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq)]
pub enum FwCode {
    NOT_IN_UPDATE_MODE = 0x80,
    ALREADY_IN_UPDATE_MODE = 0x81,
    DATA_OUT_OF_RANGE = 0x82,
    INVALID_TRANSFER_LENGTH = 0x83,
    INVALID_STATE_FOR_COMMAND = 0x84,
    INCOMPLETE_UPDATE = 0x85,
    BUSY_IN_BACKGROUND = 0x86,
    CANCEL_PENDING = 0x87,
    COMMAND_NOT_EXPECTED = 0x88,
    RETRY_REQUEST_FW_DATA = 0x89,
    UNABLE_TO_INITIATE_UPDATE = 0x8A,
    ACTIVATION_NOT_REQUIRED = 0x8B,
    SELF_CONTAINED_ACTIVATION_NOT_PERMITTED = 0x8C,
    NO_DEVICE_METADATA = 0x8D,
    RETRY_REQUEST_UPDATE = 0x8E,
    NO_PACKAGE_DATA = 0x8F,
    INVALID_TRANSFER_HANDLE = 0x90,
    INVALID_TRANSFER_OPERATION = 0x91,
    ACTIVATE_PENDING_IMAGE_NOT_PERMITTED = 0x92,
    PACKAGE_DATA_ERROR = 0x93,
}

/// Transfer Result codes for TransferComplete
///
/// Not all defined Transfer Result codes are defined in this enum,
/// arbitrary `u8` values may be expected.
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq)]
#[non_exhaustive]
pub enum TransferResult {
    Success,
    Corrupt,
    VersionMismatch,
    Aborted,
    Timeout,
    GenericError,
    Other(u8),
}

impl From<u8> for TransferResult {
    fn from(v: u8) -> Self {
        match v {
            0x00 => Self::Success,
            0x01 => Self::Corrupt,
            0x02 => Self::VersionMismatch,
            0x03 => Self::Aborted,
            0x09 => Self::Timeout,
            0x0a => Self::GenericError,
            v => Self::Other(v),
        }
    }
}

impl From<TransferResult> for u8 {
    fn from(v: TransferResult) -> u8 {
        match v {
            TransferResult::Success => 0x00,
            TransferResult::Corrupt => 0x01,
            TransferResult::VersionMismatch => 0x02,
            TransferResult::Aborted => 0x03,
            TransferResult::Timeout => 0x09,
            TransferResult::GenericError => 0x0a,
            TransferResult::Other(v) => v,
        }
    }
}

/// Verify Result codes for VerifyComplete
///
/// Not all defined Verify Result codes are defined in this enum,
/// arbitrary `u8` values may be expected in `Other` variant.
///
/// Ref "VerifyComplete command format" Table 31 of DSP0267 1.1.0
#[allow(missing_docs)]
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum VerifyResult {
    Success,
    Failure,
    VersionMismatch,
    SecurityChecksFailed,
    IncompleteImage,
    // 0x5 - 0x8 reserved
    Timeout,
    GenericError,
    Other(u8),
}

impl From<u8> for VerifyResult {
    fn from(v: u8) -> Self {
        match v {
            0x00 => Self::Success,
            0x01 => Self::Failure,
            0x02 => Self::VersionMismatch,
            0x03 => Self::SecurityChecksFailed,
            0x04 => Self::IncompleteImage,
            0x09 => Self::Timeout,
            0x0a => Self::GenericError,
            v => Self::Other(v),
        }
    }
}

impl From<VerifyResult> for u8 {
    fn from(v: VerifyResult) -> u8 {
        match v {
            VerifyResult::Success => 0x00,
            VerifyResult::Failure => 0x01,
            VerifyResult::VersionMismatch => 0x02,
            VerifyResult::SecurityChecksFailed => 0x03,
            VerifyResult::IncompleteImage => 0x04,
            VerifyResult::Timeout => 0x09,
            VerifyResult::GenericError => 0x0a,
            VerifyResult::Other(v) => v,
        }
    }
}

/// Apply Result codes for ApplyComplete
///
/// Not all defined Verify Result codes are defined in this enum,
/// arbitrary `u8` values may be expected in `Other` variant.
///
/// Ref "ApplyComplete command format" Table 32 of DSP0267 1.1.0
#[allow(missing_docs)]
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum ApplyResult {
    Success,
    SuccessModActivation,
    FailedMemoryWrite,
    Timeout,
    GenericError,
    Other(u8),
}

impl From<u8> for ApplyResult {
    fn from(v: u8) -> Self {
        match v {
            0x00 => Self::Success,
            0x01 => Self::SuccessModActivation,
            0x02 => Self::FailedMemoryWrite,
            0x09 => Self::Timeout,
            0x0a => Self::GenericError,
            v => Self::Other(v),
        }
    }
}

impl From<ApplyResult> for u8 {
    fn from(v: ApplyResult) -> u8 {
        match v {
            ApplyResult::Success => 0x00,
            ApplyResult::SuccessModActivation => 0x01,
            ApplyResult::FailedMemoryWrite => 0x02,
            ApplyResult::Timeout => 0x09,
            ApplyResult::GenericError => 0x0a,
            ApplyResult::Other(v) => v,
        }
    }
}

//type VResult<I,O> = IResult<I, O, VerboseError<I>>;
type VResult<I, O> = IResult<I, O>;

#[derive(FromPrimitive, Debug, PartialEq)]
#[repr(u8)]
enum TransferFlag {
    Start = 0x01,
    Middle = 0x02,
    End = 0x04,
}

#[cfg(feature = "alloc")]
#[derive(Debug)]
pub enum DescriptorString {
    String(String),
    Bytes(Vec<u8>),
}

#[cfg(not(feature = "alloc"))]
#[derive(Debug)]
pub enum DescriptorString {
    String(heapless::String<MAX_DESC_STRING>),
    Bytes(heapless::Vec<u8, MAX_DESC_STRING>),
}

impl fmt::Display for DescriptorString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let trim_chars = ['\0', ' '];
        match self {
            Self::String(s) => {
                write!(f, "{}", s.trim_end_matches(trim_chars).escape_default())
            }
            Self::Bytes(bs) => {
                for b in bs.iter() {
                    write!(f, "{b:02x}")?;
                }
                Ok(())
            }
        }
    }
}

impl DescriptorString {
    pub fn empty() -> Self {
        Self::Bytes(Default::default())
    }

    pub fn string_type(&self) -> u8 {
        match self {
            Self::Bytes(_) => 0,
            Self::String(_) => 1,
        }
    }

    fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Bytes(b) => b,
            Self::String(b) => b.as_bytes(),
        }
    }

    fn bytes_len(&self) -> u8 {
        self.as_bytes().len() as u8
    }
}

#[cfg(feature = "alloc")]
impl DescriptorString {
    pub fn write_utf8_bytes(&self, v: &mut Vec<u8>) {
        match self {
            Self::String(s) => {
                v.push(0x01);
                v.push(s.len() as u8);
                v.extend_from_slice(s.as_bytes());
            }
            Self::Bytes(b) => {
                v.push(0x00);
                v.push(b.len() as u8);
                v.extend_from_slice(b);
            }
        }
    }

    pub fn new_utf8(v: &[u8]) -> Option<Self> {
        if v.len() > 0xff {
            return None;
        }
        let s = core::str::from_utf8(v).ok()?;
        Some(Self::String(s.to_string()))
    }

    pub fn new_str(s: &str) -> Option<Self> {
        if s.len() > 0xff {
            return None;
        }
        Some(Self::String(s.to_string()))
    }

    pub fn new_bytes(v: &[u8]) -> Option<Self> {
        if v.len() > 0xff {
            return None;
        }
        Some(Self::Bytes(v.to_vec()))
    }

    // // TODO: use encoding_rs to handle BOM, LE, BE.
    // pub fn new_utf16(v: &[u8], _strtyp: u8) -> VResult<&[u8], Self> {
    //     let b16 = v
    //         .iter()
    //         .tuples()
    //         .map(|(a, b)| ((*a as u16) << 8 | (*b as u16)))
    //         .collect::<Vec<u16>>();

    //     let s = String::from_utf16(b16)
    //         .map_err(|_| nom::Err::Failure((v, nom::ErrorKind::Fail)))?;
    //     Ok(&[], Self::String(s))
    // }
}

#[cfg(not(feature = "alloc"))]
impl DescriptorString {
    pub fn new_utf8(v: &[u8]) -> Option<Self> {
        let s = core::str::from_utf8(v).ok()?;
        Self::new_str(s)
    }

    pub fn new_str(s: &str) -> Option<Self> {
        let s = heapless::String::try_from(s).ok()?;
        Some(Self::String(s))
    }

    pub fn new_bytes(v: &[u8]) -> Option<Self> {
        v.try_into().ok().map(|v| Self::Bytes(v))
    }

    // pub fn new_utf16(v: &[u8]) -> VResult<&[u8], Self> {
    //     debug!("from_utf16 unimplemented")
    //     let s = String::from_utf16(v)
    //         .map_err(|_| nom::Err::Failure((v, nom::ErrorKind::Fail)))?;
    //     Ok(&[], Self::String(s))
    // }
}

/// A device descriptor
#[derive(Debug)]
pub enum Descriptor {
    /// PCI Vendor ID
    PciVid(u16),
    /// IANA Enterprise ID
    Iana(u32),
    /// UUID
    Uuid(uuid::Uuid),
    /// PCI Device ID
    PciDid(u16),
    /// PCI Subsystem Vendor ID
    PciSubVid(u16),
    /// PCI Subsystem Device ID
    PciSubDid(u16),
    /// Vendor Defined
    Vendor {
        title: Option<DescriptorString>,
        #[cfg(feature = "alloc")]
        data: Vec<u8>,
        #[cfg(not(feature = "alloc"))]
        data: heapless::Vec<u8, MAX_VENDORDATA>,
    },
}

/// Parse a string with type and length
pub fn parse_string<'a>(
    typ: u8,
    len: u8,
) -> impl FnMut(&'a [u8]) -> VResult<&'a [u8], DescriptorString> {
    map_opt(take(len), move |d: &[u8]| match typ {
        0 => DescriptorString::new_bytes(d),
        // ascii or utf-8
        1 | 2 => DescriptorString::new_utf8(d),
        _ => {
            debug!("unimplemented string type {typ}");
            None
        }
    })
}

// Where we have type, length and data all adjacent (and in that order)
pub fn parse_string_adjacent(buf: &[u8]) -> VResult<&[u8], DescriptorString> {
    let (r, (typ, len)) = tuple((le_u8, le_u8))(buf)?;
    parse_string(typ, len)(r)
}

impl Descriptor {
    pub fn parse_pcivid(buf: &[u8]) -> VResult<&[u8], Self> {
        map(le_u16, Self::PciVid)(buf)
    }

    pub fn parse_iana(buf: &[u8]) -> VResult<&[u8], Self> {
        map(le_u32, Self::Iana)(buf)
    }

    pub fn parse_uuid(buf: &[u8]) -> VResult<&[u8], Self> {
        map_res(take(16usize), |b| {
            let u = uuid::Uuid::from_slice(b)?;
            Ok::<Descriptor, uuid::Error>(Self::Uuid(u))
        })(buf)
    }

    pub fn parse_pcidid(buf: &[u8]) -> VResult<&[u8], Self> {
        map(le_u16, Self::PciDid)(buf)
    }

    pub fn parse_pcisubvid(buf: &[u8]) -> VResult<&[u8], Self> {
        map(le_u16, Self::PciSubVid)(buf)
    }

    pub fn parse_pcisubdid(buf: &[u8]) -> VResult<&[u8], Self> {
        map(le_u16, Self::PciSubDid)(buf)
    }

    #[cfg(feature = "alloc")]
    fn new_vendor(t: Option<DescriptorString>, d: &[u8]) -> Option<Self> {
        Some(Self::Vendor {
            title: t,
            data: d.to_vec(),
        })
    }

    #[cfg(not(feature = "alloc"))]
    fn new_vendor(t: Option<DescriptorString>, d: &[u8]) -> Option<Self> {
        let data = d.try_into().ok()?;
        Some(Self::Vendor { title: t, data })
    }

    pub fn parse_vendor(buf: &[u8]) -> VResult<&[u8], Self> {
        // Attempt to parse with a proper title string; if not present just
        // consume everything as byte data
        let f1 = |(t, d): (_, &[u8])| Self::new_vendor(Some(t), d);
        let f2 = |d: &[u8]| Self::new_vendor(None, d);
        alt((
            map_opt(tuple((parse_string_adjacent, rest)), f1),
            map_opt(rest, f2),
        ))(buf)
    }

    fn parse_fail(buf: &[u8]) -> VResult<&[u8], Self> {
        nom::combinator::fail(buf)
    }

    pub fn parse(buf: &[u8]) -> VResult<&[u8], Self> {
        let f = |(typ, len)| {
            let g = match typ {
                0x0000 => Self::parse_pcivid,
                0x0001 => Self::parse_iana,
                0x0002 => Self::parse_uuid,
                0x0100 => Self::parse_pcidid,
                0x0101 => Self::parse_pcisubvid,
                0x0102 => Self::parse_pcisubdid,
                0xffff => Self::parse_vendor,
                _ => {
                    debug!("Unknown descriptor type 0x{typ:04x}");
                    Self::parse_fail
                }
            };
            map_parser(take(len), all_consuming(g))
        };
        flat_map(tuple((le_u16, le_u16)), f)(buf)
    }

    pub fn desc_type(&self) -> u16 {
        match self {
            Self::PciVid(_) => 0x0000,
            Self::Iana(_) => 0x0001,
            Self::Uuid(_) => 0x0002,
            Self::PciDid(_) => 0x0100,
            Self::PciSubVid(_) => 0x0101,
            Self::PciSubDid(_) => 0x0102,
            Self::Vendor { .. } => 0xffff,
        }
    }

    pub fn write_buf(&self, buf: &mut [u8]) -> Option<usize> {
        let mut b = SliceWriter::new(buf);
        match self {
            Self::PciVid(v) => b.push_le16(*v),
            Self::Iana(v) => b.push_le32(*v),
            Self::Uuid(v) => b.push(v.as_bytes()),
            Self::PciDid(v) => b.push_le16(*v),
            Self::PciSubVid(v) => b.push_le16(*v),
            Self::PciSubDid(v) => b.push_le16(*v),
            Self::Vendor { .. } => {
                // TODO encode Vendor
                debug!("Vendor descriptor write not implemented");
                None
            }
        }
    }
}

impl fmt::Display for Descriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PciVid(id) => write!(f, "pci-vendor:{id:04x}"),
            Self::Iana(id) => write!(f, "iana:{id:08x}"),
            Self::Uuid(id) => write!(f, "uuid:{id}"),
            Self::PciDid(id) => write!(f, "pci-device:{id:04x}"),
            Self::PciSubVid(id) => write!(f, "pci-subsys-vendor:{id:04x}"),
            Self::PciSubDid(id) => write!(f, "pci-subsys-device:{id:04x}"),
            Self::Vendor { title, data } => {
                match title {
                    Some(t) => write!(f, "vendor:{t}")?,
                    None => write!(f, "vendor:")?,
                }
                write!(f, "[")?;
                for b in data {
                    write!(f, "{b:02x}")?;
                }
                write!(f, "]")?;
                Ok(())
            }
        }
    }
}

impl PartialEq for Descriptor {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Vendor { data: s, .. }, Self::Vendor { data: o, .. }) => {
                s == o
            }
            (Self::Iana(s), Self::Iana(o)) => s == o,
            (Self::Uuid(s), Self::Uuid(o)) => s == o,
            (Self::PciVid(s), Self::PciVid(o)) => s == o,
            (Self::PciDid(s), Self::PciDid(o)) => s == o,
            (Self::PciSubVid(s), Self::PciSubVid(o)) => s == o,
            (Self::PciSubDid(s), Self::PciSubDid(o)) => s == o,
            _ => false,
        }
    }
}

#[derive(Debug)]
pub struct DeviceIdentifiers {
    #[cfg(feature = "alloc")]
    pub ids: Vec<Descriptor>,
    #[cfg(not(feature = "alloc"))]
    pub ids: &'static [Descriptor],
}

impl PartialEq for DeviceIdentifiers {
    fn eq(&self, other: &Self) -> bool {
        self.ids == other.ids
    }
}

#[cfg(feature = "alloc")]
impl DeviceIdentifiers {
    pub fn parse(buf: &[u8]) -> VResult<&[u8], Self> {
        length_count(le_u8, Descriptor::parse)(buf)
            .map(|(rest, ids)| (rest, Self { ids }))
    }
}

impl DeviceIdentifiers {
    /// Returns a response for QueryDeviceIdentifiers
    pub fn write_buf(&self, buf: &mut [u8]) -> Option<usize> {
        let mut b = SliceWriter::new(buf);

        if self.ids.is_empty() {
            return None;
        }

        // To be filled after the length is known
        b.push_le32(0)?;
        b.push_le8(self.ids.len() as u8)?;

        for v in self.ids.iter() {
            b.push_le16(v.desc_type())?;
            b.push_prefix_le::<u16, _>(|m| v.write_buf(m))?;
        }

        let written = b.written();

        // Now fill out the DeviceIdentifiersLength the the start.
        // Doesn't include ids len.
        let mut b = SliceWriter::new(buf);
        b.push_le32((written - 5) as u32)?;

        Some(written)
    }
}

impl fmt::Display for DeviceIdentifiers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for id in self.ids.iter() {
            write!(f, "{}{}", if first { "" } else { "," }, id)?;
            first = false;
        }
        Ok(())
    }
}

pub type PldmDate = chrono::naive::NaiveDate;

#[derive(Debug)]
#[allow(dead_code)]
pub struct ComponentVersion {
    pub stamp: u32,
    pub version: DescriptorString,
    pub date: Option<PldmDate>,
}

impl ComponentVersion {
    /// Creates a new utf-8 string `ComponentVersion`
    ///
    /// May fail on non-`alloc` if the string is too long
    pub fn new_str(s: &str) -> Option<Self> {
        Some(Self {
            stamp: 0,
            version: DescriptorString::new_str(s)?,
            date: None,
        })
    }

    /// Writes stamp, type, length, date
    ///
    /// As used for the ComponentParameterTable
    pub fn write_initial(&self, b: &mut [u8]) -> Option<usize> {
        let mut b = SliceWriter::new(b);
        b.push_le32(self.stamp)?;
        b.push_le8(self.version.string_type())?;
        b.push_le8(self.version.bytes_len())?;
        b.push_with(|m| pldm_date_write_buf(&self.date, m))?;
        Some(b.written())
    }
}

impl fmt::Display for ComponentVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.version)?;
        if let Some(d) = self.date {
            write!(f, " ({d:?})")?;
        }
        if self.stamp != 0 {
            write!(f, " [{:08x}]", self.stamp)?;
        }
        Ok(())
    }
}

pub fn pldm_date_parse(buf: &[u8]) -> VResult<&[u8], Option<PldmDate>> {
    /* YYYYMMDD */
    let (r, o) = alt((
        value(None, tag([0u8; 8])),
        map(
            tuple((
                map_parser(take(4u8), c_u32),
                map_parser(take(2u8), c_u32),
                map_parser(take(2u8), c_u32),
            )),
            Some,
        ),
    ))(buf)?;

    let d = o.and_then(|(y, m, d)| PldmDate::from_ymd_opt(y as i32, m, d));

    Ok((r, d))
}

pub fn pldm_date_write_buf(
    date: &Option<PldmDate>,
    b: &mut [u8],
) -> Option<usize> {
    let mut b = SliceWriter::new(b);
    if let Some(date) = date {
        let mut y = date.year();
        if y < 0 {
            return None;
        }
        let m = date.month();
        let d = date.day();

        // hand written to avoid fmt code bloat
        let mut w = [0u8; 8];
        for i in 0..4 {
            w[3 - i] = (y % 10) as u8;
            y /= 10;
        }
        w[4] = (m / 10) as u8;
        w[5] = (m % 10) as u8;
        w[6] = (d / 10) as u8;
        w[7] = (d % 10) as u8;
        let w = w.map(|c| b'0' + c);
        b.push(&w)?;

        // This is 3kB of code size.
        // write!(b, "{:04}{:02}{:02}", y, date.month(), date.day()).ok()?;
    } else {
        b.push(&[0u8; 8])?;
    }

    Some(b.written())
}

/// Component classification
#[allow(missing_docs)]
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum ComponentClassification {
    Unknown,
    Other,
    Firmware,
    /// Other values
    Value(u16),
}

impl From<u16> for ComponentClassification {
    fn from(x: u16) -> Self {
        match x {
            0x0000 => Self::Unknown,
            0x0001 => Self::Other,
            0x000a => Self::Firmware,
            v => Self::Value(v),
        }
    }
}

impl From<&ComponentClassification> for u16 {
    fn from(c: &ComponentClassification) -> u16 {
        match c {
            ComponentClassification::Unknown => 0x0000,
            ComponentClassification::Other => 0x0001,
            ComponentClassification::Firmware => 0x000a,
            ComponentClassification::Value(v) => *v,
        }
    }
}

#[derive(EnumSetType, Debug)]
pub enum ActivationMethod {
    PendingComponentImageSet = 7,
    PendingImage = 6,
    ACPowerCycle = 5,
    DCPowerCycle = 4,
    SystemReboot = 3,
    MediumSpecificReset = 2,
    SelfContained = 1,
    Automatic = 0,
}

pub type ActivationMethods = EnumSet<ActivationMethod>;

#[derive(EnumSetType, Debug)]
pub enum DeviceCapability {
    ComponentUpdateFailureRecovery = 0,
    ComponentUpdateFailureRetry = 1,
    FDHostFunctionalityDuringUpdate = 2,
    FDPartialUpdates = 3,
    FDUpdateModeRestrictionOSActive = 4,
    FDDowngradeRestrictions = 8,
    SecurityRevisionUpdateRequest = 9,
}

impl DeviceCapability {
    #[cfg(feature = "alloc")]
    pub fn to_desc(&self, is_set: bool) -> String {
        match self {
            Self::ComponentUpdateFailureRecovery => format!(
                "Device will{} revert to previous component on failure",
                if is_set { " not" } else { "" }
            ),
            Self::ComponentUpdateFailureRetry => format!(
                "{} restarting update on failure",
                if is_set {
                    "Requires"
                } else {
                    "Does not require"
                }
            ),
            Self::FDHostFunctionalityDuringUpdate => format!(
                "Host functionality is{} reduced during update",
                if is_set { "" } else { " not" }
            ),
            Self::FDPartialUpdates => format!(
                "Device can{} accept a partial update",
                if is_set { "" } else { "not" }
            ),
            Self::FDUpdateModeRestrictionOSActive => String::from(if is_set {
                "No host OS restrictions during update"
            } else {
                "Device unable to update while host OS active"
            }),
            Self::FDDowngradeRestrictions => String::from(if is_set {
                "No downgrade restrictions"
            } else {
                "Downgrades may be restricted"
            }),
            Self::SecurityRevisionUpdateRequest => format!(
                "Device components {} have security revision numbers",
                if is_set { "may" } else { "do not" }
            ),
        }
    }
}

#[derive(Debug, Default)]
pub struct DeviceCapabilities(EnumSet<DeviceCapability>);

impl DeviceCapabilities {
    pub fn from_u32(x: u32) -> Self {
        let x = x & EnumSet::<DeviceCapability>::all().as_u32();
        Self(EnumSet::<DeviceCapability>::from_u32(x))
    }

    pub fn as_u32(&self) -> u32 {
        self.0.as_u32()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    #[cfg(feature = "alloc")]
    pub fn values(&self) -> Vec<(DeviceCapability, bool)> {
        EnumSet::<DeviceCapability>::all()
            .iter()
            .map(|cap| (cap, self.0.contains(cap)))
            .collect()
    }
}

#[derive(EnumSetType, Debug)]
pub enum ComponentCapability {
    FDApplyState = 0,
    ComponentDowngrade = 2,
    SecurityRevisionUpdateRequest = 3,
    SecurityRevisionNotLatest = 4,
}

pub type ComponentCapabilities = EnumSet<ComponentCapability>;

/// Specific to a ComponentParameterTable entry in Get Firmware Parameters
#[derive(Debug)]
#[allow(dead_code)]
pub struct Component {
    pub classification: ComponentClassification,
    pub identifier: u16,
    pub classificationindex: u8,
    pub active: ComponentVersion,
    pub pending: ComponentVersion,
    pub activation_methods: ActivationMethods,
    pub caps_during_update: ComponentCapabilities,
}

impl Component {
    pub fn parse(buf: &[u8]) -> VResult<&[u8], Self> {
        let (
            r,
            (
                classification,
                identifier,
                classificationindex,
                c1,
                c2,
                activation_methods,
                caps_during_update,
            ),
        ) = tuple((
            le_u16,
            le_u16,
            le_u8,
            tuple((le_u32, le_u8, le_u8, pldm_date_parse)),
            tuple((le_u32, le_u8, le_u8, pldm_date_parse)),
            le_u16,
            le_u32,
        ))(buf)?;

        let (r, c1_str) = parse_string(c1.1, c1.2)(r)?;
        let (r, c2_str) = parse_string(c2.1, c2.2)(r)?;

        let c = Component {
            classification: classification.into(),
            identifier,
            classificationindex,
            active: ComponentVersion {
                stamp: c1.0,
                version: c1_str,
                date: c1.3,
            },
            pending: ComponentVersion {
                stamp: c2.0,
                version: c2_str,
                date: c2.3,
            },
            activation_methods: ActivationMethods::from_u16(activation_methods),
            caps_during_update: ComponentCapabilities::from_u32(
                caps_during_update,
            ),
        };

        Ok((r, c))
    }

    pub fn write_buf(&self, b: &mut [u8]) -> Option<usize> {
        let mut b = SliceWriter::new(b);
        b.push_le16(u16::from(&self.classification))?;
        b.push_le16(self.identifier)?;
        b.push_le8(self.classificationindex)?;
        b.push_with(|m| self.active.write_initial(m))?;
        b.push_with(|m| self.pending.write_initial(m))?;
        b.push_le16(self.activation_methods.as_u16())?;
        b.push_le32(self.caps_during_update.as_u32())?;
        b.push(self.active.version.as_bytes())?;
        b.push(self.pending.version.as_bytes())?;

        Some(b.written())
    }
}

/// An entry for Pass Component Table or Update Component
///
/// The same structure is used for both, with `size` and `flags`
/// unpopulated for Pass Component
#[allow(missing_docs)]
pub struct UpdateComponent {
    pub classification: ComponentClassification,
    pub identifier: u16,
    pub classificationindex: u8,
    pub comparisonstamp: u32,
    pub version: DescriptorString,
    /// Size, not set for Pass Component
    pub size: Option<u32>,
    /// Flags, not set for Pass Component
    pub flags: Option<u32>,
}

impl UpdateComponent {
    pub fn parse_pass_component(buf: &[u8]) -> VResult<&[u8], Self> {
        let (
            r,
            (
                classification,
                identifier,
                classificationindex,
                comparisonstamp,
                version,
            ),
        ) = tuple((le_u16, le_u16, le_u8, le_u32, parse_string_adjacent))(buf)?;

        let s = Self {
            classification: classification.into(),
            identifier,
            classificationindex,
            comparisonstamp,
            version,
            size: None,
            flags: None,
        };
        Ok((r, s))
    }
    pub fn parse_update(buf: &[u8]) -> VResult<&[u8], Self> {
        let (
            r,
            (
                classification,
                identifier,
                classificationindex,
                comparisonstamp,
                size,
                flags,
                version,
            ),
        ) = tuple((
            le_u16,
            le_u16,
            le_u8,
            le_u32,
            le_u32,
            le_u32,
            parse_string_adjacent,
        ))(buf)?;

        let s = Self {
            classification: classification.into(),
            identifier,
            classificationindex,
            comparisonstamp,
            version,
            size: Some(size),
            flags: Some(flags),
        };
        Ok((r, s))
    }
}

#[derive(Debug)]
pub struct UpdateComponentResponse {
    /// A ComponentResponseCode
    pub response_code: u8,
    pub update_flags: u32,
    pub estimate_time: u16,
}

/// Response Codes for Update Component and Pass Component Table
///
/// This list is not complete, refer to the specification
#[allow(missing_docs)]
#[repr(u8)]
#[derive(Debug, PartialEq)]
#[non_exhaustive]
pub enum ComponentResponseCode {
    Success = 0x00,
    IdenticalVersion = 0x01,
    DowngradeVersion = 0x02,
    InvalidVersion = 0x03,
    Conflict = 0x04,
    MissingPrerequisite = 0x05,
    NotSupported = 0x06,
    SecurityPreventDowngrade = 0x07,
}

impl UpdateComponentResponse {
    pub fn parse(buf: &[u8]) -> VResult<&[u8], Self> {
        let (r, (_response, response_code, update_flags, estimate_time)) =
            tuple((le_u8, le_u8, le_u32, le_u16))(buf)?;

        let s = Self {
            response_code,
            update_flags,
            estimate_time,
        };
        Ok((r, s))
    }
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct FirmwareParameters<'a> {
    pub caps: DeviceCapabilities,
    pub components: VecOrSlice<'a, Component>,
    pub active: DescriptorString,
    pub pending: DescriptorString,
}

#[cfg(feature = "alloc")]
impl FirmwareParameters<'_> {
    pub fn parse(buf: &[u8]) -> VResult<&[u8], Self> {
        let (r, p) = tuple((le_u32, le_u16, le_u8, le_u8, le_u8, le_u8))(buf)?;

        let (
            caps,
            ccount,
            active_str_type,
            active_str_len,
            pending_str_type,
            pending_str_len,
        ) = p;

        let (r, active) = parse_string(active_str_type, active_str_len)(r)?;
        let (r, pending) = parse_string(pending_str_type, pending_str_len)(r)?;

        let (r, components) = count(Component::parse, ccount as usize)(r)?;

        let fp = FirmwareParameters {
            caps: DeviceCapabilities::from_u32(caps),
            components: components.into(),
            active,
            pending,
        };

        Ok((r, fp))
    }
}

impl FirmwareParameters<'_> {
    pub fn write_buf(&self, buf: &mut [u8]) -> Option<usize> {
        let mut w = SliceWriter::new(buf);

        w.push_le32(self.caps.as_u32())?;
        w.push_le16(self.components.len() as u16)?;
        w.push_le8(self.active.string_type())?;
        w.push_le8(self.active.bytes_len())?;
        w.push_le8(self.pending.string_type())?;
        w.push_le8(self.pending.bytes_len())?;
        w.push(self.active.as_bytes())?;
        w.push(self.pending.as_bytes())?;

        for c in self.components.as_ref() {
            w.push_with(|b| c.write_buf(b))?;
        }

        Some(w.written())
    }
}

#[derive(Debug)]
pub struct RequestUpdateResponse {
    pub fd_metadata_len: u16,
    pub fd_will_sent_gpd: u8,
}

impl RequestUpdateResponse {
    pub fn parse(buf: &[u8]) -> VResult<&[u8], Self> {
        let (r, t) = tuple((le_u16, le_u8))(buf)?;
        Ok((
            r,
            RequestUpdateResponse {
                fd_metadata_len: t.0,
                fd_will_sent_gpd: t.1,
            },
        ))
    }

    pub fn write_buf(&self, b: &mut [u8]) -> Option<usize> {
        let mut b = SliceWriter::new(b);
        b.push_le16(self.fd_metadata_len)?;
        b.push_le8(self.fd_will_sent_gpd)?;
        Some(b.written())
    }
}

#[derive(Debug)]
pub struct RequestUpdateRequest {
    pub max_transfer: u32,
    pub num_components: u16,
    pub max_outstanding: u8,
    pub package_data_length: u16,
    pub component_image_set_version: DescriptorString,
}

impl RequestUpdateRequest {
    pub fn parse(buf: &[u8]) -> VResult<&[u8], Self> {
        let (r, t) =
            tuple((le_u32, le_u16, le_u8, le_u16, parse_string_adjacent))(buf)?;
        Ok((
            r,
            RequestUpdateRequest {
                max_transfer: t.0,
                num_components: t.1,
                max_outstanding: t.2,
                package_data_length: t.3,
                component_image_set_version: t.4,
            },
        ))
    }
}

#[derive(Debug)]
pub struct GetStatusResponse {
    pub current_state: PldmFDState,
    pub previous_state: PldmFDState,
    pub aux_state: u8,
    pub aux_state_status: u8,
    pub progress_percent: u8,
    pub reason_code: u8,
    pub update_option_flags_enabled: u32,
}

impl GetStatusResponse {
    pub fn parse(buf: &[u8]) -> VResult<&[u8], Self> {
        let (r, t) = tuple((
            PldmFDState::parse,
            PldmFDState::parse,
            le_u8,
            le_u8,
            le_u8,
            le_u8,
            le_u32,
        ))(buf)?;
        Ok((
            r,
            Self {
                current_state: t.0,
                previous_state: t.1,
                aux_state: t.2,
                aux_state_status: t.3,
                progress_percent: t.4,
                reason_code: t.5,
                update_option_flags_enabled: t.6,
            },
        ))
    }

    pub fn write_buf(&self, buf: &mut [u8]) -> Option<usize> {
        let mut b = SliceWriter::new(buf);
        b.push_le8(self.current_state as u8)?;
        b.push_le8(self.previous_state as u8)?;
        b.push_le8(self.aux_state)?;
        b.push_le8(self.aux_state_status)?;
        b.push_le8(self.progress_percent)?;
        b.push_le8(self.reason_code)?;
        b.push_le32(self.update_option_flags_enabled)?;
        Some(b.written())
    }
}

impl fmt::Display for GetStatusResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}", self.current_state)
    }
}

pub struct UpdateTransferProgress {
    pub cur_xfer: Option<(u32, u32)>,
    pub percent: u8,
    pub bps: f32,
    pub duration: chrono::Duration,
    pub remaining: chrono::Duration,
    pub complete: bool,
}

#[cfg(test)]
mod tests {

    use crate::*;

    #[test]
    fn date_parse() {
        let x = b"20240704x";
        let d = pldm_date_parse(x).unwrap();
        let expect = PldmDate::parse_from_str("20240704", "%Y%m%d").unwrap();
        assert_eq!(d, ("x".as_bytes(), Some(expect)));

        // negative date rejected
        let x = b"-0240704x";
        pldm_date_parse(x).unwrap_err();

        // short fails
        let x = b"2024070";
        pldm_date_parse(x).unwrap_err();

        // space rejected
        let x = b" 0240704x";
        pldm_date_parse(x).unwrap_err();

        // bad date returns None
        let x = b"20240732";
        let (_, d) = pldm_date_parse(x).unwrap();
        assert_eq!(d, None);
    }

    #[test]
    fn date_write() {
        let d = PldmDate::parse_from_str("20240704", "%Y%m%d").unwrap();

        let mut b = [99u8; 9];
        let l = pldm_date_write_buf(&Some(d), &mut b).unwrap();
        assert_eq!(b[8], 99);
        assert_eq!(l, 8);
        let b = &b[..l];
        assert_eq!(b"20240704", b);

        // short fails
        let mut b = [99u8; 7];
        assert!(pldm_date_write_buf(&Some(d), &mut b).is_none());

        // None date is all 0x00 bytes
        let mut b = [99u8; 8];
        let l = pldm_date_write_buf(&None, &mut b).unwrap();
        assert_eq!(l, 8);
        assert_eq!(b, [0u8; 8]);
    }

    #[test]
    #[rustfmt::skip]
    fn write_device_identifier() {
        let ids = vec![Descriptor::PciVid(0xccde), Descriptor::Iana(1234)];
        let di = DeviceIdentifiers { ids };

        let mut sendbuf = [0u8; 50];
        let l = di.write_buf(&mut sendbuf).unwrap();
        let sendbuf = &sendbuf[..l];
        let expect = [
            // length
            0x0e, 0x00, 0x00, 0x00,
            // count
            0x02,
            // desc 1 type
            0x00, 0x00,
            // data
            0x02, 0x00,
            // length
            0xde, 0xcc,
            // desc 2 type
            0x01, 0x00,
            // length
            0x04, 0x00,
            // data
            0xd2, 0x04, 0x00, 0x00,
        ];
        assert_eq!(sendbuf, expect);
    }
}
