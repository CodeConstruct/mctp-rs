// SPDX-License-Identifier: Apache-2.0
/*
 * PLDM firmware update utility: PLDM type 5 messaging
 *
 * Copyright (c) 2023 Code Construct
 */
#![cfg_attr(not(any(feature = "std", test)), no_std)]
#![forbid(unsafe_code)]

use core::fmt;
use log::debug;

use enumset::{EnumSet, EnumSetType};

use nom::{
    branch::alt,
    bytes::complete::{tag, take},
    character::complete::{i32 as c_i32, u32 as c_u32},
    combinator::{
        all_consuming, flat_map, map, map_opt, map_parser, map_res, rest, value,
    },
    number::complete::{le_u16, le_u32, le_u8},
    sequence::tuple,
    IResult,
};

#[cfg(feature = "alloc")]
use nom::multi::{count, length_count};

/// Firmware Device specific
pub mod fd;
/// PLDM firmware packaging
#[cfg(feature = "alloc")]
pub mod pkg;
/// Update Agent specific
#[cfg(feature = "alloc")]
pub mod ua;

pub const PLDM_TYPE_FW: u8 = 5;

/// PLDM Firmware Specification requires 255 byte length.
///
/// Can be reduced when strings are a known length.
#[cfg(not(feature = "alloc"))]
const MAX_DESC_STRING: usize = 64;

/// PLDM Firmware Specification has no length limit.
///
/// Can be reduced length is known.
#[cfg(not(feature = "alloc"))]
const MAX_VENDORDATA: usize = 64;

#[cfg(not(feature = "alloc"))]
const MAX_COMPONENTS: usize = 3;

#[derive(Debug, PartialEq)]
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
    pub fn parse(buf: &[u8]) -> VResult<&[u8], Self> {
        map_res(le_u8, TryInto::<PldmFDState>::try_into)(buf)
    }
}

//type VResult<I,O> = IResult<I, O, VerboseError<I>>;
type VResult<I, O> = IResult<I, O>;

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
                write!(
                    f,
                    "{}",
                    s.trim_end_matches(&trim_chars).escape_default()
                )
            }
            Self::Bytes(bs) => {
                for b in bs.iter() {
                    write!(f, "{:02x}", b)?;
                }
                Ok(())
            }
        }
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
        let s = core::str::from_utf8(v).ok()?;
        Some(Self::String(s.to_string()))
    }

    pub fn new_bytes(v: &[u8]) -> Option<Self> {
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

#[derive(Debug)]
pub enum Descriptor {
    PciVid(u16),
    Iana(u32),
    Uuid(uuid::Uuid),
    Vendor {
        title: Option<DescriptorString>,
        #[cfg(feature = "alloc")]
        data: Vec<u8>,
        #[cfg(not(feature = "alloc"))]
        data: heapless::Vec<u8, MAX_VENDORDATA>,
    },
}

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

    pub fn parse(buf: &[u8]) -> VResult<&[u8], Self> {
        let f = |(typ, len)| {
            let g = match typ {
                0x0000 => Self::parse_pcivid,
                0x0001 => Self::parse_iana,
                0x0002 => Self::parse_uuid,
                0xffff => Self::parse_vendor,
                _ => unimplemented!(),
            };
            map_parser(take(len), all_consuming(g))
        };
        flat_map(tuple((le_u16, le_u16)), f)(buf)
    }
}

impl fmt::Display for Descriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PciVid(id) => write!(f, "pci-vid:{:04x}", id),
            Self::Iana(id) => write!(f, "iana:{:08x}", id),
            Self::Uuid(id) => write!(f, "uuid:{}", id),
            Self::Vendor { title, data } => {
                match title {
                    Some(t) => write!(f, "vendor:{}", t)?,
                    None => write!(f, "vendor:")?,
                }
                write!(f, "[")?;
                for b in data {
                    write!(f, "{:02x}", b)?;
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

impl DeviceIdentifiers {
    #[cfg(feature = "alloc")]
    pub fn parse(buf: &[u8]) -> VResult<&[u8], Self> {
        length_count(le_u8, Descriptor::parse)(buf)
            .map(|(rest, ids)| (rest, Self { ids }))
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

impl fmt::Display for ComponentVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.version)?;
        if let Some(d) = self.date {
            write!(f, " ({:?})", d)?;
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
                map_parser(take(4u8), c_i32),
                map_parser(take(2u8), c_u32),
                map_parser(take(2u8), c_u32),
            )),
            Some,
        ),
    ))(buf)?;

    let d = o.and_then(|(y, m, d)| PldmDate::from_ymd_opt(y, m, d));

    Ok((r, d))
}

#[derive(Debug)]
pub enum ComponentClassification {
    Unknown,
    Other,
    Firmware,
}

impl From<u16> for ComponentClassification {
    fn from(x: u16) -> Self {
        match x {
            0x0000 => Self::Unknown,
            0x0001 => Self::Other,
            0x000a => Self::Firmware,
            _ => unimplemented!(),
        }
    }
}

impl From<&ComponentClassification> for u16 {
    fn from(c: &ComponentClassification) -> u16 {
        match c {
            ComponentClassification::Unknown => 0x0000,
            ComponentClassification::Other => 0x0001,
            ComponentClassification::Firmware => 0x000a,
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

type ActivationMethods = EnumSet<ActivationMethod>;

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

#[derive(Debug)]
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
    /// Specific to a ComponentParameterTable entry in Get Firmware Parameters
    #[cfg(feature = "alloc")]
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
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct FirmwareParameters {
    pub caps: DeviceCapabilities,
    #[cfg(feature = "alloc")]
    pub components: Vec<Component>,
    #[cfg(not(feature = "alloc"))]
    pub components: heapless::Vec<Component, MAX_COMPONENTS>,
    pub active: DescriptorString,
    pub pending: DescriptorString,
}

impl FirmwareParameters {
    #[cfg(feature = "alloc")]
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
            components,
            active,
            pending,
        };

        Ok((r, fp))
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
