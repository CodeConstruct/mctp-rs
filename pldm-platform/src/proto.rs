use core::{marker::PhantomData, num::ParseIntError, str::FromStr};

use deku::DekuContainerWrite;
#[allow(unused)]
use log::{debug, error, info, trace, warn};

use core::fmt::Debug;
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;

use deku::{
    ctx::Limit, deku_derive, writer::Writer, DekuEnumExt, DekuError, DekuRead,
    DekuReader, DekuUpdate, DekuWrite, DekuWriter,
};

use chrono::{DateTime, Datelike, FixedOffset, TimeDelta, TimeZone, Timelike};

use pldm::control::xfer_flag;
use pldm::{proto_error, PldmError, PldmResult};

pub mod entity_type {
    pub const PHYSICAL: u16 = 0b00000000_00000000;
    pub const LOGICAL: u16 = 0b10000000_00000000;
}

/// PLDM Platform Commands
#[allow(missing_docs)]
#[derive(FromPrimitive, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum Cmd {
    GetTerminusUID = 0x03,
    SetEventReceiver = 0x04,
    GetEventReceiver = 0x05,
    PlatformEventMessage = 0x0A,
    PollForPlatformEventMessage = 0x0B,
    EventMessageSupported = 0x0C,
    EventMessageBufferSize = 0x0D,
    SetNumericSensorEnable = 0x10,
    GetSensorReading = 0x11,
    GetSensorThresholds = 0x12,
    SetSensorThresholds = 0x13,
    RestoreSensorThresholds = 0x14,
    GetSensorHysteresis = 0x15,
    SetSensorHysteresis = 0x16,
    InitNumericSensor = 0x17,
    SetStateSensorEnables = 0x20,
    GetStateSensorReadings = 0x21,
    InitStateSensor = 0x22,
    SetNumericEffecterEnable = 0x30,
    SetNumericEffecterValue = 0x31,
    GetNumericEffecterValue = 0x32,
    SetStateEffecterEnables = 0x38,
    SetStateEffecterStates = 0x39,
    GetStateEffecterStates = 0x3A,
    GetPLDMEventLogInfo = 0x40,
    EnablePLDMEventLogging = 0x41,
    ClearPLDMEventLog = 0x42,
    GetPLDMEventLogTimestamp = 0x43,
    SetPLDMEventLogTimestamp = 0x44,
    ReadPLDMEventLog = 0x45,
    GetPLDMEventLogPolicyInfo = 0x46,
    SetPLDMEventLogPolicy = 0x47,
    FindPLDMEventLogEntry = 0x48,
    GetPDRRepositoryInfo = 0x50,
    GetPDR = 0x51,
    FindPDR = 0x52,
    RunInitAgent = 0x58,
    GetPDRRepositorySignature = 0x53,
}

impl TryFrom<u8> for Cmd {
    type Error = PldmError;

    fn try_from(value: u8) -> Result<Self, PldmError> {
        Self::from_u8(value).ok_or_else(|| {
            proto_error!("Unknown PLDM platform command", "{value:02x}")
        })
    }
}

// TODO: PlatformError type?

/// PLDM platform response codes
#[allow(missing_docs)]
pub mod plat_codes {
    pub const INVALID_SENSOR_ID: u8 = 0x80;
    pub const EVENT_GENERATION_NOT_SUPPORTED: u8 = 0x82;

    // Get PDR
    pub const INVALID_DATA_TRANSFER_HANDLE: u8 = 0x80;
    pub const INVALID_TRANSFER_OPERATION_FLAG: u8 = 0x81;
    pub const INVALID_RECORD_HANDLE: u8 = 0x82;
    pub const INVALID_RECORD_CHANGE_NUMBER: u8 = 0x83;
    pub const TRANSFER_TIMEOUT: u8 = 0x84;
    pub const REPOSITORY_UPDATE_IN_PROGRESS: u8 = 0x85;
}

pub use plat_codes::*;

// repr(u8) doesn't work with with field-less variants for Deku
#[derive(Debug, Eq, PartialEq, Hash, Clone, DekuWrite, DekuRead)]
#[deku(endian = "little", ctx = "data_size: u8", id = "data_size")]
pub enum SensorData {
    #[deku(id = 0)]
    U8(u8),
    #[deku(id = 1)]
    I8(i8),
    #[deku(id = 2)]
    U16(u16),
    #[deku(id = 3)]
    I16(i16),
    #[deku(id = 4)]
    U32(u32),
    #[deku(id = 5)]
    I32(i32),
    #[deku(id = 6)]
    U64(u64),
    #[deku(id = 7)]
    I64(i64),
}

#[allow(missing_docs)]
#[derive(
    FromPrimitive, Debug, PartialEq, Eq, Copy, Clone, DekuRead, DekuWrite,
)]
#[deku(id_type = "u8")]
#[repr(u8)]
pub enum SensorOperationalState {
    Enabled = 0,
    Disabled,
    Unavailable,
    StatusUnknown,
    Failed,
    Initializing,
    ShuttingDown,
    InTest,
}

#[allow(missing_docs)]
#[derive(
    FromPrimitive, Debug, PartialEq, Eq, Copy, Clone, DekuRead, DekuWrite,
)]
#[deku(id_type = "u8")]
#[repr(u8)]
pub enum SetSensorOperationalState {
    Enabled = 0,
    Disabled,
    Unavailable,
}

#[allow(missing_docs)]
#[derive(
    FromPrimitive, Debug, PartialEq, Eq, Copy, Clone, DekuRead, DekuWrite,
)]
#[deku(id_type = "u8")]
#[repr(u8)]
pub enum SensorEventMessageEnable {
    /// NoEventGeneration for GetSensor, NoChange for SetSensorEnable
    NoEventGeneration = 0,
    EventsDisabled,
    EventsEnabled,
    OpEventsOnlyEnabled,
    StateEventsOnlyEnabled,
}

impl SensorEventMessageEnable {
    pub fn new(op_enable: bool, state_enable: bool) -> Self {
        match (op_enable, state_enable) {
            (true, true) => Self::EventsEnabled,
            (false, false) => Self::EventsDisabled,
            (true, false) => Self::OpEventsOnlyEnabled,
            (false, true) => Self::StateEventsOnlyEnabled,
        }
    }
}

#[allow(missing_docs)]
#[derive(
    FromPrimitive, Debug, PartialEq, Eq, Copy, Clone, DekuRead, DekuWrite,
)]
#[deku(id_type = "u8")]
#[repr(u8)]
pub enum SensorState {
    Unknown = 0,
    Normal,
    Warning,
    Critical,
    Fatal,
    LowerWarning,
    LowerCritical,
    LowerFatal,
    UpperWarning,
    UpperCritical,
    UpperFatal,
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct VecWrap<T, const N: usize>(pub heapless::Vec<T, N>);

impl<T, const N: usize> From<heapless::Vec<T, N>> for VecWrap<T, N> {
    fn from(value: heapless::Vec<T, N>) -> Self {
        Self(value)
    }
}

impl<T, const N: usize> core::ops::Deref for VecWrap<T, N> {
    type Target = heapless::Vec<T, N>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T, const N: usize> core::ops::DerefMut for VecWrap<T, N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<'a, T, Predicate, Ctx, const N: usize>
    DekuReader<'a, (Limit<T, Predicate>, Ctx)> for VecWrap<T, N>
where
    Predicate: FnMut(&T) -> bool,
    Ctx: Copy,
    T: DekuReader<'a, Ctx>,
{
    fn from_reader_with_ctx<
        R: deku::no_std_io::Read + deku::no_std_io::Seek,
    >(
        reader: &mut deku::reader::Reader<R>,
        (limit, ctx): (Limit<T, Predicate>, Ctx),
    ) -> core::result::Result<Self, DekuError> {
        let Limit::Count(count) = limit else {
            return Err(DekuError::Assertion(
                "Only count implemented for heapless::Vec".into(),
            ));
        };

        let mut v = heapless::Vec::new();
        for _ in 0..count {
            v.push(T::from_reader_with_ctx(reader, ctx)?).map_err(|_| {
                DekuError::InvalidParam("Too many elements".into())
            })?
        }

        Ok(VecWrap(v))
    }
}

impl<T, Ctx, const N: usize> DekuWriter<Ctx> for VecWrap<T, N>
where
    T: DekuWriter<Ctx>,
    Ctx: Copy,
{
    // Required method
    fn to_writer<W: deku::no_std_io::Write + deku::no_std_io::Seek>(
        &self,
        writer: &mut Writer<W>,
        ctx: Ctx,
    ) -> core::result::Result<(), DekuError> {
        self.0.to_writer(writer, ctx)
    }
}

/// A null terminated ascii string.
#[derive(DekuWrite, Default, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AsciiString<const N: usize>(pub VecWrap<u8, N>);

impl<const N: usize> AsciiString<N> {
    /// Return the length of the string
    ///
    /// Null terminator is included.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns whether `len() == 0`.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Return the underlying bytes.
    ///
    /// This includes any null terminator.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl<const N: usize> core::fmt::Debug for AsciiString<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "\"")?;
        for c in self.0.escape_ascii() {
            write!(f, "{}", char::from(c))?;
        }
        write!(f, "\"")?;
        if !self.0.is_empty() && !self.0.ends_with(&[0x00]) {
            write!(f, " (missing null terminator)")?;
        }
        Ok(())
    }
}

impl<const N: usize> TryFrom<&[u8]> for AsciiString<N> {
    type Error = ();

    /// Convert from a byte slice.
    ///
    /// No null terminating byte is added, it should be provided by the caller.
    fn try_from(v: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self(VecWrap(heapless::Vec::from_slice(v)?)))
    }
}

impl<const N: usize> TryFrom<&str> for AsciiString<N> {
    type Error = ();

    /// Convert from a `str`.
    ///
    /// A null terminating byte is added.
    fn try_from(v: &str) -> Result<Self, Self::Error> {
        let mut h = heapless::Vec::from_slice(v.as_bytes())?;
        h.push(0x00).map_err(|_| ())?;
        Ok(Self(VecWrap(h)))
    }
}

impl<'a, Predicate, const N: usize> DekuReader<'a, (Limit<u8, Predicate>, ())>
    for AsciiString<N>
where
    Predicate: FnMut(&u8) -> bool,
{
    fn from_reader_with_ctx<
        R: deku::no_std_io::Read + deku::no_std_io::Seek,
    >(
        reader: &mut deku::reader::Reader<R>,
        (limit, _ctx): (Limit<u8, Predicate>, ()),
    ) -> core::result::Result<Self, DekuError> {
        let Limit::Count(count) = limit else {
            return Err(DekuError::Assertion(
                "Only count implemented for heapless::Vec".into(),
            ));
        };

        let mut v = heapless::Vec::new();
        for _ in 0..count {
            v.push(u8::from_reader_with_ctx(reader, ())?).map_err(|_| {
                DekuError::InvalidParam("Too many elements".into())
            })?
        }

        Ok(AsciiString(VecWrap(v)))
    }
}

#[derive(Debug, DekuRead, DekuWrite, PartialEq, Eq, Clone, Copy)]
#[deku(endian = "little")]
pub struct SensorId(pub u16);

impl FromStr for SensorId {
    type Err = ParseIntError;
    fn from_str(s: &str) -> core::result::Result<Self, Self::Err> {
        Ok(Self(if let Some(s) = s.strip_prefix("0x") {
            u16::from_str_radix(s, 16)
        } else {
            s.parse()
        }?))
    }
}

#[derive(Debug, DekuRead, DekuWrite, PartialEq, Eq, Clone)]
pub struct GetSensorReadingReq {
    pub sensor: SensorId,
    pub rearm: bool,
}

#[deku_derive(DekuRead, DekuWrite)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetSensorReadingResp {
    #[deku(temp, temp_value = "reading.deku_id().unwrap()")]
    data_size: u8,
    pub op_state: SensorOperationalState,
    pub event_enable: SensorEventMessageEnable,
    pub present_state: SensorState,
    pub previous_state: SensorState,
    pub event_state: SensorState,
    #[deku(ctx = "*data_size")]
    pub reading: SensorData,
}

#[deku_derive(DekuRead, DekuWrite)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetStateSensorReadingsReq {
    pub sensor: SensorId,
    pub rearm: u8,
    #[deku(temp, temp_value = "0")]
    rsvd: u8,
}

#[derive(Debug, DekuRead, DekuWrite, Clone, PartialEq, Eq)]
pub struct StateField {
    pub op_state: SensorOperationalState,
    pub present_state: u8,
    pub previous_state: u8,
    pub event_state: u8,
}

impl StateField {
    pub fn debug_state_set(&self, state_set: u16) -> StateFieldDebug<'_> {
        StateFieldDebug {
            inner: self,
            state_set,
        }
    }
}

pub struct StateDebug<T: FromPrimitive + Debug> {
    state: u8,
    state_set: PhantomData<T>,
}

impl<T: FromPrimitive + Debug> StateDebug<T> {
    fn new(state: u8) -> Self {
        Self {
            state,
            state_set: PhantomData,
        }
    }
}

impl<T: FromPrimitive + Debug> Debug for StateDebug<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if let Some(v) = T::from_u8(self.state) {
            write!(f, "{} {:?}", self.state, &v)
        } else {
            write!(f, "{} (unrecognised state)", self.state)
        }
    }
}

/// Print debug formatting with a given StateSet value `T`.
///
/// Will print u8 version for unknown state set.
pub struct StateFieldDebug<'a> {
    inner: &'a StateField,
    state_set: u16,
}

impl StateFieldDebug<'_> {
    pub fn debug_from_u8<T: FromPrimitive + Debug>(
        &self,
        f: &mut core::fmt::Formatter,
    ) -> core::fmt::Result {
        f.debug_struct("StateField")
            .field("op_state", &self.inner.op_state)
            .field(
                "present_state",
                &StateDebug::<T>::new(self.inner.present_state),
            )
            .field(
                "previous_state",
                &StateDebug::<T>::new(self.inner.previous_state),
            )
            .field(
                "event_state",
                &StateDebug::<T>::new(self.inner.present_state),
            )
            .finish()
    }
}

impl Debug for StateFieldDebug<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use crate::state_sets::*;
        match self.state_set {
            OperationFaultStatus::ID => {
                self.debug_from_u8::<OperationFaultStatus>(f)
            }
            DeviceInitialization::ID => {
                self.debug_from_u8::<DeviceInitialization>(f)
            }
            HardwareSecurity::ID => self.debug_from_u8::<HardwareSecurity>(f),
            _ => {
                debug!("Unrecognised state set {:#04x}", self.state_set);
                write!(f, "{:?}", self.inner)
            }
        }
    }
}

#[deku_derive(DekuRead, DekuWrite)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetStateSensorReadingsResp {
    #[deku(temp, temp_value = "self.fields.len() as u8")]
    pub composite_sensor_count: u8,
    #[deku(count = "composite_sensor_count")]
    pub fields: VecWrap<StateField, 8>,
}

#[derive(Debug, DekuRead, DekuWrite, Clone, PartialEq, Eq)]
pub struct SetNumericSensorEnableReq {
    pub sensor: SensorId,
    pub set_op_state: SetSensorOperationalState,
    pub event_enable: SensorEventMessageEnable,
}

#[derive(Debug, DekuRead, DekuWrite, Clone, PartialEq, Eq)]
pub struct SetEnableField {
    pub set_op_state: SetSensorOperationalState,
    pub event_enable: SensorEventMessageEnable,
}

#[deku_derive(DekuRead, DekuWrite)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetStateSensorEnablesReq {
    pub sensor: SensorId,

    #[deku(temp, temp_value = "self.fields.len() as u8")]
    pub composite_sensor_count: u8,

    #[deku(count = "composite_sensor_count")]
    pub fields: VecWrap<SetEnableField, 8>,
}

#[deku_derive(DekuRead, DekuWrite)]
#[derive(Debug, Clone, Eq, PartialEq)]
#[deku(id_type = "u8")]
#[repr(u8)]
pub enum PDRRepositoryState {
    Available = 0,
    UpdateInProgress,
    Failed,
}

// TODO
#[deku_derive(DekuRead, DekuWrite)]
#[derive(Clone, PartialEq, Eq, Default)]
pub struct Timestamp104(pub [u8; 13]);

impl core::fmt::Debug for Timestamp104 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if let Ok(dt) = DateTime::<FixedOffset>::try_from(self) {
            write!(f, "Timestamp104({dt:?})")
        } else {
            write!(f, "Timestamp104(invalid {:?})", self.0)
        }
    }
}

impl TryFrom<&Timestamp104> for DateTime<FixedOffset> {
    type Error = ();

    fn try_from(t: &Timestamp104) -> Result<Self, Self::Error> {
        let t = &t.0;
        let tz = i16::from_le_bytes(t[..=1].try_into().unwrap());
        let tz = FixedOffset::east_opt(tz as i32 * 60).ok_or_else(|| {
            trace!("Bad timezone {tz}");
        })?;
        let year = u16::from_le_bytes(t[10..=11].try_into().unwrap());
        let dt = tz
            .with_ymd_and_hms(
                year as i32,
                t[9] as u32,
                t[8] as u32,
                t[7] as u32,
                t[6] as u32,
                t[5] as u32,
            )
            .earliest()
            .ok_or_else(|| {
                trace!("Bad timestamp");
            })?;
        // read a u32 and mask to 24 bit
        let micros =
            u32::from_le_bytes(t[2..=5].try_into().unwrap()) & 0xffffff;
        let dt = dt + TimeDelta::microseconds(micros as i64);
        Ok(dt)
    }
}

impl TryFrom<&DateTime<FixedOffset>> for Timestamp104 {
    type Error = ();

    fn try_from(dt: &DateTime<FixedOffset>) -> Result<Self, Self::Error> {
        let mut t = [0; 13];
        let off = dt.offset().local_minus_utc() as u16;
        t[0..=1].copy_from_slice(&off.to_le_bytes());

        let date = dt.date_naive();
        let time = dt.time();
        // can be > 1e9 for leap seconds, discard that.
        let micros = (time.nanosecond() % 1_000_000_000) / 1000;
        t[2..=4].copy_from_slice(&micros.to_le_bytes()[..3]);
        t[5] = time.second() as u8;
        t[6] = time.minute() as u8;
        t[7] = time.hour() as u8;
        t[8] = date.day() as u8;
        t[9] = date.month() as u8;
        let year: u16 = date.year().try_into().map_err(|_| {
            trace!("Year out of range");
        })?;
        t[10..=11].copy_from_slice(&year.to_le_bytes());

        Ok(Timestamp104(t))
    }
}

#[deku_derive(DekuRead, DekuWrite)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetPDRRepositoryInfoResp {
    pub state: PDRRepositoryState,
    pub update_time: Timestamp104,
    pub oem_update_time: Timestamp104,
    pub record_count: u32,
    pub repository_size: u32,
    pub largest_record_size: u32,
    pub data_transfer_handle_timeout: u8,
}

#[deku_derive(DekuRead, DekuWrite)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[deku(id_type = "u8")]
#[repr(u8)]
pub enum TransferOperationFlag {
    NextPart = 0,
    FirstPart = 1,
}

#[deku_derive(DekuRead, DekuWrite)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetPDRReq {
    pub record_handle: u32,
    pub data_transfer_handle: u32,
    pub transfer_operation_flag: TransferOperationFlag,
    pub request_count: u16,
    pub record_change_number: u16,
}

const MAX_PDR_TRANSFER: usize = 100;

#[deku_derive(DekuRead, DekuWrite)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetPDRResp {
    pub next_record_handle: u32,
    pub next_data_transfer_handle: u32,
    pub transfer_flag: u8,

    #[deku(temp, temp_value = "self.record_data.len() as u16")]
    response_count: u16,
    #[deku(count = "response_count")]
    pub record_data: VecWrap<u8, MAX_PDR_TRANSFER>,

    /// CRC over entire PDR, when transfer_flag == end
    // TODO
    #[deku(cond = "*transfer_flag & xfer_flag::END != 0")]
    pub crc: Option<u8>,
}

impl GetPDRResp {
    pub fn new_single(
        record_handle: u32,
        record: PdrRecord,
    ) -> PldmResult<Self> {
        let mut pdr = Pdr {
            record_handle,
            pdr_header_version: PDR_VERSION_1,
            record_change_number: 0,
            data_length: 0,
            record,
        };
        pdr.update()?;

        let mut s = GetPDRResp {
            next_record_handle: 0,
            next_data_transfer_handle: 0,
            transfer_flag: xfer_flag::START_AND_END,
            record_data: Default::default(),
            // TODO crc
            crc: Some(0),
        };
        let cap = s.record_data.capacity();
        s.record_data.resize_default(cap).unwrap();
        let len = pdr.to_slice(&mut s.record_data)?;
        s.record_data.truncate(len);
        Ok(s)
    }
}

#[derive(Default)]
struct Length {
    pos: i64,
    len: u64,
}

impl Length {
    fn len<CTX>(c: &impl DekuWriter<CTX>, ctx: CTX) -> Result<u64, DekuError> {
        let mut l = Length::default();
        let mut w = deku::writer::Writer::new(&mut l);
        c.to_writer(&mut w, ctx)?;
        Ok(l.len)
    }
}

impl deku::no_std_io::Write for &mut Length {
    fn write(&mut self, buf: &[u8]) -> deku::no_std_io::Result<usize> {
        self.pos += buf.len() as i64;
        self.len = self.len.max(self.pos as u64);
        Ok(buf.len())
    }
    fn flush(&mut self) -> deku::no_std_io::Result<()> {
        Ok(())
    }
}

impl deku::no_std_io::Seek for &mut Length {
    fn seek(
        &mut self,
        pos: deku::no_std_io::SeekFrom,
    ) -> deku::no_std_io::Result<u64> {
        use deku::no_std_io;
        match pos {
            no_std_io::SeekFrom::Start(p) => self.pos = p as i64,
            no_std_io::SeekFrom::End(_p) => {
                return Err(no_std_io::Error::from(
                    no_std_io::ErrorKind::UnexpectedEof,
                ));
            }
            no_std_io::SeekFrom::Current(p) => self.pos += p,
        }
        Ok(self.pos as u64)
    }
}

pub const PDR_VERSION_1: u8 = 1;

#[deku_derive(DekuRead, DekuWrite)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pdr {
    pub record_handle: u32,
    pub pdr_header_version: u8,
    #[deku(temp, temp_value = "self.record.pdr_type()")]
    pdr_type: u8,
    pub record_change_number: u16,
    #[deku(update = "Length::len(&self.record, self.record.pdr_type())?")]
    pub data_length: u16,

    #[deku(ctx = "*pdr_type")]
    pub record: PdrRecord,
}

#[non_exhaustive]
#[deku_derive(DekuRead, DekuWrite)]
#[derive(Debug, Clone, PartialEq, Eq)]
#[deku(ctx = "pdr_type: u8", id = "pdr_type")]
pub enum PdrRecord {
    #[deku(id = 30)]
    FileDescriptor(FileDescriptorPdr),
}

impl PdrRecord {
    pub fn pdr_type(&self) -> u8 {
        match self {
            Self::FileDescriptor(_) => 30,
        }
    }
}

#[deku_derive(DekuRead, DekuWrite)]
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, PartialOrd, Ord)]
#[deku(id_type = "u8")]
#[repr(u8)]
pub enum FileClassification {
    OEM = 0,
    BootLog,
    SerialTxFIFO,
    SerialRxFIFO,
    DiagnosticLog,
    CrashDumpFile,
    SecurityLog,
    FRUDataFile,
    TelemetryDataFile,
    TelemetryDataLog,
    OtherLog = 0xFD,
    OtherFile = 0xFE,
    FileDirectory = 0xFF,
}

pub mod file_capabilities {
    pub const EX_READ_OPEN: u16 = 1 << 0;
    pub const EX_WRITE_OPEN: u16 = 1 << 1;
    pub const FILE_TRUNC: u16 = 1 << 2;
    pub const DATA_TYPE: u16 = 1 << 3;
    pub const POLLED: u16 = 1 << 4;
    pub const PUSHED: u16 = 1 << 5;
    pub const DATA_VOLATILITY: u16 = 1 << 6;
    pub const FILE_MODIFY: u16 = 1 << 7;
    pub const FC_ZERO_LENGTH_PERMITTED: u16 = 1 << 8;
    pub const FC_WRITES_PERMITTED: u16 = 1 << 9;
}

#[deku_derive(DekuRead, DekuWrite)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileDescriptorPdr {
    pub terminus_handle: u16,
    pub file_identifier: u16,
    pub entity_type: u16,
    pub entity_instance: u16,
    pub container_id: u16,
    pub superior_directory: u16,
    pub file_classification: FileClassification,
    /// OEM File Classification
    ///
    /// `oem_file_classification_name` must be `Some` if this is
    /// non-zero (may be an empty string).
    pub oem_file_classification: u8,
    pub capabilities: u16,
    pub file_version: u32,
    pub file_max_size: u32,
    pub file_max_desc_count: u8,

    #[deku(temp, temp_value = "self.file_name.len() as u8")]
    pub file_name_len: u8,
    /// File name.
    ///
    /// A null terminated string.
    // TODO: max length
    #[deku(count = "file_name_len")]
    pub file_name: AsciiString<MAX_PDR_TRANSFER>,

    #[deku(skip, cond = "*oem_file_classification == 0")]
    #[deku(
        temp,
        temp_value = "self.oem_file_classification_name.as_ref().map(|f| f.len()).unwrap_or(0) as u8"
    )]
    pub oem_file_name_len: u8,

    /// OEM file classification name.
    ///
    /// A null terminated string. Must be `None` if `oem_file_classification == 0`.
    #[deku(skip, cond = "*oem_file_classification == 0")]
    #[deku(
        assert = "(*oem_file_classification > 0) == oem_file_classification_name.is_some()"
    )]
    #[deku(count = "oem_file_name_len")]
    pub oem_file_classification_name: Option<AsciiString<MAX_PDR_TRANSFER>>,
}
