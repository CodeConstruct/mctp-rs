use core::{marker::PhantomData, num::ParseIntError, str::FromStr};

#[allow(unused)]
use log::{debug, error, info, trace, warn};

use core::fmt::Debug;
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;

use deku::{
    ctx::Limit, deku_derive, writer::Writer, DekuEnumExt, DekuError, DekuRead,
    DekuReader, DekuWrite, DekuWriter,
};

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

// TODO: PlatformError type?

/// PLDM platform response codes
#[allow(missing_docs)]
mod plat_codes {
    pub const INVALID_SENSOR_ID: u8 = 0x80;
    pub const EVENT_GENERATION_NOT_SUPPORTED: u8 = 0x82;
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

#[derive(Debug, Clone)]
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
#[derive(Debug, Clone)]
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
#[derive(Debug, Clone)]
pub struct GetStateSensorReadingsReq {
    pub sensor: SensorId,
    pub rearm: u8,
    #[deku(temp, temp_value = "0")]
    rsvd: u8,
}

#[derive(Debug, DekuRead, DekuWrite, Clone)]
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
#[derive(Debug, Clone)]
pub struct GetStateSensorReadingsResp {
    #[deku(temp, temp_value = "self.fields.len() as u8")]
    pub composite_sensor_count: u8,
    #[deku(count = "composite_sensor_count")]
    pub fields: VecWrap<StateField, 8>,
}

#[derive(Debug, DekuRead, DekuWrite, Clone)]
pub struct SetNumericSensorEnableReq {
    pub sensor: SensorId,
    pub set_op_state: SetSensorOperationalState,
    pub event_enable: SensorEventMessageEnable,
}

#[derive(Debug, DekuRead, DekuWrite, Clone)]
pub struct SetEnableField {
    pub set_op_state: SetSensorOperationalState,
    pub event_enable: SensorEventMessageEnable,
}

#[deku_derive(DekuRead, DekuWrite)]
#[derive(Debug, Clone)]
pub struct SetStateSensorEnablesReq {
    pub sensor: SensorId,

    #[deku(temp, temp_value = "self.fields.len() as u8")]
    pub composite_sensor_count: u8,

    #[deku(count = "composite_sensor_count")]
    pub fields: VecWrap<SetEnableField, 8>,
}
