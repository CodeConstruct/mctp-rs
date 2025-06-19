/// PLDM State Set definitions.
/// From DSP0249. Only contains a subset at present.
use num_derive::FromPrimitive;

#[allow(missing_docs)]
#[derive(FromPrimitive, Debug, PartialEq, Eq, Copy, Clone)]
#[repr(u8)]
pub enum OperationFaultStatus {
    Unknown = 0,
    Normal,
    Error,
    NonRecoverableError,
}

impl OperationFaultStatus {
    pub const ID: u16 = 10;
}

#[allow(missing_docs)]
#[derive(FromPrimitive, Debug, PartialEq, Eq, Copy, Clone)]
#[repr(u8)]
pub enum DeviceInitialization {
    Unknown = 0,
    Normal,
    InitializationInProgress,
    InitializationHung,
    InitializationFailed,
}

impl DeviceInitialization {
    pub const ID: u16 = 20;
}

#[allow(missing_docs)]
#[derive(FromPrimitive, Debug, PartialEq, Eq, Copy, Clone)]
#[repr(u8)]
pub enum HardwareSecurity {
    Unknown = 0,
    HardwareSecurityVerified,
    HardwareSecurityUnverified,
}

impl HardwareSecurity {
    pub const ID: u16 = 99;
}
