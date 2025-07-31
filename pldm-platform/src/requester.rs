#[allow(unused)]
use log::{debug, error, info, trace, warn};

use num_traits::FromPrimitive;

use crate::proto::*;
use crate::PLDM_TYPE_PLATFORM;
use pldm::{
    control::xfer_flag, pldm_xfer_buf_async, proto_error, CCode, PldmError,
    PldmRequest, Result,
};

use deku::{DekuContainerRead, DekuContainerWrite};

use heapless::Vec;

/// Reads a numeric sensor.
pub async fn get_sensor_reading(
    comm: &mut impl mctp::AsyncReqChannel,
    sensor: SensorId,
    rearm: bool,
) -> Result<GetSensorReadingResp> {
    let r = GetSensorReadingReq { sensor, rearm };

    let mut buf = [0; 10];
    let l = r.to_slice(&mut buf).map_err(|_| PldmError::NoSpace)?;
    let buf = &buf[..l];

    let req = PldmRequest::new_borrowed(
        PLDM_TYPE_PLATFORM,
        Cmd::GetSensorReading as u8,
        buf,
    );

    let mut rx = [0; 30];
    let resp = pldm_xfer_buf_async(comm, req, &mut rx).await?;

    let ((rest, _), ret) = GetSensorReadingResp::from_bytes((&resp.data, 0))
        .map_err(|e| {
            trace!("GetSensorReading parse error {e}");
            proto_error!("Bad GetSensorReading response")
        })?;

    if !rest.is_empty() {
        return Err(proto_error!("Extra response"));
    }

    Ok(ret)
}

/// Reads a simple state sensor.
///
/// Reads sensor offset 0.
pub async fn get_simple_state_sensor_reading(
    comm: &mut impl mctp::AsyncReqChannel,
    sensor: SensorId,
    rearm: bool,
) -> Result<StateField> {
    let r = GetStateSensorReadingsReq {
        sensor,
        rearm: rearm as u8,
    };

    let mut buf = [0; 10];
    let l = r.to_slice(&mut buf).map_err(|_| PldmError::NoSpace)?;
    let buf = &buf[..l];

    let req = PldmRequest::new_borrowed(
        PLDM_TYPE_PLATFORM,
        Cmd::GetStateSensorReadings as u8,
        buf,
    );

    let mut rx = [0; 50];
    let resp = pldm_xfer_buf_async(comm, req, &mut rx).await?;

    match CCode::from_u8(resp.cc) {
        Some(CCode::SUCCESS) => (),
        Some(e) => {
            return Err(proto_error!("Error response", "{e:?}"));
        }
        None if resp.cc == INVALID_SENSOR_ID => {
            return Err(proto_error!("Invalid Sensor ID"));
        }
        None => return Err(proto_error!("Error", "{}", resp.cc)),
    }

    let ((rest, _), mut ret) = GetStateSensorReadingsResp::from_bytes((
        &resp.data, 0,
    ))
    .map_err(|e| {
        trace!("GetStateSensorReadings parse error {e}");
        proto_error!("Bad GetStateSensorReadings response")
    })?;

    if !rest.is_empty() {
        return Err(proto_error!("Extra response"));
    }

    if ret.fields.len() != 1 {
        return Err(proto_error!("Incorrect sensor count"));
    }

    Ok(ret.fields.swap_remove(0))
}

/// SetNumericSensorEnable
///
/// `op_event_enable` and `state_event_enable` are ignored if `event_no_change` is set.
pub async fn set_numeric_sensor_enable(
    comm: &mut impl mctp::AsyncReqChannel,
    sensor: SensorId,
    set_op_state: SetSensorOperationalState,
    event_no_change: bool,
    op_event_enable: bool,
    state_event_enable: bool,
) -> Result<()> {
    let event_enable = if event_no_change {
        SensorEventMessageEnable::NoEventGeneration
    } else {
        SensorEventMessageEnable::new(op_event_enable, state_event_enable)
    };

    let r = SetNumericSensorEnableReq {
        sensor,
        set_op_state,
        event_enable,
    };

    let mut buf = [0; 10];
    let l = r.to_slice(&mut buf).map_err(|_| PldmError::NoSpace)?;
    let buf = &buf[..l];

    let req = PldmRequest::new_borrowed(
        PLDM_TYPE_PLATFORM,
        Cmd::SetNumericSensorEnable as u8,
        buf,
    );

    let mut rx = [0; 50];
    let resp = pldm_xfer_buf_async(comm, req, &mut rx).await?;

    match CCode::from_u8(resp.cc) {
        Some(CCode::SUCCESS) => (),
        Some(e) => {
            return Err(proto_error!("Error response", "{e:?}"));
        }
        None if resp.cc == INVALID_SENSOR_ID => {
            return Err(proto_error!("Invalid Sensor ID"));
        }
        None if resp.cc == EVENT_GENERATION_NOT_SUPPORTED => {
            return Err(proto_error!("Event generation not supported"));
        }
        None => return Err(proto_error!("Error", "{}", resp.cc)),
    }

    Ok(())
}

/// SetStateSensorEnables
///
/// Sets field 0 of a sensor.
/// `op_event_enable` and `state_event_enable` are ignored if `event_no_change` is set.
pub async fn set_simple_state_sensor_enables(
    comm: &mut impl mctp::AsyncReqChannel,
    sensor: SensorId,
    set_op_state: SetSensorOperationalState,
    event_no_change: bool,
    op_event_enable: bool,
    state_event_enable: bool,
) -> Result<()> {
    let event_enable = if event_no_change {
        SensorEventMessageEnable::NoEventGeneration
    } else {
        SensorEventMessageEnable::new(op_event_enable, state_event_enable)
    };

    let f = SetEnableField {
        set_op_state,
        event_enable,
    };
    let fields = Vec::from_slice(&[f]).unwrap().into();
    let r = SetStateSensorEnablesReq { sensor, fields };

    let mut buf = [0; 10];
    let l = r.to_slice(&mut buf).map_err(|_| PldmError::NoSpace)?;
    let buf = &buf[..l];

    let req = PldmRequest::new_borrowed(
        PLDM_TYPE_PLATFORM,
        Cmd::SetStateSensorEnables as u8,
        buf,
    );

    let mut rx = [0; 50];
    let resp = pldm_xfer_buf_async(comm, req, &mut rx).await?;

    match CCode::from_u8(resp.cc) {
        Some(CCode::SUCCESS) => (),
        Some(e) => {
            return Err(proto_error!("Error response", "{e:?}"));
        }
        None if resp.cc == INVALID_SENSOR_ID => {
            return Err(proto_error!("Invalid Sensor ID"));
        }
        None if resp.cc == EVENT_GENERATION_NOT_SUPPORTED => {
            return Err(proto_error!("Event generation not supported"));
        }
        None => return Err(proto_error!("Error", "{}", resp.cc)),
    }

    Ok(())
}

/// Get PDR Repository Info
pub async fn get_pdr_repository_info(
    comm: &mut impl mctp::AsyncReqChannel,
) -> Result<GetPDRRepositoryInfoResp> {
    let req = PldmRequest::new_borrowed(
        PLDM_TYPE_PLATFORM,
        Cmd::GetPDRRepositoryInfo as u8,
        &[],
    );

    let mut rx = [0; 50];
    let resp = pldm_xfer_buf_async(comm, req, &mut rx).await?;

    let ((rest, _), ret) =
        GetPDRRepositoryInfoResp::from_bytes((&resp.data, 0)).map_err(|e| {
            trace!("GetPDRRepositoryInfo parse error {e}");
            proto_error!("Bad GetPDRRepositoryInfo response")
        })?;

    if !rest.is_empty() {
        return Err(proto_error!("Extra response"));
    }

    Ok(ret)
}

/// An iterator over PDR records, returned by [`get_pdr`].
pub struct GetPdrIter<'a, C: mctp::AsyncReqChannel> {
    next_handle: u32,
    done: bool,
    comm: &'a mut C,
}

impl<'a, C: mctp::AsyncReqChannel> GetPdrIter<'a, C> {
    fn new(comm: &'a mut C) -> Self {
        Self {
            next_handle: 0,
            done: false,
            comm,
        }
    }

    /// Return the next PDR from the host.
    ///
    /// `None` will be returned after the last record.
    /// `Some(Err)` may be returned on error, further calls to next() may still
    /// return more records successfully.
    pub async fn next(&mut self) -> Option<Result<PdrRecord>> {
        self.next_inner().await.transpose()
    }

    // Inner function to use `?`.
    async fn next_inner(&mut self) -> Result<Option<PdrRecord>> {
        if self.done {
            return Ok(None);
        }

        // TODO: callers pass a buffer? might be nice to
        // reuse between tx/rx.
        let mut rxbuf = [0; 200];

        let getpdr = GetPDRReq {
            record_handle: self.next_handle,
            data_transfer_handle: 0,
            transfer_operation_flag: TransferOperationFlag::FirstPart,
            // subtract 4 bytes pldm header, 12 bytes PDR header/crc
            request_count: (rxbuf.len() - 4 - 12) as u16,
            record_change_number: 0,
        };
        let mut txdata = [0; 13];
        let l = getpdr.to_slice(&mut txdata)?;
        let txdata = &txdata[..l];
        let req = PldmRequest::new_borrowed(
            PLDM_TYPE_PLATFORM,
            Cmd::GetPDR as u8,
            txdata,
        );

        // Failure prior to parsing a next_handle should stop the iterator,
        // setting self.done and returning the failure Result.
        // Other errors don't stop the iterator, they are just returned as a Result.

        let resp = pldm_xfer_buf_async(self.comm, req, &mut rxbuf)
            .await
            .inspect_err(|_| self.done = true)?;
        let ((rest, _), pdrrsp) = GetPDRResp::from_bytes((&resp.data, 0))
            .map_err(|e| {
                trace!("GetPDR parse error {e:?}");
                self.done = true;
                proto_error!("Bad GetPDR response")
            })?;
        if !rest.is_empty() {
            self.done = true;
            return Err(proto_error!("Extra response"));
        }

        if pdrrsp.next_record_handle == 0 {
            // Last handle
            self.done = true
        }
        self.next_handle = pdrrsp.next_record_handle;

        if pdrrsp.record_data.len() > getpdr.request_count as usize {
            return Err(proto_error!(
                "Get PDR returned extra record data",
                "Requested {}, got {}",
                getpdr.request_count,
                pdrrsp.record_data.len()
            ));
        }

        // This is a current limitation of this implementation,
        // not a problem with the response. We can't attempt
        // to parse the record_data since it will be incomplete.
        if pdrrsp.transfer_flag != xfer_flag::START_AND_END {
            return Err(proto_error!("Can't handle multipart"));
        }

        let ((rest, _), pdr) = Pdr::from_bytes((&pdrrsp.record_data, 0))
            .map_err(|e| {
                trace!("GetPDR parse error {e}");
                proto_error!("Bad GetPDR response")
            })?;
        if !rest.is_empty() {
            return Err(proto_error!("Extra PDR response"));
        }

        let expect_len = pdrrsp.record_data.len() - 10;
        if pdr.data_length as usize != expect_len {
            warn!(
                "Incorrect PDR data_length, got {}, expect {}",
                pdr.data_length, expect_len
            );
        }

        if pdr.pdr_header_version != PDR_VERSION_1 {
            return Err(proto_error!("PDR unknown version"));
        }

        Ok(Some(pdr.record))
    }
}

/// Return a `GetPdrIter` to iterate over Get PDR requests.
pub fn get_pdr<C>(comm: &mut C) -> GetPdrIter<'_, C>
where
    C: mctp::AsyncReqChannel,
{
    GetPdrIter::new(comm)
}
