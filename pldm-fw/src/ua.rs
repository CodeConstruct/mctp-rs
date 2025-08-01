// SPDX-License-Identifier: MIT OR Apache-2.0
/*
 * PLDM firmware update utility.
 *
 * Copyright (c) 2023 Code Construct
 */

//! PLDM Firmware Update Agent
//!
//! Update Agent requires `std` feature.
use log::{debug, error};

use thiserror::Error;

use nom::{
    combinator::{all_consuming, map},
    multi::length_value,
    number::complete::le_u32,
    sequence::tuple,
    IResult,
};

use pldm::PldmError;

use crate::pkg;
use crate::{
    DeviceIdentifiers, FirmwareParameters, FwCode, GetStatusResponse,
    PldmFDState, RequestUpdateResponse, UpdateComponentResponse,
    UpdateTransferProgress, PLDM_TYPE_FW,
};

pub type Result<T> = core::result::Result<T, PldmUpdateError>;

#[derive(Error, Debug)]
pub enum PldmUpdateError {
    #[error("PLDM error: {0}")]
    Pldm(#[from] PldmError),
    #[error("PLDM protocol error: {0}")]
    Protocol(String),
    #[error("PLDM command (0x{0:02x}) failed with 0x{1:02x}")]
    Command(u8, u8),
    #[error("PLDM Update error: {0}")]
    Update(String),
    #[error("PLDM Package error: {0}")]
    Package(#[from] pkg::PldmPackageError),
    // #[error("MCTP IO error: {0}")]
    // MCTPIO(#[from] std::io::Error)
}

impl PldmUpdateError {
    fn new_command(cmd: u8, cc: u8) -> Self {
        Self::Command(cmd, cc)
    }

    fn new_proto(desc: String) -> Self {
        Self::Protocol(desc)
    }

    fn new_update(desc: String) -> Self {
        Self::Update(desc)
    }
}

#[derive(Debug)]
pub struct Update {
    pub package: pkg::Package,
    pub index: u8,
    pub components: Vec<usize>,
}

impl Update {
    pub fn new(
        dev: &DeviceIdentifiers,
        _fwp: &FirmwareParameters,
        pkg: pkg::Package,
        index: Option<u8>,
        force_device: Option<usize>,
        force_components: Vec<usize>,
    ) -> Result<Self> {
        let dev = match force_device {
            Some(n) => {
                if n >= pkg.devices.len() {
                    return Err(PldmUpdateError::new_update(
                        "invalid device index".into(),
                    ));
                }
                &pkg.devices[n]
            }
            None => {
                let fwdevs = pkg
                    .devices
                    .iter()
                    .filter(|d| &d.ids == dev)
                    .collect::<Vec<_>>();

                if fwdevs.is_empty() {
                    return Err(PldmUpdateError::new_update(
                        "no matching devices".into(),
                    ));
                }

                if fwdevs.len() != 1 {
                    return Err(PldmUpdateError::new_update(
                        "multiple matching devices".into(),
                    ));
                }

                *fwdevs.first().unwrap()
            }
        };

        let index = index.unwrap_or(0u8);

        let components = if !force_components.is_empty() {
            if force_components.iter().any(|c| c >= &pkg.components.len()) {
                return Err(PldmUpdateError::new_update(
                    "invalid components".into(),
                ));
            }

            force_components
        } else {
            dev.components.as_index_vec()
        };

        Ok(Self {
            package: pkg,
            components,
            index,
        })
    }
}

pub fn query_device_identifiers(
    comm: &mut impl mctp::ReqChannel,
) -> Result<DeviceIdentifiers> {
    let req = pldm::PldmRequest::new(PLDM_TYPE_FW, 0x01);

    let rsp = pldm::pldm_xfer(comm, req)?;

    if rsp.cc != 0 {
        return Err(PldmUpdateError::new_command(0x01, rsp.cc));
    }

    let f = length_value(map(le_u32, |l| l + 1), DeviceIdentifiers::parse);

    let res = all_consuming(f)(&rsp.data);

    res.map(|(_, d)| d).map_err(|_e| {
        PldmUpdateError::new_proto("can't parse QDI response".into())
    })
}

pub fn query_firmware_parameters(
    comm: &mut impl mctp::ReqChannel,
) -> Result<FirmwareParameters<'_>> {
    let req = pldm::PldmRequest::new(PLDM_TYPE_FW, 0x02);

    let rsp = pldm::pldm_xfer(comm, req)?;

    if rsp.cc != 0 {
        return Err(PldmUpdateError::new_command(0x02, rsp.cc));
    }

    let f = FirmwareParameters::parse;

    let res = all_consuming(f)(&rsp.data);

    res.map(|(_, d)| d).map_err(|_e| {
        PldmUpdateError::new_proto("can't parse QFP response".into())
    })
}

const XFER_SIZE: usize = 16 * 1024;

pub fn request_update(
    comm: &mut impl mctp::ReqChannel,
    update: &Update,
) -> Result<RequestUpdateResponse> {
    check_fd_state(comm, PldmFDState::Idle)?;

    let sz = XFER_SIZE as u32;
    let mut data = vec![];
    data.extend_from_slice(&sz.to_le_bytes());
    data.extend_from_slice(&1u16.to_le_bytes()); // NumberOfComponents
    data.extend_from_slice(&1u8.to_le_bytes()); // MaximumOutstandingTransferRequests
    data.extend_from_slice(&0u16.to_le_bytes()); // PackageDataLength
    update.package.version.write_utf8_bytes(&mut data);

    let req = pldm::PldmRequest::new_data(PLDM_TYPE_FW, 0x10, data);
    let rsp = pldm::pldm_xfer(comm, req)?;

    if rsp.cc != 0 {
        return Err(PldmUpdateError::new_command(0x10, rsp.cc));
    }

    let res = all_consuming(RequestUpdateResponse::parse)(&rsp.data);

    res.map(|(_, d)| d).map_err(|_e| {
        PldmUpdateError::new_proto("can't parse RU response".into())
    })
}

pub fn cancel_update(comm: &mut impl mctp::ReqChannel) -> Result<()> {
    let req = pldm::PldmRequest::new(PLDM_TYPE_FW, 0x1d);
    let rsp = pldm::pldm_xfer(comm, req)?;
    debug!("cancel rsp: cc {:x}, data {:?}", rsp.cc, rsp.data);
    Ok(())
}

pub fn update_component(
    comm: &mut impl mctp::ReqChannel,
    listener: &mut impl mctp::Listener,
    package: &pkg::Package,
    component: &pkg::PackageComponent,
    index: u8,
) -> Result<()> {
    update_component_progress(comm, listener, package, component, index, |_| ())
}

pub fn pass_component_table(
    comm: &mut impl mctp::ReqChannel,
    update: &Update,
) -> Result<()> {
    let components = &update.components;
    let len = components.len();

    check_fd_state(comm, PldmFDState::LearnComponents)?;

    for (n, idx) in components.iter().enumerate() {
        let component = update.package.components.get(*idx).unwrap();

        let mut data = vec![];
        data.push(xfer_flags(n, len));
        let c = u16::from(&component.classification);
        data.extend_from_slice(&c.to_le_bytes());
        data.extend_from_slice(&component.identifier.to_le_bytes());

        data.extend_from_slice(&update.index.to_le_bytes());

        data.extend_from_slice(&component.comparison_stamp.to_le_bytes());

        component.version.write_utf8_bytes(&mut data);

        let req = pldm::PldmRequest::new_data(PLDM_TYPE_FW, 0x13, data);
        let rsp = pldm::pldm_xfer(comm, req)?;

        if rsp.cc != 0 {
            return Err(PldmUpdateError::new_command(0x13, rsp.cc));
        }

        if rsp.data.len() < 2 {
            return Err(PldmUpdateError::new_proto(
                "Invalid PCT response".into(),
            ));
        }

        if rsp.data[0] != 0 {
            match rsp.data[1] {
                0x00 => (),
                0x06 => {
                    return Err(PldmUpdateError::new_update(format!(
                        "unsupported component {}",
                        rsp.data[1]
                    )))
                }
                x => {
                    return Err(PldmUpdateError::new_proto(format!(
                        "unknown PCT response {x:02x}"
                    )))
                }
            }
        }
    }

    Ok(())
}

fn xfer_flags(idx: usize, len: usize) -> u8 {
    let mut xfer_flags: u8 = 0x0;
    if idx == 0 {
        xfer_flags |= 0x1;
    }
    if idx == len - 1 {
        xfer_flags |= 0x4;
    }
    if xfer_flags == 0 {
        xfer_flags = 0x2;
    }
    xfer_flags
}

pub fn update_component_progress<F>(
    comm: &mut impl mctp::ReqChannel,
    listener: &mut impl mctp::Listener,
    package: &pkg::Package,
    component: &pkg::PackageComponent,
    index: u8,
    mut progress: F,
) -> Result<()>
where
    F: FnMut(&UpdateTransferProgress),
{
    check_fd_state(comm, PldmFDState::ReadyXfer)?;

    let mut data = vec![];
    let c = u16::from(&component.classification);
    data.extend_from_slice(&c.to_le_bytes());
    data.extend_from_slice(&component.identifier.to_le_bytes());

    data.extend_from_slice(&index.to_le_bytes());

    data.extend_from_slice(&component.comparison_stamp.to_le_bytes());

    let sz: u32 = component.file_size as u32;
    let mut sz_done: u32 = 0;
    data.extend_from_slice(&sz.to_le_bytes());

    // todo: flags: request forced update?
    data.extend_from_slice(&0u32.to_le_bytes());

    component.version.write_utf8_bytes(&mut data);

    let req = pldm::PldmRequest::new_data(PLDM_TYPE_FW, 0x14, data);
    let rsp = pldm::pldm_xfer(comm, req)?;

    if rsp.cc != 0 {
        return Err(PldmUpdateError::new_command(0x14, rsp.cc));
    }

    let (_, res) =
        all_consuming(UpdateComponentResponse::parse)(rsp.data.as_ref())
            .map_err(|_e| {
                PldmUpdateError::new_proto(
                    "can't parse Update Component response".into(),
                )
            })?;

    if res.response_code != 0 {
        return Err(PldmUpdateError::new_update(format!(
            "Update Component rejected with code 0x{:02x}",
            res.response_code
        )));
    }

    let start = chrono::Utc::now();

    loop {
        // we should be in update mode, handle incoming data requests
        let (fw_req, mut req_ep) = pldm::pldm_rx_req(listener)?;

        if fw_req.typ != PLDM_TYPE_FW {
            return Err(PldmUpdateError::new_proto(format!(
                "unexpected type during update: {fw_req:?}"
            )));
        }

        match fw_req.cmd {
            0x15 => {
                /* Request Firmware Data */
                let res: IResult<_, _> = all_consuming(tuple((le_u32, le_u32)))(
                    fw_req.data.as_ref(),
                );

                let (_, (offset, len)) = res.map_err(|_e| {
                    PldmUpdateError::new_proto("RFD parse error".into())
                })?;

                let mut buf = vec![0u8; len as usize];

                package.read_component(component, offset, &mut buf)?;

                let mut fw_resp = fw_req.response();

                fw_resp.cc = 0;
                fw_resp.set_data(buf);

                pldm::pldm_tx_resp(&mut req_ep, &fw_resp)?;

                sz_done += len;
                let elapsed = chrono::Utc::now() - start;

                let bps;
                let remaining;
                if elapsed.is_zero() || sz_done == 0 {
                    bps = 0.;
                    remaining = chrono::TimeDelta::days(1);
                } else {
                    let rate = elapsed / sz_done as i32; // time per byte

                    /* blocks may be repeated */
                    let sz_left = sz.saturating_sub(sz_done);

                    remaining = rate * sz_left as i32;
                    // OK unwrap, overflows after 200k years
                    bps = 1_000_000.0 / rate.num_microseconds().unwrap() as f32;
                }
                let percent = ((100 * (sz_done as u64)) / sz as u64) as u8;

                let u = UpdateTransferProgress {
                    cur_xfer: Some((offset, len)),
                    percent,
                    bps,
                    remaining,
                    duration: elapsed,
                    complete: false,
                };

                progress(&u);
            }
            0x16 => {
                /* Transfer Complete */
                let res = fw_req.data[0];
                let elapsed = chrono::Utc::now() - start;

                if res == 0 {
                    let rate = elapsed
                        .checked_div(sz_done as i32)
                        .and_then(|r| r.num_microseconds())
                        .unwrap_or(0);
                    let bps = if rate > 0 {
                        1_000_000.0 / rate as f32
                    } else {
                        0.
                    };

                    let u = UpdateTransferProgress {
                        cur_xfer: None,
                        percent: 100,
                        bps,
                        remaining: chrono::Duration::zero(),
                        duration: elapsed,
                        complete: false,
                    };

                    progress(&u);
                } else {
                    error!("firmware transfer error: 0x{res:02x}");
                }
                let mut fw_resp = fw_req.response();
                fw_resp.cc = 0;
                pldm::pldm_tx_resp(&mut req_ep, &fw_resp)?;
                break;
            }
            _ => {
                return Err(PldmUpdateError::new_proto(format!(
                    "unexpected command during update: {fw_req:?}"
                )));
            }
        }
    }

    /* Verify results.. */
    let (fw_req, mut req_ep) = pldm::pldm_rx_req(listener)?;
    match fw_req.cmd {
        0x17 => {
            let res = fw_req.data[0];
            if res != 0 {
                return Err(PldmUpdateError::new_update(
                    "firmware verify failure".into(),
                ));
            }
        }
        _ => {
            return Err(PldmUpdateError::new_update(
                "unexpected command in verify state".into(),
            ))
        }
    }
    let mut fw_resp = fw_req.response();
    fw_resp.cc = 0;
    pldm::pldm_tx_resp(&mut req_ep, &fw_resp)?;
    drop(req_ep);

    /* Apply */
    let (fw_req, mut req_ep) = pldm::pldm_rx_req(listener)?;
    match fw_req.cmd {
        0x18 => {
            let res = fw_req.data[0];
            if res != 0 {
                return Err(PldmUpdateError::new_update(
                    "firmware apply failure".into(),
                ));
            }
        }
        _ => {
            return Err(PldmUpdateError::new_update(
                "unexpected command in apply state".into(),
            ));
        }
    }

    let mut fw_resp = fw_req.response();
    fw_resp.cc = 0;
    pldm::pldm_tx_resp(&mut req_ep, &fw_resp)?;

    check_fd_state(comm, PldmFDState::ReadyXfer)?;

    Ok(())
}

pub fn update_components(
    comm: &mut impl mctp::ReqChannel,
    listener: &mut impl mctp::Listener,
    update: &mut Update,
) -> Result<()> {
    update_components_progress(comm, listener, update, |_| ())
}

pub fn update_components_progress<F>(
    comm: &mut impl mctp::ReqChannel,
    listener: &mut impl mctp::Listener,
    update: &mut Update,
    mut progress: F,
) -> Result<()>
where
    F: FnMut(&UpdateTransferProgress),
{
    let components = update.components.clone();

    for idx in components {
        let component = update.package.components.get(idx).unwrap();
        update_component_progress(
            comm,
            listener,
            &update.package,
            component,
            update.index,
            &mut progress,
        )?;
    }

    Ok(())
}

pub fn activate_firmware(
    comm: &mut impl mctp::ReqChannel,
    self_activate: bool,
) -> Result<()> {
    check_fd_state(comm, PldmFDState::ReadyXfer)?;

    let self_activation_req: u8 = if self_activate { 1 } else { 0 };

    let mut data = vec![];
    data.extend_from_slice(&self_activation_req.to_le_bytes());

    let req = pldm::PldmRequest::new_data(PLDM_TYPE_FW, 0x1a, data);
    let rsp = pldm::pldm_xfer(comm, req)?;

    if rsp.cc == 0 || rsp.cc == FwCode::ACTIVATION_NOT_REQUIRED as u8 {
        Ok(())
    } else {
        Err(PldmUpdateError::new_command(0x1a, rsp.cc))
    }
}

fn check_fd_state(
    comm: &mut impl mctp::ReqChannel,
    expected_state: PldmFDState,
) -> Result<()> {
    let req = pldm::PldmRequest::new(PLDM_TYPE_FW, 0x1b);
    let rsp = pldm::pldm_xfer(comm, req)?;

    if rsp.cc != 0 {
        return Err(PldmUpdateError::new_command(0x1b, rsp.cc));
    }

    let (_, res) = all_consuming(GetStatusResponse::parse)(rsp.data.as_ref())
        .map_err(|_e| {
        PldmUpdateError::new_proto("can't parse Get Status response".into())
    })?;

    //todo: flag
    debug!("state: {:?}", res.current_state);

    if res.current_state != expected_state {
        return Err(PldmUpdateError::new_proto(format!(
            "invalid state {:?}",
            res.current_state
        )));
    }

    Ok(())
}
