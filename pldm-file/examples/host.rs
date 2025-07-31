use anyhow::{bail, Context, Result};
use deku::DekuContainerRead;
#[allow(unused_imports)]
use log::{debug, info, trace, warn};

use mctp::{AsyncListener, AsyncRespChannel};
use mctp_linux::MctpLinuxAsyncListener;
use pldm::{PldmRequest, PldmResponse};
use std::cell::RefCell;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;

struct Host {
    file: RefCell<File>,
}

const FILENAME: &str = "pldm-file-host.bin";
// Arbitrary, 0 is reserved.
const PDR_HANDLE: u32 = 1;

impl Host {
    fn new() -> Result<Self> {
        Ok(Self {
            file: RefCell::new(File::open(FILENAME).with_context(|| {
                format!("cannot open input file {FILENAME}")
            })?),
        })
    }
}

impl pldm_file::host::Host for Host {
    fn read(&self, buf: &mut [u8], offset: usize) -> std::io::Result<usize> {
        let mut file = self.file.borrow_mut();
        file.seek(SeekFrom::Start(offset as u64))?;
        file.read(buf)
    }
}

type FileResponder = pldm_file::host::Responder<1>;

fn main() -> Result<()> {
    env_logger::init();

    let mut listener = MctpLinuxAsyncListener::new(mctp::MCTP_TYPE_PLDM, None)?;
    let mut pldm_ctrl = pldm::control::responder::Responder::<2>::new();
    let mut pldm_file = FileResponder::new();
    let mut host = Host::new().context("unable to create file host")?;

    FileResponder::register(&mut pldm_ctrl)?;

    let mut buf = [0u8; 4096];

    smol::block_on(async {
        loop {
            let (typ, _ic, buf, chan) = listener.recv(&mut buf).await?;

            if typ != mctp::MCTP_TYPE_PLDM {
                warn!("unexpected MCTP type {typ}");
                continue;
            }

            let req = PldmRequest::from_buf_borrowed(buf)
                .context("invalid PLDM message")?;

            const MP_RECV: u8 = pldm::control::Cmd::MultipartReceive as u8;

            match (req.typ, req.cmd) {
                // we pass all of the multipart receive commands over to
                // the pldm-file handler
                (pldm::control::PLDM_TYPE_CONTROL, MP_RECV) => pldm_file
                    .multipart_request_in(chan, &req, &pldm_ctrl, &mut host)
                    .await
                    .context("PLDM file multipart handler failed")?,
                (pldm::control::PLDM_TYPE_CONTROL, _) => pldm_ctrl
                    .handle_async(&req, chan)
                    .await
                    .context("PLDM control handler failed")?,
                (pldm_file::PLDM_TYPE_FILE_TRANSFER, _) => pldm_file
                    .request_in(chan, &req, &mut host)
                    .await
                    .context("PLDM file handler failed")?,
                (pldm_platform::PLDM_TYPE_PLATFORM, _) => {
                    handle_platform(chan, &req, &host)
                        .await
                        .context("PLDM platform handler failed")?
                }
                (t, _) => {
                    Err(anyhow::anyhow!("unexpected PLDM type {t}"))?;
                }
            }
        }
    })
}

async fn handle_platform<R: AsyncRespChannel>(
    mut comm: R,
    req: &PldmRequest<'_>,
    host: &Host,
) -> Result<()> {
    use pldm_platform::deku::DekuContainerWrite;
    use pldm_platform::proto::*;

    assert_eq!(req.typ, pldm_platform::PLDM_TYPE_PLATFORM);

    let mut resp = req.response();

    resp.cc = match Cmd::try_from(req.cmd)? {
        Cmd::GetPDRRepositoryInfo => {
            let pdrinfo = GetPDRRepositoryInfoResp {
                state: PDRRepositoryState::Available,
                update_time: [0u8; 13],
                oem_update_time: [0u8; 13],
                record_count: 1,
                // TODO. "An implementation is allowed to round this number up to the nearest kilobyte (1024 bytes)."
                repository_size: 1024,
                // TODO
                largest_record_size: 128,
                // No Timeout
                data_transfer_handle_timeout: 0x00,
            };
            resp.set_data(pdrinfo.to_bytes().context("Encoding failed")?);
            Ok(pldm::CCode::SUCCESS as u8)
        }
        Cmd::GetPDR => handle_get_pdr(req, &mut resp, host),
        other => {
            warn!("Unsupported PLDM platform command {other:?}");
            Ok(pldm::CCode::ERROR_UNSUPPORTED_PLDM_CMD as u8)
        }
    }?;

    pldm::pldm_tx_resp_async(&mut comm, &resp)
        .await
        .context("Sending response failed")
}

fn handle_get_pdr(
    req: &PldmRequest<'_>,
    resp: &mut PldmResponse,
    host: &Host,
) -> Result<u8> {
    use pldm_platform::deku::DekuContainerWrite;
    use pldm_platform::proto::*;

    let ((rest, _), pdr_req) = GetPDRReq::from_bytes((&req.data, 0))?;
    if !rest.is_empty() {
        bail!("Extra Get PDR Request bytes");
    }

    if pdr_req.record_handle != 0 {
        warn!("Only support first PDR Handle");
        return Ok(plat_codes::INVALID_RECORD_HANDLE);
    }
    if pdr_req.data_transfer_handle != 0 {
        warn!("Don't support multipart PDR");
        return Ok(plat_codes::INVALID_DATA_TRANSFER_HANDLE);
    }
    if pdr_req.transfer_operation_flag != TransferOperationFlag::FirstPart {
        warn!("Don't support multipart PDR");
        return Ok(plat_codes::INVALID_TRANSFER_OPERATION_FLAG);
    }
    if pdr_req.record_change_number != 0 {
        warn!("Don't support multipart PDR");
        return Ok(plat_codes::INVALID_RECORD_CHANGE_NUMBER);
    }

    let file_max_size = host
        .file
        .borrow()
        .metadata()
        .context("Metadata failed")?
        .size()
        .try_into()
        .context("File size > u32")?;

    let pdr_resp = GetPDRResp::new_single(
        PDR_HANDLE,
        PdrRecord::FileDescriptor(FileDescriptorPdr {
            terminus_handle: 0,
            file_identifier: 0,
            // Management Controller Firmware
            // TODO
            entity_type: entity_type::LOGICAL | 36,
            entity_instance: 0,
            container_id: 0,
            superior_directory: 0,
            file_classification: FileClassification::OtherFile,
            oem_file_classification: 0,
            capabilities: file_capabilities::EX_READ_OPEN,
            file_version: 0xFFFFFFFF,
            file_max_size,
            // TODO
            file_max_desc_count: 1,
            file_name: FILENAME.try_into().expect("Filename too long"),
            oem_file_name: Default::default(),
        }),
    )?;
    let enc = pdr_resp.to_bytes().context("Encoding failed")?;
    trace!("enc {enc:02x?}");
    resp.set_data(enc);

    Ok(pldm::CCode::SUCCESS as u8)
}
