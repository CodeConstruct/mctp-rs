use anyhow::{Context, Result};
use log::warn;
use mctp::AsyncListener;
use mctp_linux::MctpLinuxAsyncListener;
use pldm::PldmRequest;
use std::cell::RefCell;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

struct Host {
    file: RefCell<File>,
}

const FILENAME: &str = "pldm-file-host.bin";

impl Host {
    fn new() -> Result<Self> {
        Ok(Self {
            file: RefCell::new(
                File::open(FILENAME).context("cannot open input file")?,
            ),
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
                (t, _) => {
                    Err(anyhow::anyhow!("unexpected PLDM type {t}"))?;
                }
            }
        }
    })
}
