//! Decode a single Get PDR Response
//!
//! This has basic handling, see requester.rs for a real implementation.

use pldm_platform::deku::DekuContainerRead;
use pldm_platform::proto::*;

use log::*;

fn main() {
    env_logger::init();

    let a: Vec<_> = std::env::args().collect();
    let f = a.get(1).expect("Need input file argument");
    println!("loading {f}");
    let d = std::fs::read(f).unwrap();

    let ((rest, _), pdrrsp) = GetPDRResp::from_bytes((&d, 0))
        .map_err(|e| {
            println!("GetPDR parse error {e:?}");
            panic!("Bad GetPDR response")
        })
        .unwrap();
    println!("rsp {pdrrsp:?}");
    assert!(rest.len() == 0);

    let ((rest, _), pdr) = Pdr::from_bytes((&pdrrsp.record_data, 0))
        .map_err(|e| {
            trace!("GetPDR parse error {e}");
            panic!("Bad GetPDR response")
        })
        .unwrap();
    if !rest.is_empty() {
        panic!("Extra PDR response");
    }
    assert!(rest.len() == 0);

    println!("PDR {pdr:?}");
}
