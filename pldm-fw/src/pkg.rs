// SPDX-License-Identifier: MIT OR Apache-2.0
/*
 * PLDM firmware update utility: PLDM type 5 package parsing
 *
 * Copyright (c) 2023 Code Construct
 */

use nom::{
    bytes::complete::take,
    combinator::{all_consuming, map, map_res},
    multi::{count, length_count},
    number::complete::{le_u16, le_u32, le_u8},
    sequence::tuple,
    Finish, IResult,
};
use std::io::{BufReader, Read};
use std::os::unix::fs::FileExt;
use thiserror::Error;
use uuid::{uuid, Uuid};

const PKG_UUID_1_0_X: Uuid = uuid!("f018878c-cb7d-4943-9800-a02f059aca02");
const PKG_UUID_1_1_X: Uuid = uuid!("1244d264-8d7d-4718-a030-fc8a56587d5a");

use crate::{
    parse_string, parse_string_adjacent, ComponentClassification, Descriptor,
    DescriptorString, DeviceIdentifiers,
};

type VResult<I, O> = IResult<I, O>;

#[derive(Error, Debug)]
pub enum PldmPackageError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    // TODO: would be nice to extract this directly from a nom ParseError,
    // including Context...
    #[error("PLDM package format error: {0}")]
    Format(String),
}

impl PldmPackageError {
    fn new_format(s: &str) -> Self {
        Self::Format(s.into())
    }
}

type Result<T> = std::result::Result<T, PldmPackageError>;

#[derive(Debug)]
pub struct ComponentBitmap {
    n_bits: usize,
    bits: Vec<u8>,
}

impl<'a> ComponentBitmap {
    pub fn parse(
        component_bits: u16,
    ) -> impl FnMut(&'a [u8]) -> VResult<&'a [u8], Self> {
        let bytes = component_bits.div_ceil(8);
        map(take(bytes), move |b: &[u8]| ComponentBitmap {
            n_bits: component_bits as usize,
            bits: b.to_vec(),
        })
    }

    pub fn bit(&self, i: usize) -> bool {
        let idx = i / 8;
        let offt = i % 8;
        self.bits[idx] & (1 << offt) != 0
    }

    pub fn as_index_str(&self) -> String {
        (0usize..self.n_bits)
            .filter(|&i| self.bit(i))
            .map(|i| i.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    }

    pub fn as_index_vec(&self) -> Vec<usize> {
        (0usize..self.n_bits).filter(|&i| self.bit(i)).collect()
    }
}

#[derive(Debug)]
pub struct PackageDevice {
    pub ids: DeviceIdentifiers,
    pub option_flags: u32,
    pub version: DescriptorString,
    pub components: ComponentBitmap,
}

impl PackageDevice {
    pub fn parse(buf: &[u8], component_bits: u16) -> VResult<&[u8], Self> {
        let (
            r,
            (len, desc_count, flags, set_ver_type, set_ver_len, pkg_data_len),
        ) = tuple((le_u16, le_u8, le_u32, le_u8, le_u8, le_u16))(buf)?;

        // split the length bytes into r
        let (rest, r) = take(len - 11)(r)?;

        let (r, components) = ComponentBitmap::parse(component_bits)(r)?;
        let (r, set_ver) = parse_string(set_ver_type, set_ver_len)(r)?;
        let (r, ids) = count(Descriptor::parse, desc_count as usize)(r)?;
        let (_, _pkg_data) = all_consuming(take(pkg_data_len))(r)?;

        let pkgdev = PackageDevice {
            ids: DeviceIdentifiers { ids },
            option_flags: flags,
            version: set_ver,
            components,
        };

        Ok((rest, pkgdev))
    }
}

#[derive(Debug)]
pub struct PackageComponent {
    pub classification: ComponentClassification,
    pub identifier: u16,
    pub comparison_stamp: u32,
    pub options: u16,
    pub activation_method: u16,
    pub file_offset: usize,
    pub file_size: usize,
    pub version: DescriptorString,
}

impl PackageComponent {
    pub fn parse(buf: &[u8]) -> VResult<&[u8], Self> {
        let (
            r,
            (
                classification,
                identifier,
                comparison_stamp,
                options,
                activation_method,
                file_offset,
                file_size,
                version,
            ),
        ) = tuple((
            le_u16,
            le_u16,
            le_u32,
            le_u16,
            le_u16,
            le_u32,
            le_u32,
            parse_string_adjacent,
        ))(buf)?;

        let c = PackageComponent {
            classification: classification.into(),
            identifier,
            comparison_stamp,
            options,
            activation_method,
            file_offset: file_offset as usize,
            file_size: file_size as usize,
            version,
        };
        Ok((r, c))
    }
}

#[derive(Debug)]
pub struct Package {
    pub identifier: Uuid,
    pub version: DescriptorString,
    pub devices: Vec<PackageDevice>,
    pub components: Vec<PackageComponent>,
    file: std::fs::File,
}

impl Package {
    pub fn parse(file: std::fs::File) -> Result<Self> {
        // just enough length to retrieve the header size field, after which
        // we can parse the rest of the header.
        const HDR_INIT_SIZE: usize = 16 + 1 + 2;

        let mut reader = BufReader::new(&file);
        let mut init = [0u8; HDR_INIT_SIZE];
        reader.read_exact(&mut init)?;

        let (_, (identifier, _hdr_format, hdr_size)) = all_consuming(tuple((
            map_res(
                take::<_, _, nom::error::Error<_>>(16usize),
                Uuid::from_slice,
            ),
            le_u8,
            le_u16,
        )))(&init)
        .map_err(|_| PldmPackageError::new_format("can't parse header"))?;

        let mut hdr_usize = hdr_size as usize;
        if hdr_usize < HDR_INIT_SIZE {
            return Err(PldmPackageError::new_format("invalid header size"));
        }

        hdr_usize -= HDR_INIT_SIZE;

        let mut buf = vec![0; hdr_usize];
        reader.read_exact(&mut buf).map_err(|_| {
            PldmPackageError::new_format(
                "reported header size is larger than file",
            )
        })?;

        let (r, (_release_date_time, component_bitmap_length, version)) =
            tuple((take(13usize), le_u16, parse_string_adjacent))(&buf)
                .finish()
                .map_err(|_| {
                    PldmPackageError::new_format("can't parse header")
                })?;

        let f = |d| PackageDevice::parse(d, component_bitmap_length);
        let (r, devices) = length_count(le_u8, f)(r)
            .finish()
            .map_err(|_| PldmPackageError::new_format("can't parse devices"))?;

        /* this is the first divergence in package format versions; the
         * downstream device identification area is only present in 1.1.x
         */
        let r = match identifier {
            PKG_UUID_1_0_X => r,
            PKG_UUID_1_1_X => {
                let (r, _downstream_devices) =
                    length_count(le_u8, f)(r).finish().map_err(|_| {
                        PldmPackageError::new_format(
                            "can't parse downstream devices",
                        )
                    })?;
                r
            }
            _ => {
                return Err(PldmPackageError::new_format(&format!(
                    "unknown package UUID {identifier}"
                )))
            }
        };

        let f = |d| PackageComponent::parse(d);
        let (_, components) =
            length_count(le_u16, f)(r).finish().map_err(|_| {
                PldmPackageError::new_format("can't parse components")
            })?;

        let mut whole_header = Vec::new();
        whole_header.extend_from_slice(&init);
        whole_header.extend_from_slice(&buf);
        let (cs_payload, checksum) =
            whole_header.split_at(whole_header.len() - 4);
        // safe unwrap, know init.len() > 4
        let checksum = u32::from_le_bytes(checksum.try_into().unwrap());
        let crc32 = crc::Crc::<u32>::new(&crc::CRC_32_ISO_HDLC);
        let cs_calc = crc32.checksum(cs_payload);
        if cs_calc != checksum {
            return Err(PldmPackageError::new_format(
                "Incorrect header checksum",
            ));
        }

        Ok(Package {
            identifier,
            version,
            devices,
            components,
            file,
        })
    }

    pub fn new_virtual(
        classification: ComponentClassification,
        identifier: u16,
        payload_file: std::fs::File,
    ) -> Result<Self> {
        let metadata = payload_file.metadata()?;
        let payload_len = metadata
            .len()
            .try_into()
            .map_err(|_| PldmPackageError::new_format("invalid file size?"))?;

        let comp = PackageComponent {
            classification,
            identifier,
            comparison_stamp: 0,
            options: 0,
            activation_method: 0,
            file_offset: 0,
            file_size: payload_len,
            version: DescriptorString::String("0000".into()),
        };
        Ok(Self {
            identifier: PKG_UUID_1_1_X,
            version: DescriptorString::String("0000".into()),
            components: vec![comp],
            devices: vec![],
            file: payload_file,
        })
    }

    pub fn read_component(
        &self,
        component: &PackageComponent,
        offset: u32,
        buf: &mut [u8],
    ) -> Result<usize> {
        let file_offset = offset as u64 + component.file_offset as u64;
        Ok(self.file.read_at(buf, file_offset)?)
    }
}

/// Write `bytes` to a fresh anonymous temporary file and return a handle to
/// it, seeked back to the start ready for reading.
#[cfg(test)]
pub(crate) fn temp_file_with(bytes: &[u8]) -> std::fs::File {
    use std::io::{Seek, SeekFrom, Write};

    let mut f = tempfile::tempfile().unwrap();
    f.write_all(bytes).unwrap();
    f.seek(SeekFrom::Start(0)).unwrap();
    f
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Build the bytes of a minimal, well-formed v1.1.x firmware update
    /// package.
    ///
    /// The package describes a single device identified by one PCI Vendor
    /// ID descriptor (`vid`), whose component bitmap selects every supplied
    /// component. Each entry of `components` becomes a component image
    /// appended after the (CRC-protected) package header, with matching
    /// file offset/size fields.
    pub(crate) fn build_v11_package(vid: u16, components: &[&[u8]]) -> Vec<u8> {
        let ncomp = components.len();
        assert!(ncomp >= 1);

        // --- single device record ---
        let bitmap_bytes = ncomp.div_ceil(8);
        let mut bitmap = vec![0u8; bitmap_bytes];
        for i in 0..ncomp {
            bitmap[i / 8] |= 1u8 << (i % 8);
        }
        let set_ver = b"0000";

        let mut descs = Vec::new();
        descs.extend_from_slice(&0x0000u16.to_le_bytes()); // type: PCI Vendor ID
        descs.extend_from_slice(&2u16.to_le_bytes()); // length
        descs.extend_from_slice(&vid.to_le_bytes()); // data
        let desc_count = 1u8;
        let pkg_data_len = 0u16;

        let mut rec_body = Vec::new();
        rec_body.extend_from_slice(&bitmap);
        rec_body.extend_from_slice(set_ver);
        rec_body.extend_from_slice(&descs);
        let rec_len = (11 + rec_body.len()) as u16;

        let mut device = Vec::new();
        device.extend_from_slice(&rec_len.to_le_bytes());
        device.push(desc_count);
        device.extend_from_slice(&0u32.to_le_bytes()); // option flags
        device.push(1u8); // set version string type (utf-8)
        device.push(set_ver.len() as u8);
        device.extend_from_slice(&pkg_data_len.to_le_bytes());
        device.extend_from_slice(&rec_body);

        // Header bytes following the 19-byte init region, excluding the
        // trailing 4-byte checksum. `offsets` carries each component's
        // absolute file offset.
        let build_pre = |offsets: &[usize]| -> Vec<u8> {
            let mut pre = Vec::new();
            pre.extend_from_slice(&[0u8; 13]); // release date/time
            pre.extend_from_slice(&(ncomp as u16).to_le_bytes()); // bitmap length (bits)

            // package version string (type, length, data)
            pre.push(1u8);
            pre.push(4u8);
            pre.extend_from_slice(b"0000");
            // device id record area
            pre.push(1u8); // device count
            pre.extend_from_slice(&device);
            // downstream device id record area (1.1.x): none
            pre.push(0u8);
            // component image information area
            pre.extend_from_slice(&(ncomp as u16).to_le_bytes());
            for (i, c) in components.iter().enumerate() {
                pre.extend_from_slice(&0x000au16.to_le_bytes()); // classification: firmware
                pre.extend_from_slice(&(i as u16).to_le_bytes()); // identifier
                pre.extend_from_slice(&0u32.to_le_bytes()); // comparison stamp
                pre.extend_from_slice(&0u16.to_le_bytes()); // options
                pre.extend_from_slice(&0u16.to_le_bytes()); // activation method
                pre.extend_from_slice(&(offsets[i] as u32).to_le_bytes());
                pre.extend_from_slice(&(c.len() as u32).to_le_bytes());
                // component version string (type, length, data)
                pre.push(1u8);
                pre.push(4u8);
                pre.extend_from_slice(b"0000");
            }
            pre
        };

        const HDR_INIT_SIZE: usize = 16 + 1 + 2;

        // First pass with placeholder offsets to learn the header size,
        // which is independent of the (fixed-size) offset field values.
        let pre_len = build_pre(&vec![0usize; ncomp]).len();
        let hdr_size = HDR_INIT_SIZE + pre_len + 4;

        // Second pass: real offsets point past the header into the payload
        // area.
        let mut offsets = vec![0usize; ncomp];
        let mut cum = hdr_size;
        for (i, c) in components.iter().enumerate() {
            offsets[i] = cum;
            cum += c.len();
        }
        let pre = build_pre(&offsets);

        let mut header = Vec::new();
        header.extend_from_slice(PKG_UUID_1_1_X.as_bytes());
        header.push(1u8); // header format revision
        header.extend_from_slice(&(hdr_size as u16).to_le_bytes());
        header.extend_from_slice(&pre);

        let crc32 = crc::Crc::<u32>::new(&crc::CRC_32_ISO_HDLC);
        let checksum = crc32.checksum(&header);
        header.extend_from_slice(&checksum.to_le_bytes());
        assert_eq!(header.len(), hdr_size);

        let mut file = header;
        for c in components {
            file.extend_from_slice(c);
        }
        file
    }
}
