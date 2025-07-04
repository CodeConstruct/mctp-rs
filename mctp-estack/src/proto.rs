#![warn(missing_docs)]
#[allow(unused)]
use crate::fmt::*;
use core::fmt::Debug;

use mctp::*;

/// MCTP packet header.
#[derive(Debug, Hash, PartialEq, Eq, Clone)]
pub struct MctpHeader {
    pub dest: Eid,
    pub src: Eid,
    pub som: bool,
    pub eom: bool,
    pub seq: u8,
    pub tag: Tag,
}

impl MctpHeader {
    pub const LEN: usize = 4;

    /// Decode header from a packet.
    ///
    /// Source and destination EIDs are not checked for validity.
    pub fn decode(packet: &[u8]) -> Result<Self> {
        let Some(header) = packet.get(..Self::LEN) else {
            warn!("bad len {:?}", packet);
            return Err(Error::InvalidInput);
        };

        // Ignore rsvd

        if header[0] & 0xf != MCTP_HEADER_VERSION_1 {
            trace!("Bad MCTP version");
            return Err(Error::InvalidInput);
        }

        let owner = (header[3] & 0b0000_1000) != 0;
        let tv = TagValue(header[3] & 0b0000_0111);
        let tag = if owner {
            Tag::Owned(tv)
        } else {
            Tag::Unowned(tv)
        };

        Ok(Self {
            dest: Eid(header[1]),
            src: Eid(header[2]),
            som: (header[3] & 0b1000_0000) != 0,
            eom: (header[3] & 0b0100_0000) != 0,
            seq: (header[3] >> 4) & 0b11,
            tag,
        })
    }

    /// Encode a header.
    ///
    /// Will fail if tag or sequence is invalid.
    pub fn encode(&self) -> Result<[u8; 4]> {
        if self.seq > 0b11 {
            trace!("Bad seq");
            return Err(Error::InvalidInput);
        }

        if self.tag.tag().0 > 0b111 {
            trace!("Bad tag");
            return Err(Error::InvalidInput);
        }

        let to = matches!(self.tag, Tag::Owned(_));

        let b3 = (self.som as u8) << 7
            | (self.eom as u8) << 6
            | self.seq << 4
            | (to as u8) << 3
            | self.tag.tag().0;

        Ok([MCTP_HEADER_VERSION_1, self.dest.0, self.src.0, b3])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_header() {
        // Test all settable bits.
        for src in 0..=8 {
            for dest in 0..=8 {
                for b3 in 0..=0xff {
                    let src = (1u32 << src) as u8;
                    let dest = (1u32 << dest) as u8;
                    let hdr = [0x1, dest, src, b3];
                    let m = MctpHeader::decode(&hdr).unwrap();
                    let h2 = m.encode().unwrap();
                    assert_eq!(hdr, h2);
                }
            }
        }
    }

    #[test]
    fn version_header() {
        // Bad version
        MctpHeader::decode([0x00, 0, 0, 0].as_slice()).unwrap_err();
        MctpHeader::decode([0x02, 0, 0, 0].as_slice()).unwrap_err();
        // Reserved bytes ignored.
        MctpHeader::decode([0xf1, 0, 0, 0].as_slice()).unwrap();
    }

    #[test]
    fn bad_encode() {
        let h = MctpHeader {
            src: Eid(8),
            dest: Eid(9),
            tag: Tag::Owned(TagValue(0)),
            seq: 0,
            som: true,
            eom: true,
        };

        h.encode().unwrap();

        let mut h2 = h.clone();
        h2.tag = Tag::Owned(TagValue(12));
        h2.encode().expect_err("Bad tag value");

        let mut h2 = h.clone();
        h2.tag = Tag::Unowned(TagValue(12));
        h2.encode().expect_err("Bad tag value");

        let mut h2 = h.clone();
        h2.seq = 16;
        h2.encode().expect_err("Bad seq value");
    }
}
