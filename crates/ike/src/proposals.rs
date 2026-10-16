//! The proposals the client offers, and mapping of the responder's choice
//! back to concrete ciphers. Weak algorithms (DES/3DES/MD5/MODP<1536) are never
//! offered.

use crate::constants::{encr, integ, prf, ProtocolId, TransformType, TsType};
use crate::crypto::Prf;
use crate::dh::DhGroup;
use crate::esp::EspCipher;
use crate::payloads::{Proposal, SaPayload, TrafficSelector, Transform, TsPayload};
use crate::sa::Negotiated;
use crate::sk::{Encr, Integ};

fn tf(ttype: TransformType, id: u16, key_bits: Option<u16>) -> Transform {
    Transform {
        transform_type: ttype as u8,
        transform_id: id,
        key_length: key_bits,
    }
}

/// IKE SA proposals, in preference order (all share the KE group):
///   1. AES-256-GCM-16 + PRF-HMAC-SHA2-384
///   2. AES-256-CBC + PRF-HMAC-SHA2-256 + HMAC-SHA2-256-128
///   3. AES-128-CBC + PRF-HMAC-SHA2-256 + HMAC-SHA2-256-128
pub fn ike_proposals(dh: DhGroup) -> SaPayload {
    let d = || tf(TransformType::Dh, dh.transform_id(), None);
    SaPayload {
        proposals: vec![
            Proposal {
                proposal_num: 1,
                protocol_id: ProtocolId::Ike as u8,
                spi: vec![],
                transforms: vec![
                    tf(TransformType::Encr, encr::AES_GCM_16, Some(256)),
                    tf(TransformType::Prf, prf::HMAC_SHA2_384, None),
                    d(),
                ],
            },
            Proposal {
                proposal_num: 2,
                protocol_id: ProtocolId::Ike as u8,
                spi: vec![],
                transforms: vec![
                    tf(TransformType::Encr, encr::AES_CBC, Some(256)),
                    tf(TransformType::Prf, prf::HMAC_SHA2_256, None),
                    tf(TransformType::Integ, integ::HMAC_SHA2_256_128, None),
                    d(),
                ],
            },
            Proposal {
                proposal_num: 3,
                protocol_id: ProtocolId::Ike as u8,
                spi: vec![],
                transforms: vec![
                    tf(TransformType::Encr, encr::AES_CBC, Some(128)),
                    tf(TransformType::Prf, prf::HMAC_SHA2_256, None),
                    tf(TransformType::Integ, integ::HMAC_SHA2_256_128, None),
                    d(),
                ],
            },
        ],
    }
}

/// Child SA (ESP) proposals: AES-256-GCM-16, then AES-256-CBC + SHA2-256-128.
pub fn child_proposals(spi: [u8; 4]) -> SaPayload {
    SaPayload {
        proposals: vec![
            Proposal {
                proposal_num: 1,
                protocol_id: ProtocolId::Esp as u8,
                spi: spi.to_vec(),
                transforms: vec![
                    tf(TransformType::Encr, encr::AES_GCM_16, Some(256)),
                    tf(TransformType::Esn, 0, None),
                ],
            },
            Proposal {
                proposal_num: 2,
                protocol_id: ProtocolId::Esp as u8,
                spi: spi.to_vec(),
                transforms: vec![
                    tf(TransformType::Encr, encr::AES_CBC, Some(256)),
                    tf(TransformType::Integ, integ::HMAC_SHA2_256_128, None),
                    tf(TransformType::Esn, 0, None),
                ],
            },
        ],
    }
}

/// The IPv4 "any" traffic selector (0.0.0.0-255.255.255.255, all protocols).
pub fn ts_any_v4() -> TsPayload {
    TsPayload {
        selectors: vec![TrafficSelector {
            ts_type: TsType::Ipv4AddrRange as u8,
            ip_protocol_id: 0,
            start_port: 0,
            end_port: 65535,
            start_addr: vec![0, 0, 0, 0],
            end_addr: vec![255, 255, 255, 255],
        }],
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ChildSelectError {
    /// No proposal, or the SPI is not 4 bytes.
    Malformed,
    /// The responder chose a cipher this build does not implement.
    UnsupportedCipher,
}

/// Map the responder's chosen Child SA proposal to an ESP cipher and the SPI
/// the responder assigned (used on packets we send to it).
pub fn select_child(sa: &SaPayload) -> Result<(EspCipher, [u8; 4]), ChildSelectError> {
    let prop = sa.proposals.first().ok_or(ChildSelectError::Malformed)?;
    if prop.protocol_id != ProtocolId::Esp as u8 || prop.spi.len() != 4 {
        return Err(ChildSelectError::Malformed);
    }
    let spi = [prop.spi[0], prop.spi[1], prop.spi[2], prop.spi[3]];
    let mut enc = None;
    let mut integ_id = None;
    for t in &prop.transforms {
        match TransformType::from_u8(t.transform_type) {
            Some(TransformType::Encr) => enc = Some((t.transform_id, t.key_length)),
            Some(TransformType::Integ) => integ_id = Some(t.transform_id),
            _ => {}
        }
    }
    let cipher = match (enc, integ_id) {
        (Some((encr::AES_GCM_16, Some(256))), None | Some(integ::NONE)) => EspCipher::Aes256Gcm16,
        (Some((encr::AES_CBC, Some(256))), Some(integ::HMAC_SHA2_256_128)) => {
            EspCipher::Aes256CbcSha256
        }
        _ => return Err(ChildSelectError::UnsupportedCipher),
    };
    Ok((cipher, spi))
}

/// Human-readable IKE suite, e.g. "AES-256-GCM-16 / PRF-HMAC-SHA2-384 / MODP-2048".
pub fn describe_ike(n: &Negotiated, dh: DhGroup) -> String {
    let e = match n.suite.encr {
        Encr::Aes128Cbc => "AES-128-CBC",
        Encr::Aes256Cbc => "AES-256-CBC",
        Encr::Aes128Gcm16 => "AES-128-GCM-16",
        Encr::Aes256Gcm16 => "AES-256-GCM-16",
    };
    let p = match n.prf {
        Prf::HmacSha1 => "PRF-HMAC-SHA1",
        Prf::HmacSha256 => "PRF-HMAC-SHA2-256",
        Prf::HmacSha384 => "PRF-HMAC-SHA2-384",
        Prf::HmacSha512 => "PRF-HMAC-SHA2-512",
    };
    let d = dh_name(dh);
    match n.suite.integ {
        None => format!("{e} / {p} / {d}"),
        Some(i) => {
            let i = match i {
                Integ::HmacSha1_96 => "HMAC-SHA1-96",
                Integ::HmacSha256_128 => "HMAC-SHA2-256-128",
                Integ::HmacSha384_192 => "HMAC-SHA2-384-192",
                Integ::HmacSha512_256 => "HMAC-SHA2-512-256",
            };
            format!("{e} / {i} / {p} / {d}")
        }
    }
}

pub fn dh_name(dh: DhGroup) -> &'static str {
    match dh {
        DhGroup::Curve25519 => "Curve25519",
        DhGroup::Modp1536 => "MODP-1536",
        DhGroup::Modp2048 => "MODP-2048",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn select_child_gcm_and_cbc() {
        let offered = child_proposals([1, 2, 3, 4]);
        let mut gcm = offered.clone();
        gcm.proposals.truncate(1);
        gcm.proposals[0].spi = vec![9, 9, 9, 9];
        assert_eq!(
            select_child(&gcm),
            Ok((EspCipher::Aes256Gcm16, [9, 9, 9, 9]))
        );
        let mut cbc = offered;
        cbc.proposals.remove(0);
        assert_eq!(select_child(&cbc).unwrap().0, EspCipher::Aes256CbcSha256);
    }

    #[test]
    fn select_child_rejects_unsupported() {
        let mut p = child_proposals([1, 2, 3, 4]);
        p.proposals.truncate(1);
        p.proposals[0].transforms[0].key_length = Some(128);
        assert_eq!(select_child(&p), Err(ChildSelectError::UnsupportedCipher));
        assert_eq!(
            select_child(&SaPayload { proposals: vec![] }),
            Err(ChildSelectError::Malformed)
        );
    }

    #[test]
    fn ike_proposals_roundtrip_and_never_weak() {
        let sa = ike_proposals(DhGroup::Modp2048);
        assert_eq!(SaPayload::decode(&sa.encode()).unwrap(), sa);
        for p in &sa.proposals {
            for t in &p.transforms {
                if t.transform_type == TransformType::Encr as u8 {
                    assert!(t.transform_id != encr::DES_CBC && t.transform_id != encr::DES3_CBC);
                }
            }
        }
    }
}
