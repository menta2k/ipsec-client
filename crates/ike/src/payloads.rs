//! Typed encoders/decoders for IKEv2 payload bodies (the `data` field of a
//! [`crate::message::RawPayload`]). Covers the payloads that define SA
//! negotiation and authentication (RFC 7296 §3.3-§3.13).

use crate::constants::{ATTR_KEY_LENGTH, ATTR_TV_FLAG};

#[derive(Debug, PartialEq, Eq)]
pub enum DecodeError {
    Truncated,
    BadLength,
    BadField,
}

// --------------------------------------------------------------------------
// Security Association (SA) payload: proposals -> transforms -> attributes
// --------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transform {
    pub transform_type: u8,
    pub transform_id: u16,
    /// Key length in bits (AES etc.), carried as a TV attribute when present.
    pub key_length: Option<u16>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proposal {
    pub proposal_num: u8,
    pub protocol_id: u8,
    /// SPI (empty for the IKE SA in IKE_SA_INIT; 4 bytes for ESP/AH).
    pub spi: Vec<u8>,
    pub transforms: Vec<Transform>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SaPayload {
    pub proposals: Vec<Proposal>,
}

impl SaPayload {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for (i, p) in self.proposals.iter().enumerate() {
            let last = i + 1 == self.proposals.len();
            let mut pbody = Vec::new();
            // transforms
            for (j, t) in p.transforms.iter().enumerate() {
                let t_last = j + 1 == p.transforms.len();
                let mut tbody = Vec::new();
                tbody.push(t.transform_type);
                tbody.push(0); // reserved
                tbody.extend_from_slice(&t.transform_id.to_be_bytes());
                if let Some(kl) = t.key_length {
                    // TV attribute: (0x8000 | 14) then 16-bit value
                    tbody.extend_from_slice(&(ATTR_TV_FLAG | ATTR_KEY_LENGTH).to_be_bytes());
                    tbody.extend_from_slice(&kl.to_be_bytes());
                }
                let tlen = (4 + tbody.len()) as u16;
                pbody.push(if t_last { 0 } else { 3 }); // 3 = "more", 0 = last
                pbody.push(0);
                pbody.extend_from_slice(&tlen.to_be_bytes());
                pbody.extend_from_slice(&tbody);
            }
            // proposal header
            let plen = (8 + p.spi.len() + pbody.len()) as u16;
            out.push(if last { 0 } else { 2 }); // 2 = "more", 0 = last
            out.push(0); // reserved
            out.extend_from_slice(&plen.to_be_bytes());
            out.push(p.proposal_num);
            out.push(p.protocol_id);
            out.push(p.spi.len() as u8);
            out.push(p.transforms.len() as u8);
            out.extend_from_slice(&p.spi);
            out.extend_from_slice(&pbody);
        }
        out
    }

    pub fn decode(mut buf: &[u8]) -> Result<SaPayload, DecodeError> {
        let mut proposals = Vec::new();
        loop {
            if buf.len() < 8 {
                return Err(DecodeError::Truncated);
            }
            let more = buf[0];
            let plen = u16::from_be_bytes([buf[2], buf[3]]) as usize;
            let proposal_num = buf[4];
            let protocol_id = buf[5];
            let spi_size = buf[6] as usize;
            let num_transforms = buf[7] as usize;
            if plen < 8 || plen > buf.len() || 8 + spi_size > plen {
                return Err(DecodeError::BadLength);
            }
            let spi = buf[8..8 + spi_size].to_vec();
            let transforms = decode_transforms(&buf[8 + spi_size..plen], num_transforms)?;
            proposals.push(Proposal {
                proposal_num,
                protocol_id,
                spi,
                transforms,
            });
            if more == 0 {
                break;
            }
            buf = &buf[plen..];
        }
        Ok(SaPayload { proposals })
    }
}

fn decode_transforms(mut buf: &[u8], count: usize) -> Result<Vec<Transform>, DecodeError> {
    let mut transforms = Vec::with_capacity(count);
    for _ in 0..count {
        if buf.len() < 8 {
            return Err(DecodeError::Truncated);
        }
        let tlen = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        let transform_type = buf[4];
        let transform_id = u16::from_be_bytes([buf[6], buf[7]]);
        if tlen < 8 || tlen > buf.len() {
            return Err(DecodeError::BadLength);
        }
        let mut key_length = None;
        let mut attrs = &buf[8..tlen];
        while attrs.len() >= 4 {
            let at = u16::from_be_bytes([attrs[0], attrs[1]]);
            if at & ATTR_TV_FLAG != 0 {
                let val = u16::from_be_bytes([attrs[2], attrs[3]]);
                if at & 0x7fff == ATTR_KEY_LENGTH {
                    key_length = Some(val);
                }
                attrs = &attrs[4..];
            } else {
                // TLV: 2-byte type, 2-byte length, then value
                let alen = u16::from_be_bytes([attrs[2], attrs[3]]) as usize;
                if 4 + alen > attrs.len() {
                    return Err(DecodeError::BadLength);
                }
                attrs = &attrs[4 + alen..];
            }
        }
        transforms.push(Transform {
            transform_type,
            transform_id,
            key_length,
        });
        buf = &buf[tlen..];
    }
    Ok(transforms)
}

// --------------------------------------------------------------------------
// Key Exchange (KE) payload
// --------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KePayload {
    pub dh_group: u16,
    pub key_exchange_data: Vec<u8>,
}

impl KePayload {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + self.key_exchange_data.len());
        out.extend_from_slice(&self.dh_group.to_be_bytes());
        out.extend_from_slice(&[0, 0]); // reserved
        out.extend_from_slice(&self.key_exchange_data);
        out
    }
    pub fn decode(buf: &[u8]) -> Result<KePayload, DecodeError> {
        if buf.len() < 4 {
            return Err(DecodeError::Truncated);
        }
        Ok(KePayload {
            dh_group: u16::from_be_bytes([buf[0], buf[1]]),
            key_exchange_data: buf[4..].to_vec(),
        })
    }
}

// --------------------------------------------------------------------------
// Identification (IDi/IDr) payload
// --------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdPayload {
    pub id_type: u8,
    pub id_data: Vec<u8>,
}

impl IdPayload {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + self.id_data.len());
        out.push(self.id_type);
        out.extend_from_slice(&[0, 0, 0]); // reserved
        out.extend_from_slice(&self.id_data);
        out
    }
    pub fn decode(buf: &[u8]) -> Result<IdPayload, DecodeError> {
        if buf.len() < 4 {
            return Err(DecodeError::Truncated);
        }
        Ok(IdPayload {
            id_type: buf[0],
            id_data: buf[4..].to_vec(),
        })
    }
    /// The "IDx'" octets used in AUTH computation: the ID payload body minus its
    /// generic payload header, i.e. starting at the ID type byte (RFC 7296 §2.15).
    pub fn signed_octets(&self) -> Vec<u8> {
        self.encode()
    }
}

// --------------------------------------------------------------------------
// Authentication (AUTH) payload
// --------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthPayload {
    pub auth_method: u8,
    pub auth_data: Vec<u8>,
}

impl AuthPayload {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + self.auth_data.len());
        out.push(self.auth_method);
        out.extend_from_slice(&[0, 0, 0]);
        out.extend_from_slice(&self.auth_data);
        out
    }
    pub fn decode(buf: &[u8]) -> Result<AuthPayload, DecodeError> {
        if buf.len() < 4 {
            return Err(DecodeError::Truncated);
        }
        Ok(AuthPayload {
            auth_method: buf[0],
            auth_data: buf[4..].to_vec(),
        })
    }
}

// --------------------------------------------------------------------------
// Notify payload
// --------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NotifyPayload {
    pub protocol_id: u8,
    pub notify_type: u16,
    pub spi: Vec<u8>,
    pub data: Vec<u8>,
}

impl NotifyPayload {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + self.spi.len() + self.data.len());
        out.push(self.protocol_id);
        out.push(self.spi.len() as u8);
        out.extend_from_slice(&self.notify_type.to_be_bytes());
        out.extend_from_slice(&self.spi);
        out.extend_from_slice(&self.data);
        out
    }
    pub fn decode(buf: &[u8]) -> Result<NotifyPayload, DecodeError> {
        if buf.len() < 4 {
            return Err(DecodeError::Truncated);
        }
        let spi_size = buf[1] as usize;
        let notify_type = u16::from_be_bytes([buf[2], buf[3]]);
        if 4 + spi_size > buf.len() {
            return Err(DecodeError::BadLength);
        }
        Ok(NotifyPayload {
            protocol_id: buf[0],
            notify_type,
            spi: buf[4..4 + spi_size].to_vec(),
            data: buf[4 + spi_size..].to_vec(),
        })
    }
}

// --------------------------------------------------------------------------
// Delete payload
// --------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeletePayload {
    pub protocol_id: u8,
    pub spis: Vec<Vec<u8>>,
}

impl DeletePayload {
    pub fn encode(&self) -> Vec<u8> {
        let spi_size = self.spis.first().map(|s| s.len()).unwrap_or(0);
        let mut out = Vec::new();
        out.push(self.protocol_id);
        out.push(spi_size as u8);
        out.extend_from_slice(&(self.spis.len() as u16).to_be_bytes());
        for s in &self.spis {
            out.extend_from_slice(s);
        }
        out
    }
    pub fn decode(buf: &[u8]) -> Result<DeletePayload, DecodeError> {
        if buf.len() < 4 {
            return Err(DecodeError::Truncated);
        }
        let spi_size = buf[1] as usize;
        let num = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        let mut spis = Vec::with_capacity(num);
        let mut off = 4;
        for _ in 0..num {
            if off + spi_size > buf.len() {
                return Err(DecodeError::BadLength);
            }
            spis.push(buf[off..off + spi_size].to_vec());
            off += spi_size;
        }
        Ok(DeletePayload {
            protocol_id: buf[0],
            spis,
        })
    }
}

// --------------------------------------------------------------------------
// Configuration payload (CP) - mode-config / virtual IP (RFC 7296 §3.15)
// --------------------------------------------------------------------------

/// CP config types and attribute types.
pub mod cfg {
    pub const CFG_REQUEST: u8 = 1;
    pub const CFG_REPLY: u8 = 2;
    pub const INTERNAL_IP4_ADDRESS: u16 = 1;
    pub const INTERNAL_IP4_NETMASK: u16 = 2;
    pub const INTERNAL_IP4_DNS: u16 = 3;
    pub const INTERNAL_IP4_SUBNET: u16 = 13;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigPayload {
    pub cfg_type: u8,
    /// (attribute type, value). Empty value in a CFG_REQUEST means "please assign".
    pub attributes: Vec<(u16, Vec<u8>)>,
}

impl ConfigPayload {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![self.cfg_type, 0, 0, 0];
        for (t, v) in &self.attributes {
            out.extend_from_slice(&(t & 0x7fff).to_be_bytes());
            out.extend_from_slice(&(v.len() as u16).to_be_bytes());
            out.extend_from_slice(v);
        }
        out
    }

    /// A standard client request: assign an internal IPv4 address, netmask, DNS.
    pub fn request_defaults() -> ConfigPayload {
        ConfigPayload {
            cfg_type: cfg::CFG_REQUEST,
            attributes: vec![
                (cfg::INTERNAL_IP4_ADDRESS, vec![]),
                (cfg::INTERNAL_IP4_NETMASK, vec![]),
                (cfg::INTERNAL_IP4_DNS, vec![]),
            ],
        }
    }

    pub fn decode(buf: &[u8]) -> Result<ConfigPayload, DecodeError> {
        if buf.len() < 4 {
            return Err(DecodeError::Truncated);
        }
        let cfg_type = buf[0];
        let mut attributes = Vec::new();
        let mut off = 4;
        while off + 4 <= buf.len() {
            let t = u16::from_be_bytes([buf[off], buf[off + 1]]) & 0x7fff;
            let len = u16::from_be_bytes([buf[off + 2], buf[off + 3]]) as usize;
            if off + 4 + len > buf.len() {
                return Err(DecodeError::BadLength);
            }
            attributes.push((t, buf[off + 4..off + 4 + len].to_vec()));
            off += 4 + len;
        }
        Ok(ConfigPayload {
            cfg_type,
            attributes,
        })
    }

    /// Find the first value for an attribute type.
    pub fn attribute(&self, t: u16) -> Option<&[u8]> {
        self.attributes
            .iter()
            .find(|(at, _)| *at == t)
            .map(|(_, v)| v.as_slice())
    }
}

// --------------------------------------------------------------------------
// Traffic Selector (TSi/TSr) payload
// --------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrafficSelector {
    pub ts_type: u8,
    pub ip_protocol_id: u8,
    pub start_port: u16,
    pub end_port: u16,
    pub start_addr: Vec<u8>,
    pub end_addr: Vec<u8>,
}

impl TrafficSelector {
    fn addr_len(ts_type: u8) -> usize {
        match ts_type {
            8 => 16, // IPv6
            _ => 4,  // IPv4
        }
    }
    fn encode(&self, out: &mut Vec<u8>) {
        let sel_len = (8 + self.start_addr.len() + self.end_addr.len()) as u16;
        out.push(self.ts_type);
        out.push(self.ip_protocol_id);
        out.extend_from_slice(&sel_len.to_be_bytes());
        out.extend_from_slice(&self.start_port.to_be_bytes());
        out.extend_from_slice(&self.end_port.to_be_bytes());
        out.extend_from_slice(&self.start_addr);
        out.extend_from_slice(&self.end_addr);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TsPayload {
    pub selectors: Vec<TrafficSelector>,
}

impl TsPayload {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(self.selectors.len() as u8);
        out.extend_from_slice(&[0, 0, 0]); // reserved
        for s in &self.selectors {
            s.encode(&mut out);
        }
        out
    }
    pub fn decode(buf: &[u8]) -> Result<TsPayload, DecodeError> {
        if buf.len() < 4 {
            return Err(DecodeError::Truncated);
        }
        let num = buf[0] as usize;
        let mut selectors = Vec::with_capacity(num);
        let mut off = 4;
        for _ in 0..num {
            if off + 8 > buf.len() {
                return Err(DecodeError::Truncated);
            }
            let ts_type = buf[off];
            let ip_protocol_id = buf[off + 1];
            let sel_len = u16::from_be_bytes([buf[off + 2], buf[off + 3]]) as usize;
            let alen = TrafficSelector::addr_len(ts_type);
            if sel_len < 8 + 2 * alen || off + sel_len > buf.len() {
                return Err(DecodeError::BadLength);
            }
            let start_port = u16::from_be_bytes([buf[off + 4], buf[off + 5]]);
            let end_port = u16::from_be_bytes([buf[off + 6], buf[off + 7]]);
            let start_addr = buf[off + 8..off + 8 + alen].to_vec();
            let end_addr = buf[off + 8 + alen..off + 8 + 2 * alen].to_vec();
            selectors.push(TrafficSelector {
                ts_type,
                ip_protocol_id,
                start_port,
                end_port,
                start_addr,
                end_addr,
            });
            off += sel_len;
        }
        Ok(TsPayload { selectors })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{dh, encr, integ, prf, ProtocolId, TransformType};

    fn ike_proposal() -> SaPayload {
        SaPayload {
            proposals: vec![Proposal {
                proposal_num: 1,
                protocol_id: ProtocolId::Ike as u8,
                spi: vec![],
                transforms: vec![
                    Transform {
                        transform_type: TransformType::Encr as u8,
                        transform_id: encr::AES_CBC,
                        key_length: Some(256),
                    },
                    Transform {
                        transform_type: TransformType::Prf as u8,
                        transform_id: prf::HMAC_SHA2_256,
                        key_length: None,
                    },
                    Transform {
                        transform_type: TransformType::Integ as u8,
                        transform_id: integ::HMAC_SHA2_256_128,
                        key_length: None,
                    },
                    Transform {
                        transform_type: TransformType::Dh as u8,
                        transform_id: dh::MODP_2048,
                        key_length: None,
                    },
                ],
            }],
        }
    }

    #[test]
    fn sa_roundtrip_with_keylen_attr() {
        let sa = ike_proposal();
        let enc = sa.encode();
        let dec = SaPayload::decode(&enc).unwrap();
        assert_eq!(dec, sa);
        assert_eq!(dec.proposals[0].transforms[0].key_length, Some(256));
    }

    #[test]
    fn ke_and_nonce_and_id() {
        let ke = KePayload {
            dh_group: dh::CURVE25519,
            key_exchange_data: vec![7u8; 32],
        };
        assert_eq!(KePayload::decode(&ke.encode()).unwrap(), ke);

        let id = IdPayload {
            id_type: 3,
            id_data: b"user@example.com".to_vec(),
        };
        assert_eq!(IdPayload::decode(&id.encode()).unwrap(), id);
    }

    #[test]
    fn notify_with_spi() {
        let n = NotifyPayload {
            protocol_id: ProtocolId::Esp as u8,
            notify_type: crate::constants::notify::REKEY_SA,
            spi: vec![0xde, 0xad, 0xbe, 0xef],
            data: vec![],
        };
        assert_eq!(NotifyPayload::decode(&n.encode()).unwrap(), n);
    }

    #[test]
    fn traffic_selector_roundtrip() {
        let ts = TsPayload {
            selectors: vec![TrafficSelector {
                ts_type: crate::constants::TsType::Ipv4AddrRange as u8,
                ip_protocol_id: 0,
                start_port: 0,
                end_port: 65535,
                start_addr: vec![0, 0, 0, 0],
                end_addr: vec![255, 255, 255, 255],
            }],
        };
        assert_eq!(TsPayload::decode(&ts.encode()).unwrap(), ts);
    }

    #[test]
    fn config_payload_request_and_reply() {
        let req = ConfigPayload::request_defaults();
        let enc = req.encode();
        assert_eq!(enc[0], cfg::CFG_REQUEST);
        assert_eq!(ConfigPayload::decode(&enc).unwrap(), req);
        // a reply assigning 10.1.2.3 / DNS 8.8.8.8
        let reply = ConfigPayload {
            cfg_type: cfg::CFG_REPLY,
            attributes: vec![
                (cfg::INTERNAL_IP4_ADDRESS, vec![10, 1, 2, 3]),
                (cfg::INTERNAL_IP4_DNS, vec![8, 8, 8, 8]),
            ],
        };
        let back = ConfigPayload::decode(&reply.encode()).unwrap();
        assert_eq!(
            back.attribute(cfg::INTERNAL_IP4_ADDRESS),
            Some(&[10, 1, 2, 3][..])
        );
    }

    #[test]
    fn delete_roundtrip() {
        let d = DeletePayload {
            protocol_id: ProtocolId::Esp as u8,
            spis: vec![vec![1, 2, 3, 4], vec![5, 6, 7, 8]],
        };
        assert_eq!(DeletePayload::decode(&d.encode()).unwrap(), d);
    }
}
