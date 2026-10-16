//! IKEv2 initiator handshake (RFC 7296 §1.2): drive IKE_SA_INIT and IKE_AUTH,
//! then protect INFORMATIONAL exchanges on the established IKE SA.
//!
//! 1. [`Initiator::build_ike_sa_init`] emits the first request (SA, KE, Ni).
//! 2. The caller sends it, receives the reply, and computes the DH shared
//!    secret from the responder's KE payload using its own private key.
//! 3. [`Initiator::process_ike_sa_init_reply`] derives SKEYSEED and the seven
//!    IKE keys from the responder's chosen proposal.
//! 4. IKE_AUTH messages are built with [`Initiator::encrypt`] (PSK or EAP
//!    flows), and the responder's AUTH is checked with
//!    [`Initiator::verify_responder_psk_auth`] before any user credential is
//!    released.
//!
//! The type performs no I/O; DH and transport are the caller's.

use crate::constants::TransformType;
use crate::constants::{
    AuthMethod, ExchangeType, PayloadType, ProtocolId, FLAG_INITIATOR, FLAG_RESPONSE,
};
use crate::crypto::{self, IkeKeys, KeyLengths, Prf};
use crate::message::{write_payload_chain, Message, RawPayload};
use crate::payloads::DeletePayload;
use crate::payloads::{AuthPayload, IdPayload, KePayload, Proposal, SaPayload, TsPayload};
use crate::sk::{self, Encr, Integ, Suite};
use sha1::{Digest, Sha1};
use zeroize::Zeroizing;

/// The cryptographic parameters selected by the responder, derived from the
/// single proposal it echoes in the IKE_SA_INIT reply.
#[derive(Clone, Copy, Debug)]
pub struct Negotiated {
    pub prf: Prf,
    pub suite: Suite,
    pub key_lengths: KeyLengths,
}

fn map_encr(id: u16, key_bits: Option<u16>) -> Option<Encr> {
    use crate::constants::encr;
    match (id, key_bits) {
        (encr::AES_CBC, Some(128)) => Some(Encr::Aes128Cbc),
        (encr::AES_CBC, Some(256)) => Some(Encr::Aes256Cbc),
        (encr::AES_GCM_16, Some(128)) => Some(Encr::Aes128Gcm16),
        (encr::AES_GCM_16, Some(256)) => Some(Encr::Aes256Gcm16),
        _ => None,
    }
}

fn map_integ(id: u16) -> Option<Integ> {
    use crate::constants::integ;
    match id {
        integ::HMAC_SHA1_96 => Some(Integ::HmacSha1_96),
        integ::HMAC_SHA2_256_128 => Some(Integ::HmacSha256_128),
        integ::HMAC_SHA2_384_192 => Some(Integ::HmacSha384_192),
        integ::HMAC_SHA2_512_256 => Some(Integ::HmacSha512_256),
        _ => None,
    }
}

/// Map a chosen IKE proposal to the crypto parameters needed to key the SA.
pub fn negotiate_from_proposal(p: &Proposal) -> Option<Negotiated> {
    let mut encr = None;
    let mut prf = None;
    let mut integ = None;
    for t in &p.transforms {
        match TransformType::from_u8(t.transform_type) {
            Some(TransformType::Encr) => encr = map_encr(t.transform_id, t.key_length),
            Some(TransformType::Prf) => prf = Prf::from_transform_id(t.transform_id),
            Some(TransformType::Integ) => integ = map_integ(t.transform_id),
            _ => {}
        }
    }
    let encr = encr?;
    let prf = prf?;
    let suite = if encr.is_aead() {
        Suite { encr, integ: None }
    } else {
        Suite {
            encr,
            integ: Some(integ?),
        }
    };
    let key_lengths = KeyLengths {
        prf_key: prf.output_len(),
        integ_key: suite.integ.map(|i| i.key_len()).unwrap_or(0),
        encr_key: encr.keymat_len(),
    };
    Some(Negotiated {
        prf,
        suite,
        key_lengths,
    })
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    NotReady,
    MissingPayload(PayloadType),
    Parse,
    NoProposalChosen,
    /// The responder authenticated with a method other than a shared key.
    UnsupportedAuthMethod(u8),
    /// The responder's AUTH payload does not verify (wrong PSK or MITM).
    AuthMismatch,
}

/// A decrypted message received on the IKE SA.
#[derive(Debug)]
pub struct Inbound {
    pub exchange: u8,
    pub flags: u8,
    pub message_id: u32,
    pub payloads: Vec<RawPayload>,
}

impl Inbound {
    /// True if this is a response (to one of our requests).
    pub fn is_response(&self) -> bool {
        self.flags & FLAG_RESPONSE != 0
    }
}

/// Static configuration for an initiator exchange.
pub struct InitiatorConfig {
    /// Proposals offered in the IKE_SA_INIT SA payload.
    pub proposals: SaPayload,
    /// DH group offered in the KE payload (must appear in a proposal).
    pub dh_group: u16,
    /// PRF used for the key schedule (must match the chosen PRF transform).
    pub prf: Prf,
    /// Derived-key byte lengths for the chosen transforms.
    pub key_lengths: KeyLengths,
    /// Local identity (IDi).
    pub idi: IdPayload,
    /// Pre-shared key for AUTH.
    pub psk: Zeroizing<Vec<u8>>,
}

/// Initiator half of an IKE SA.
pub struct Initiator {
    cfg: InitiatorConfig,
    spi_i: [u8; 8],
    nonce_i: Vec<u8>,
    sa_init_request: Option<Vec<u8>>,
    sa_init_reply: Option<Vec<u8>>,
    spi_r: Option<[u8; 8]>,
    nonce_r: Option<Vec<u8>>,
    keys: Option<IkeKeys>,
    negotiated: Option<Negotiated>,
}

impl Initiator {
    /// Create an initiator. `spi_i` and `nonce_i` must be fresh random values
    /// (the caller provides them so this crate needs no RNG dependency).
    pub fn new(cfg: InitiatorConfig, spi_i: [u8; 8], nonce_i: Vec<u8>) -> Self {
        Initiator {
            cfg,
            spi_i,
            nonce_i,
            sa_init_request: None,
            sa_init_reply: None,
            spi_r: None,
            nonce_r: None,
            keys: None,
            negotiated: None,
        }
    }

    /// Build the IKE_SA_INIT request (message id 0). `dh_pubkey` is the local
    /// DH/ECDH public value for the configured group. The serialised request is
    /// retained for the later AUTH computation.
    pub fn build_ike_sa_init(&mut self, dh_pubkey: &[u8], extra: &[RawPayload]) -> Vec<u8> {
        let ke = KePayload {
            dh_group: self.cfg.dh_group,
            key_exchange_data: dh_pubkey.to_vec(),
        };
        let mut payloads = vec![
            RawPayload {
                payload_type: PayloadType::Sa as u8,
                critical: false,
                data: self.cfg.proposals.encode(),
            },
            RawPayload {
                payload_type: PayloadType::Ke as u8,
                critical: false,
                data: ke.encode(),
            },
            RawPayload {
                payload_type: PayloadType::Nonce as u8,
                critical: false,
                data: self.nonce_i.clone(),
            },
        ];
        payloads.extend_from_slice(extra);
        let msg = Message {
            initiator_spi: self.spi_i,
            responder_spi: [0; 8],
            exchange_type: ExchangeType::IkeSaInit as u8,
            flags: FLAG_INITIATOR,
            message_id: 0,
            payloads,
        };
        let bytes = msg.to_bytes();
        self.sa_init_request = Some(bytes.clone());
        bytes
    }

    /// Process the IKE_SA_INIT reply and derive the IKE SA keys. `dh_shared` is
    /// `g^ir`, computed by the caller from the responder's KE payload and the
    /// local private key.
    pub fn process_ike_sa_init_reply(
        &mut self,
        reply: &[u8],
        dh_shared: &[u8],
    ) -> Result<&IkeKeys, Error> {
        let msg = Message::parse(reply).map_err(|_| Error::Parse)?;
        if msg.exchange() != Some(ExchangeType::IkeSaInit) {
            return Err(Error::Parse);
        }
        let nonce = msg
            .find(PayloadType::Nonce)
            .ok_or(Error::MissingPayload(PayloadType::Nonce))?;
        // A responder must select exactly one proposal; its absence is fatal.
        let sa = msg.find(PayloadType::Sa).ok_or(Error::NoProposalChosen)?;
        msg.find(PayloadType::Ke)
            .ok_or(Error::MissingPayload(PayloadType::Ke))?;

        // Determine the chosen crypto parameters from the responder's proposal.
        let negotiated = SaPayload::decode(&sa.data)
            .ok()
            .and_then(|p| p.proposals.into_iter().next())
            .and_then(|p| negotiate_from_proposal(&p))
            .ok_or(Error::NoProposalChosen)?;

        self.spi_r = Some(msg.responder_spi);
        self.nonce_r = Some(nonce.data.clone());
        self.sa_init_reply = Some(reply[..msg_len(reply)].to_vec());

        let skeyseed = crypto::skeyseed(negotiated.prf, &self.nonce_i, &nonce.data, dh_shared);
        let keys = crypto::derive_ike_keys(
            negotiated.prf,
            &skeyseed,
            &self.nonce_i,
            &nonce.data,
            self.spi_i,
            msg.responder_spi,
            negotiated.key_lengths,
        );
        self.keys = Some(keys);
        self.negotiated = Some(negotiated);
        Ok(self.keys.as_ref().unwrap())
    }

    /// The derived IKE keys, available after a successful SA_INIT reply.
    pub fn keys(&self) -> Option<&IkeKeys> {
        self.keys.as_ref()
    }

    pub fn responder_spi(&self) -> Option<[u8; 8]> {
        self.spi_r
    }

    pub fn initiator_spi(&self) -> [u8; 8] {
        self.spi_i
    }

    pub fn nonce_i(&self) -> &[u8] {
        &self.nonce_i
    }

    /// Build the complete, encrypted IKE_AUTH request (message id 1). `extra`
    /// carries any additional inner payloads (e.g. a Config payload or Notify)
    /// appended after TSi/TSr. Requires keys from a prior SA_INIT reply.
    pub fn build_ike_auth_message(
        &self,
        child_sa: &SaPayload,
        tsi: &TsPayload,
        tsr: &TsPayload,
        extra: &[RawPayload],
    ) -> Result<Vec<u8>, Error> {
        let keys = self.keys.as_ref().ok_or(Error::NotReady)?;
        let suite = self.negotiated.ok_or(Error::NotReady)?.suite;
        let spi_r = self.spi_r.ok_or(Error::NotReady)?;
        let mut payloads = self.build_ike_auth_payloads(child_sa, tsi, tsr)?;
        payloads.extend_from_slice(extra);
        let first = payloads[0].payload_type;
        let mut inner = Vec::new();
        write_payload_chain(&payloads, &mut inner);
        Ok(sk::encrypt_message(
            self.spi_i,
            spi_r,
            ExchangeType::IkeAuth as u8,
            FLAG_INITIATOR,
            1,
            first,
            &inner,
            &suite,
            &keys.sk_ei,
            &keys.sk_ai,
        ))
    }

    /// Verify + decrypt an IKE_AUTH reply, returning its inner payloads.
    pub fn process_ike_auth_reply(&self, bytes: &[u8]) -> Result<Vec<RawPayload>, Error> {
        let keys = self.keys.as_ref().ok_or(Error::NotReady)?;
        let suite = self.negotiated.ok_or(Error::NotReady)?.suite;
        let (first, inner) = sk::decrypt_message(bytes, &suite, &keys.sk_er, &keys.sk_ar)
            .map_err(|_| Error::Parse)?;
        crate::message::parse_payload_chain(first, &inner).map_err(|_| Error::Parse)
    }

    /// The crypto parameters chosen by the responder (after an SA_INIT reply).
    pub fn negotiated(&self) -> Option<Negotiated> {
        self.negotiated
    }

    /// PRF chosen by the responder, falling back to the configured one.
    fn prf(&self) -> Prf {
        self.negotiated.map(|n| n.prf).unwrap_or(self.cfg.prf)
    }

    /// Compute an AUTH value using an arbitrary shared key: the PSK for
    /// pre-shared-key auth, or the EAP MSK for the final AUTH after EAP
    /// (RFC 7296 §2.15/§2.16 — same formula, different key).
    pub fn compute_auth_with_key(&self, key: &[u8]) -> Result<Vec<u8>, Error> {
        let keys = self.keys.as_ref().ok_or(Error::NotReady)?;
        let req = self.sa_init_request.as_ref().ok_or(Error::NotReady)?;
        let nr = self.nonce_r.as_ref().ok_or(Error::NotReady)?;
        let prf = self.prf();
        let idi_prime = self.cfg.idi.signed_octets();
        let signed = crypto::initiator_signed_octets(prf, req, nr, &keys.sk_pi, &idi_prime);
        Ok(crypto::psk_auth(prf, key, &signed))
    }

    /// Compute the pre-shared-key AUTH value for IKE_AUTH (RFC 7296 §2.15).
    pub fn compute_psk_auth(&self) -> Result<Vec<u8>, Error> {
        self.compute_auth_with_key(&self.cfg.psk)
    }

    /// Verify the responder's IDr + AUTH (shared-key MIC) found in decrypted
    /// IKE_AUTH reply payloads, using the configured PSK. Comparison is
    /// constant-time. This MUST succeed before user credentials are sent.
    pub fn verify_responder_psk_auth(&self, inner: &[RawPayload]) -> Result<(), Error> {
        self.verify_responder_auth_with_key(inner, &self.cfg.psk)
    }

    /// Verify the responder's AUTH computed with an arbitrary shared key (the
    /// PSK, or the EAP MSK on the final EAP round).
    pub fn verify_responder_auth_with_key(
        &self,
        inner: &[RawPayload],
        key: &[u8],
    ) -> Result<(), Error> {
        let keys = self.keys.as_ref().ok_or(Error::NotReady)?;
        let reply = self.sa_init_reply.as_ref().ok_or(Error::NotReady)?;
        let idr = inner
            .iter()
            .find(|p| p.payload_type == PayloadType::Idr as u8)
            .ok_or(Error::MissingPayload(PayloadType::Idr))?;
        let auth = inner
            .iter()
            .find(|p| p.payload_type == PayloadType::Auth as u8)
            .ok_or(Error::MissingPayload(PayloadType::Auth))?;
        let idr = IdPayload::decode(&idr.data).map_err(|_| Error::Parse)?;
        let auth = AuthPayload::decode(&auth.data).map_err(|_| Error::Parse)?;
        if auth.auth_method != AuthMethod::SharedKeyMic as u8 {
            return Err(Error::UnsupportedAuthMethod(auth.auth_method));
        }
        let prf = self.prf();
        let signed = crypto::responder_signed_octets(
            prf,
            reply,
            &self.nonce_i,
            &keys.sk_pr,
            &idr.signed_octets(),
        );
        let expected = crypto::psk_auth(prf, key, &signed);
        if crate::ct_eq(&expected, &auth.auth_data) {
            Ok(())
        } else {
            Err(Error::AuthMismatch)
        }
    }

    /// The IDi payload (as a raw payload) this initiator presents.
    pub fn idi_raw(&self) -> RawPayload {
        RawPayload {
            payload_type: PayloadType::Idi as u8,
            critical: false,
            data: self.cfg.idi.encode(),
        }
    }

    /// Encrypt an arbitrary inner payload chain as an IKE_AUTH-exchange message
    /// with the given message id (used to drive the multi-round EAP exchange).
    pub fn encrypt(&self, message_id: u32, payloads: &[RawPayload]) -> Result<Vec<u8>, Error> {
        let keys = self.keys.as_ref().ok_or(Error::NotReady)?;
        let suite = self.negotiated.ok_or(Error::NotReady)?.suite;
        let spi_r = self.spi_r.ok_or(Error::NotReady)?;
        let first = payloads
            .first()
            .map(|p| p.payload_type)
            .ok_or(Error::NotReady)?;
        let mut inner = Vec::new();
        write_payload_chain(payloads, &mut inner);
        Ok(sk::encrypt_message(
            self.spi_i,
            spi_r,
            ExchangeType::IkeAuth as u8,
            FLAG_INITIATOR,
            message_id,
            first,
            &inner,
            &suite,
            &keys.sk_ei,
            &keys.sk_ai,
        ))
    }

    /// Derive `len` bytes of Child SA keying material: `prf+(SK_d, Ni | Nr)`
    /// (RFC 7296 §2.17, no PFS). Caller splits it per the negotiated ESP cipher.
    pub fn child_keymat(&self, len: usize) -> Result<Zeroizing<Vec<u8>>, Error> {
        let keys = self.keys.as_ref().ok_or(Error::NotReady)?;
        let nr = self.nonce_r.as_ref().ok_or(Error::NotReady)?;
        let prf = self.prf();
        Ok(crate::esp::child_keymat(
            prf,
            &keys.sk_d,
            &self.nonce_i,
            nr,
            len,
        ))
    }

    /// Decrypt an encrypted IKE message and return its inner payloads.
    pub fn decrypt(&self, bytes: &[u8]) -> Result<Vec<RawPayload>, Error> {
        let keys = self.keys.as_ref().ok_or(Error::NotReady)?;
        let suite = self.negotiated.ok_or(Error::NotReady)?.suite;
        let (first, inner) = sk::decrypt_message(bytes, &suite, &keys.sk_er, &keys.sk_ar)
            .map_err(|_| Error::Parse)?;
        crate::message::parse_payload_chain(first, &inner).map_err(|_| Error::Parse)
    }

    /// Decrypt a gateway-sent message, also returning its exchange type, flags
    /// and message id (needed to answer gateway-initiated exchanges like DPD).
    pub fn decrypt_full(&self, bytes: &[u8]) -> Result<(u8, u8, u32, Vec<RawPayload>), Error> {
        if bytes.len() < crate::message::HEADER_LEN {
            return Err(Error::Parse);
        }
        let exchange = bytes[18];
        let flags = bytes[19];
        let message_id = u32::from_be_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]);
        let payloads = self.decrypt(bytes)?;
        Ok((exchange, flags, message_id, payloads))
    }

    /// Decrypt any message received on the IKE SA (requests and responses),
    /// returning its header fields and inner payloads.
    pub fn decrypt_inbound(&self, bytes: &[u8]) -> Result<Inbound, Error> {
        let (exchange, flags, message_id, payloads) = self.decrypt_full(bytes)?;
        Ok(Inbound {
            exchange,
            flags,
            message_id,
            payloads,
        })
    }

    /// Build an INFORMATIONAL request (e.g. an empty liveness check when
    /// `payloads` is empty).
    pub fn build_informational_request(
        &self,
        message_id: u32,
        payloads: &[RawPayload],
    ) -> Result<Vec<u8>, Error> {
        self.encrypt_informational(FLAG_INITIATOR, message_id, payloads)
    }

    /// Build the response to a gateway-initiated INFORMATIONAL request.
    pub fn build_informational_response(
        &self,
        message_id: u32,
        payloads: &[RawPayload],
    ) -> Result<Vec<u8>, Error> {
        self.encrypt_informational(FLAG_INITIATOR | FLAG_RESPONSE, message_id, payloads)
    }

    fn encrypt_informational(
        &self,
        flags: u8,
        message_id: u32,
        payloads: &[RawPayload],
    ) -> Result<Vec<u8>, Error> {
        let keys = self.keys.as_ref().ok_or(Error::NotReady)?;
        let suite = self.negotiated.ok_or(Error::NotReady)?.suite;
        let spi_r = self.spi_r.ok_or(Error::NotReady)?;
        let first = payloads.first().map(|p| p.payload_type).unwrap_or(0);
        let mut inner = Vec::new();
        write_payload_chain(payloads, &mut inner);
        Ok(sk::encrypt_message(
            self.spi_i,
            spi_r,
            ExchangeType::Informational as u8,
            flags,
            message_id,
            first,
            &inner,
            &suite,
            &keys.sk_ei,
            &keys.sk_ai,
        ))
    }

    /// If `bytes` is a gateway-initiated INFORMATIONAL request (dead-peer
    /// detection), return the matching empty INFORMATIONAL response to send back.
    pub fn dpd_response(&self, bytes: &[u8]) -> Option<Vec<u8>> {
        let (exchange, flags, message_id, _payloads) = self.decrypt_full(bytes).ok()?;
        if exchange != ExchangeType::Informational as u8 || flags & FLAG_RESPONSE != 0 {
            return None;
        }
        self.encrypt_informational(FLAG_INITIATOR | FLAG_RESPONSE, message_id, &[])
            .ok()
    }

    /// Build an INFORMATIONAL request that deletes the IKE SA (clean teardown).
    pub fn build_delete(&self, message_id: u32) -> Result<Vec<u8>, Error> {
        let del = DeletePayload {
            protocol_id: ProtocolId::Ike as u8,
            spis: vec![],
        };
        let p = RawPayload {
            payload_type: PayloadType::Delete as u8,
            critical: false,
            data: del.encode(),
        };
        self.encrypt_informational(FLAG_INITIATOR, message_id, &[p])
    }

    /// Build the inner payload chain for IKE_AUTH: IDi, AUTH (PSK), SA (child),
    /// TSi, TSr. The caller encrypts this chain into an SK payload using
    /// SK_ei/SK_ai and wraps it in an IKE_AUTH message (message id 1).
    pub fn build_ike_auth_payloads(
        &self,
        child_sa: &SaPayload,
        tsi: &TsPayload,
        tsr: &TsPayload,
    ) -> Result<Vec<RawPayload>, Error> {
        let auth_value = self.compute_psk_auth()?;
        let auth = AuthPayload {
            auth_method: AuthMethod::SharedKeyMic as u8,
            auth_data: auth_value,
        };
        Ok(vec![
            RawPayload {
                payload_type: PayloadType::Idi as u8,
                critical: false,
                data: self.cfg.idi.encode(),
            },
            RawPayload {
                payload_type: PayloadType::Auth as u8,
                critical: false,
                data: auth.encode(),
            },
            RawPayload {
                payload_type: PayloadType::Sa as u8,
                critical: false,
                data: child_sa.encode(),
            },
            RawPayload {
                payload_type: PayloadType::Tsi as u8,
                critical: false,
                data: tsi.encode(),
            },
            RawPayload {
                payload_type: PayloadType::Tsr as u8,
                critical: false,
                data: tsr.encode(),
            },
        ])
    }
}

/// Length of the IKE message in `buf` per its header (clamped to the buffer).
fn msg_len(buf: &[u8]) -> usize {
    if buf.len() < crate::message::HEADER_LEN {
        return buf.len();
    }
    let l = u32::from_be_bytes([buf[24], buf[25], buf[26], buf[27]]) as usize;
    l.min(buf.len())
}

/// NAT-detection hash (RFC 7296 §2.23): `SHA1(SPIi | SPIr | IP | Port)`, with
/// the port in network byte order. Used to build the NAT_DETECTION_SOURCE_IP /
/// NAT_DETECTION_DESTINATION_IP notify payloads in IKE_SA_INIT.
pub fn nat_detection_hash(spi_i: [u8; 8], spi_r: [u8; 8], ip: &[u8], port: u16) -> Vec<u8> {
    let mut h = Sha1::new();
    h.update(spi_i);
    h.update(spi_r);
    h.update(ip);
    h.update(port.to_be_bytes());
    h.finalize().to_vec()
}

/// Convenience: a standard IKE child-SA proposal for ESP with a 4-byte SPI.
pub fn esp_proposal(spi: [u8; 4], transforms: Vec<crate::payloads::Transform>) -> SaPayload {
    SaPayload {
        proposals: vec![crate::payloads::Proposal {
            proposal_num: 1,
            protocol_id: ProtocolId::Esp as u8,
            spi: spi.to_vec(),
            transforms,
        }],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{dh, encr, integ, prf, IdType, TransformType};
    use crate::payloads::{Proposal, TrafficSelector, Transform};

    fn ike_proposals() -> SaPayload {
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
                        transform_id: dh::CURVE25519,
                        key_length: None,
                    },
                ],
            }],
        }
    }

    fn cfg() -> InitiatorConfig {
        InitiatorConfig {
            proposals: ike_proposals(),
            dh_group: dh::CURVE25519,
            prf: Prf::HmacSha256,
            key_lengths: KeyLengths {
                prf_key: 32,
                integ_key: 32,
                encr_key: 32,
            },
            idi: IdPayload {
                id_type: IdType::Rfc822Addr as u8,
                id_data: b"vpnuser@corp".to_vec(),
            },
            psk: Zeroizing::new(b"super-secret-psk".to_vec()),
        }
    }

    #[test]
    fn full_initiator_flow() {
        let mut init = Initiator::new(cfg(), [0x11; 8], vec![0xAA; 32]);

        // 1) IKE_SA_INIT request
        let req = init.build_ike_sa_init(&[0x42u8; 32], &[]);
        let parsed = Message::parse(&req).unwrap();
        assert_eq!(parsed.exchange(), Some(ExchangeType::IkeSaInit));
        assert_eq!(parsed.flags, FLAG_INITIATOR);
        assert!(parsed.find(PayloadType::Sa).is_some());
        assert!(parsed.find(PayloadType::Ke).is_some());

        // 2) craft a plausible responder reply (SA, KE, Nr)
        let reply = Message {
            initiator_spi: [0x11; 8],
            responder_spi: [0x22; 8],
            exchange_type: ExchangeType::IkeSaInit as u8,
            flags: crate::constants::FLAG_RESPONSE,
            message_id: 0,
            payloads: vec![
                RawPayload {
                    payload_type: PayloadType::Sa as u8,
                    critical: false,
                    data: ike_proposals().encode(),
                },
                RawPayload {
                    payload_type: PayloadType::Ke as u8,
                    critical: false,
                    data: KePayload {
                        dh_group: dh::CURVE25519,
                        key_exchange_data: vec![0x43; 32],
                    }
                    .encode(),
                },
                RawPayload {
                    payload_type: PayloadType::Nonce as u8,
                    critical: false,
                    data: vec![0xBB; 32],
                },
            ],
        }
        .to_bytes();

        // 3) derive keys (DH shared secret supplied by caller)
        let keys = init
            .process_ike_sa_init_reply(&reply, &[0x99u8; 32])
            .unwrap()
            .clone();
        assert_eq!(keys.sk_ei.len(), 32);
        assert_eq!(init.responder_spi(), Some([0x22; 8]));

        // 4) IKE_AUTH payloads with PSK AUTH
        let child = esp_proposal(
            [1, 2, 3, 4],
            vec![
                Transform {
                    transform_type: TransformType::Encr as u8,
                    transform_id: encr::AES_CBC,
                    key_length: Some(256),
                },
                Transform {
                    transform_type: TransformType::Integ as u8,
                    transform_id: integ::HMAC_SHA2_256_128,
                    key_length: None,
                },
            ],
        );
        let any_ts = TsPayload {
            selectors: vec![TrafficSelector {
                ts_type: crate::constants::TsType::Ipv4AddrRange as u8,
                ip_protocol_id: 0,
                start_port: 0,
                end_port: 65535,
                start_addr: vec![0, 0, 0, 0],
                end_addr: vec![255, 255, 255, 255],
            }],
        };
        let inner = init
            .build_ike_auth_payloads(&child, &any_ts, &any_ts)
            .unwrap();
        assert_eq!(inner[0].payload_type, PayloadType::Idi as u8);
        assert_eq!(inner[1].payload_type, PayloadType::Auth as u8);
        let auth = AuthPayload::decode(&inner[1].data).unwrap();
        assert_eq!(auth.auth_method, AuthMethod::SharedKeyMic as u8);
        assert_eq!(auth.auth_data.len(), 32); // HMAC-SHA256 output

        // AUTH must be reproducible and depend on the SA_INIT request bytes.
        let again = init.compute_psk_auth().unwrap();
        assert_eq!(again, auth.auth_data);
    }

    #[test]
    fn auth_before_keys_is_not_ready() {
        let init = Initiator::new(cfg(), [0; 8], vec![0; 32]);
        assert_eq!(init.compute_psk_auth(), Err(Error::NotReady));
    }
}
