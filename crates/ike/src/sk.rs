//! Encrypted payload (SK) handling for IKE_AUTH and later exchanges
//! (RFC 7296 §3.14, RFC 5282 for AEAD).
//!
//! An encrypted IKE message is the IKE header followed by an SK payload. For a
//! CBC + HMAC suite the SK body is `IV | ciphertext | ICV`, where the ciphertext
//! is `AES-CBC(SK_e, IV, inner | pad | pad_length)` and the ICV is
//! `trunc(HMAC(SK_a, everything-before-ICV))` (encrypt-then-MAC). For an AEAD
//! suite (AES-GCM) the SK body is `explicit_IV(8) | ciphertext | tag(16)`, the
//! GCM nonce is `salt(4) | explicit_IV(8)` (the 4-byte salt is the tail of SK_e),
//! the associated data is the IKE header plus the SK generic header, and there
//! is no separate integrity transform.

use crate::constants::{PayloadType, IKE_VERSION};
use crate::crypto::Prf;
use crate::message::HEADER_LEN;
use crate::rng;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit as AesKeyInit};
use aes::{Aes128, Aes256};
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce};

const BLOCK: usize = 16;
const GCM_SALT: usize = 4;
const GCM_IV: usize = 8;
const GCM_TAG: usize = 16;

/// Encryption transforms supported by the SK layer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Encr {
    Aes128Cbc,
    Aes256Cbc,
    /// AES-GCM with a 16-octet ICV (ENCR_AES_GCM_16).
    Aes128Gcm16,
    Aes256Gcm16,
}

impl Encr {
    pub fn is_aead(self) -> bool {
        matches!(self, Encr::Aes128Gcm16 | Encr::Aes256Gcm16)
    }
    /// Raw AES key size (without the AEAD salt).
    pub fn cipher_key_len(self) -> usize {
        match self {
            Encr::Aes128Cbc | Encr::Aes128Gcm16 => 16,
            Encr::Aes256Cbc | Encr::Aes256Gcm16 => 32,
        }
    }
    fn salt_len(self) -> usize {
        if self.is_aead() {
            GCM_SALT
        } else {
            0
        }
    }
    /// Length of SK_ei/SK_er to derive: cipher key plus any AEAD salt.
    pub fn keymat_len(self) -> usize {
        self.cipher_key_len() + self.salt_len()
    }
    /// Explicit IV carried in the packet (16 for CBC, 8 for GCM).
    pub fn iv_len(self) -> usize {
        if self.is_aead() {
            GCM_IV
        } else {
            BLOCK
        }
    }
}

/// Integrity (MAC) transforms, used only with non-AEAD ciphers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Integ {
    HmacSha1_96,
    HmacSha256_128,
    HmacSha384_192,
    HmacSha512_256,
}

impl Integ {
    fn prf(self) -> Prf {
        match self {
            Integ::HmacSha1_96 => Prf::HmacSha1,
            Integ::HmacSha256_128 => Prf::HmacSha256,
            Integ::HmacSha384_192 => Prf::HmacSha384,
            Integ::HmacSha512_256 => Prf::HmacSha512,
        }
    }
    pub fn icv_len(self) -> usize {
        match self {
            Integ::HmacSha1_96 => 12,
            Integ::HmacSha256_128 => 16,
            Integ::HmacSha384_192 => 24,
            Integ::HmacSha512_256 => 32,
        }
    }
    pub fn key_len(self) -> usize {
        match self {
            Integ::HmacSha1_96 => 20,
            Integ::HmacSha256_128 => 32,
            Integ::HmacSha384_192 => 48,
            Integ::HmacSha512_256 => 64,
        }
    }
}

/// The negotiated cipher plus integrity. For AEAD ciphers `integ` is `None`.
#[derive(Clone, Copy, Debug)]
pub struct Suite {
    pub encr: Encr,
    pub integ: Option<Integ>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum SkError {
    Truncated,
    NotEncrypted,
    IcvMismatch,
    BadPadding,
    BadKeyLength,
    AeadFailure,
}

// --- AES-CBC (no padding; the SK layer manages its own padding) ---

enum CbcCipher {
    A128(Box<Aes128>),
    A256(Box<Aes256>),
}

impl CbcCipher {
    fn new(key: &[u8]) -> Result<CbcCipher, SkError> {
        Ok(match key.len() {
            16 => CbcCipher::A128(Box::new(
                Aes128::new_from_slice(key).map_err(|_| SkError::BadKeyLength)?,
            )),
            32 => CbcCipher::A256(Box::new(
                Aes256::new_from_slice(key).map_err(|_| SkError::BadKeyLength)?,
            )),
            _ => return Err(SkError::BadKeyLength),
        })
    }
    fn enc(&self, b: &mut [u8; BLOCK]) {
        let g = GenericArray::from_mut_slice(b);
        match self {
            CbcCipher::A128(c) => c.encrypt_block(g),
            CbcCipher::A256(c) => c.encrypt_block(g),
        }
    }
    fn dec(&self, b: &mut [u8; BLOCK]) {
        let g = GenericArray::from_mut_slice(b);
        match self {
            CbcCipher::A128(c) => c.decrypt_block(g),
            CbcCipher::A256(c) => c.decrypt_block(g),
        }
    }
}

fn cbc_encrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, SkError> {
    let cipher = CbcCipher::new(key)?;
    let mut prev = [0u8; BLOCK];
    prev.copy_from_slice(iv);
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks(BLOCK) {
        let mut b = [0u8; BLOCK];
        b.copy_from_slice(chunk);
        for i in 0..BLOCK {
            b[i] ^= prev[i];
        }
        cipher.enc(&mut b);
        prev = b;
        out.extend_from_slice(&b);
    }
    Ok(out)
}

fn cbc_decrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, SkError> {
    let cipher = CbcCipher::new(key)?;
    if !data.len().is_multiple_of(BLOCK) || data.is_empty() {
        return Err(SkError::BadPadding);
    }
    let mut prev = [0u8; BLOCK];
    prev.copy_from_slice(iv);
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks(BLOCK) {
        let mut b = [0u8; BLOCK];
        b.copy_from_slice(chunk);
        let saved = b;
        cipher.dec(&mut b);
        for i in 0..BLOCK {
            b[i] ^= prev[i];
        }
        prev = saved;
        out.extend_from_slice(&b);
    }
    Ok(out)
}

// --- AES-GCM (AEAD) ---

fn gcm_seal(key: &[u8], nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, SkError> {
    let nonce = Nonce::from_slice(nonce);
    let pl = Payload {
        msg: plaintext,
        aad,
    };
    match key.len() {
        16 => Aes128Gcm::new_from_slice(key)
            .map_err(|_| SkError::BadKeyLength)?
            .encrypt(nonce, pl)
            .map_err(|_| SkError::AeadFailure),
        32 => Aes256Gcm::new_from_slice(key)
            .map_err(|_| SkError::BadKeyLength)?
            .encrypt(nonce, pl)
            .map_err(|_| SkError::AeadFailure),
        _ => Err(SkError::BadKeyLength),
    }
}

fn gcm_open(key: &[u8], nonce: &[u8], aad: &[u8], ct_tag: &[u8]) -> Result<Vec<u8>, SkError> {
    let nonce = Nonce::from_slice(nonce);
    let pl = Payload { msg: ct_tag, aad };
    match key.len() {
        16 => Aes128Gcm::new_from_slice(key)
            .map_err(|_| SkError::BadKeyLength)?
            .decrypt(nonce, pl)
            .map_err(|_| SkError::AeadFailure),
        32 => Aes256Gcm::new_from_slice(key)
            .map_err(|_| SkError::BadKeyLength)?
            .decrypt(nonce, pl)
            .map_err(|_| SkError::AeadFailure),
        _ => Err(SkError::BadKeyLength),
    }
}

fn mac(integ: Integ, key: &[u8], data: &[u8]) -> Vec<u8> {
    integ.prf().mac(key, data)[..integ.icv_len()].to_vec()
}

/// Serialise the IKE header + SK generic header for a message of total length
/// `total` whose SK payload is `sk_payload_len` bytes, carrying `first_inner`.
#[allow(clippy::too_many_arguments)]
fn header_and_sk(
    initiator_spi: [u8; 8],
    responder_spi: [u8; 8],
    exchange_type: u8,
    flags: u8,
    message_id: u32,
    first_inner: u8,
    sk_payload_len: usize,
    total: usize,
) -> Vec<u8> {
    let mut h = Vec::with_capacity(HEADER_LEN + 4);
    h.extend_from_slice(&initiator_spi);
    h.extend_from_slice(&responder_spi);
    h.push(PayloadType::Sk as u8);
    h.push(IKE_VERSION);
    h.push(exchange_type);
    h.push(flags);
    h.extend_from_slice(&message_id.to_be_bytes());
    h.extend_from_slice(&(total as u32).to_be_bytes());
    h.push(first_inner);
    h.push(0);
    h.extend_from_slice(&(sk_payload_len as u16).to_be_bytes());
    h
}

/// Build a complete encrypted IKE message.
#[allow(clippy::too_many_arguments)]
pub fn encrypt_message(
    initiator_spi: [u8; 8],
    responder_spi: [u8; 8],
    exchange_type: u8,
    flags: u8,
    message_id: u32,
    first_inner: u8,
    inner_chain: &[u8],
    suite: &Suite,
    sk_e: &[u8],
    sk_a: &[u8],
) -> Vec<u8> {
    if suite.encr.is_aead() {
        // AES-GCM: pad_length only (no block alignment needed).
        let mut plain = Vec::with_capacity(inner_chain.len() + 1);
        plain.extend_from_slice(inner_chain);
        plain.push(0u8);

        let mut iv = [0u8; GCM_IV];
        rng::fill(&mut iv);
        let ck = suite.encr.cipher_key_len();
        let key = &sk_e[..ck];
        let mut nonce = [0u8; GCM_SALT + GCM_IV];
        nonce[..GCM_SALT].copy_from_slice(&sk_e[ck..ck + GCM_SALT]);
        nonce[GCM_SALT..].copy_from_slice(&iv);

        let sk_payload_len = 4 + GCM_IV + plain.len() + GCM_TAG;
        let total = HEADER_LEN + sk_payload_len;
        let aad = header_and_sk(
            initiator_spi,
            responder_spi,
            exchange_type,
            flags,
            message_id,
            first_inner,
            sk_payload_len,
            total,
        );
        let ct_tag = gcm_seal(key, &nonce, &aad, &plain).expect("valid GCM key");
        let mut msg = aad;
        msg.extend_from_slice(&iv);
        msg.extend_from_slice(&ct_tag);
        return msg;
    }

    // CBC + HMAC (encrypt-then-MAC)
    let integ = suite.integ.expect("CBC suite needs an integrity transform");
    let pad = (BLOCK - ((inner_chain.len() + 1) % BLOCK)) % BLOCK;
    let mut plain = Vec::with_capacity(inner_chain.len() + pad + 1);
    plain.extend_from_slice(inner_chain);
    plain.extend(std::iter::repeat_n(0u8, pad));
    plain.push(pad as u8);

    let mut iv = vec![0u8; suite.encr.iv_len()];
    rng::fill(&mut iv);
    let ct = cbc_encrypt(sk_e, &iv, &plain).expect("valid SK_e length");

    let icv_len = integ.icv_len();
    let sk_payload_len = 4 + iv.len() + ct.len() + icv_len;
    let total = HEADER_LEN + sk_payload_len;
    let mut msg = header_and_sk(
        initiator_spi,
        responder_spi,
        exchange_type,
        flags,
        message_id,
        first_inner,
        sk_payload_len,
        total,
    );
    msg.extend_from_slice(&iv);
    msg.extend_from_slice(&ct);
    let mac_region_end = msg.len();
    msg.extend(std::iter::repeat_n(0u8, icv_len));
    let icv = mac(integ, sk_a, &msg[..mac_region_end]);
    msg[mac_region_end..].copy_from_slice(&icv);
    msg
}

/// Verify + decrypt an encrypted IKE message, returning the first inner payload
/// type and the decrypted inner payload chain bytes.
pub fn decrypt_message(
    bytes: &[u8],
    suite: &Suite,
    sk_e: &[u8],
    sk_a: &[u8],
) -> Result<(u8, Vec<u8>), SkError> {
    if bytes.len() < HEADER_LEN + 4 {
        return Err(SkError::Truncated);
    }
    if bytes[16] != PayloadType::Sk as u8 {
        return Err(SkError::NotEncrypted);
    }
    let total = u32::from_be_bytes([bytes[24], bytes[25], bytes[26], bytes[27]]) as usize;
    if total > bytes.len() || total < HEADER_LEN + 4 {
        return Err(SkError::Truncated);
    }
    let first_inner = bytes[HEADER_LEN];
    let sk_payload_len =
        u16::from_be_bytes([bytes[HEADER_LEN + 2], bytes[HEADER_LEN + 3]]) as usize;
    if HEADER_LEN + sk_payload_len > total || sk_payload_len < 4 {
        return Err(SkError::Truncated);
    }
    let body_start = HEADER_LEN + 4;
    let sk_end = HEADER_LEN + sk_payload_len;
    let iv_len = suite.encr.iv_len();

    let mut plain = if suite.encr.is_aead() {
        if sk_payload_len < 4 + iv_len + GCM_TAG {
            return Err(SkError::Truncated);
        }
        let iv = &bytes[body_start..body_start + iv_len];
        let ct_tag = &bytes[body_start + iv_len..sk_end];
        let ck = suite.encr.cipher_key_len();
        if sk_e.len() < ck + GCM_SALT {
            return Err(SkError::BadKeyLength);
        }
        let key = &sk_e[..ck];
        let mut nonce = [0u8; GCM_SALT + GCM_IV];
        nonce[..GCM_SALT].copy_from_slice(&sk_e[ck..ck + GCM_SALT]);
        nonce[GCM_SALT..].copy_from_slice(iv);
        let aad = &bytes[..body_start];
        gcm_open(key, &nonce, aad, ct_tag)?
    } else {
        let integ = suite.integ.ok_or(SkError::BadKeyLength)?;
        let icv_len = integ.icv_len();
        if sk_payload_len < 4 + iv_len + icv_len {
            return Err(SkError::Truncated);
        }
        let icv_start = sk_end - icv_len;
        let expected = mac(integ, sk_a, &bytes[..icv_start]);
        if !crate::ct_eq(&expected, &bytes[icv_start..icv_start + icv_len]) {
            return Err(SkError::IcvMismatch);
        }
        let iv = &bytes[body_start..body_start + iv_len];
        let ct = &bytes[body_start + iv_len..icv_start];
        cbc_decrypt(sk_e, iv, ct)?
    };

    let pad_len = *plain.last().ok_or(SkError::BadPadding)? as usize;
    if pad_len + 1 > plain.len() {
        return Err(SkError::BadPadding);
    }
    plain.truncate(plain.len() - pad_len - 1);
    Ok((first_inner, plain))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{ExchangeType, FLAG_INITIATOR};
    use crate::message::{parse_payload_chain, write_payload_chain, Message, RawPayload};

    fn payloads() -> Vec<RawPayload> {
        vec![
            RawPayload {
                payload_type: PayloadType::Idi as u8,
                critical: false,
                data: b"user@corp".to_vec(),
            },
            RawPayload {
                payload_type: PayloadType::Auth as u8,
                critical: false,
                data: vec![0x44; 32],
            },
        ]
    }

    fn roundtrip(suite: Suite, sk_e: &[u8], sk_a: &[u8]) {
        let ps = payloads();
        let mut inner = Vec::new();
        write_payload_chain(&ps, &mut inner);
        let first = ps[0].payload_type;
        let msg = encrypt_message(
            [1; 8],
            [2; 8],
            ExchangeType::IkeAuth as u8,
            FLAG_INITIATOR,
            1,
            first,
            &inner,
            &suite,
            sk_e,
            sk_a,
        );
        let outer = Message::parse(&msg).unwrap();
        assert_eq!(outer.payloads.len(), 1);
        assert_eq!(outer.payloads[0].payload_type, PayloadType::Sk as u8);
        let (got_first, dec) = decrypt_message(&msg, &suite, sk_e, sk_a).unwrap();
        assert_eq!(got_first, first);
        assert_eq!(parse_payload_chain(got_first, &dec).unwrap(), ps);
    }

    #[test]
    fn cbc_roundtrip() {
        roundtrip(
            Suite {
                encr: Encr::Aes256Cbc,
                integ: Some(Integ::HmacSha256_128),
            },
            &[0x11; 32],
            &[0x22; 32],
        );
    }

    #[test]
    fn gcm_roundtrip() {
        // SK_e for GCM-256 = 32-byte key || 4-byte salt.
        roundtrip(
            Suite {
                encr: Encr::Aes256Gcm16,
                integ: None,
            },
            &[0x11; 36],
            &[],
        );
        roundtrip(
            Suite {
                encr: Encr::Aes128Gcm16,
                integ: None,
            },
            &[0x11; 20],
            &[],
        );
    }

    #[test]
    fn cbc_tamper_fails() {
        let suite = Suite {
            encr: Encr::Aes256Cbc,
            integ: Some(Integ::HmacSha256_128),
        };
        let mut msg = encrypt_message(
            [1; 8],
            [2; 8],
            ExchangeType::IkeAuth as u8,
            FLAG_INITIATOR,
            1,
            PayloadType::Idi as u8,
            b"xxxxxxxxxxxxxxxx",
            &suite,
            &[0x11; 32],
            &[0x22; 32],
        );
        let n = msg.len();
        msg[n - 20] ^= 1;
        assert_eq!(
            decrypt_message(&msg, &suite, &[0x11; 32], &[0x22; 32]),
            Err(SkError::IcvMismatch)
        );
    }

    #[test]
    fn gcm_tamper_fails() {
        let suite = Suite {
            encr: Encr::Aes256Gcm16,
            integ: None,
        };
        let mut msg = encrypt_message(
            [1; 8],
            [2; 8],
            ExchangeType::IkeAuth as u8,
            FLAG_INITIATOR,
            1,
            PayloadType::Idi as u8,
            b"xxxxxxxxxxxxxxxx",
            &suite,
            &[0x11; 36],
            &[],
        );
        let n = msg.len();
        msg[n - 10] ^= 1;
        assert_eq!(
            decrypt_message(&msg, &suite, &[0x11; 36], &[]),
            Err(SkError::AeadFailure)
        );
    }
}
