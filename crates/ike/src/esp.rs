//! ESP (RFC 4303) data-plane transforms for the negotiated Child SA, plus
//! Child SA key derivation (RFC 7296 §2.17) and anti-replay (RFC 4303 §3.4.3).
//!
//! Supports the two suites the client offers for the Child SA:
//! AES-256-CBC + HMAC-SHA-256-128, and AES-256-GCM-16 (AEAD). Behind NAT the
//! resulting ESP packet is carried directly as the UDP payload to port 4500
//! (RFC 3948 UDP-ESP; the non-zero SPI distinguishes it from the IKE non-ESP
//! marker).
//!
//! Direction (we are the initiator): outbound packets use the initiator keys and
//! the responder's SPI; inbound packets use the responder keys and our SPI
//! (RFC 7296 §2.17 key order: encr_i, integ_i, encr_r, integ_r).
//!
//! A [`ChildSa`] can be [`split`](ChildSa::split) into an [`EspOutbound`] and an
//! [`EspInbound`] half so the two relay directions never contend on a lock.

use crate::crypto::Prf;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit as AesKeyInit};
use aes::Aes256;
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

/// ESP cipher suites supported for the Child SA.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EspCipher {
    /// AES-256-CBC with HMAC-SHA-256-128 integrity.
    Aes256CbcSha256,
    /// AES-256-GCM with a 16-octet ICV.
    Aes256Gcm16,
}

impl EspCipher {
    /// Per-direction key material length taken from the keymat (key + any salt +
    /// integrity key).
    fn dir_len(self) -> usize {
        match self {
            EspCipher::Aes256CbcSha256 => 32 + 32, // enc + integ
            EspCipher::Aes256Gcm16 => 32 + 4,      // enc + salt
        }
    }
    /// Total keymat required (both directions).
    pub fn keymat_len(self) -> usize {
        self.dir_len() * 2
    }
    /// Human-readable suite name.
    pub fn name(self) -> &'static str {
        match self {
            EspCipher::Aes256CbcSha256 => "AES-256-CBC / HMAC-SHA2-256-128",
            EspCipher::Aes256Gcm16 => "AES-256-GCM-16",
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum EspError {
    Short,
    BadSpi,
    IcvMismatch,
    BadPadding,
    Replay,
    /// The 32-bit outbound sequence number space is exhausted; the SA must be
    /// replaced (RFC 4303 §3.3.3).
    SeqExhausted,
}

/// Per-direction cipher state, built once from the keymat.
enum DirCipher {
    Cbc {
        aes: Box<Aes256>,
        integ: Zeroizing<Vec<u8>>,
    },
    Gcm {
        aead: Box<Aes256Gcm>,
        salt: [u8; 4],
    },
}

impl DirCipher {
    fn new(cipher: EspCipher, k: &[u8]) -> DirCipher {
        match cipher {
            EspCipher::Aes256CbcSha256 => DirCipher::Cbc {
                aes: Box::new(Aes256::new_from_slice(&k[..32]).expect("aes-256 key")),
                integ: Zeroizing::new(k[32..64].to_vec()),
            },
            EspCipher::Aes256Gcm16 => {
                let mut salt = [0u8; 4];
                salt.copy_from_slice(&k[32..36]);
                DirCipher::Gcm {
                    aead: Box::new(Aes256Gcm::new_from_slice(&k[..32]).expect("aes-256-gcm key")),
                    salt,
                }
            }
        }
    }
}

/// Outbound (encrypting) half of a Child SA.
pub struct EspOutbound {
    spi: [u8; 4],
    dir: DirCipher,
    seq: u32,
}

/// Inbound (decrypting, replay-checking) half of a Child SA.
pub struct EspInbound {
    spi: [u8; 4],
    dir: DirCipher,
    highest: u32,
    window: u64,
}

/// A bidirectional ESP Child SA.
pub struct ChildSa {
    cipher: EspCipher,
    out: EspOutbound,
    inb: EspInbound,
}

const REPLAY_BITS: u32 = 64;

impl ChildSa {
    /// Build a Child SA from `prf+(SK_d, Ni | Nr)` keymat. `out_spi` is the SPI
    /// the responder assigned (used on packets we send); `in_spi` is the SPI we
    /// chose (expected on packets we receive).
    pub fn from_keymat(
        cipher: EspCipher,
        keymat: &[u8],
        out_spi: [u8; 4],
        in_spi: [u8; 4],
    ) -> ChildSa {
        let d = cipher.dir_len();
        let (ki, kr) = keymat.split_at(d);
        ChildSa {
            cipher,
            out: EspOutbound {
                spi: out_spi,
                dir: DirCipher::new(cipher, ki),
                seq: 0,
            },
            inb: EspInbound {
                spi: in_spi,
                dir: DirCipher::new(cipher, &kr[..d]),
                highest: 0,
                window: 0,
            },
        }
    }

    pub fn cipher(&self) -> EspCipher {
        self.cipher
    }
    pub fn out_spi(&self) -> [u8; 4] {
        self.out.spi
    }
    pub fn in_spi(&self) -> [u8; 4] {
        self.inb.spi
    }

    /// Encrypt an inner packet (see [`EspOutbound::encrypt`]).
    pub fn encrypt(&mut self, next_header: u8, inner: &[u8]) -> Result<Vec<u8>, EspError> {
        self.out.encrypt(next_header, inner)
    }

    /// Decrypt an inbound packet (see [`EspInbound::decrypt`]).
    pub fn decrypt(&mut self, pkt: &[u8]) -> Result<(u8, Vec<u8>), EspError> {
        self.inb.decrypt(pkt)
    }

    /// Split into independently owned outbound and inbound halves.
    pub fn split(self) -> (EspOutbound, EspInbound) {
        (self.out, self.inb)
    }
}

impl EspOutbound {
    pub fn spi(&self) -> [u8; 4] {
        self.spi
    }

    /// Encrypt an inner IP packet into an ESP packet (the UDP-4500 payload).
    /// `next_header` is the IP protocol of the inner packet (4 = IPv4-in-IP for
    /// tunnel mode).
    pub fn encrypt(&mut self, next_header: u8, inner: &[u8]) -> Result<Vec<u8>, EspError> {
        if self.seq == u32::MAX {
            return Err(EspError::SeqExhausted);
        }
        self.seq += 1;
        let seq = self.seq;
        match &self.dir {
            DirCipher::Cbc { aes, integ } => {
                // plaintext = inner | pad | pad_len | next_header, 16-aligned.
                let block = 16;
                let min = inner.len() + 2;
                let pad = (block - (min % block)) % block;
                let mut esp = Vec::with_capacity(8 + 16 + min + pad + 16);
                esp.extend_from_slice(&self.spi);
                esp.extend_from_slice(&seq.to_be_bytes());
                let mut iv = [0u8; 16];
                crate::rng::fill(&mut iv);
                esp.extend_from_slice(&iv);
                let ct_start = esp.len();
                esp.extend_from_slice(inner);
                for i in 1..=pad {
                    esp.push(i as u8);
                }
                esp.push(pad as u8);
                esp.push(next_header);
                cbc_encrypt_in_place(aes, &iv, &mut esp[ct_start..]);
                let icv = hmac_sha256_128(integ, &esp);
                esp.extend_from_slice(&icv);
                Ok(esp)
            }
            DirCipher::Gcm { aead, salt } => {
                let align = 4;
                let min = inner.len() + 2;
                let pad = (align - (min % align)) % align;
                let mut pt = Vec::with_capacity(min + pad);
                pt.extend_from_slice(inner);
                for i in 1..=pad {
                    pt.push(i as u8);
                }
                pt.push(pad as u8);
                pt.push(next_header);

                // RFC 4106 §3.1: the explicit IV must be unique under the key, not
                // random. Use the per-SA sequence number zero-extended to 64 bits
                // (as strongSwan iv_gen_seq / Linux seqiv do): it strictly
                // increases and encryption stops at SeqExhausted, so the GCM
                // nonce (salt | IV) never repeats for this SA's key.
                let iv = u64::from(seq).to_be_bytes();
                let mut nonce = [0u8; 12];
                nonce[..4].copy_from_slice(salt);
                nonce[4..].copy_from_slice(&iv);

                let mut aad = [0u8; 8];
                aad[..4].copy_from_slice(&self.spi);
                aad[4..].copy_from_slice(&seq.to_be_bytes());
                let ct_tag = aead
                    .encrypt(
                        Nonce::from_slice(&nonce),
                        Payload {
                            msg: &pt,
                            aad: &aad,
                        },
                    )
                    .expect("gcm encrypt");

                let mut esp = Vec::with_capacity(16 + ct_tag.len());
                esp.extend_from_slice(&aad);
                esp.extend_from_slice(&iv);
                esp.extend_from_slice(&ct_tag);
                Ok(esp)
            }
        }
    }
}

impl EspInbound {
    pub fn spi(&self) -> [u8; 4] {
        self.spi
    }

    /// Decrypt+verify an inbound ESP packet, returning (next_header, inner IP).
    /// The anti-replay window is only advanced after the ICV verifies.
    pub fn decrypt(&mut self, pkt: &[u8]) -> Result<(u8, Vec<u8>), EspError> {
        if pkt.len() < 8 {
            return Err(EspError::Short);
        }
        if pkt[..4] != self.spi {
            return Err(EspError::BadSpi);
        }
        let seq = u32::from_be_bytes([pkt[4], pkt[5], pkt[6], pkt[7]]);
        self.replay_check(seq)?;

        let pt = match &self.dir {
            DirCipher::Cbc { aes, integ } => {
                if pkt.len() < 8 + 16 + 16 {
                    return Err(EspError::Short);
                }
                let icv_at = pkt.len() - 16;
                let expect = hmac_sha256_128(integ, &pkt[..icv_at]);
                if !crate::ct_eq(&expect, &pkt[icv_at..]) {
                    return Err(EspError::IcvMismatch);
                }
                let iv = &pkt[8..24];
                let ct = &pkt[24..icv_at];
                if ct.is_empty() || !ct.len().is_multiple_of(16) {
                    return Err(EspError::BadPadding);
                }
                cbc_decrypt(aes, iv, ct)
            }
            DirCipher::Gcm { aead, salt } => {
                if pkt.len() < 8 + 8 + 16 {
                    return Err(EspError::Short);
                }
                let iv = &pkt[8..16];
                let ct_tag = &pkt[16..];
                let mut nonce = [0u8; 12];
                nonce[..4].copy_from_slice(salt);
                nonce[4..].copy_from_slice(iv);
                aead.decrypt(
                    Nonce::from_slice(&nonce),
                    Payload {
                        msg: ct_tag,
                        aad: &pkt[..8],
                    },
                )
                .map_err(|_| EspError::IcvMismatch)?
            }
        };

        if pt.len() < 2 {
            return Err(EspError::BadPadding);
        }
        let pad_len = pt[pt.len() - 2] as usize;
        let next_header = pt[pt.len() - 1];
        if pad_len + 2 > pt.len() {
            return Err(EspError::BadPadding);
        }
        let mut inner = pt;
        inner.truncate(inner.len() - 2 - pad_len);
        self.replay_update(seq);
        Ok((next_header, inner))
    }

    fn replay_check(&self, seq: u32) -> Result<(), EspError> {
        if seq == 0 {
            return Err(EspError::Replay);
        }
        if seq > self.highest {
            return Ok(());
        }
        let diff = self.highest - seq;
        if diff >= REPLAY_BITS {
            return Err(EspError::Replay);
        }
        if self.window & (1u64 << diff) != 0 {
            return Err(EspError::Replay);
        }
        Ok(())
    }

    fn replay_update(&mut self, seq: u32) {
        if seq > self.highest {
            let shift = seq - self.highest;
            if shift >= REPLAY_BITS {
                self.window = 1;
            } else {
                self.window = (self.window << shift) | 1;
            }
            self.highest = seq;
        } else {
            let diff = self.highest - seq;
            if diff < REPLAY_BITS {
                self.window |= 1u64 << diff;
            }
        }
    }
}

/// Derive the Child SA keymat: `prf+(SK_d, Ni | Nr)` (no PFS) of `len` bytes.
pub fn child_keymat(prf: Prf, sk_d: &[u8], ni: &[u8], nr: &[u8], len: usize) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(crate::crypto::derive_child_keys(
        prf, sk_d, ni, nr, None, len,
    ))
}

// --- primitives ---

fn cbc_encrypt_in_place(cipher: &Aes256, iv: &[u8; 16], data: &mut [u8]) {
    let mut prev = *iv;
    for chunk in data.chunks_mut(16) {
        for i in 0..16 {
            chunk[i] ^= prev[i];
        }
        cipher.encrypt_block(GenericArray::from_mut_slice(chunk));
        prev.copy_from_slice(chunk);
    }
}

fn cbc_decrypt(cipher: &Aes256, iv: &[u8], data: &[u8]) -> Vec<u8> {
    let mut prev = [0u8; 16];
    prev.copy_from_slice(iv);
    let mut out = data.to_vec();
    for chunk in out.chunks_mut(16) {
        let mut saved = [0u8; 16];
        saved.copy_from_slice(chunk);
        cipher.decrypt_block(GenericArray::from_mut_slice(chunk));
        for i in 0..16 {
            chunk[i] ^= prev[i];
        }
        prev = saved;
    }
    out
}

fn hmac_sha256_128(key: &[u8], data: &[u8]) -> [u8; 16] {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("hmac key");
    m.update(data);
    let full = m.finalize().into_bytes();
    let mut icv = [0u8; 16];
    icv.copy_from_slice(&full[..16]);
    icv
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an initiator SA and the matching peer SA (keys/SPIs mirrored) so a
    /// packet encrypted by one decrypts on the other.
    fn pair(cipher: EspCipher) -> (ChildSa, ChildSa) {
        let km: Vec<u8> = (0..cipher.keymat_len() as u8).collect();
        let a_out = [0xAA, 0xAA, 0xAA, 0xAA];
        let a_in = [0xBB, 0xBB, 0xBB, 0xBB];
        let a = ChildSa::from_keymat(cipher, &km, a_out, a_in);
        let d = cipher.dir_len();
        let mut swapped = Vec::with_capacity(km.len());
        swapped.extend_from_slice(&km[d..]);
        swapped.extend_from_slice(&km[..d]);
        let b = ChildSa::from_keymat(cipher, &swapped, a_in, a_out);
        (a, b)
    }

    fn roundtrip(cipher: EspCipher) {
        let (mut a, mut b) = pair(cipher);
        for len in [0usize, 1, 13, 14, 15, 16, 17, 100, 1400] {
            let inner: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let pkt = a.encrypt(4, &inner).unwrap();
            assert_eq!(&pkt[..4], &[0xAA, 0xAA, 0xAA, 0xAA]);
            let (nh, got) = b.decrypt(&pkt).unwrap();
            assert_eq!(nh, 4);
            assert_eq!(got, inner);
        }
    }

    #[test]
    fn cbc_roundtrip() {
        roundtrip(EspCipher::Aes256CbcSha256);
    }

    #[test]
    fn gcm_roundtrip() {
        roundtrip(EspCipher::Aes256Gcm16);
    }

    #[test]
    fn split_halves_interoperate() {
        let (a, b) = pair(EspCipher::Aes256Gcm16);
        let (mut a_out, _a_in) = a.split();
        let (_b_out, mut b_in) = b.split();
        let pkt = a_out.encrypt(4, b"hello world").unwrap();
        assert_eq!(b_in.decrypt(&pkt).unwrap().1, b"hello world");
    }

    #[test]
    fn gcm_explicit_iv_is_sequence_number() {
        let (mut a, mut b) = pair(EspCipher::Aes256Gcm16);
        for expected in 1u32..=5 {
            let pkt = a.encrypt(4, b"payload").unwrap();
            let seq = u32::from_be_bytes([pkt[4], pkt[5], pkt[6], pkt[7]]);
            assert_eq!(seq, expected);
            assert_eq!(&pkt[8..16], &u64::from(seq).to_be_bytes());
            assert_eq!(b.decrypt(&pkt).unwrap().1, b"payload");
        }
    }

    #[test]
    fn gcm_iv_never_repeats_and_stops_at_seq_exhaustion() {
        let (mut a, mut b) = pair(EspCipher::Aes256Gcm16);
        let mut seen = std::collections::HashSet::new();
        for _ in 0..1000 {
            let pkt = a.encrypt(4, b"x").unwrap();
            assert!(seen.insert(pkt[8..16].to_vec()), "GCM explicit IV reused");
        }
        // The last usable sequence number yields the last IV; the SA then
        // refuses to encrypt rather than wrapping and reusing a nonce.
        a.out.seq = u32::MAX - 1;
        let last = a.encrypt(4, b"x").unwrap();
        assert_eq!(&last[8..16], &u64::from(u32::MAX).to_be_bytes());
        assert!(seen.insert(last[8..16].to_vec()));
        assert!(b.decrypt(&last).is_ok());
        assert_eq!(a.encrypt(4, b"x"), Err(EspError::SeqExhausted));
    }

    #[test]
    fn tamper_rejected() {
        for c in [EspCipher::Aes256Gcm16, EspCipher::Aes256CbcSha256] {
            let (mut a, mut b) = pair(c);
            let mut pkt = a.encrypt(4, b"payload payload!").unwrap();
            let n = pkt.len();
            pkt[n - 5] ^= 1;
            assert_eq!(b.decrypt(&pkt), Err(EspError::IcvMismatch));
        }
    }

    #[test]
    fn tampered_packet_does_not_advance_replay_window() {
        let (mut a, mut b) = pair(EspCipher::Aes256Gcm16);
        let good = a.encrypt(4, b"first").unwrap();
        let mut bad = good.clone();
        let n = bad.len();
        bad[n - 1] ^= 0xff;
        assert!(b.decrypt(&bad).is_err());
        // The genuine packet with the same sequence number is still accepted.
        assert!(b.decrypt(&good).is_ok());
    }

    #[test]
    fn anti_replay() {
        let (mut a, mut b) = pair(EspCipher::Aes256CbcSha256);
        let p1 = a.encrypt(4, b"packet one aaaa").unwrap();
        let p2 = a.encrypt(4, b"packet two bbbb").unwrap();
        assert!(b.decrypt(&p2).is_ok()); // seq 2
        assert!(b.decrypt(&p1).is_ok()); // seq 1 (within window, first time)
        assert_eq!(b.decrypt(&p1), Err(EspError::Replay)); // seq 1 again
    }

    #[test]
    fn out_of_window_dropped() {
        let (mut a, mut b) = pair(EspCipher::Aes256Gcm16);
        let old = a.encrypt(4, b"old").unwrap();
        let mut last = Vec::new();
        for _ in 0..70 {
            last = a.encrypt(4, b"x").unwrap();
        }
        assert!(b.decrypt(&last).is_ok()); // seq 71
        assert_eq!(b.decrypt(&old), Err(EspError::Replay)); // seq 1, 70 behind
    }

    #[test]
    fn wrong_spi_and_short_rejected() {
        let (mut a, _b) = pair(EspCipher::Aes256CbcSha256);
        let km = vec![0u8; EspCipher::Aes256CbcSha256.keymat_len()];
        let mut other =
            ChildSa::from_keymat(EspCipher::Aes256CbcSha256, &km, [1, 2, 3, 4], [9, 9, 9, 9]);
        let pkt = a.encrypt(4, b"hello").unwrap();
        assert_eq!(other.decrypt(&pkt), Err(EspError::BadSpi));
        assert_eq!(other.decrypt(&[9, 9, 9]), Err(EspError::Short));
        assert_eq!(
            other.decrypt(&[9, 9, 9, 9, 0, 0, 0, 1, 0]),
            Err(EspError::Short)
        );
    }
}
