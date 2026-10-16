//! IKEv2 key derivation (RFC 7296 §2.13-§2.16): the PRF, `prf+`, SKEYSEED,
//! the seven IKE SA keys, CHILD SA keymat, and the pre-shared-key AUTH value.
//!
//! All derived key material is returned in zeroize-on-drop containers.

use hmac::{Hmac, Mac};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Pseudo-random functions negotiated as IKEv2 PRF transforms.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Prf {
    HmacSha1,
    HmacSha256,
    HmacSha384,
    HmacSha512,
}

impl Prf {
    /// Map an IKEv2 PRF transform id (RFC 7296 / IANA) to a PRF.
    pub fn from_transform_id(id: u16) -> Option<Prf> {
        use crate::constants::prf::*;
        Some(match id {
            HMAC_SHA1 => Prf::HmacSha1,
            HMAC_SHA2_256 => Prf::HmacSha256,
            HMAC_SHA2_384 => Prf::HmacSha384,
            HMAC_SHA2_512 => Prf::HmacSha512,
            _ => return None,
        })
    }

    /// Output length (bytes).
    pub fn output_len(self) -> usize {
        match self {
            Prf::HmacSha1 => 20,
            Prf::HmacSha256 => 32,
            Prf::HmacSha384 => 48,
            Prf::HmacSha512 => 64,
        }
    }

    /// Compute `prf(key, data)`.
    pub fn mac(self, key: &[u8], data: &[u8]) -> Vec<u8> {
        macro_rules! go {
            ($d:ty) => {{
                // `Mac::new_from_slice` accepts a key of any length (HMAC).
                let mut m = <Hmac<$d>>::new_from_slice(key).expect("HMAC key any length");
                m.update(data);
                m.finalize().into_bytes().to_vec()
            }};
        }
        match self {
            Prf::HmacSha1 => go!(sha1::Sha1),
            Prf::HmacSha256 => go!(sha2::Sha256),
            Prf::HmacSha384 => go!(sha2::Sha384),
            Prf::HmacSha512 => go!(sha2::Sha512),
        }
    }
}

/// `prf+(K, S)` = T1 | T2 | ... where T1 = prf(K, S|0x01),
/// Tn = prf(K, Tn-1 | S | n) (RFC 7296 §2.13). Produces `out_len` bytes.
pub fn prf_plus(prf: Prf, key: &[u8], seed: &[u8], out_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(out_len + prf.output_len());
    let mut t: Vec<u8> = Vec::new();
    let mut counter: u8 = 1;
    while out.len() < out_len {
        let mut input = Vec::with_capacity(t.len() + seed.len() + 1);
        input.extend_from_slice(&t);
        input.extend_from_slice(seed);
        input.push(counter);
        t = prf.mac(key, &input);
        out.extend_from_slice(&t);
        counter = counter.wrapping_add(1);
        if counter == 0 {
            break; // prf+ is defined for at most 255 iterations
        }
    }
    out.truncate(out_len);
    out
}

/// SKEYSEED = prf(Ni | Nr, g^ir) for an initial IKE SA (RFC 7296 §2.14).
pub fn skeyseed(prf: Prf, nonce_i: &[u8], nonce_r: &[u8], dh_shared: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut key = Vec::with_capacity(nonce_i.len() + nonce_r.len());
    key.extend_from_slice(nonce_i);
    key.extend_from_slice(nonce_r);
    Zeroizing::new(prf.mac(&key, dh_shared))
}

/// SKEYSEED for a rekeyed IKE SA: prf(SK_d(old), g^ir(new) | Ni | Nr).
pub fn skeyseed_rekey(prf: Prf, old_sk_d: &[u8], new_dh: &[u8], ni: &[u8], nr: &[u8]) -> Vec<u8> {
    let mut s = Vec::with_capacity(new_dh.len() + ni.len() + nr.len());
    s.extend_from_slice(new_dh);
    s.extend_from_slice(ni);
    s.extend_from_slice(nr);
    prf.mac(old_sk_d, &s)
}

/// Byte lengths of the derived keys for the chosen transforms.
#[derive(Clone, Copy, Debug)]
pub struct KeyLengths {
    /// SK_d / SK_pi / SK_pr length = the PRF key size.
    pub prf_key: usize,
    /// SK_ai / SK_ar length = the integrity key size.
    pub integ_key: usize,
    /// SK_ei / SK_er length = the encryption key size.
    pub encr_key: usize,
}

/// The seven keys produced from SKEYSEED (RFC 7296 §2.14). Zeroized on drop;
/// `Debug` prints only key lengths.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct IkeKeys {
    pub sk_d: Vec<u8>,
    pub sk_ai: Vec<u8>,
    pub sk_ar: Vec<u8>,
    pub sk_ei: Vec<u8>,
    pub sk_er: Vec<u8>,
    pub sk_pi: Vec<u8>,
    pub sk_pr: Vec<u8>,
}

impl std::fmt::Debug for IkeKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "IkeKeys {{ sk_d: {}B, sk_a: {}B, sk_e: {}B, sk_p: {}B }}",
            self.sk_d.len(),
            self.sk_ai.len(),
            self.sk_ei.len(),
            self.sk_pi.len()
        )
    }
}

/// Derive the IKE SA keys:
/// `{SK_d | SK_ai | SK_ar | SK_ei | SK_er | SK_pi | SK_pr}
///   = prf+(SKEYSEED, Ni | Nr | SPIi | SPIr)` (RFC 7296 §2.14).
pub fn derive_ike_keys(
    prf: Prf,
    skeyseed: &[u8],
    nonce_i: &[u8],
    nonce_r: &[u8],
    spi_i: [u8; 8],
    spi_r: [u8; 8],
    lens: KeyLengths,
) -> IkeKeys {
    let mut seed = Vec::new();
    seed.extend_from_slice(nonce_i);
    seed.extend_from_slice(nonce_r);
    seed.extend_from_slice(&spi_i);
    seed.extend_from_slice(&spi_r);

    let total = lens.prf_key + 2 * lens.integ_key + 2 * lens.encr_key + 2 * lens.prf_key;
    let km = Zeroizing::new(prf_plus(prf, skeyseed, &seed, total));

    let mut o = 0;
    let mut take = |n: usize| {
        let s = km[o..o + n].to_vec();
        o += n;
        s
    };
    IkeKeys {
        sk_d: take(lens.prf_key),
        sk_ai: take(lens.integ_key),
        sk_ar: take(lens.integ_key),
        sk_ei: take(lens.encr_key),
        sk_er: take(lens.encr_key),
        sk_pi: take(lens.prf_key),
        sk_pr: take(lens.prf_key),
    }
}

/// CHILD SA keying material: `prf+(SK_d, Ni | Nr)`, or with PFS
/// `prf+(SK_d, g^ir(new) | Ni | Nr)` (RFC 7296 §2.17). The caller slices the
/// result into the child's encryption/integrity keys (initiator keys first).
pub fn derive_child_keys(
    prf: Prf,
    sk_d: &[u8],
    nonce_i: &[u8],
    nonce_r: &[u8],
    pfs_dh: Option<&[u8]>,
    out_len: usize,
) -> Vec<u8> {
    let mut seed = Vec::new();
    if let Some(dh) = pfs_dh {
        seed.extend_from_slice(dh);
    }
    seed.extend_from_slice(nonce_i);
    seed.extend_from_slice(nonce_r);
    prf_plus(prf, sk_d, &seed, out_len)
}

/// The pre-shared-key AUTH value (RFC 7296 §2.15):
/// `prf(prf(Shared Secret, "Key Pad for IKEv2"), <SignedOctets>)`.
pub fn psk_auth(prf: Prf, psk: &[u8], signed_octets: &[u8]) -> Vec<u8> {
    let inner = Zeroizing::new(prf.mac(psk, b"Key Pad for IKEv2"));
    prf.mac(&inner, signed_octets)
}

/// InitiatorSignedOctets = RealMessageInit | Nr | prf(SK_pi, IDi')
/// (RFC 7296 §2.15). `idi_prime` is the IDi payload body (type + reserved +
/// data), i.e. `IdPayload::signed_octets()`.
pub fn initiator_signed_octets(
    prf: Prf,
    real_message_init: &[u8],
    nonce_r: &[u8],
    sk_pi: &[u8],
    idi_prime: &[u8],
) -> Vec<u8> {
    let maced_id = prf.mac(sk_pi, idi_prime);
    let mut out = Vec::with_capacity(real_message_init.len() + nonce_r.len() + maced_id.len());
    out.extend_from_slice(real_message_init);
    out.extend_from_slice(nonce_r);
    out.extend_from_slice(&maced_id);
    out
}

/// ResponderSignedOctets = RealMessageResp | Ni | prf(SK_pr, IDr').
pub fn responder_signed_octets(
    prf: Prf,
    real_message_resp: &[u8],
    nonce_i: &[u8],
    sk_pr: &[u8],
    idr_prime: &[u8],
) -> Vec<u8> {
    let maced_id = prf.mac(sk_pr, idr_prime);
    let mut out = Vec::with_capacity(real_message_resp.len() + nonce_i.len() + maced_id.len());
    out.extend_from_slice(real_message_resp);
    out.extend_from_slice(nonce_i);
    out.extend_from_slice(&maced_id);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_sha256_rfc4231_case1() {
        let key = [0x0bu8; 20];
        let out = Prf::HmacSha256.mac(&key, b"Hi There");
        assert_eq!(
            hex::encode(out),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn hmac_sha1_rfc2202_case1() {
        let key = [0x0bu8; 20];
        let out = Prf::HmacSha1.mac(&key, b"Hi There");
        assert_eq!(hex::encode(out), "b617318655057264e28bc0b6fb378c8ef146be00");
    }

    #[test]
    fn prf_plus_length_and_determinism() {
        let km1 = prf_plus(Prf::HmacSha256, b"key", b"seed", 100);
        let km2 = prf_plus(Prf::HmacSha256, b"key", b"seed", 100);
        assert_eq!(km1.len(), 100);
        assert_eq!(km1, km2);
        // first 32 bytes must equal T1 = prf(key, seed|0x01)
        let mut t1_input = b"seed".to_vec();
        t1_input.push(1);
        let t1 = Prf::HmacSha256.mac(b"key", &t1_input);
        assert_eq!(&km1[..32], &t1[..]);
    }

    #[test]
    fn ike_keys_partition_prf_plus() {
        let prf = Prf::HmacSha256;
        let seed = skeyseed(prf, b"Ni", b"Nr", b"shared-secret");
        let lens = KeyLengths {
            prf_key: 32,
            integ_key: 32,
            encr_key: 32,
        };
        let keys = derive_ike_keys(prf, &seed, b"Ni", b"Nr", [1; 8], [2; 8], lens);
        assert_eq!(keys.sk_d.len(), 32);
        assert_eq!(keys.sk_ei.len(), 32);
        assert_eq!(keys.sk_pr.len(), 32);
        // The concatenation must equal prf+ over the same seed.
        let mut km_seed = b"Ni".to_vec();
        km_seed.extend_from_slice(b"Nr");
        km_seed.extend_from_slice(&[1u8; 8]);
        km_seed.extend_from_slice(&[2u8; 8]);
        let km = prf_plus(prf, &seed, &km_seed, 32 * 7);
        assert_eq!(&keys.sk_d, &km[..32]);
        assert_eq!(&keys.sk_pr, &km[32 * 6..32 * 7]);
    }

    #[test]
    fn psk_auth_is_double_prf() {
        let a = psk_auth(Prf::HmacSha1, b"secret", b"signed-octets");
        let inner = Prf::HmacSha1.mac(b"secret", b"Key Pad for IKEv2");
        let expect = Prf::HmacSha1.mac(&inner, b"signed-octets");
        assert_eq!(a, expect);
    }
}
