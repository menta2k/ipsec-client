//! Diffie-Hellman key agreement for the IKE_SA_INIT KE payload.
//!
//! Supports the groups gateways commonly offer: Curve25519
//! (group 31), MODP-1536 (group 5), and MODP-2048 (group 14). The MODP primes
//! are the RFC 3526 values (verified against the RFC text), generator 2. The
//! negotiated group's public value goes in the KE payload, and the shared
//! secret feeds [`crate::crypto::skeyseed`].

use crate::rng;
use num_bigint::BigUint;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

/// RFC 3526 MODP-1536 (group 5) prime, generator 2.
const MODP1536_PRIME_HEX: &str = "\
FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74\
020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437\
4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED\
EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05\
98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB\
9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF";

/// RFC 3526 MODP-2048 (group 14) prime, generator 2.
const MODP2048_PRIME_HEX: &str = "\
FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74\
020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437\
4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED\
EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05\
98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB\
9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B\
E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718\
3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";

/// Supported DH groups.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DhGroup {
    Curve25519,
    Modp1536,
    Modp2048,
}

impl DhGroup {
    /// IKEv2 transform id for this group.
    pub fn transform_id(self) -> u16 {
        use crate::constants::dh;
        match self {
            DhGroup::Curve25519 => dh::CURVE25519,
            DhGroup::Modp1536 => dh::MODP_1536,
            DhGroup::Modp2048 => dh::MODP_2048,
        }
    }

    pub fn from_transform_id(id: u16) -> Option<DhGroup> {
        use crate::constants::dh;
        match id {
            x if x == dh::CURVE25519 => Some(DhGroup::Curve25519),
            x if x == dh::MODP_1536 => Some(DhGroup::Modp1536),
            x if x == dh::MODP_2048 => Some(DhGroup::Modp2048),
            _ => None,
        }
    }

    /// Length in bytes of the public value / KE data.
    pub fn public_len(self) -> usize {
        match self {
            DhGroup::Curve25519 => 32,
            DhGroup::Modp1536 => 192,
            DhGroup::Modp2048 => 256,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum DhError {
    UnsupportedGroup,
    BadPeerLength,
    InvalidPeerValue,
}

/// Private DH value. `StaticSecret` zeroizes itself on drop; the MODP exponent
/// is kept as zeroizing bytes and only expanded into a `BigUint` transiently.
enum Secret {
    X25519(StaticSecret),
    Modp(Zeroizing<[u8; 32]>),
}

/// A DH keypair with the private value retained for the shared-secret step.
pub struct DhKeypair {
    group: DhGroup,
    secret: Secret,
    public: Vec<u8>,
}

/// Returns (prime, byte length) for a MODP group.
fn modp_params(group: DhGroup) -> Option<(BigUint, usize)> {
    let (hex, len) = match group {
        DhGroup::Modp1536 => (MODP1536_PRIME_HEX, 192),
        DhGroup::Modp2048 => (MODP2048_PRIME_HEX, 256),
        DhGroup::Curve25519 => return None,
    };
    Some((
        BigUint::parse_bytes(hex.as_bytes(), 16).expect("valid MODP prime"),
        len,
    ))
}

fn left_pad(mut bytes: Vec<u8>, len: usize) -> Vec<u8> {
    if bytes.len() >= len {
        return bytes;
    }
    let mut out = vec![0u8; len - bytes.len()];
    out.append(&mut bytes);
    out
}

impl DhKeypair {
    /// Generate a fresh ephemeral keypair for `group`.
    pub fn generate(group: DhGroup) -> DhKeypair {
        match group {
            DhGroup::Curve25519 => {
                let mut sk = [0u8; 32];
                rng::fill(&mut sk);
                let secret = StaticSecret::from(sk);
                let public = PublicKey::from(&secret).to_bytes().to_vec();
                DhKeypair {
                    group,
                    secret: Secret::X25519(secret),
                    public,
                }
            }
            DhGroup::Modp1536 | DhGroup::Modp2048 => {
                let (p, len) = modp_params(group).unwrap();
                let g = BigUint::from(2u32);
                // 256-bit private exponent (>= 112-bit security for these groups).
                let mut x = Zeroizing::new([0u8; 32]);
                rng::fill(&mut x[..]);
                let xb = BigUint::from_bytes_be(&x[..]);
                let public = left_pad(g.modpow(&xb, &p).to_bytes_be(), len);
                DhKeypair {
                    group,
                    secret: Secret::Modp(x),
                    public,
                }
            }
        }
    }

    pub fn group(&self) -> DhGroup {
        self.group
    }

    /// The public value for the KE payload.
    pub fn public(&self) -> &[u8] {
        &self.public
    }

    /// Compute the shared secret `g^ir` from the peer's KE data.
    pub fn compute_shared(&self, peer_public: &[u8]) -> Result<Zeroizing<Vec<u8>>, DhError> {
        if peer_public.len() != self.group.public_len() {
            return Err(DhError::BadPeerLength);
        }
        match &self.secret {
            Secret::X25519(secret) => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(peer_public);
                let shared = secret.diffie_hellman(&PublicKey::from(arr));
                if !shared.was_contributory() {
                    return Err(DhError::InvalidPeerValue);
                }
                Ok(Zeroizing::new(shared.as_bytes().to_vec()))
            }
            Secret::Modp(x) => {
                let (p, len) = modp_params(self.group).ok_or(DhError::UnsupportedGroup)?;
                let peer = BigUint::from_bytes_be(peer_public);
                let one = BigUint::from(1u32);
                // Reject degenerate peer values (<= 1 or >= p-1).
                if peer <= one || peer >= &p - &one {
                    return Err(DhError::InvalidPeerValue);
                }
                let x = BigUint::from_bytes_be(&x[..]);
                Ok(Zeroizing::new(left_pad(
                    peer.modpow(&x, &p).to_bytes_be(),
                    len,
                )))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modp_primes_have_expected_shape() {
        // RFC 3526 MODP primes begin and end with 0xFFFFFFFFFFFFFFFF.
        for g in [DhGroup::Modp1536, DhGroup::Modp2048] {
            let (p, len) = modp_params(g).unwrap();
            let be = p.to_bytes_be();
            assert_eq!(be.len(), len);
            assert_eq!(&be[..8], &[0xff; 8]);
            assert_eq!(&be[len - 8..], &[0xff; 8]);
            // bit length is exactly 1536 or 2048
            assert_eq!(p.bits() as usize, len * 8);
        }
    }

    #[test]
    fn x25519_agreement() {
        let a = DhKeypair::generate(DhGroup::Curve25519);
        let b = DhKeypair::generate(DhGroup::Curve25519);
        assert_eq!(a.public().len(), 32);
        assert_eq!(
            *a.compute_shared(b.public()).unwrap(),
            *b.compute_shared(a.public()).unwrap()
        );
    }

    #[test]
    fn modp1536_agreement() {
        let a = DhKeypair::generate(DhGroup::Modp1536);
        let b = DhKeypair::generate(DhGroup::Modp1536);
        assert_eq!(a.public().len(), 192);
        let s = a.compute_shared(b.public()).unwrap();
        assert_eq!(*s, *b.compute_shared(a.public()).unwrap());
        assert_eq!(s.len(), 192);
    }

    #[test]
    fn modp2048_agreement() {
        let a = DhKeypair::generate(DhGroup::Modp2048);
        let b = DhKeypair::generate(DhGroup::Modp2048);
        assert_eq!(a.public().len(), 256);
        let s = a.compute_shared(b.public()).unwrap();
        assert_eq!(*s, *b.compute_shared(a.public()).unwrap());
        assert_eq!(s.len(), 256);
    }

    #[test]
    fn rejects_bad_peer() {
        let a = DhKeypair::generate(DhGroup::Curve25519);
        assert_eq!(
            a.compute_shared(&[0u8; 10]).err(),
            Some(DhError::BadPeerLength)
        );
        // An all-zero X25519 point is a low-order point (non-contributory).
        assert_eq!(
            a.compute_shared(&[0u8; 32]).err(),
            Some(DhError::InvalidPeerValue)
        );
        // A peer value of exactly 1 (255 zero bytes then 0x01) is degenerate.
        let m = DhKeypair::generate(DhGroup::Modp2048);
        let mut one = vec![0u8; 256];
        one[255] = 1;
        assert_eq!(
            m.compute_shared(&one).err(),
            Some(DhError::InvalidPeerValue)
        );
    }
}
