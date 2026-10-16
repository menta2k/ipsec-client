//! EAP (RFC 3748) and EAP-MSCHAPv2 (RFC 2759 / RFC 3079), as used by IKEv2
//! remote-access gateways (e.g. FortiGate dialup): the gateway authenticates with PSK (verified separately)
//! and the user authenticates with username/password over EAP-MSCHAPv2. After
//! EAP succeeds, the MSCHAPv2 MSK keys the final IKEv2 AUTH (RFC 7296 §2.16).
//!
//! The MSCHAPv2 and MPPE-key constants and algorithms here are the RFC 2759 /
//! RFC 3079 values, checked by the known-answer tests at the bottom (RFC 2759
//! §9.2 NT-Response + AuthenticatorResponse; RFC 3079 MasterKey + MasterSendKey).

use crate::rng;
use des::cipher::{BlockEncrypt, KeyInit};
use des::Des;
use md4::Md4;
use sha1::{Digest, Sha1};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

// EAP codes (RFC 3748 §4).
pub const EAP_REQUEST: u8 = 1;
pub const EAP_RESPONSE: u8 = 2;
pub const EAP_SUCCESS: u8 = 3;
pub const EAP_FAILURE: u8 = 4;

// EAP method types.
pub const TYPE_IDENTITY: u8 = 1;
pub const TYPE_NAK: u8 = 3;
pub const TYPE_MSCHAPV2: u8 = 26;

// MSCHAPv2 op-codes (RFC 2759 §5).
pub const MS_CHALLENGE: u8 = 1;
pub const MS_RESPONSE: u8 = 2;
pub const MS_SUCCESS: u8 = 3;
pub const MS_FAILURE: u8 = 4;

/// A parsed EAP packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Eap {
    pub code: u8,
    pub identifier: u8,
    pub type_: Option<u8>,
    pub data: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum EapError {
    Truncated,
}

impl Eap {
    pub fn parse(buf: &[u8]) -> Result<Eap, EapError> {
        if buf.len() < 4 {
            return Err(EapError::Truncated);
        }
        let code = buf[0];
        let identifier = buf[1];
        let len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        if len < 4 || len > buf.len() {
            return Err(EapError::Truncated);
        }
        if (code == EAP_REQUEST || code == EAP_RESPONSE) && len >= 5 {
            Ok(Eap {
                code,
                identifier,
                type_: Some(buf[4]),
                data: buf[5..len].to_vec(),
            })
        } else {
            Ok(Eap {
                code,
                identifier,
                type_: None,
                data: Vec::new(),
            })
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(self.code);
        out.push(self.identifier);
        let total = 4 + self
            .type_
            .map(|_| 1 + self.data.len())
            .unwrap_or(self.data.len());
        out.extend_from_slice(&(total as u16).to_be_bytes());
        if let Some(t) = self.type_ {
            out.push(t);
        }
        out.extend_from_slice(&self.data);
        out
    }
}

// --- MSCHAPv2 primitives (RFC 2759 §8) ---

fn md4(data: &[u8]) -> [u8; 16] {
    let mut h = Md4::new();
    h.update(data);
    h.finalize().into()
}

fn utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
}

/// NtPasswordHash = MD4(UTF-16LE(password)).
pub fn nt_password_hash(password: &str) -> [u8; 16] {
    let pw = Zeroizing::new(utf16le(password));
    md4(&pw)
}

/// HashNtPasswordHash = MD4(NtPasswordHash).
pub fn hash_nt_password_hash(h: &[u8; 16]) -> [u8; 16] {
    md4(h)
}

fn sha1(parts: &[&[u8]]) -> [u8; 20] {
    let mut h = Sha1::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// ChallengeHash = SHA1(PeerChallenge | AuthenticatorChallenge | UserName)[..8].
fn challenge_hash(peer: &[u8; 16], auth: &[u8; 16], username: &[u8]) -> [u8; 8] {
    let d = sha1(&[peer, auth, username]);
    let mut c = [0u8; 8];
    c.copy_from_slice(&d[..8]);
    c
}

/// Expand a 7-byte block into an 8-byte DES key (7 data bits per byte in the
/// high positions; the LSB parity bit is ignored by DES).
fn str_to_des_key(b: &[u8]) -> [u8; 8] {
    let mut k = [0u8; 8];
    k[0] = b[0] >> 1;
    k[1] = ((b[0] & 0x01) << 6) | (b[1] >> 2);
    k[2] = ((b[1] & 0x03) << 5) | (b[2] >> 3);
    k[3] = ((b[2] & 0x07) << 4) | (b[3] >> 4);
    k[4] = ((b[3] & 0x0f) << 3) | (b[4] >> 5);
    k[5] = ((b[4] & 0x1f) << 2) | (b[5] >> 6);
    k[6] = ((b[5] & 0x3f) << 1) | (b[6] >> 7);
    k[7] = b[6] & 0x7f;
    for byte in k.iter_mut() {
        *byte <<= 1; // move 7 data bits into the high bits
    }
    k
}

fn des_encrypt_block(key7: &[u8], data: &[u8; 8]) -> [u8; 8] {
    let key8 = str_to_des_key(key7);
    let cipher = Des::new_from_slice(&key8).expect("8-byte DES key");
    let mut block = *data;
    let ga = des::cipher::generic_array::GenericArray::from_mut_slice(&mut block);
    cipher.encrypt_block(ga);
    block
}

/// ChallengeResponse: pad the 16-byte hash to 21 bytes, split into three 7-byte
/// DES keys, DES-encrypt the 8-byte challenge under each, concatenate (24 bytes).
fn challenge_response(challenge: &[u8; 8], password_hash: &[u8; 16]) -> [u8; 24] {
    let mut z = [0u8; 21];
    z[..16].copy_from_slice(password_hash);
    let mut out = [0u8; 24];
    out[0..8].copy_from_slice(&des_encrypt_block(&z[0..7], challenge));
    out[8..16].copy_from_slice(&des_encrypt_block(&z[7..14], challenge));
    out[16..24].copy_from_slice(&des_encrypt_block(&z[14..21], challenge));
    out
}

/// GenerateNTResponse (RFC 2759 §8.1).
pub fn generate_nt_response(
    auth_challenge: &[u8; 16],
    peer_challenge: &[u8; 16],
    username: &[u8],
    password: &str,
) -> [u8; 24] {
    let challenge = challenge_hash(peer_challenge, auth_challenge, username);
    let hash = Zeroizing::new(nt_password_hash(password));
    challenge_response(&challenge, &hash)
}

const MAGIC1: &[u8] = b"Magic server to client signing constant";
const MAGIC2: &[u8] = b"Pad to make it do more than one iteration";

/// GenerateAuthenticatorResponse (RFC 2759 §8.7): the "S=<40 hex>" string the
/// server sends and the client verifies.
pub fn generate_authenticator_response(
    password: &str,
    nt_response: &[u8; 24],
    peer_challenge: &[u8; 16],
    auth_challenge: &[u8; 16],
    username: &[u8],
) -> String {
    let pw_hash = nt_password_hash(password);
    let pw_hash_hash = hash_nt_password_hash(&pw_hash);
    let digest = sha1(&[&pw_hash_hash, nt_response, MAGIC1]);
    let challenge = challenge_hash(peer_challenge, auth_challenge, username);
    let digest2 = sha1(&[&digest, &challenge, MAGIC2]);
    let mut s = String::from("S=");
    for b in digest2 {
        s.push_str(&format!("{b:02X}"));
    }
    s
}

// --- MPPE / EAP-MSCHAPv2 session keys (RFC 3079 §3) ---

const MPPE_MASTER: &[u8] = b"This is the MPPE Master Key";
const MPPE_SEND: &[u8] =
    b"On the client side, this is the send key; on the server side, it is the receive key.";
const MPPE_RECV: &[u8] =
    b"On the client side, this is the receive key; on the server side, it is the send key.";

fn get_master_key(pw_hash_hash: &[u8; 16], nt_response: &[u8; 24]) -> [u8; 16] {
    let d = sha1(&[pw_hash_hash, nt_response, MPPE_MASTER]);
    let mut k = [0u8; 16];
    k.copy_from_slice(&d[..16]);
    k
}

fn get_asymmetric_start_key(
    master: &[u8; 16],
    is_send: bool,
    is_server: bool,
    len: usize,
) -> Vec<u8> {
    let pad1 = [0x00u8; 40];
    let pad2 = [0xf2u8; 40];
    let s = match (is_send, is_server) {
        (true, true) | (false, false) => MPPE_RECV,
        (true, false) | (false, true) => MPPE_SEND,
    };
    let d = sha1(&[master, &pad1, s, &pad2]);
    d[..len].to_vec()
}

/// The 64-byte EAP MSK for MSCHAPv2 (peer side):
/// `MasterReceiveKey | MasterSendKey | 32 zero bytes` (RFC 3079 + the
/// EAP-MSCHAPv2 key-derivation definition).
pub fn eap_msk(password: &str, nt_response: &[u8; 24]) -> [u8; 64] {
    let pw_hash = Zeroizing::new(nt_password_hash(password));
    let pw_hash_hash = Zeroizing::new(hash_nt_password_hash(&pw_hash));
    let master = Zeroizing::new(get_master_key(&pw_hash_hash, nt_response));
    // EAP-MSCHAPv2 (draft-ietf-pppext-eap-mschapv2 §4) derives both keys with
    // IsServer = TRUE on both ends so peer and authenticator agree:
    //   MasterReceiveKey = GetAsymmetricStartKey(MK, 16, send=FALSE, server=TRUE)
    //   MasterSendKey    = GetAsymmetricStartKey(MK, 16, send=TRUE,  server=TRUE)
    //   MSK = MasterReceiveKey | MasterSendKey | 32 zero bytes
    let recv = get_asymmetric_start_key(&master, false, true, 16);
    let send = get_asymmetric_start_key(&master, true, true, 16);
    let mut msk = [0u8; 64];
    msk[..16].copy_from_slice(&recv);
    msk[16..32].copy_from_slice(&send);
    msk
}

// --- high-level response building ---

/// Everything derived for one MSCHAPv2 response. Zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MsChapResponse {
    pub peer_challenge: [u8; 16],
    pub nt_response: [u8; 24],
    pub msk: [u8; 64],
}

/// Compute an MSCHAPv2 response (fresh random PeerChallenge) and the MSK.
pub fn make_response(auth_challenge: &[u8; 16], username: &str, password: &str) -> MsChapResponse {
    let mut peer_challenge = [0u8; 16];
    rng::fill(&mut peer_challenge);
    let nt_response = generate_nt_response(
        auth_challenge,
        &peer_challenge,
        username.as_bytes(),
        password,
    );
    let msk = eap_msk(password, &nt_response);
    MsChapResponse {
        peer_challenge,
        nt_response,
        msk,
    }
}

/// Build the EAP type-26 data for an MSCHAPv2 Response packet.
pub fn build_mschap_response_data(
    mschap_id: u8,
    peer_challenge: &[u8; 16],
    nt_response: &[u8; 24],
    username: &str,
) -> Vec<u8> {
    // Response value (49 bytes): PeerChallenge(16) | Reserved(8) | NT-Response(24) | Flags(1)
    let mut value = Vec::with_capacity(49);
    value.extend_from_slice(peer_challenge);
    value.extend_from_slice(&[0u8; 8]);
    value.extend_from_slice(nt_response);
    value.push(0);
    let name = username.as_bytes();
    let ms_len = (4 + 1 + value.len() + name.len()) as u16; // opcode+id+mslen + vsize + value + name
    let mut data = Vec::new();
    data.push(MS_RESPONSE);
    data.push(mschap_id);
    data.extend_from_slice(&ms_len.to_be_bytes());
    data.push(49);
    data.extend_from_slice(&value);
    data.extend_from_slice(name);
    data
}

#[cfg(test)]
mod tests {
    use super::*;

    const AUTH_CHAL: [u8; 16] = [
        0x5B, 0x5D, 0x7C, 0x7D, 0x7B, 0x3F, 0x2F, 0x3E, 0x3C, 0x2C, 0x60, 0x21, 0x32, 0x26, 0x26,
        0x28,
    ];
    const PEER_CHAL: [u8; 16] = [
        0x21, 0x40, 0x23, 0x24, 0x25, 0x5E, 0x26, 0x2A, 0x28, 0x29, 0x5F, 0x2B, 0x3A, 0x33, 0x7C,
        0x7E,
    ];

    #[test]
    fn rfc2759_nt_response() {
        // RFC 2759 §9.2: UserName "User", Password "clientPass".
        let ntr = generate_nt_response(&AUTH_CHAL, &PEER_CHAL, b"User", "clientPass");
        assert_eq!(
            hex::encode_upper(ntr),
            "82309ECD8D708B5EA08FAA3981CD83544233114A3D85D6DF"
        );
    }

    #[test]
    fn rfc2759_authenticator_response() {
        let ntr = generate_nt_response(&AUTH_CHAL, &PEER_CHAL, b"User", "clientPass");
        let s =
            generate_authenticator_response("clientPass", &ntr, &PEER_CHAL, &AUTH_CHAL, b"User");
        assert_eq!(s, "S=407A5589115FD0D6209F510FE9C04566932CDA56");
    }

    #[test]
    fn rfc2759_password_hashes() {
        let h = nt_password_hash("clientPass");
        assert_eq!(hex::encode_upper(h), "44EBBA8D5312B8D611474411F56989AE");
        let hh = hash_nt_password_hash(&h);
        assert_eq!(hex::encode_upper(hh), "41C00C584BD2D91C4017A2A12FA59F3F");
    }

    #[test]
    fn rfc3079_master_and_send_key() {
        // RFC 3079 §3.5 worked example (same credentials).
        let ntr = generate_nt_response(&AUTH_CHAL, &PEER_CHAL, b"User", "clientPass");
        let pw_hash = nt_password_hash("clientPass");
        let pw_hash_hash = hash_nt_password_hash(&pw_hash);
        let master = get_master_key(&pw_hash_hash, &ntr);
        assert_eq!(
            hex::encode_upper(master),
            "FDECE3717A8C838CB388E527AE3CDD31"
        );
        // MasterSendKey is the server-side send key: (is_send=true, is_server=true).
        let send = get_asymmetric_start_key(&master, true, true, 16);
        assert_eq!(hex::encode_upper(send), "8B7CDC149B993A1BA118CB153F56DCCB");
        // The EAP MSK places MasterSendKey in bytes [16..32] and zero-pads the tail.
        let msk = eap_msk("clientPass", &ntr);
        assert_eq!(
            hex::encode_upper(&msk[16..32]),
            "8B7CDC149B993A1BA118CB153F56DCCB"
        );
        assert_eq!(&msk[32..], &[0u8; 32]);
    }

    #[test]
    fn eap_packet_roundtrip() {
        let e = Eap {
            code: EAP_RESPONSE,
            identifier: 7,
            type_: Some(TYPE_IDENTITY),
            data: b"vpnuser".to_vec(),
        };
        let bytes = e.encode();
        assert_eq!(bytes[0], EAP_RESPONSE);
        assert_eq!(
            u16::from_be_bytes([bytes[2], bytes[3]]) as usize,
            bytes.len()
        );
        assert_eq!(Eap::parse(&bytes).unwrap(), e);
    }
}
