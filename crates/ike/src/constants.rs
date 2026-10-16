//! IKEv2 protocol constants (RFC 7296 and the IANA IKEv2 registries).
//!
//! On-wire numbers reproduced directly from RFC 7296 and the IANA registries.

/// IKEv2 exchange types (RFC 7296 §3.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ExchangeType {
    IkeSaInit = 34,
    IkeAuth = 35,
    CreateChildSa = 36,
    Informational = 37,
}

impl ExchangeType {
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            34 => Self::IkeSaInit,
            35 => Self::IkeAuth,
            36 => Self::CreateChildSa,
            37 => Self::Informational,
            _ => return None,
        })
    }
}

/// Payload types (RFC 7296 §3.2). `None` (0) terminates a payload chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PayloadType {
    None = 0,
    Sa = 33,
    Ke = 34,
    Idi = 35,
    Idr = 36,
    Cert = 37,
    Certreq = 38,
    Auth = 39,
    Nonce = 40,
    Notify = 41,
    Delete = 42,
    VendorId = 43,
    Tsi = 44,
    Tsr = 45,
    Sk = 46,
    Cp = 47,
    Eap = 48,
}

impl PayloadType {
    pub fn from_u8(v: u8) -> Option<Self> {
        use PayloadType::*;
        Some(match v {
            0 => None,
            33 => Sa,
            34 => Ke,
            35 => Idi,
            36 => Idr,
            37 => Cert,
            38 => Certreq,
            39 => Auth,
            40 => Nonce,
            41 => Notify,
            42 => Delete,
            43 => VendorId,
            44 => Tsi,
            45 => Tsr,
            46 => Sk,
            47 => Cp,
            48 => Eap,
            _ => return Option::None,
        })
    }
}

/// Header flags (RFC 7296 §3.1).
pub const FLAG_INITIATOR: u8 = 0x08;
pub const FLAG_VERSION: u8 = 0x10;
pub const FLAG_RESPONSE: u8 = 0x20;

/// IKEv2 major/minor version nibble value for the version byte (2.0).
pub const IKE_VERSION: u8 = 0x20;

/// Protocol IDs (RFC 7296 §3.3.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ProtocolId {
    None = 0,
    Ike = 1,
    Ah = 2,
    Esp = 3,
}

/// Transform types within a proposal (RFC 7296 §3.3.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum TransformType {
    Encr = 1,
    Prf = 2,
    Integ = 3,
    Dh = 4,
    Esn = 5,
}

impl TransformType {
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            1 => Self::Encr,
            2 => Self::Prf,
            3 => Self::Integ,
            4 => Self::Dh,
            5 => Self::Esn,
            _ => return None,
        })
    }
}

/// Encryption transform IDs (IANA "Transform Type 1").
pub mod encr {
    pub const DES_CBC: u16 = 2;
    pub const DES3_CBC: u16 = 3;
    pub const AES_CBC: u16 = 12;
    pub const AES_CTR: u16 = 13;
    pub const AES_GCM_16: u16 = 20; // AES-GCM w/ 16-octet ICV
    pub const AES_GCM_12: u16 = 19;
    pub const AES_GCM_8: u16 = 18;
    pub const CHACHA20_POLY1305: u16 = 28;
}

/// PRF transform IDs (IANA "Transform Type 2").
pub mod prf {
    pub const HMAC_MD5: u16 = 1;
    pub const HMAC_SHA1: u16 = 2;
    pub const AES128_XCBC: u16 = 4;
    pub const HMAC_SHA2_256: u16 = 5;
    pub const HMAC_SHA2_384: u16 = 6;
    pub const HMAC_SHA2_512: u16 = 7;
}

/// Integrity transform IDs (IANA "Transform Type 3").
pub mod integ {
    pub const NONE: u16 = 0;
    pub const HMAC_MD5_96: u16 = 1;
    pub const HMAC_SHA1_96: u16 = 2;
    pub const AES_XCBC_96: u16 = 5;
    pub const HMAC_SHA2_256_128: u16 = 12;
    pub const HMAC_SHA2_384_192: u16 = 13;
    pub const HMAC_SHA2_512_256: u16 = 14;
}

/// Diffie-Hellman group transform IDs (IANA "Transform Type 4").
pub mod dh {
    pub const MODP_768: u16 = 1;
    pub const MODP_1024: u16 = 2;
    pub const MODP_1536: u16 = 5;
    pub const MODP_2048: u16 = 14;
    pub const MODP_3072: u16 = 15;
    pub const MODP_4096: u16 = 16;
    pub const ECP_256: u16 = 19;
    pub const ECP_384: u16 = 20;
    pub const ECP_521: u16 = 21;
    pub const BRAINPOOL_256: u16 = 28;
    pub const CURVE25519: u16 = 31;
}

/// Transform attribute type for key length (RFC 7296 §3.3.5), used by
/// variable-key ciphers such as AES: a TV attribute `0x800E` + 16-bit value.
pub const ATTR_KEY_LENGTH: u16 = 14;
/// High bit set in an attribute type field marks a TV (type/value) format.
pub const ATTR_TV_FLAG: u16 = 0x8000;

/// Authentication method (RFC 7296 §3.8).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AuthMethod {
    RsaSig = 1,
    SharedKeyMic = 2, // pre-shared key MAC
    DssSig = 3,
    EcdsaSha256 = 9,
    EcdsaSha384 = 10,
    EcdsaSha512 = 11,
    DigitalSignature = 14, // RFC 7427
}

/// ID types (RFC 7296 §3.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum IdType {
    Ipv4Addr = 1,
    Fqdn = 2,
    Rfc822Addr = 3,
    Ipv6Addr = 5,
    DerAsn1Dn = 9,
    DerAsn1Gn = 10,
    KeyId = 11,
}

/// A selection of Notify message types (RFC 7296 §3.10.1 + IANA).
pub mod notify {
    // Errors (1..=16383)
    pub const UNSUPPORTED_CRITICAL_PAYLOAD: u16 = 1;
    pub const INVALID_IKE_SPI: u16 = 4;
    pub const INVALID_MAJOR_VERSION: u16 = 5;
    pub const INVALID_SYNTAX: u16 = 7;
    pub const INVALID_MESSAGE_ID: u16 = 9;
    pub const INVALID_SPI: u16 = 11;
    pub const NO_PROPOSAL_CHOSEN: u16 = 14;
    pub const INVALID_KE_PAYLOAD: u16 = 17;
    pub const AUTHENTICATION_FAILED: u16 = 24;
    pub const SINGLE_PAIR_REQUIRED: u16 = 34;
    pub const NO_ADDITIONAL_SAS: u16 = 35;
    pub const INTERNAL_ADDRESS_FAILURE: u16 = 36;
    pub const TS_UNACCEPTABLE: u16 = 38;
    pub const INVALID_SELECTORS: u16 = 39;
    // Status (16384..=65535)
    pub const INITIAL_CONTACT: u16 = 16384;
    pub const SET_WINDOW_SIZE: u16 = 16385;
    pub const NAT_DETECTION_SOURCE_IP: u16 = 16388;
    pub const NAT_DETECTION_DESTINATION_IP: u16 = 16389;
    pub const COOKIE: u16 = 16390;
    pub const USE_TRANSPORT_MODE: u16 = 16391;
    pub const REKEY_SA: u16 = 16393;
    pub const ESP_TFC_PADDING_NOT_SUPPORTED: u16 = 16394;
    pub const NON_FIRST_FRAGMENTS_ALSO: u16 = 16395;
    pub const MOBIKE_SUPPORTED: u16 = 16396;
    pub const EAP_ONLY_AUTHENTICATION: u16 = 16417;
    pub const CHILDLESS_IKEV2_SUPPORTED: u16 = 16420;
    pub const SIGNATURE_HASH_ALGORITHMS: u16 = 16431;
}

/// Traffic-selector types (RFC 7296 §3.13.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum TsType {
    Ipv4AddrRange = 7,
    Ipv6AddrRange = 8,
}
