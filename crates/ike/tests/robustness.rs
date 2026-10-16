//! Hostile-input robustness: parsers must return errors, never panic, on any
//! truncation or bit-flip of valid messages (Constitution III).

use ike::constants::PayloadType;
use ike::dh::{DhGroup, DhKeypair};
use ike::eap::Eap;
use ike::message::{Message, RawPayload};
use ike::payloads::*;
use ike::proposals;
use ike::sa::{Initiator, InitiatorConfig};

fn sample_message() -> Vec<u8> {
    let kp = DhKeypair::generate(DhGroup::Curve25519);
    let cfg = InitiatorConfig {
        proposals: proposals::ike_proposals(DhGroup::Curve25519),
        dh_group: DhGroup::Curve25519.transform_id(),
        prf: ike::crypto::Prf::HmacSha256,
        key_lengths: ike::crypto::KeyLengths {
            prf_key: 32,
            integ_key: 32,
            encr_key: 32,
        },
        idi: IdPayload {
            id_type: 2,
            id_data: b"client".to_vec(),
        },
        psk: zeroize::Zeroizing::new(b"k".to_vec()),
    };
    let mut init = Initiator::new(cfg, [7; 8], vec![1; 32]);
    let cp = RawPayload {
        payload_type: PayloadType::Cp as u8,
        critical: false,
        data: ConfigPayload::request_defaults().encode(),
    };
    let ts = RawPayload {
        payload_type: PayloadType::Tsi as u8,
        critical: false,
        data: proposals::ts_any_v4().encode(),
    };
    init.build_ike_sa_init(kp.public(), &[cp, ts])
}

fn parse_everything(buf: &[u8]) {
    if let Ok(m) = Message::parse(buf) {
        for p in &m.payloads {
            let _ = SaPayload::decode(&p.data);
            let _ = KePayload::decode(&p.data);
            let _ = IdPayload::decode(&p.data);
            let _ = AuthPayload::decode(&p.data);
            let _ = NotifyPayload::decode(&p.data);
            let _ = DeletePayload::decode(&p.data);
            let _ = ConfigPayload::decode(&p.data);
            let _ = TsPayload::decode(&p.data);
            let _ = Eap::parse(&p.data);
        }
    }
    let _ = SaPayload::decode(buf);
    let _ = TsPayload::decode(buf);
    let _ = ConfigPayload::decode(buf);
    let _ = Eap::parse(buf);
}

#[test]
fn truncations_never_panic() {
    let msg = sample_message();
    for n in 0..=msg.len() {
        parse_everything(&msg[..n]);
    }
}

#[test]
fn bit_flips_never_panic() {
    let msg = sample_message();
    for i in 0..msg.len() {
        for bit in [0x01u8, 0x80, 0xff] {
            let mut m = msg.clone();
            m[i] ^= bit;
            parse_everything(&m);
        }
    }
}
