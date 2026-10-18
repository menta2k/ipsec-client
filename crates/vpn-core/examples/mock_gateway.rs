//! A standalone IKEv2/ESP gateway for end-to-end tests of the real service
//! where strongSwan is not available (macOS runners, 004 T021). It is the
//! `vpn-core` mock responder on UDP 500 and 4500:
//!
//! ```text
//! mock_gateway <listen-address>
//! ```
//!
//! PSK `gateway-psk`; EAP user `alice`, password `correct horse`; the client
//! gets 10.10.0.2 and DNS 10.10.0.1, and 10.10.0.0/16 is behind the gateway,
//! where every packet is echoed back with source and destination swapped.
//! It prints `ready` once listening, then one line per change in what it
//! observed (for example `delete` when the client sends an IKE DELETE).

use std::net::Ipv4Addr;
use std::time::Duration;
use vpn_core::mock::{MockResponder, ResponderConfig};

fn main() {
    let addr: Ipv4Addr = match std::env::args().nth(1).map(|a| a.parse()) {
        Some(Ok(a)) => a,
        _ => {
            eprintln!("usage: mock_gateway <listen-address>");
            std::process::exit(2);
        }
    };
    let gw = match MockResponder::start_on(addr, 500, 4500, ResponderConfig::default()) {
        Ok(g) => g,
        Err(e) => {
            eprintln!("error: cannot listen on {addr}:500/4500: {e}");
            std::process::exit(1);
        }
    };
    println!("ready");
    let mut last = String::new();
    loop {
        let o = gw.obs();
        let line = format!(
            "sa_init={} established={} delete={} esp_echoed={}",
            o.sa_init_count, o.established, o.got_delete, o.esp_echoed
        );
        if line != last {
            println!("{line}");
            last = line;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}
