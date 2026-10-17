//! `live_workers()` is process-wide, so this check runs in its own test
//! binary: no other test can leave abandoned workers behind here.

use ipsec_plap::ipc::{live_workers, PipeApi};
use ipsec_plap::logic::ServiceApi;
use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[test]
fn finished_workers_are_no_longer_counted() {
    assert_eq!(live_workers(), 0);
    let api = PipeApi::with(
        Arc::new(|| Err(io::Error::from(io::ErrorKind::NotFound))),
        Duration::from_secs(1),
    );
    for _ in 0..5 {
        let _ = api.status();
        let _ = api.events();
    }
    // Workers drop their guard right after delivering a result.
    let deadline = Instant::now() + Duration::from_secs(2);
    while live_workers() > 0 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(live_workers(), 0, "a finished worker is still counted");
}
