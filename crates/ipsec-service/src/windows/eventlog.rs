//! Minimal Windows Event Log reporting for service lifecycle events
//! (Constitution VI). Uses source "IpsecClient" under the Application log.

use super::wide;
use windows_sys::Win32::System::EventLog::{
    DeregisterEventSource, RegisterEventSourceW, ReportEventW, EVENTLOG_ERROR_TYPE,
    EVENTLOG_INFORMATION_TYPE,
};

pub fn info(msg: &str) {
    report(msg, EVENTLOG_INFORMATION_TYPE);
}

pub fn error(msg: &str) {
    report(msg, EVENTLOG_ERROR_TYPE);
}

fn report(msg: &str, kind: u16) {
    let src = wide(crate::paths::SERVICE_NAME);
    let text = wide(msg);
    // SAFETY: wide strings are NUL-terminated and outlive the calls; the
    // source handle is deregistered before returning.
    unsafe {
        let h = RegisterEventSourceW(std::ptr::null(), src.as_ptr());
        if h.is_null() {
            return;
        }
        let strings = [text.as_ptr()];
        ReportEventW(
            h,
            kind,
            0,
            1000,
            std::ptr::null_mut(),
            1,
            0,
            strings.as_ptr(),
            std::ptr::null(),
        );
        DeregisterEventSource(h);
    }
}
