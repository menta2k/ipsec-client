//! macOS integration for the GUI (004 US5): notifications through
//! `UNUserNotificationCenter` and the "Start at login" item through
//! `SMAppService`. Rust bindings only (objc2); no Objective-C is compiled.
//!
//! Both need the app bundle (`IPsec Client.app`): run from `cargo run` the
//! app has no bundle identifier, notifications are skipped with one log line
//! and the login item reports itself unavailable.

use objc2::runtime::Bool;
use objc2_foundation::{NSBundle, NSError, NSString};
use objc2_service_management::{SMAppService, SMAppServiceStatus};
use objc2_user_notifications::{
    UNAuthorizationOptions, UNMutableNotificationContent, UNNotificationRequest,
    UNUserNotificationCenter,
};
use std::sync::Once;

/// One identifier: each notification replaces the previous one, so the
/// notification centre shows the current state rather than a history.
const NOTIFICATION_ID: &str = "net.ipsec-client.state";

fn in_bundle() -> bool {
    NSBundle::mainBundle().bundleIdentifier().is_some()
}

/// Ask for permission to post notifications, once, at start-up (the system
/// asks the user the first time only).
pub fn init_notifications() {
    if !in_bundle() {
        eprintln!("note: notifications are only available when run from IPsec Client.app");
        return;
    }
    let handler = block2::RcBlock::new(|_granted: Bool, _error: *mut NSError| {});
    UNUserNotificationCenter::currentNotificationCenter()
        .requestAuthorizationWithOptions_completionHandler(
            UNAuthorizationOptions::Alert | UNAuthorizationOptions::Sound,
            &handler,
        );
}

/// Post `title` / `body`. Without permission the system drops it silently.
pub fn notify(title: &str, body: &str) {
    static NO_BUNDLE: Once = Once::new();
    if !in_bundle() {
        NO_BUNDLE.call_once(|| eprintln!("note: notification skipped (no app bundle): {title}"));
        return;
    }
    let content = UNMutableNotificationContent::new();
    content.setTitle(&NSString::from_str(title));
    content.setBody(&NSString::from_str(body));
    let request = UNNotificationRequest::requestWithIdentifier_content_trigger(
        &NSString::from_str(NOTIFICATION_ID),
        &content,
        None,
    );
    UNUserNotificationCenter::currentNotificationCenter()
        .addNotificationRequest_withCompletionHandler(&request, None);
}

/// State of the "Start at login" item.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoginItem {
    Enabled,
    Disabled,
    /// Registered, but the user must allow it under Login Items.
    NeedsApproval,
    /// Not running from the app bundle.
    Unavailable,
}

pub fn login_item() -> LoginItem {
    if !in_bundle() {
        return LoginItem::Unavailable;
    }
    // SAFETY: plain class method and getter on the main app's service object;
    // no arguments, results are owned (`Retained`) or plain integers.
    let status = unsafe { SMAppService::mainAppService().status() };
    match status {
        SMAppServiceStatus::Enabled => LoginItem::Enabled,
        SMAppServiceStatus::RequiresApproval => LoginItem::NeedsApproval,
        _ => LoginItem::Disabled,
    }
}

/// Turn "Start at login" on or off. The error text comes from the system.
pub fn set_login_item(enabled: bool) -> Result<(), String> {
    if !in_bundle() {
        return Err("only available when run from IPsec Client.app".into());
    }
    // SAFETY: as in `login_item`; the methods take no arguments and report
    // failure through the returned `NSError`.
    let result = unsafe {
        let service = SMAppService::mainAppService();
        if enabled {
            service.registerAndReturnError()
        } else {
            service.unregisterAndReturnError()
        }
    };
    result.map_err(|e| e.localizedDescription().to_string())
}

/// Open System Settings at General > Login Items (to approve the item).
pub fn open_login_items_settings() {
    // SAFETY: a class method without arguments or results.
    unsafe { SMAppService::openSystemSettingsLoginItems() };
}

/// True the first time the bundled app runs for this user; records it in
/// `~/Library/Application Support/net.ipsec-client.gui/launched`. Run from
/// `cargo run` (no bundle) every launch counts as the first.
pub fn first_launch() -> bool {
    if !in_bundle() {
        return true;
    }
    let Some(home) = std::env::var_os("HOME") else {
        return true;
    };
    let dir = std::path::Path::new(&home).join("Library/Application Support/net.ipsec-client.gui");
    let marker = dir.join("launched");
    if marker.exists() {
        return false;
    }
    let _ = std::fs::create_dir_all(&dir).and_then(|()| std::fs::write(&marker, b""));
    true
}
