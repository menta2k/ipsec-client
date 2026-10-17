//! Embeds the application icon in the Windows executable, so Explorer, the
//! Start menu shortcut and Add/Remove Programs show it. The icon is rendered
//! from `src/icon.rs`; no image file is checked in.

#[path = "src/icon.rs"]
#[allow(dead_code)]
mod icon;

use std::{env, fs, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=src/icon.rs");
    println!("cargo:rerun-if-changed=build.rs");
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    let out = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let ico = out.join("app.ico");
    fs::write(&ico, icon::ico(&icon::ICO_SIZES, icon::APP)).expect("write app.ico");
    let rc = out.join("app.rc");
    let ico_path = ico.display().to_string().replace('\\', "\\\\");
    fs::write(&rc, format!("1 ICON \"{ico_path}\"\n")).expect("write app.rc");
    embed_resource::compile(&rc, embed_resource::NONE)
        .manifest_optional()
        .expect("compile icon resource");
}
