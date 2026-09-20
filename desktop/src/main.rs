#[cfg(feature = "read-only-downloads")]
mod advice;
#[cfg_attr(feature = "read-only-downloads", path = "read_only.rs")]
mod app;
mod scope;
use serde_json::{json, Value};
use std::{
    ffi::{CStr, CString},
    path::{Path, PathBuf},
    sync::OnceLock,
};
static DESKTOP: OnceLock<app::Desktop> = OnceLock::new();
unsafe extern "C" {
    fn sp_bundle_paths() -> *mut libc::c_char;
    fn sp_run();
}
// The UI sends only fixed commands and opaque IDs. Paths never enter this interface.
#[no_mangle]
extern "C" fn sp_dispatch(
    command: *const libc::c_char,
    args: *const libc::c_char,
) -> *mut libc::c_char {
    let response = std::panic::catch_unwind(|| {
        if command.is_null() || args.is_null() {
            return json!({"error":"INVALID_ARGUMENT"});
        }
        let command = unsafe { CStr::from_ptr(command) }.to_string_lossy();
        let args: Value = match serde_json::from_slice(unsafe { CStr::from_ptr(args) }.to_bytes()) {
            Ok(v) => v,
            Err(_) => return json!({"error":"INVALID_ARGUMENT"}),
        };
        match DESKTOP
            .get()
            .ok_or_else(|| "STARTUP_FAILED".to_string())
            .and_then(|d| d.dispatch(&command, &args))
        {
            Ok(data) => json!({"data":data}),
            Err(error) => json!({"error":error}),
        }
    })
    .unwrap_or_else(|_| json!({"error":"SESSION_FAILED"}));
    CString::new(response.to_string()).unwrap().into_raw()
}
#[no_mangle]
extern "C" fn sp_release(ptr: *mut libc::c_char) {
    if !ptr.is_null() {
        unsafe {
            drop(CString::from_raw(ptr));
        }
    }
}
fn main() {
    let ptr = unsafe { sp_bundle_paths() };
    if ptr.is_null() {
        eprintln!("BUNDLE_REQUIRED");
        return;
    }
    let paths: Value =
        serde_json::from_slice(unsafe { CStr::from_ptr(ptr) }.to_bytes()).expect("bundle paths");
    unsafe {
        libc::free(ptr.cast());
    }
    match app::Desktop::open(
        Path::new(paths["resources"].as_str().expect("resources")),
        PathBuf::from(paths["data"].as_str().expect("data")),
    ) {
        Ok(app) => {
            let _ = DESKTOP.set(app);
            unsafe {
                sp_run();
            }
        }
        Err(error) => eprintln!("{error}"),
    }
}
