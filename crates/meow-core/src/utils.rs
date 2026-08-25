#[cfg(target_os = "windows")]
use std::{ffi::OsStr, os::windows::ffi::OsStrExt};

#[cfg(target_os = "windows")]
pub fn to_wide(s: &str) -> Vec<u16> {
    OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

#[cfg(not(target_os = "windows"))]
pub fn to_wide(s: &str) -> Vec<u16> {
    // Placeholder: wide strings are only used on Windows
    let _ = s;
    Vec::new()
}
