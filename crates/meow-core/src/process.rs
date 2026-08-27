#[cfg(target_os = "windows")]
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
#[cfg(target_os = "windows")]
use windows_sys::Win32::Graphics::Gdi::{
    BI_RGB, BITMAPINFO, BITMAPINFOHEADER, CreateCompatibleDC, CreateDIBSection, DIB_RGB_COLORS,
    DeleteDC, DeleteObject, SelectObject,
};
#[cfg(target_os = "windows")]
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
#[cfg(target_os = "windows")]
use windows_sys::Win32::System::Threading::{
    IsWow64Process, OpenProcess, PROCESS_DUP_HANDLE, PROCESS_QUERY_INFORMATION,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
    QueryFullProcessImageNameW,
};
#[cfg(target_os = "windows")]
use windows_sys::Win32::UI::Shell::{SHFILEINFOW, SHGFI_ICON, SHGFI_SMALLICON, SHGetFileInfoW};
#[cfg(target_os = "windows")]
use windows_sys::Win32::UI::WindowsAndMessaging::{DI_IMAGE, DestroyIcon, DrawIconEx};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessArch {
    X64,
    X86,
    Unknown,
}

#[cfg(target_os = "windows")]
pub fn get_process_arch(pid: u32) -> ProcessArch {
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if handle.is_null() {
            return ProcessArch::Unknown;
        }
        let mut wow64: i32 = 0;
        let ok = IsWow64Process(handle, &mut wow64);
        CloseHandle(handle);
        if ok == 0 {
            return ProcessArch::Unknown;
        }
        if wow64 != 0 {
            ProcessArch::X86
        } else {
            ProcessArch::X64
        }
    }
}

#[cfg(not(target_os = "windows"))]
pub fn get_process_arch(_pid: u32) -> ProcessArch {
    ProcessArch::X64
}

#[cfg(target_os = "windows")]
fn parse_null_terminated_utf16(arr: &[u16]) -> String {
    let end = arr.iter().position(|&c| c == 0).unwrap_or(arr.len());
    String::from_utf16_lossy(&arr[..end])
}

#[cfg(not(target_os = "windows"))]
pub fn list_processes() -> Vec<(String, u32, ProcessArch)> {
    vec![
        ("steam.exe".into(), 1234, ProcessArch::X64),
        ("game.exe".into(), 5678, ProcessArch::X64),
        ("notepad.exe".into(), 9012, ProcessArch::X64),
        ("explorer.exe".into(), 3456, ProcessArch::X64),
        ("chrome.exe".into(), 7890, ProcessArch::X64),
        ("discord.exe".into(), 1357, ProcessArch::X64),
        ("obsidian.exe".into(), 2468, ProcessArch::X64),
        ("vscode.exe".into(), 1111, ProcessArch::X64),
    ]
}

#[cfg(not(target_os = "windows"))]
pub fn find_process_id(name: &str) -> Option<u32> {
    list_processes()
        .iter()
        .find(|(n, _, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, p, _)| *p)
}

#[cfg(not(target_os = "windows"))]
pub fn get_process_handle(pid: u32) -> isize {
    let _ = pid;
    -1
}

#[cfg(not(target_os = "windows"))]
pub fn get_hwnd_of_process_id(target_pid: u32) -> Option<isize> {
    let _ = target_pid;
    None
}

#[cfg(target_os = "windows")]
pub fn list_processes() -> Vec<(String, u32, ProcessArch)> {
    let mut result = Vec::new();
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == INVALID_HANDLE_VALUE {
            return result;
        }

        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..std::mem::zeroed()
        };

        if Process32FirstW(snapshot, &mut entry) != 0 {
            loop {
                let name = parse_null_terminated_utf16(&entry.szExeFile);
                result.push((
                    name,
                    entry.th32ProcessID,
                    get_process_arch(entry.th32ProcessID),
                ));
                if Process32NextW(snapshot, &mut entry) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snapshot);
    }
    result.retain(|(_, pid, _)| *pid != 0);
    result.sort_by_key(|a| a.0.to_ascii_lowercase());
    result.dedup_by(|a, b| a.0.eq_ignore_ascii_case(&b.0));
    result
}

#[cfg(target_os = "windows")]
pub fn find_process_id(name: &str) -> Option<u32> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == INVALID_HANDLE_VALUE {
            return None;
        }

        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..std::mem::zeroed()
        };

        if Process32FirstW(snapshot, &mut entry) != 0 {
            loop {
                let current_name = parse_null_terminated_utf16(&entry.szExeFile);
                if current_name.eq_ignore_ascii_case(name) {
                    CloseHandle(snapshot);
                    return Some(entry.th32ProcessID);
                }
                if Process32NextW(snapshot, &mut entry) == 0 {
                    break;
                }
            }
        }

        CloseHandle(snapshot);
        None
    }
}

#[cfg(target_os = "windows")]
pub fn get_process_handle(pid: u32) -> HANDLE {
    unsafe {
        OpenProcess(
            PROCESS_VM_READ
                | PROCESS_VM_WRITE
                | PROCESS_VM_OPERATION
                | PROCESS_QUERY_INFORMATION
                | PROCESS_DUP_HANDLE,
            0,
            pid,
        )
    }
}

#[cfg(target_os = "windows")]
pub fn get_hwnd_of_process_id(target_pid: u32) -> Option<isize> {
    use std::sync::atomic::{AtomicIsize, Ordering};
    use windows_sys::Win32::Foundation::LPARAM;
    use windows_sys::Win32::UI::WindowsAndMessaging::{EnumWindows, GetWindowThreadProcessId};

    static FOUND_HWND: AtomicIsize = AtomicIsize::new(0);
    FOUND_HWND.store(0, Ordering::SeqCst);

    unsafe extern "system" fn enum_callback(
        hwnd: *mut core::ffi::c_void,
        l_param: LPARAM,
    ) -> windows_sys::core::BOOL {
        let target_pid = l_param as u32;
        let mut pid = 0u32;
        unsafe { GetWindowThreadProcessId(hwnd, &mut pid) };
        if pid == target_pid {
            FOUND_HWND.store(hwnd as isize, Ordering::SeqCst);
            0
        } else {
            1
        }
    }

    unsafe {
        EnumWindows(Some(enum_callback), target_pid as LPARAM);
    }

    let hwnd = FOUND_HWND.load(Ordering::SeqCst);
    if hwnd != 0 { Some(hwnd) } else { None }
}

#[cfg(target_os = "windows")]
fn icon_to_rgba(hicon: *mut core::ffi::c_void) -> Option<(Vec<u8>, u32, u32)> {
    unsafe {
        let w = 16i32;
        let h = 16i32;

        let hdc_screen = CreateCompatibleDC(std::ptr::null_mut());

        let mut bmi: BITMAPINFO = std::mem::zeroed();
        bmi.bmiHeader.biSize = std::mem::size_of::<BITMAPINFOHEADER>() as u32;
        bmi.bmiHeader.biWidth = w;
        bmi.bmiHeader.biHeight = -h;
        bmi.bmiHeader.biPlanes = 1;
        bmi.bmiHeader.biBitCount = 32;
        bmi.bmiHeader.biCompression = BI_RGB;

        let mut bits: *mut core::ffi::c_void = std::ptr::null_mut();
        let hbmp = CreateDIBSection(
            hdc_screen,
            &bmi,
            DIB_RGB_COLORS,
            &mut bits,
            std::ptr::null_mut(),
            0,
        );

        if hbmp.is_null() || bits.is_null() {
            DeleteDC(hdc_screen);
            return None;
        }

        let old_bmp = SelectObject(hdc_screen, hbmp);
        DrawIconEx(
            hdc_screen,
            0,
            0,
            hicon,
            w,
            h,
            0,
            std::ptr::null_mut(),
            DI_IMAGE,
        );
        SelectObject(hdc_screen, old_bmp);

        let stride = (w as usize) * 4;
        let total = stride * h as usize;
        let raw = std::slice::from_raw_parts(bits as *const u8, total).to_vec();

        DeleteObject(hbmp);
        DeleteDC(hdc_screen);

        let mut pixels = raw;
        for chunk in pixels.as_chunks_mut::<4>().0 {
            chunk.swap(0, 2);
        }

        Some((pixels, w as u32, h as u32))
    }
}

#[cfg(target_os = "windows")]
pub fn extract_process_icon(pid: u32) -> Option<(Vec<u8>, u32, u32)> {
    if pid == 0 {
        return None;
    }
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if handle.is_null() {
            return None;
        }

        let mut buf = [0u16; 260];
        let mut size = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(handle, 0, buf.as_mut_ptr(), &mut size);
        CloseHandle(handle);

        if ok == 0 {
            return None;
        }

        let exe_path = &buf[..size as usize];
        let mut shfi: SHFILEINFOW = std::mem::zeroed();
        SHGetFileInfoW(
            exe_path.as_ptr(),
            0,
            &mut shfi,
            std::mem::size_of::<SHFILEINFOW>() as u32,
            SHGFI_ICON | SHGFI_SMALLICON,
        );

        if shfi.hIcon.is_null() {
            return None;
        }

        let result = icon_to_rgba(shfi.hIcon);
        DestroyIcon(shfi.hIcon);
        result
    }
}

#[cfg(not(target_os = "windows"))]
pub fn extract_process_icon(_pid: u32) -> Option<(Vec<u8>, u32, u32)> {
    None
}
