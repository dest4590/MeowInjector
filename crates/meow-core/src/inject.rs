#[cfg(target_os = "windows")]
use std::ffi::CString;
#[cfg(target_os = "windows")]
use std::fs;
#[cfg(target_os = "windows")]
use std::path::Path;

#[cfg(target_os = "windows")]
use pelite::pe64::{Pe, PeFile};

#[cfg(target_os = "windows")]
use crate::driver::Driver;

#[cfg(target_os = "windows")]
use thiserror::Error;

#[cfg(target_os = "windows")]
const MEM_COMMIT: u32 = 0x00001000;
#[cfg(target_os = "windows")]
const MEM_RESERVE: u32 = 0x00002000;
#[cfg(target_os = "windows")]
const PAGE_EXECUTE_READWRITE: u32 = 0x40;
#[cfg(target_os = "windows")]
const PAGE_READWRITE: u32 = 0x04;

#[cfg(target_os = "windows")]
const EVENT_MIN: u32 = 0x00000001;
#[cfg(target_os = "windows")]
const EVENT_MAX: u32 = 0x7FFFFFFF;
#[cfg(target_os = "windows")]
const WINEVENT_INCONTEXT: u32 = 0x0004;

#[cfg(target_os = "windows")]
#[derive(Debug, Error)]
pub enum InjectError {
    #[error("DLL not found: {0}")]
    DllNotFound(String),
    #[error("Failed to read DLL: {0}")]
    ReadError(String),
    #[error("Invalid PE: {0:?}")]
    InvalidPe(pelite::Error),
    #[error("Failed to allocate image memory")]
    AllocateImageFailed,
    #[error("Failed to write PE headers")]
    WriteHeadersFailed,
    #[error("Failed to write section: {0}")]
    WriteSectionFailed(String),
    #[error("No relocations: {0:?}")]
    NoRelocations(pelite::Error),
    #[error("Failed to read reloc at 0x{:X}", .0)]
    ReadRelocFailed(usize),
    #[error("Failed to write reloc at 0x{:X}", .0)]
    WriteRelocFailed(usize),
    #[error("No imports: {0:?}")]
    NoImports(pelite::Error),
    #[error("Failed to load locally: {0}")]
    LoadLibraryFailed(String),
    #[error("Module not found in target: {0}")]
    ModuleNotFound(String),
    #[error("Bad DLL name: {0:?}")]
    BadDllName(pelite::Error),
    #[error("DLL name is not valid UTF-8")]
    InvalidUtf8,
    #[error("DLL name contains null byte")]
    NullByte,
    #[error("Can't resolve {0}!{1}")]
    UnresolvedImport(String, String),
    #[error("Bad import name")]
    BadImportName,
    #[error("Name has null byte")]
    NameNullByte,
    #[error("Failed to find HWND for target process")]
    HwndNotFound,
    #[error("SetWinEventHook failed")]
    HookFailed,
    #[error("Timeout loading {0} in target")]
    Timeout(String),
    #[error("LoadLibraryW returned NULL for {0}")]
    NullLoadResult(String),
    #[error("Failed to read LoadLibraryW result")]
    ReadResultFailed,
    #[error("Failed to allocate shellcode memory")]
    AllocateShellcodeFailed,
    #[error("Failed to write shellcode")]
    WriteShellcodeFailed,
    #[error("Failed to allocate name buffer in target")]
    AllocateNameFailed,
    #[error("Failed to allocate result buffer")]
    AllocateResultFailed,
    #[error("Failed to allocate signal")]
    AllocateSignalFailed,
    #[error("Timeout waiting for DllMain")]
    DllMainTimeout,
    #[error("kernel32 not found in target")]
    Kernel32NotFound,
    #[error("LoadLibraryW not found locally")]
    LoadLibraryWNotFound,
    #[error("Failed to load kernel32 locally")]
    LoadKernel32Failed,
    #[error("Failed to load ntdll.dll")]
    LoadNtdllFailed,
    #[error("protect_memory failed, trying to continue")]
    ProtectFailed,
}

const IMAGE_DIRECTORY_ENTRY_EXCEPTION: usize = 3;
#[cfg(target_os = "windows")]
const IMAGE_DIRECTORY_ENTRY_TLS: usize = 9;

#[cfg(target_os = "windows")]
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct BootstrapPatches {
    exception_functions_addr: u64,
    exception_functions_count: u32,
    rtl_add_function_table_remote: u64,
    tls_callbacks_addr: u64,
}

#[cfg(target_os = "windows")]
pub fn manual_map(driver: &Driver, pid: u32, dll_path: &str) -> Result<(), InjectError> {
    let path = Path::new(dll_path);
    if !path.exists() {
        return Err(InjectError::DllNotFound(dll_path.to_string()));
    }

    let dll_bytes = fs::read(path).map_err(|e| InjectError::ReadError(e.to_string()))?;
    let file = PeFile::from_bytes(&dll_bytes).map_err(InjectError::InvalidPe)?;

    let optional = file.optional_header();
    let size_of_image = optional.SizeOfImage as usize;
    let image_base = optional.ImageBase as usize;
    let entry_point_rva = optional.AddressOfEntryPoint as usize;

    log::info!(
        "PE image base: 0x{:X}, size: 0x{:X}",
        image_base,
        size_of_image
    );

    let remote_base = driver
        .allocate_memory(
            pid,
            size_of_image,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        )
        .ok_or(InjectError::AllocateImageFailed)?;

    log::info!(
        "Remote base: 0x{:X}..0x{:X}",
        remote_base,
        remote_base + size_of_image
    );

    if !driver.protect_memory(pid, remote_base, size_of_image, PAGE_EXECUTE_READWRITE) {
        log::error!(
            "protect_memory failed on image range 0x{:X}..0x{:X}",
            remote_base,
            remote_base + size_of_image
        );
        return Err(InjectError::ProtectFailed);
    }

    if !driver.write_memory(pid, remote_base, dll_bytes.as_ptr(), 0x1000) {
        return Err(InjectError::WriteHeadersFailed);
    }

    map_sections(driver, pid, &file, &dll_bytes, remote_base)?;

    let delta = remote_base as isize - image_base as isize;
    if delta != 0 {
        process_relocations(driver, pid, &file, remote_base, delta)?;
    }

    resolve_imports(driver, pid, &file, remote_base)?;

    let patches = collect_bootstrap_patches(driver, pid, &file, &dll_bytes, remote_base, image_base);
    log::info!(
        "Bootstrap: .pdata=0x{:X} ({} entries), RtlAddFunctionTable=0x{:X}, TLS callbacks=0x{:X}",
        patches.exception_functions_addr,
        patches.exception_functions_count,
        patches.rtl_add_function_table_remote,
        patches.tls_callbacks_addr
    );

    let entry_point = remote_base + entry_point_rva;
    log::info!("Entry point: 0x{:X}", entry_point);

    call_dll_main(driver, pid, remote_base, entry_point, &patches)?;

    log::info!("Manual map complete!");
    Ok(())
}

#[cfg(target_os = "windows")]
fn rva_to_file_offset(file: &PeFile<'_>, rva: u32) -> Option<usize> {
    for section in file.section_headers() {
        let sv = section.VirtualAddress;
        let sz = section.VirtualSize.max(section.SizeOfRawData);
        if rva >= sv && rva < sv + sz {
            return Some((section.PointerToRawData + (rva - sv)) as usize);
        }
    }
    None
}

#[cfg(target_os = "windows")]
fn collect_bootstrap_patches(
    driver: &Driver,
    pid: u32,
    file: &PeFile<'_>,
    dll_bytes: &[u8],
    remote_base: usize,
    image_base: usize,
) -> BootstrapPatches {
    let mut patches = BootstrapPatches::default();

    let optional = file.optional_header();
    let dirs = optional.DataDirectory;

    if let Some(exc_dir) = dirs.get(IMAGE_DIRECTORY_ENTRY_EXCEPTION) {
        if exc_dir.Size != 0 && exc_dir.VirtualAddress != 0 {
            patches.exception_functions_addr = (remote_base + exc_dir.VirtualAddress as usize) as u64;
            patches.exception_functions_count = exc_dir.Size / 12;
            patches.rtl_add_function_table_remote =
                resolve_ntdll_export(driver, pid, "RtlAddFunctionTable").unwrap_or(0);        }
    }

    if let Some(tls_dir) = dirs.get(IMAGE_DIRECTORY_ENTRY_TLS) {
        if tls_dir.Size != 0 && tls_dir.VirtualAddress != 0 {
            const ADDR_OF_CALLBACKS_OFFSET: usize = 0x18;
            if let Some(file_off) = rva_to_file_offset(file, tls_dir.VirtualAddress) {
                let want = file_off + ADDR_OF_CALLBACKS_OFFSET + 8;
                if want <= dll_bytes.len() {
                    let mut buf = [0u8; 8];
                    buf.copy_from_slice(
                        &dll_bytes[file_off + ADDR_OF_CALLBACKS_OFFSET..file_off + ADDR_OF_CALLBACKS_OFFSET + 8],
                    );
                    let callbacks_va = u64::from_le_bytes(buf);
                    if callbacks_va != 0 {
                        let delta = remote_base as i64 - image_base as i64;
                        patches.tls_callbacks_addr = (callbacks_va as i64 + delta) as u64;
                    }
                }
            }
        }
    }

    patches
}

#[cfg(target_os = "windows")]
fn resolve_ntdll_export(driver: &Driver, pid: u32, name: &str) -> Option<u64> {
    use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};

    let ntdll_remote = driver.get_module_base(pid, "ntdll.dll")?;
    let ntdll_local = unsafe { LoadLibraryA(c"ntdll.dll".as_ptr() as *const u8) };
    if ntdll_local.is_null() {
        return None;
    }
    let name_c = CString::new(name).ok()?;
    let local = unsafe { GetProcAddress(ntdll_local, name_c.as_ptr() as *const u8) }?;
    let delta = ntdll_remote as isize - ntdll_local as isize;
    Some(local as u64 + delta as u64)
}

#[cfg(target_os = "windows")]
fn map_sections(
    driver: &Driver,
    pid: u32,
    file: &PeFile<'_>,
    dll_bytes: &[u8],
    remote_base: usize,
) -> Result<(), InjectError> {
    for section in file.section_headers() {
        let name = std::str::from_utf8(&section.Name)
            .unwrap_or("?")
            .trim_matches('\0');

        let vsize = section.VirtualSize as usize;
        let raw_size = section.SizeOfRawData as usize;

        if vsize == 0 {
            continue;
        }

        let raw_data = if raw_size > 0 {
            let offset = section.PointerToRawData as usize;
            if offset + raw_size <= dll_bytes.len() {
                &dll_bytes[offset..offset + raw_size]
            } else {
                &[]
            }
        } else {
            &[]
        };

        let mut section_data = vec![0u8; vsize];
        let copy_len = raw_data.len().min(vsize);
        section_data[..copy_len].copy_from_slice(&raw_data[..copy_len]);

        let remote_addr = remote_base + section.VirtualAddress as usize;

        if !driver.write_memory(pid, remote_addr, section_data.as_ptr(), vsize) {
            return Err(InjectError::WriteSectionFailed(name.to_string()));
        }

        log::info!(
            "Section '{}': 0x{:X}, vsize=0x{:X}",
            name,
            remote_addr,
            vsize
        );
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn process_relocations(
    driver: &Driver,
    pid: u32,
    file: &PeFile<'_>,
    remote_base: usize,
    delta: isize,
) -> Result<(), InjectError> {
    let base_relocs = match file.base_relocs() {
        Ok(base_relocs) => base_relocs,
        Err(e) if e.is_null() => {
            log::info!("No relocation table present, skipping relocations");
            return Ok(());
        }
        Err(e) => return Err(InjectError::NoRelocations(e)),
    };

    for block in base_relocs.iter_blocks() {
        let words = block.words();

        for word in words {
            let reloc_type = block.type_of(word);
            let reloc_rva = block.rva_of(word);

            if reloc_type == 0 {
                continue;
            }

            let remote_addr = remote_base + reloc_rva as usize;

            if reloc_type == 10 {
                let mut current = [0u8; 8];
                if !driver.read_memory(pid, remote_addr, current.as_mut_ptr(), 8) {
                    return Err(InjectError::ReadRelocFailed(remote_addr));
                }
                let val = u64::from_ne_bytes(current);
                let new_val = val.wrapping_add(delta as u64);
                let bytes = new_val.to_ne_bytes();
                if !driver.write_memory(pid, remote_addr, bytes.as_ptr(), 8) {
                    return Err(InjectError::WriteRelocFailed(remote_addr));
                }
            } else if reloc_type == 3 {
                let mut current = [0u8; 4];
                if !driver.read_memory(pid, remote_addr, current.as_mut_ptr(), 4) {
                    return Err(InjectError::ReadRelocFailed(remote_addr));
                }
                let val = u32::from_ne_bytes(current);
                let new_val = val.wrapping_add(delta as u32);
                let bytes = new_val.to_ne_bytes();
                if !driver.write_memory(pid, remote_addr, bytes.as_ptr(), 4) {
                    return Err(InjectError::WriteRelocFailed(remote_addr));
                }
            }
        }
    }

    Ok(())
}

#[cfg(target_os = "windows")]
fn load_library_remote(driver: &Driver, pid: u32, dll_name: &str) -> Result<usize, InjectError> {
    use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};

    let kernel32_remote = driver
        .get_module_base(pid, "kernel32.dll")
        .ok_or(InjectError::Kernel32NotFound)?;

    let kernel32_local = unsafe { LoadLibraryA(c"kernel32.dll".as_ptr() as *const u8) };
    if kernel32_local.is_null() {
        return Err(InjectError::LoadKernel32Failed);
    }

    let loadlibraryw_local =
        unsafe { GetProcAddress(kernel32_local, c"LoadLibraryW".as_ptr() as *const u8) }
            .ok_or(InjectError::LoadLibraryWNotFound)?;

    let delta = kernel32_remote as isize - kernel32_local as isize;
    let loadlibraryw_remote = loadlibraryw_local as usize + delta as usize;

    log::info!(
        "LoadLibraryW remote: 0x{:X} (kernel32 remote=0x{:X}, delta=0x{:X})",
        loadlibraryw_remote,
        kernel32_remote,
        delta
    );

    use std::os::windows::ffi::OsStrExt;
    let wide_name: Vec<u16> = std::ffi::OsStr::new(dll_name)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let name_size = wide_name.len() * 2;

    let name_remote = driver
        .allocate_memory(pid, name_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
        .ok_or(InjectError::AllocateNameFailed)?;
    let _ = driver.write_memory(pid, name_remote, wide_name.as_ptr() as *const u8, name_size);

    let result_remote = driver
        .allocate_memory(pid, 8, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
        .ok_or(InjectError::AllocateResultFailed)?;

    let signal_remote = driver
        .allocate_memory(pid, 4, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
        .ok_or(InjectError::AllocateSignalFailed)?;

    let shellcode = build_shellcode_load_library(
        name_remote as u64,
        loadlibraryw_remote as u64,
        result_remote as u64,
        signal_remote as u64,
    );

    let shellcode_remote = driver
        .allocate_memory(
            pid,
            0x1000,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        )
        .ok_or(InjectError::AllocateShellcodeFailed)?;
    let _ = driver.write_memory(pid, shellcode_remote, shellcode.as_ptr(), shellcode.len());

    execute_shellcode_via_hook(driver, pid, shellcode_remote, signal_remote, 10)?;

    let mut result = [0u8; 8];
    if !driver.read_memory(pid, result_remote, result.as_mut_ptr(), 8) {
        return Err(InjectError::ReadResultFailed);
    }

    let base = u64::from_ne_bytes(result) as usize;
    if base == 0 {
        return Err(InjectError::NullLoadResult(dll_name.to_string()));
    }

    log::info!("Loaded {} in target at 0x{:X}", dll_name, base);
    Ok(base)
}

#[cfg(target_os = "windows")]
fn resolve_imports(
    driver: &Driver,
    pid: u32,
    file: &PeFile<'_>,
    remote_base: usize,
) -> Result<(), InjectError> {
    use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};

    let imports = match file.imports() {
        Ok(imports) => imports,
        Err(e) if e.is_null() => {
            log::info!("No import table present, skipping import resolution");
            return Ok(());
        }
        Err(e) => return Err(InjectError::NoImports(e)),
    };

    for desc in imports {
        let dll_name_cstr = desc.dll_name().map_err(InjectError::BadDllName)?;

        let dll_name = dll_name_cstr
            .to_str()
            .map_err(|_| InjectError::InvalidUtf8)?;

        let dll_name_c = CString::new(dll_name).map_err(|_| InjectError::NullByte)?;

        let local_base = unsafe { LoadLibraryA(dll_name_c.as_ptr() as *const u8) };
        if local_base.is_null() {
            return Err(InjectError::LoadLibraryFailed(dll_name.to_string()));
        }
        let local_base_val = local_base as usize;

        let remote_module = match driver.get_module_base(pid, dll_name) {
            Some(base) => {
                let b = base;
                log::info!(
                    "{}: local=0x{:X}, remote=0x{:X}",
                    dll_name,
                    local_base_val,
                    b
                );
                b
            }
            None => {
                log::info!(
                    "{} not found via get_module_base, loading in target...",
                    dll_name
                );
                match load_library_remote(driver, pid, dll_name) {
                    Ok(base) => {
                        log::info!("{}: loaded in target at 0x{:X}", dll_name, base);
                        base
                    }
                    Err(e) => {
                        return Err(InjectError::ModuleNotFound(format!("{} ({})", dll_name, e)));
                    }
                }
            }
        };

        let int = desc.int().map_err(InjectError::NoImports)?;
        let iat = desc.iat().map_err(InjectError::NoImports)?;

        let image = desc.image();
        let first_thunk_rva = image.FirstThunk;

        for (i, _iat_va) in iat.enumerate() {
            let import_rva = first_thunk_rva + (i as u32) * 8;
            let remote_ia_addr = remote_base + import_rva as usize;

            let int_entry = match int.clone().nth(i) {
                Some(Ok(entry)) => entry,
                _ => continue,
            };

            match int_entry {
                pelite::pe64::imports::Import::ByOrdinal { ord } => {
                    let ordinal_ptr = ord as usize as *const u8;
                    let addr =
                        unsafe { GetProcAddress(local_base as *mut _, ordinal_ptr as *const _) };
                    if let Some(func) = addr {
                        let remote_addr = func as usize
                            + (remote_module as isize - local_base_val as isize) as usize;
                        let bytes = (remote_addr as u64).to_ne_bytes();
                        let _ = driver.write_memory(pid, remote_ia_addr, bytes.as_ptr(), 8);
                        log::info!("  Ordinal {} -> 0x{:X}", ord, remote_addr);
                    }
                }
                pelite::pe64::imports::Import::ByName { name, .. } => {
                    let name_str = name.to_str().map_err(|_| InjectError::BadImportName)?;
                    let name_c = CString::new(name_str).map_err(|_| InjectError::NameNullByte)?;

                    let addr = unsafe {
                        GetProcAddress(local_base as *mut _, name_c.as_ptr() as *const u8)
                    };
                    if let Some(func) = addr {
                        let remote_addr = func as usize
                            + (remote_module as isize - local_base_val as isize) as usize;
                        let bytes = (remote_addr as u64).to_ne_bytes();
                        let _ = driver.write_memory(pid, remote_ia_addr, bytes.as_ptr(), 8);
                        log::info!("  {}!{} -> 0x{:X}", dll_name, name_str, remote_addr);
                    } else {
                        return Err(InjectError::UnresolvedImport(
                            dll_name.to_string(),
                            name_str.to_string(),
                        ));
                    }
                }
            }
        }
    }

    Ok(())
}

#[cfg(target_os = "windows")]
fn call_dll_main(
    driver: &Driver,
    pid: u32,
    remote_base: usize,
    entry_point: usize,
    patches: &BootstrapPatches
) -> Result<(), InjectError> {
    let signal_size = std::mem::size_of::<u32>();
    let signal_addr = driver
        .allocate_memory(pid, signal_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
        .ok_or(InjectError::AllocateSignalFailed)?;

    log::info!("Signal addr: 0x{:X}", signal_addr);

    let shellcode = build_shellcode_entry_point(
        remote_base as u64,
        entry_point as u64,
        signal_addr as u64,
        patches,
    );

    let shellcode_size = 0x1000;
    let shellcode_addr = driver
        .allocate_memory(
            pid,
            shellcode_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        )
        .ok_or(InjectError::AllocateShellcodeFailed)?;

    log::info!(
        "Shellcode addr: 0x{:X}, size: 0x{:X}",
        shellcode_addr,
        shellcode_size
    );

    if !driver.write_memory(pid, shellcode_addr, shellcode.as_ptr(), shellcode.len()) {
        return Err(InjectError::WriteShellcodeFailed);
    }

    log::info!("Hook set, waiting for DllMain...");

    execute_shellcode_via_hook(driver, pid, shellcode_addr, signal_addr, 10)?;

    log::info!("DllMain called successfully");
    Ok(())
}

#[cfg(target_os = "windows")]
fn build_shellcode_entry_point(
    remote_base: u64,
    entry_point: u64,
    signal_addr: u64,
    patches: &BootstrapPatches,
) -> Vec<u8> {
    let mut sc = Vec::with_capacity(256);

    sc.extend_from_slice(&[0x53, 0x56, 0x57]);
    sc.extend_from_slice(&[0x48, 0x83, 0xEC, 0x20]);

    sc.extend_from_slice(&[0x48, 0xBE]);
    sc.extend_from_slice(&remote_base.to_le_bytes());

    sc.extend_from_slice(&[0x48, 0xBF]);
    sc.extend_from_slice(&signal_addr.to_le_bytes());

    if patches.exception_functions_addr != 0
        && patches.exception_functions_count != 0
        && patches.rtl_add_function_table_remote != 0
    {
        sc.extend_from_slice(&[0x48, 0xB9]);
        sc.extend_from_slice(&patches.exception_functions_addr.to_le_bytes());
        sc.extend_from_slice(&[0xBA]);
        sc.extend_from_slice(&patches.exception_functions_count.to_le_bytes());
        sc.extend_from_slice(&[0x4C, 0x8B, 0xC6]);
        sc.extend_from_slice(&[0x48, 0xB8]);
        sc.extend_from_slice(&patches.rtl_add_function_table_remote.to_le_bytes());
        sc.extend_from_slice(&[0xFF, 0xD0]);
    }

    if patches.tls_callbacks_addr != 0 {
        sc.extend_from_slice(&[0x48, 0xBB]);
        sc.extend_from_slice(&patches.tls_callbacks_addr.to_le_bytes());

        let loop_start = sc.len();
        sc.extend_from_slice(&[0x48, 0x8B, 0x03]);
        sc.extend_from_slice(&[0x48, 0x85, 0xC0]);
        sc.extend_from_slice(&[0x0F, 0x84, 0x00, 0x00, 0x00, 0x00]);
        let je_operand_off = sc.len() - 4;

        sc.extend_from_slice(&[0x48, 0x8B, 0xCE]);
        sc.extend_from_slice(&[0xBA, 0x01, 0x00, 0x00, 0x00]);
        sc.extend_from_slice(&[0x4D, 0x31, 0xC0]);
        sc.extend_from_slice(&[0xFF, 0xD0]);
        sc.extend_from_slice(&[0x48, 0x83, 0xC3, 0x08]);
        sc.extend_from_slice(&[0xE9, 0x00, 0x00, 0x00, 0x00]);
        let jmp_operand_off = sc.len() - 4;
        let after_jmp = sc.len();
        let rel_back = (loop_start as i32) - (after_jmp as i32);
        sc[jmp_operand_off..jmp_operand_off + 4].copy_from_slice(&rel_back.to_le_bytes());

        let end_of_loop = sc.len();
        let rel_fwd = (end_of_loop as i32) - (je_operand_off as i32 + 4);
        sc[je_operand_off..je_operand_off + 4].copy_from_slice(&rel_fwd.to_le_bytes());
    }

    sc.extend_from_slice(&[0x48, 0x8B, 0xCE]);
    sc.extend_from_slice(&[0xBA, 0x01, 0x00, 0x00, 0x00]);
    sc.extend_from_slice(&[0x41, 0xB8, 0x01, 0x00, 0x00, 0x00]);
    sc.extend_from_slice(&[0x48, 0xB8]);
    sc.extend_from_slice(&entry_point.to_le_bytes());
    sc.extend_from_slice(&[0xFF, 0xD0]);

    sc.extend_from_slice(&[0xC7, 0x07, 0x69, 0x00, 0x00, 0x00]);

    sc.extend_from_slice(&[0x48, 0x83, 0xC4, 0x20]);
    sc.extend_from_slice(&[0x5F, 0x5E, 0x5B]);
    sc.push(0xC3);

    sc
}

#[cfg(target_os = "windows")]
fn build_shellcode_load_library(
    name_remote: u64,
    loadlibraryw_remote: u64,
    result_remote: u64,
    signal_remote: u64,
) -> Vec<u8> {
    let mut shellcode = Vec::with_capacity(64);
    shellcode.extend_from_slice(&[0x48, 0x83, 0xEC, 0x28]);
    shellcode.extend_from_slice(&[0x48, 0xB9]);
    shellcode.extend_from_slice(&name_remote.to_le_bytes());
    shellcode.extend_from_slice(&[0x48, 0xB8]);
    shellcode.extend_from_slice(&loadlibraryw_remote.to_le_bytes());
    shellcode.extend_from_slice(&[0xFF, 0xD0]);
    shellcode.extend_from_slice(&[0x49, 0xBB]);
    shellcode.extend_from_slice(&result_remote.to_le_bytes());
    shellcode.extend_from_slice(&[0x49, 0x89, 0x03]);
    shellcode.extend_from_slice(&[0x49, 0xBB]);
    shellcode.extend_from_slice(&signal_remote.to_le_bytes());
    shellcode.extend_from_slice(&[0x41, 0xC7, 0x03, 0x69, 0x00, 0x00, 0x00]);
    shellcode.extend_from_slice(&[0x48, 0x83, 0xC4, 0x28]);
    shellcode.extend_from_slice(&[0xC3]);
    shellcode
}

#[cfg(target_os = "windows")]
fn execute_shellcode_via_hook(
    driver: &Driver,
    pid: u32,
    shellcode_addr: usize,
    signal_addr: usize,
    timeout_secs: u64,
) -> Result<(), InjectError> {
    use windows_sys::Win32::System::LibraryLoader::LoadLibraryA;
    use windows_sys::Win32::UI::Accessibility::{SetWinEventHook, UnhookWinEvent};
    use windows_sys::Win32::UI::WindowsAndMessaging::GetWindowThreadProcessId;

    let hwnd = crate::process::get_hwnd_of_process_id(pid).ok_or(InjectError::HwndNotFound)?;
    let mut w_pid = 0u32;
    let thread_id = unsafe { GetWindowThreadProcessId(hwnd as *mut core::ffi::c_void, &mut w_pid) };

    let ntdll = unsafe { LoadLibraryA(c"ntdll.dll".as_ptr() as *const u8) };
    if ntdll.is_null() {
        return Err(InjectError::LoadNtdllFailed);
    }

    let hook = unsafe {
        SetWinEventHook(
            EVENT_MIN,
            EVENT_MAX,
            ntdll,
            Some(std::mem::transmute::<
                usize,
                unsafe extern "system" fn(
                    *mut core::ffi::c_void,
                    u32,
                    *mut core::ffi::c_void,
                    i32,
                    i32,
                    u32,
                    u32,
                ),
            >(shellcode_addr)),
            pid,
            thread_id,
            WINEVENT_INCONTEXT,
        )
    };
    if hook.is_null() {
        return Err(InjectError::HookFailed);
    }

    let mut signal = [0u8; 4];
    let start = std::time::Instant::now();
    let timeout = std::time::Duration::from_secs(timeout_secs);
    loop {
        if start.elapsed() > timeout {
            unsafe {
                UnhookWinEvent(hook);
            }
            return Err(InjectError::DllMainTimeout);
        }
        if driver.read_memory(pid, signal_addr, signal.as_mut_ptr(), 4) && signal[0] == 0x69 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    unsafe {
        UnhookWinEvent(hook);
    }
    Ok(())
}
