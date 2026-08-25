#[cfg(target_os = "windows")]
use std::ptr::null_mut;
#[cfg(target_os = "windows")]
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
#[cfg(target_os = "windows")]
use windows_sys::Win32::Storage::FileSystem::CreateFileW;
#[cfg(target_os = "windows")]
use windows_sys::Win32::System::IO::DeviceIoControl;

#[cfg(target_os = "windows")]
use crate::utils::to_wide;
#[cfg(target_os = "windows")]
use thiserror::Error;

#[cfg(target_os = "windows")]
#[derive(Debug, Error)]
pub enum DriverError {
    #[error("driver handle is invalid")]
    InvalidHandle,
    #[error("IOCTL call failed")]
    IoctlFailed,
    #[error("module base not found for: {0}")]
    ModuleNotFound(String),
    #[error("memory allocation failed")]
    AllocationFailed,
}

#[cfg(target_os = "windows")]
const FILE_ATTRIBUTE_NORMAL: u32 = 0x00000080;
#[cfg(target_os = "windows")]
const OPEN_EXISTING: u32 = 0x00000003;
#[cfg(target_os = "windows")]
const FILE_SHARE_READ: u32 = 0x00000001;
#[cfg(target_os = "windows")]
const FILE_SHARE_WRITE: u32 = 0x00000002;
#[cfg(target_os = "windows")]
const GENERIC_READ: u32 = 0x80000000;
#[cfg(target_os = "windows")]
const GENERIC_WRITE: u32 = 0x40000000;

#[derive(Debug, Clone)]
pub struct Driver {
    #[cfg(target_os = "windows")]
    handle: HANDLE,
}
#[cfg(target_os = "windows")]
impl Driver {
    pub fn open(device_path: &str) -> Self {
        let wide_path = to_wide(device_path);
        unsafe {
            let handle = CreateFileW(
                wide_path.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                null_mut(),
            );
            Self { handle }
        }
    }

    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.handle != INVALID_HANDLE_VALUE
    }

    #[must_use]
    pub fn read_memory(&self, pid: u32, address: usize, buffer: *mut u8, size: usize) -> bool {
        unsafe {
            let request = KReadWriteRequest {
                pid,
                _pad: 0,
                src: address as u64,
                dst: buffer as u64,
                size: size as u64,
            };
            let mut bytes_returned = 0;
            DeviceIoControl(
                self.handle,
                IOCTL_READ_MEMORY,
                &request as *const _ as *const _,
                std::mem::size_of::<KReadWriteRequest>() as u32,
                std::ptr::null_mut(),
                0,
                &mut bytes_returned,
                std::ptr::null_mut(),
            ) != 0
        }
    }

    #[must_use]
    pub fn write_memory(
        &self,
        pid: u32,
        destination: usize,
        source: *const u8,
        size: usize,
    ) -> bool {
        unsafe {
            let request = KReadWriteRequest {
                pid,
                _pad: 0,
                dst: destination as u64,
                src: source as u64,
                size: size as u64,
            };
            let mut bytes_returned = 0;
            DeviceIoControl(
                self.handle,
                IOCTL_WRITE_MEMORY,
                &request as *const _ as *const _,
                std::mem::size_of::<KReadWriteRequest>() as u32,
                std::ptr::null_mut(),
                0,
                &mut bytes_returned,
                std::ptr::null_mut(),
            ) != 0
        }
    }

    pub fn get_module_base(&self, pid: u32, module_name: &str) -> Option<usize> {
        unsafe {
            let mut wide_name = to_wide(module_name);
            wide_name.resize(260, 0);

            let mut request = KGetModuleBaseRequest {
                pid,
                _pad: 0,
                handle: 0,
                name: [0; 260],
            };
            for (i, &c) in wide_name.iter().enumerate().take(260) {
                request.name[i] = c;
            }

            let mut bytes_returned = 0;
            let success = DeviceIoControl(
                self.handle,
                IOCTL_GET_MODULE_BASE,
                &request as *const _ as *const _,
                std::mem::size_of::<KGetModuleBaseRequest>() as u32,
                &mut request as *mut _ as *mut _,
                std::mem::size_of::<KGetModuleBaseRequest>() as u32,
                &mut bytes_returned,
                std::ptr::null_mut(),
            );

            if success != 0 && request.handle != 0 {
                Some(request.handle as usize)
            } else {
                None
            }
        }
    }

    pub fn allocate_memory(
        &self,
        pid: u32,
        size: usize,
        alloc_type: u32,
        protect: u32,
    ) -> Option<usize> {
        unsafe {
            let mut request = KAllocMemRequest {
                pid,
                allocation_type: alloc_type,
                protect,
                _pad: 0,
                addr: 0,
                size,
            };
            let mut bytes_returned = 0;
            DeviceIoControl(
                self.handle,
                IOCTL_ALLOCATE_VIRTUAL_MEMORY,
                &request as *const _ as *const _,
                std::mem::size_of::<KAllocMemRequest>() as u32,
                &mut request as *mut _ as *mut _,
                std::mem::size_of::<KAllocMemRequest>() as u32,
                &mut bytes_returned,
                std::ptr::null_mut(),
            );

            if request.addr != 0 {
                Some(request.addr as usize)
            } else {
                None
            }
        }
    }

    #[must_use]
    pub fn protect_memory(&self, pid: u32, address: usize, size: usize, protect: u32) -> bool {
        unsafe {
            let mut request = KProtectMemRequest {
                pid,
                addr: address as u64,
                size,
                protect,
            };
            let mut bytes_returned = 0;
            DeviceIoControl(
                self.handle,
                IOCTL_PROTECT_VIRTUAL_MEMORY,
                &request as *const _ as *const _,
                std::mem::size_of::<KProtectMemRequest>() as u32,
                &mut request as *mut _ as *mut _,
                std::mem::size_of::<KProtectMemRequest>() as u32,
                &mut bytes_returned,
                std::ptr::null_mut(),
            ) != 0
        }
    }

    pub fn read_memory_fallible(
        &self,
        pid: u32,
        address: usize,
        buffer: *mut u8,
        size: usize,
    ) -> Result<(), DriverError> {
        if !self.read_memory(pid, address, buffer, size) {
            return Err(DriverError::IoctlFailed);
        }
        Ok(())
    }

    pub fn write_memory_fallible(
        &self,
        pid: u32,
        destination: usize,
        source: *const u8,
        size: usize,
    ) -> Result<(), DriverError> {
        if !self.write_memory(pid, destination, source, size) {
            return Err(DriverError::IoctlFailed);
        }
        Ok(())
    }

    pub fn get_module_base_fallible(
        &self,
        pid: u32,
        module_name: &str,
    ) -> Result<usize, DriverError> {
        self.get_module_base(pid, module_name)
            .ok_or_else(|| DriverError::ModuleNotFound(module_name.to_owned()))
    }

    pub fn protect_memory_fallible(
        &self,
        pid: u32,
        address: usize,
        size: usize,
        protect: u32,
    ) -> Result<(), DriverError> {
        if !self.protect_memory(pid, address, size, protect) {
            return Err(DriverError::IoctlFailed);
        }
        Ok(())
    }
}

#[cfg(target_os = "windows")]
impl Drop for Driver {
    fn drop(&mut self) {
        if self.is_valid() {
            unsafe { CloseHandle(self.handle) };
        }
    }
}

#[cfg(target_os = "windows")]
const IOCTL_READ_MEMORY: u32 = (0x22 << 16) | (0x81C << 2);
#[cfg(target_os = "windows")]
const IOCTL_WRITE_MEMORY: u32 = (0x22 << 16) | (0x9AF << 2);
#[cfg(target_os = "windows")]
const IOCTL_GET_MODULE_BASE: u32 = (0x22 << 16) | (0xA2B << 2);
#[cfg(target_os = "windows")]
const IOCTL_PROTECT_VIRTUAL_MEMORY: u32 = (0x22 << 16) | (0xB3D << 2);
#[cfg(target_os = "windows")]
const IOCTL_ALLOCATE_VIRTUAL_MEMORY: u32 = (0x22 << 16) | (0xC4F << 2);

#[cfg(target_os = "windows")]
#[repr(C)]
#[derive(Clone, Copy)]
struct KReadWriteRequest {
    pid: u32,
    _pad: u32,
    src: u64,
    dst: u64,
    size: u64,
}

#[cfg(target_os = "windows")]
#[repr(C)]
#[derive(Clone, Copy)]
struct KGetModuleBaseRequest {
    pid: u32,
    _pad: u32,
    handle: u64,
    name: [u16; 260],
}

#[cfg(target_os = "windows")]
#[repr(C)]
#[derive(Clone, Copy)]
struct KAllocMemRequest {
    pid: u32,
    allocation_type: u32,
    protect: u32,
    _pad: u32,
    addr: u64,
    size: usize,
}

#[cfg(target_os = "windows")]
#[repr(C)]
#[derive(Clone, Copy)]
struct KProtectMemRequest {
    pid: u32,
    protect: u32,
    addr: u64,
    size: usize,
}
