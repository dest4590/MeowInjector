#![cfg_attr(not(test), no_std)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(unsafe_op_in_unsafe_fn)]

extern crate alloc;

use core::alloc::{GlobalAlloc, Layout};
use core::ffi::c_void;
use core::mem;

use wdk::println;
use wdk_sys::ntddk::{
    ExAllocatePool2, ExFreePool, IoCreateDevice, IoCreateSymbolicLink, IoDeleteDevice,
    IoDeleteSymbolicLink, IoGetCurrentProcess, IofCompleteRequest, KeStackAttachProcess,
    KeUnstackDetachProcess, ObfDereferenceObject, PsLookupProcessByProcessId,
    RtlCompareUnicodeString, RtlInitUnicodeString, ZwAllocateVirtualMemory,
};
use wdk_sys::{
    CCHAR, DEVICE_OBJECT, DO_BUFFERED_IO, DO_DEVICE_INITIALIZING, DRIVER_OBJECT,
    FILE_DEVICE_SECURE_OPEN, FILE_DEVICE_UNKNOWN, HANDLE, IRP, KAPC_STATE, NTSTATUS,
    PCUNICODE_STRING, PDRIVER_OBJECT, PEPROCESS, STATUS_INVALID_PARAMETER, STATUS_SUCCESS,
    STATUS_UNSUCCESSFUL, UNICODE_STRING,
};

const POOL_FLAG_NON_PAGED: u64 = 0;

unsafe extern "system" {
    fn IoCreateDriver(
        DriverObjectName: *mut UNICODE_STRING,
        InitializationRoutine: unsafe extern "system" fn(
            PDRIVER_OBJECT,
            PCUNICODE_STRING,
        ) -> NTSTATUS,
    ) -> NTSTATUS;

    fn MmCopyVirtualMemory(
        SourceProcess: PEPROCESS,
        SourceAddress: *const c_void,
        TargetProcess: PEPROCESS,
        TargetAddress: *mut c_void,
        BufferSize: usize,
        PreviousMode: u8,
        ReturnSize: *mut usize,
    ) -> NTSTATUS;

    fn PsGetProcessPeb(Process: PEPROCESS) -> *mut c_void;

    fn ZwProtectVirtualMemory(
        ProcessHandle: HANDLE,
        BaseAddress: *mut *mut c_void,
        RegionSize: *mut usize,
        NewProtect: u32,
        OldProtect: *mut u32,
    ) -> NTSTATUS;
}

struct WdkAllocator;

unsafe impl GlobalAlloc for WdkAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ExAllocatePool2(POOL_FLAG_NON_PAGED, layout.size() as u64, 0x6D656F77) as *mut u8
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        ExFreePool(ptr as *mut c_void);
    }
}

#[cfg(not(test))]
#[global_allocator]
static GLOBAL_ALLOCATOR: WdkAllocator = WdkAllocator;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

const IOCTL_READ_MEMORY: u32 = (0x22 << 16) | (0x81C << 2) | 0;
const IOCTL_WRITE_MEMORY: u32 = (0x22 << 16) | (0x9AF << 2) | 0;
const IOCTL_GET_MODULE_BASE: u32 = (0x22 << 16) | (0xA2B << 2) | 0;
const IOCTL_PROTECT_VIRTUAL_MEMORY: u32 = (0x22 << 16) | (0xB3D << 2) | 0;
const IOCTL_ALLOCATE_VIRTUAL_MEMORY: u32 = (0x22 << 16) | (0xC4F << 2) | 0;

#[repr(C)]
#[derive(Clone, Copy)]
struct KReadWriteRequest {
    pid: u32,
    _pad: u32,
    src: u64,
    dst: u64,
    size: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct KGetModuleBaseRequest {
    pid: u32,
    _pad: u32,
    handle: u64,
    name: [u16; 260],
}

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

#[repr(C)]
#[derive(Clone, Copy)]
struct KProtectMemRequest {
    pid: u32,
    protect: u32,
    addr: u64,
    size: usize,
}

macro_rules! wide_string {
    ($s:expr) => {{
        const S: &str = concat!($s, "\0");
        const LEN: usize = S.len();
        const OUTPUT: [u16; LEN] = {
            let bytes = S.as_bytes();
            let mut out = [0u16; LEN];
            let mut i = 0;
            while i < LEN {
                out[i] = bytes[i] as u16;
                i += 1;
            }
            out
        };
        OUTPUT
    }};
}

static DEVICE_NAME_W: [u16; 15] = wide_string!("\\Device\\{meow}");
static DOS_DEVICE_NAME_W: [u16; 19] = wide_string!("\\DosDevices\\{meow}");
static DRIVER_NAME_W: [u16; 15] = wide_string!("\\Driver\\{meow}");

const PEB_LDR_OFFSET: usize = 0x18;
const LDR_INITIALIZED_OFFSET: usize = 0x04;
const LDR_IN_MEMORY_ORDER_OFFSET: usize = 0x10;

const LDR_ENTRY_DLL_BASE_OFFSET: usize = 0x30;
const LDR_ENTRY_NAME_LENGTH_OFFSET: usize = 0x58;
const LDR_ENTRY_NAME_BUFFER_OFFSET: usize = 0x58 + 8;
const LDR_ENTRY_FLINK_OFFSET: usize = 0x00;

static mut GLOBAL_DEVICE_OBJECT: *mut DEVICE_OBJECT = core::ptr::null_mut();

#[cfg_attr(not(test), unsafe(export_name = "DriverEntry"))]
pub unsafe extern "system" fn driver_entry(
    _driver: PDRIVER_OBJECT,
    _registry_path: PCUNICODE_STRING,
) -> NTSTATUS {
    println!("[meow] DriverEntry called");

    let mut drv_name: UNICODE_STRING = mem::zeroed();
    RtlInitUnicodeString(&mut drv_name, DRIVER_NAME_W.as_ptr());

    let nt_status = IoCreateDriver(&mut drv_name as *mut _, init_driver_entry);

    println!("[meow] IoCreateDriver returned: {:#x}", nt_status);
    nt_status
}

unsafe extern "system" fn init_driver_entry(
    driver: PDRIVER_OBJECT,
    _registry_path: PCUNICODE_STRING,
) -> NTSTATUS {
    let status = init_driver(driver);
    println!("[meow] init_driver returned: {:#x}", status);
    status
}

fn init_driver(driver: PDRIVER_OBJECT) -> NTSTATUS {
    unsafe {
        let mut dev_name: UNICODE_STRING = mem::zeroed();
        let mut dos_name: UNICODE_STRING = mem::zeroed();
        RtlInitUnicodeString(&mut dev_name, DEVICE_NAME_W.as_ptr());
        RtlInitUnicodeString(&mut dos_name, DOS_DEVICE_NAME_W.as_ptr());

        let mut device_object: *mut DEVICE_OBJECT = core::ptr::null_mut();
        let status = IoCreateDevice(
            driver,
            0,
            &mut dev_name,
            FILE_DEVICE_UNKNOWN,
            FILE_DEVICE_SECURE_OPEN,
            0,
            &mut device_object,
        );

        if status != STATUS_SUCCESS {
            println!("[meow] IoCreateDevice failed: {:#x}", status);
            return status;
        }

        let status = IoCreateSymbolicLink(&mut dos_name, &mut dev_name);
        if status != STATUS_SUCCESS {
            println!("[meow] IoCreateSymbolicLink failed: {:#x}", status);
            IoDeleteDevice(device_object);
            return status;
        }

        extern "C" fn handle_create_close(_device: *mut DEVICE_OBJECT, irp: *mut IRP) -> NTSTATUS {
            unsafe {
                (*irp).IoStatus.__bindgen_anon_1.Status = STATUS_SUCCESS;
                (*irp).IoStatus.Information = 0;
                IofCompleteRequest(irp, 0 as CCHAR);
            }
            STATUS_SUCCESS
        }

        let drv = &mut *driver;
        drv.MajorFunction[0] = Some(handle_create_close);
        drv.MajorFunction[1] = Some(handle_create_close);
        drv.MajorFunction[14] = Some(handle_ioctl);
        drv.DriverUnload = Some(handle_unload);

        (*device_object).Flags |= DO_BUFFERED_IO;
        (*device_object).Flags &= !DO_DEVICE_INITIALIZING;

        GLOBAL_DEVICE_OBJECT = device_object;
    }

    println!("[meow] Device ready -- \\\\.\\{{meow}}");
    STATUS_SUCCESS
}

extern "C" fn handle_unload(driver: *mut DRIVER_OBJECT) {
    println!("[meow] Unloading...");

    unsafe {
        let mut dos_name: UNICODE_STRING = mem::zeroed();
        RtlInitUnicodeString(&mut dos_name, DOS_DEVICE_NAME_W.as_ptr());
        let _ = IoDeleteSymbolicLink(&mut dos_name);

        let drv = &mut *driver;
        if !drv.DeviceObject.is_null() {
            IoDeleteDevice(drv.DeviceObject);
        }
    }

    println!("[meow] Unloaded -- bye bye~");
}

extern "C" fn handle_ioctl(_device: *mut DEVICE_OBJECT, irp: *mut IRP) -> NTSTATUS {
    unsafe {
        let stack = (*irp)
            .Tail
            .Overlay
            .__bindgen_anon_2
            .__bindgen_anon_1
            .CurrentStackLocation;
        if stack.is_null() {
            (*irp).IoStatus.__bindgen_anon_1.Status = STATUS_UNSUCCESSFUL;
            (*irp).IoStatus.Information = 0;
            IofCompleteRequest(irp, 0 as CCHAR);
            return STATUS_UNSUCCESSFUL;
        }

        let control_code = (*stack).Parameters.DeviceIoControl.IoControlCode;
        let input_len = (*stack).Parameters.DeviceIoControl.InputBufferLength as usize;
        let buffer = (*irp).AssociatedIrp.SystemBuffer as *mut u8;

        let (status, info_size) = match control_code {
            IOCTL_ALLOCATE_VIRTUAL_MEMORY => handle_alloc_mem(buffer, input_len),
            IOCTL_PROTECT_VIRTUAL_MEMORY => handle_protect_mem(buffer, input_len),
            IOCTL_READ_MEMORY => handle_read_mem(buffer, input_len),
            IOCTL_WRITE_MEMORY => handle_write_mem(buffer, input_len),
            IOCTL_GET_MODULE_BASE => handle_get_module(buffer, input_len),
            _ => (STATUS_INVALID_PARAMETER, 0),
        };

        (*irp).IoStatus.__bindgen_anon_1.Status = status;
        (*irp).IoStatus.Information = info_size as u64;
        IofCompleteRequest(irp, 0 as CCHAR);
        status
    }
}

unsafe fn with_process_context<F, T>(pid: u32, f: F) -> Result<T, NTSTATUS>
where
    F: FnOnce(PEPROCESS) -> T,
{
    let mut target_proc: PEPROCESS = core::ptr::null_mut();
    let status = PsLookupProcessByProcessId(pid as HANDLE, &mut target_proc);
    if status < 0 {
        return Err(status);
    }

    let mut apc: KAPC_STATE = mem::zeroed();
    KeStackAttachProcess(target_proc, &mut apc);

    let result = f(target_proc);

    KeUnstackDetachProcess(&mut apc);
    ObfDereferenceObject(target_proc as *mut c_void);

    Ok(result)
}

unsafe fn handle_alloc_mem(buffer: *mut u8, input_len: usize) -> (NTSTATUS, usize) {
    let size = mem::size_of::<KAllocMemRequest>();
    if input_len < size {
        return (STATUS_INVALID_PARAMETER, 0);
    }

    let req = &mut *(buffer as *mut KAllocMemRequest);
    let pid = req.pid;

    match with_process_context(pid, |target_proc| {
        let _ = target_proc;
        let mut addr: *mut c_void = req.addr as *mut c_void;
        let mut alloc_size: u64 = req.size as u64;

        let status = ZwAllocateVirtualMemory(
            (-1isize) as HANDLE,
            &mut addr,
            0,
            &mut alloc_size,
            req.allocation_type,
            req.protect,
        );

        if status >= 0 {
            req.addr = addr as u64;
            req.size = alloc_size as usize;
        }

        status
    }) {
        Ok(status) => (status, size),
        Err(status) => (status, size),
    }
}

unsafe fn handle_protect_mem(buffer: *mut u8, input_len: usize) -> (NTSTATUS, usize) {
    let size = mem::size_of::<KProtectMemRequest>();
    if input_len < size {
        return (STATUS_INVALID_PARAMETER, 0);
    }

    let req = &mut *(buffer as *mut KProtectMemRequest);
    let pid = req.pid;

    match with_process_context(pid, |target_proc| {
        let _ = target_proc;
        let mut old_prot: u32 = 0;
        let mut addr = req.addr as *mut c_void;
        let mut prot_size: usize = req.size;

        let status = ZwProtectVirtualMemory(
            (-1isize) as HANDLE,
            &mut addr,
            &mut prot_size,
            req.protect,
            &mut old_prot,
        );

        if status >= 0 {
            req.protect = old_prot;
        }

        status
    }) {
        Ok(status) => (status, size),
        Err(status) => (status, size),
    }
}

unsafe fn handle_read_mem(buffer: *mut u8, input_len: usize) -> (NTSTATUS, usize) {
    let size = mem::size_of::<KReadWriteRequest>();
    if input_len < size {
        return (STATUS_INVALID_PARAMETER, 0);
    }

    let req = &mut *(buffer as *mut KReadWriteRequest);
    let pid = req.pid;

    let mut target_proc: PEPROCESS = core::ptr::null_mut();
    let status = PsLookupProcessByProcessId(pid as HANDLE, &mut target_proc);
    if status < 0 {
        return (status, size);
    }

    let status = copy_memory(
        target_proc,
        IoGetCurrentProcess(),
        req.src as *const c_void,
        req.dst as *mut c_void,
        req.size as usize,
    );

    ObfDereferenceObject(target_proc as *mut c_void);

    (status, size)
}

unsafe fn handle_write_mem(buffer: *mut u8, input_len: usize) -> (NTSTATUS, usize) {
    let size = mem::size_of::<KReadWriteRequest>();
    if input_len < size {
        return (STATUS_INVALID_PARAMETER, 0);
    }

    let req = &mut *(buffer as *mut KReadWriteRequest);
    let pid = req.pid;

    let mut target_proc: PEPROCESS = core::ptr::null_mut();
    let status = PsLookupProcessByProcessId(pid as HANDLE, &mut target_proc);
    if status < 0 {
        return (status, size);
    }

    let status = copy_memory(
        IoGetCurrentProcess(),
        target_proc,
        req.src as *const c_void,
        req.dst as *mut c_void,
        req.size as usize,
    );

    ObfDereferenceObject(target_proc as *mut c_void);

    (status, size)
}

unsafe fn handle_get_module(buffer: *mut u8, input_len: usize) -> (NTSTATUS, usize) {
    let size = mem::size_of::<KGetModuleBaseRequest>();
    if input_len < size {
        return (STATUS_INVALID_PARAMETER, 0);
    }

    let req = &mut *(buffer as *mut KGetModuleBaseRequest);
    let base = get_module_handle(req.pid, req.name.as_ptr());
    req.handle = base;

    (STATUS_SUCCESS, size)
}

unsafe fn copy_memory(
    source_process: PEPROCESS,
    target_process: PEPROCESS,
    source_address: *const c_void,
    target_address: *mut c_void,
    size: usize,
) -> NTSTATUS {
    let mut bytes_copied: usize = 0;
    MmCopyVirtualMemory(
        source_process,
        source_address,
        target_process,
        target_address,
        size,
        0,
        &mut bytes_copied,
    )
}

unsafe fn get_module_handle(pid: u32, module_name: *const u16) -> u64 {
    let mut target_proc: PEPROCESS = core::ptr::null_mut();
    let status = PsLookupProcessByProcessId(pid as HANDLE, &mut target_proc);
    if status < 0 {
        return 0;
    }

    let mut apc: KAPC_STATE = mem::zeroed();
    KeStackAttachProcess(target_proc, &mut apc);

    let peb = PsGetProcessPeb(target_proc);
    let mut base: u64 = 0;

    if !peb.is_null() {
        let ldr = read_ptr(peb as *const u8, PEB_LDR_OFFSET);
        if !ldr.is_null() {
            let initialized = read_byte(ldr as *const u8, LDR_INITIALIZED_OFFSET);
            if initialized != 0 {
                let list_flink = read_ptr(ldr as *const u8, LDR_IN_MEMORY_ORDER_OFFSET);
                if !list_flink.is_null() {
                    base = walk_module_list(list_flink as *const c_void, module_name);
                }
            }
        }
    }

    KeUnstackDetachProcess(&mut apc);
    ObfDereferenceObject(target_proc as *mut c_void);

    base
}

unsafe fn walk_module_list(start: *const c_void, target_name: *const u16) -> u64 {
    let target_len = wide_len(target_name);
    if target_len == 0 {
        return 0;
    }

    let mut target_unicode: UNICODE_STRING = mem::zeroed();
    target_unicode.Length = (target_len * 2) as u16;
    target_unicode.MaximumLength = (target_len * 2 + 2) as u16;
    target_unicode.Buffer = target_name as *mut u16;

    let mut current = start as *const u8;

    for _ in 0..512 {
        if current.is_null() {
            break;
        }

        let dll_base = read_ptr(current, LDR_ENTRY_DLL_BASE_OFFSET);
        let name_length = read_u16(current, LDR_ENTRY_NAME_LENGTH_OFFSET);
        let name_buffer = read_ptr(current, LDR_ENTRY_NAME_BUFFER_OFFSET);

        if !dll_base.is_null() && !name_buffer.is_null() && name_length > 0 {
            let entry_unicode = UNICODE_STRING {
                Length: name_length,
                MaximumLength: name_length,
                Buffer: name_buffer as *mut u16,
            };

            if RtlCompareUnicodeString(&entry_unicode, &target_unicode, 1) == 0 {
                return dll_base as u64;
            }
        }

        let flink = read_ptr(current, LDR_ENTRY_FLINK_OFFSET);
        if flink.is_null() || (flink as *const u8) == start as *const u8 {
            break;
        }
        current = flink as *const u8;
    }

    0
}

unsafe fn read_ptr(base: *const u8, offset: usize) -> *mut c_void {
    *(base.add(offset) as *const *mut c_void)
}

unsafe fn read_byte(base: *const u8, offset: usize) -> u8 {
    *base.add(offset)
}

unsafe fn read_u16(base: *const u8, offset: usize) -> u16 {
    *(base.add(offset) as *const u16)
}

unsafe fn wide_len(ptr: *const u16) -> usize {
    if ptr.is_null() {
        return 0;
    }
    let mut len = 0;
    while *ptr.add(len) != 0 && len < 260 {
        len += 1;
    }
    len
}
