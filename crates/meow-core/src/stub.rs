use dynasmrt::{DynasmApi, DynasmLabelApi, dynasm};

pub fn build_load_library_stub(
    name_remote: u64,
    loadlibraryw_remote: u64,
    result_remote: u64,
    signal_remote: u64,
) -> Vec<u8> {
    let mut ops = dynasmrt::x64::Assembler::new().unwrap();
    dynasm!(ops
        ; .arch x64
        ; sub rsp, BYTE 0x28
        ; mov rcx, QWORD name_remote as i64
        ; mov rax, QWORD loadlibraryw_remote as i64
        ; call rax
        ; mov r11, QWORD result_remote as i64
        ; mov QWORD [r11], rax
        ; mov r11, QWORD signal_remote as i64
        ; mov DWORD [r11], 0x69 as _
        ; add rsp, BYTE 0x28
        ; ret
    );
    ops.finalize().unwrap().to_vec()
}

#[allow(clippy::too_many_arguments)]
pub fn build_entry_point_stub(
    remote_base: u64,
    entry_point: u64,
    signal_addr: u64,
    exception_functions_addr: u64,
    exception_functions_count: u32,
    rtl_add_function_table_remote: u64,
    tls_callbacks_addr: u64,
) -> Vec<u8> {
    let mut ops = dynasmrt::x64::Assembler::new().unwrap();

    dynasm!(ops
        ; .arch x64
        ; push rbx
        ; push rsi
        ; push rdi
        ; sub rsp, BYTE 0x20
        ; mov rsi, QWORD remote_base as i64
        ; mov rdi, QWORD signal_addr as i64
    );

    if exception_functions_addr != 0
        && exception_functions_count != 0
        && rtl_add_function_table_remote != 0
    {
        dynasm!(ops
            ; .arch x64
            ; mov rcx, QWORD exception_functions_addr as i64
            ; mov edx, DWORD exception_functions_count as _
            ; mov r8, rsi
            ; mov rax, QWORD rtl_add_function_table_remote as i64
            ; call rax
        );
    }

    if tls_callbacks_addr != 0 {
        dynasm!(ops
            ; .arch x64
            ; mov rbx, QWORD tls_callbacks_addr as i64
            ; ->tls_loop:
            ; mov rax, QWORD [rbx]
            ; test rax, rax
            ; jz ->tls_done
            ; mov rcx, rsi
            ; mov edx, DWORD 1 as _
            ; xor r8, r8
            ; call rax
            ; add rbx, BYTE 8
            ; jmp ->tls_loop
            ; ->tls_done:
        );
    }

    dynasm!(ops
        ; .arch x64
        ; mov rcx, rsi
        ; mov edx, DWORD 1 as _
        ; mov r8d, DWORD 1 as _
        ; mov rax, QWORD entry_point as i64
        ; call rax
        ; mov DWORD [rdi], 0x69 as _
        ; add rsp, BYTE 0x20
        ; pop rdi
        ; pop rsi
        ; pop rbx
        ; ret
    );

    ops.finalize().unwrap().to_vec()
}

pub fn manual_map_stub() -> Vec<u8> {
    let mut ops = dynasmrt::x64::Assembler::new().unwrap();
    dynasm!(ops
        ; .arch x64
        ; push rsi
        ; push r14
        ; push r15
        ; sub rsp, BYTE 0x20
        ; mov r15, QWORD [rcx+8]
        ; mov r14, rcx
        ; mov rsi, QWORD [rcx]
        ; cmp DWORD [r15+0x94], BYTE 0
        ; je ->call_entry
        ; mov QWORD [rsp+0x50], rdi
        ; mov edi, DWORD [r15+0x90]
        ; add rdi, BYTE 0x0c
        ; add rdi, rsi
        ; mov eax, DWORD [rdi]
        ; test eax, eax
        ; je ->restore
        ; mov QWORD [rsp+0x40], rbx
        ; mov QWORD [rsp+0x48], rbp
        ; ->reloc_block:
        ; mov ecx, eax
        ; mov rax, QWORD [r14+0x10]
        ; add rcx, rsi
        ; call rax
        ; mov ebx, DWORD [rdi+4]
        ; mov rbp, rax
        ; add rbx, rsi
        ; mov rcx, QWORD [rbx]
        ; test rcx, rcx
        ; je ->next_dll
        ; ->import_loop:
        ; mov r8, QWORD [r14+0x18]
        ; lea rdx, [rsi+2]
        ; add rdx, rcx
        ; mov rcx, rbp
        ; call r8
        ; mov QWORD [rbx], rax
        ; lea rbx, [rbx+8]
        ; mov rcx, QWORD [rbx]
        ; test rcx, rcx
        ; jne ->import_loop
        ; ->next_dll:
        ; mov eax, DWORD [rdi+0x14]
        ; add rdi, BYTE 0x14
        ; test eax, eax
        ; jne ->reloc_block
        ; mov rbp, QWORD [rsp+0x48]
        ; mov rbx, QWORD [rsp+0x40]
        ; ->restore:
        ; mov rdi, QWORD [rsp+0x50]
        ; ->call_entry:
        ; mov eax, DWORD [r15+0x28]
        ; xor r8d, r8d
        ; add rax, rsi
        ; mov edx, DWORD 1 as _
        ; mov rcx, rsi
        ; call rax
        ; xor eax, eax
        ; add rsp, BYTE 0x20
        ; pop r15
        ; pop r14
        ; pop rsi
        ; ret
    );
    ops.finalize().unwrap().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_library_stub_roundtrip() {
        let sc = build_load_library_stub(0x1111, 0x2222, 0x3333, 0x4444);
        assert!(!sc.is_empty());
        assert_eq!(&sc[..4], &[0x48, 0x83, 0xEC, 0x28]);
        assert_eq!(sc[sc.len() - 1], 0xC3);
        assert!(sc.windows(8).any(|w| w == 0x1111u64.to_le_bytes()));
        assert!(sc.windows(8).any(|w| w == 0x2222u64.to_le_bytes()));
        assert!(sc.windows(8).any(|w| w == 0x3333u64.to_le_bytes()));
        assert!(sc.windows(8).any(|w| w == 0x4444u64.to_le_bytes()));
    }

    #[test]
    fn entry_point_stub_without_optionals() {
        let sc = build_entry_point_stub(0x1111, 0x2222, 0x3333, 0, 0, 0, 0);
        assert!(!sc.is_empty());
        assert_eq!(sc[sc.len() - 1], 0xC3);
        assert!(sc.windows(8).any(|w| w == 0x1111u64.to_le_bytes()));
        assert!(sc.windows(8).any(|w| w == 0x2222u64.to_le_bytes()));
        assert!(sc.windows(8).any(|w| w == 0x3333u64.to_le_bytes()));
    }

    #[test]
    fn entry_point_stub_with_optionals_is_longer() {
        let plain = build_entry_point_stub(0x1111, 0x2222, 0x3333, 0, 0, 0, 0);
        let full = build_entry_point_stub(0x1111, 0x2222, 0x3333, 0x4444, 3, 0x5555, 0x6666);
        assert!(full.len() > plain.len());
        assert!(full.windows(8).any(|w| w == 0x4444u64.to_le_bytes()));
        assert!(full.windows(8).any(|w| w == 0x5555u64.to_le_bytes()));
        assert!(full.windows(8).any(|w| w == 0x6666u64.to_le_bytes()));
    }

    #[test]
    fn manual_map_stub_ends_with_ret() {
        let sc = manual_map_stub();
        assert!(sc.len() > 100);
        assert_eq!(sc[sc.len() - 1], 0xC3);
    }
}
