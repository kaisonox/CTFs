from simulate_aes_asm import encrypt_block_uc
from pack_and_sim import derive_round_keys_from_seed, compute_gap
import random
import re


block_code = """
.text:00007FF7ACDE1004 65 48 8B 04 25                 mov     rax, gs:60h
.text:00007FF7ACDE1004 60 00 00 00
.text:00007FF7ACDE100D 48 8B 40 20                    mov     rax, [rax+20h]
.text:00007FF7ACDE1011 48 8B 48 20                    mov     rcx, [rax+20h]
.text:00007FF7ACDE1015 31 D2                          xor     edx, edx
.text:00007FF7ACDE1017 45 31 C0                       xor     r8d, r8d
.text:00007FF7ACDE101A 45 31 C9                       xor     r9d, r9d
.text:00007FF7ACDE101D 48 8D 44 24 10                 lea     rax, [rsp+10h]
.text:00007FF7ACDE1022 48 89 44 24 20                 mov     [rsp+20h], rax
.text:00007FF7ACDE1027 48 8D 04 24                    lea     rax, [rsp]
.text:00007FF7ACDE102B 48 89 44 24 28                 mov     [rsp+28h], rax
.text:00007FF7ACDE1030 C7 44 24 30 08                 mov     dword ptr [rsp+30h], 8
.text:00007FF7ACDE1030 00 00 00
.text:00007FF7ACDE1038 48 C7 44 24 38                 mov     qword ptr [rsp+38h], 0
.text:00007FF7ACDE1038 00 00 00 00
.text:00007FF7ACDE1041 48 C7 44 24 40                 mov     qword ptr [rsp+40h], 0
.text:00007FF7ACDE1041 00 00 00 00
.text:00007FF7ACDE104A 49 89 CA                       mov     r10, rcx
.text:00007FF7ACDE104D B8 06 00 00 00                 mov     eax, 6
.text:00007FF7ACDE1052 85 C0                          test    eax, eax
.text:00007FF7ACDE1054 74 05                          jz      short loc_7FF7ACDE1059+2
.text:00007FF7ACDE1056 EB 01                          jmp     short near ptr loc_7FF7ACDE1059
.text:00007FF7ACDE1058                ; ---------------------------------------------------------------------------
.text:00007FF7ACDE1058 C3                             retn
.text:00007FF7ACDE1059                ; ---------------------------------------------------------------------------
.text:00007FF7ACDE1059
.text:00007FF7ACDE1059                loc_7FF7ACDE1059:                       ; CODE XREF: .text:00007FF7ACDE1054↑j
.text:00007FF7ACDE1059                                                        ; .text:00007FF7ACDE1056↑j
.text:00007FF7ACDE1059 48 83 EC 08                    sub     rsp, 8
.text:00007FF7ACDE105D 0F 05                          syscall                 ; Low latency system call
.text:00007FF7ACDE105F 48 83 C4 08                    add     rsp, 8
.text:00007FF7ACDE1063 66 8B 04 24                    mov     ax, [rsp]
.text:00007FF7ACDE1067 0F B7 C0                       movzx   eax, ax
.text:00007FF7ACDE106A 66 8B 5C 24 02                 mov     bx, [rsp+2]
.text:00007FF7ACDE106F 66 89 5C 24 40                 mov     [rsp+40h], bx
.text:00007FF7ACDE1074 66 0F 6E C0                    movd    xmm0, eax
.text:00007FF7ACDE1078 66 0F 70 C0 00                 pshufd  xmm0, xmm0, 0
.text:00007FF7ACDE107D 66 0F 6F C8                    movdqa  xmm1, xmm0
.text:00007FF7ACDE1081 66 0F 73 F9 02                 pslldq  xmm1, 2
.text:00007FF7ACDE1086 66 0F EF C1                    pxor    xmm0, xmm1
.text:00007FF7ACDE108A 66 0F 73 F9 04                 pslldq  xmm1, 4
.text:00007FF7ACDE108F 66 0F EF C1                    pxor    xmm0, xmm1
.text:00007FF7ACDE1093 BB B9 79 37 9E                 mov     ebx, 9E3779B9h
.text:00007FF7ACDE1098 66 0F 6E D3                    movd    xmm2, ebx
.text:00007FF7ACDE109C 66 0F 70 D2 00                 pshufd  xmm2, xmm2, 0
.text:00007FF7ACDE10A1 BB 15 7C 4A 7F                 mov     ebx, 7F4A7C15h
.text:00007FF7ACDE10A6 66 0F 6E DB                    movd    xmm3, ebx
.text:00007FF7ACDE10AA 66 0F 70 DB 00                 pshufd  xmm3, xmm3, 0
.text:00007FF7ACDE10AF 66 0F 6F E8                    movdqa  xmm5, xmm0
.text:00007FF7ACDE10B3 66 0F EF EA                    pxor    xmm5, xmm2
.text:00007FF7ACDE10B7 66 0F 6F F0                    movdqa  xmm6, xmm0
.text:00007FF7ACDE10BB 66 0F 73 DE 01                 psrldq  xmm6, 1
.text:00007FF7ACDE10C0 66 0F EF F3                    pxor    xmm6, xmm3
.text:00007FF7ACDE10C4 66 0F 6F FD                    movdqa  xmm7, xmm5
.text:00007FF7ACDE10C8 66 0F EF FE                    pxor    xmm7, xmm6
.text:00007FF7ACDE10CC 66 0F 6F E6                    movdqa  xmm4, xmm6
.text:00007FF7ACDE10D0 66 0F 38 DB E4                 aesimc  xmm4, xmm4
.text:00007FF7ACDE10D5 66 89 C2                       mov     dx, ax
.text:00007FF7ACDE10D8 66 C1 C2 {rol_dx}              rol     dx, rol_dx
.text:00007FF7ACDE10DC 66 0F 7E FB                    movd    ebx, xmm7
.text:00007FF7ACDE10E0 81 E3 FF FF 00                 and     ebx, 0FFFFh
.text:00007FF7ACDE10E0 00
.text:00007FF7ACDE10E6 85 DB                          test    ebx, ebx
.text:00007FF7ACDE10E8 74 01                          jz      short loc_7FF7ACDE10EA+1
.text:00007FF7ACDE10EA EB 00                          jmp     short $+2
.text:00007FF7ACDE10EC                ; ---------------------------------------------------------------------------
.text:00007FF7ACDE10EC
.text:00007FF7ACDE10EC                loc_7FF7ACDE10EC:                       ; CODE XREF: .text:00007FF7ACDE10E8↑j
.text:00007FF7ACDE10EC                                                        ; .text:00007FF7ACDE10EA↑j
.text:00007FF7ACDE10EC 66 31 D0                       xor     ax, dx
.text:00007FF7ACDE10EF 66 31 D8                       xor     ax, bx
.text:00007FF7ACDE10F2 66 6B C0 {imul_ax}             imul    ax, imul_ax
.text:00007FF7ACDE10F6 0F B7 C0                       movzx   eax, ax
.text:00007FF7ACDE10F9 25 FF 01 00 00                 and     eax, 1FFh
.text:00007FF7ACDE10FE 05 00 01 00 00                 add     eax, 100h
.text:00007FF7ACDE1103 48 8D 3D 5A 00                 lea     rdi, unk_7FF7ACDE1164
.text:00007FF7ACDE1103 00 00
.text:00007FF7ACDE110A 48 8D 3C 07                    lea     rdi, [rdi+rax]
.text:00007FF7ACDE110E 48 89 FE                       mov     rsi, rdi
.text:00007FF7ACDE1111 48 81 C6 50 01                 add     rsi, 150h     ; Adjusted for BLOCK_SIZE
.text:00007FF7ACDE1111 00 00
.text:00007FF7ACDE1118 B9 16 00 00 00                 mov     ecx, 16h      ; Adjusted for BLOCK_SIZE
.text:00007FF7ACDE111D
.text:00007FF7ACDE111D                loc_7FF7ACDE111D:                     ; CODE XREF: .text:00007FF7ACDE1137↓j
.text:00007FF7ACDE111D F3 0F 6F 0E                    movdqu  xmm1, xmmword ptr [rsi]
.text:00007FF7ACDE1121 66 0F EF CF                    pxor    xmm1, xmm7
.text:00007FF7ACDE1125 66 0F 38 DE CC                 aesdec  xmm1, xmm4
.text:00007FF7ACDE112A 66 0F 38 DF CD                 aesdeclast xmm1, xmm5
.text:00007FF7ACDE112F F3 0F 7F 0E                    movdqu  xmmword ptr [rsi], xmm1
.text:00007FF7ACDE1133 48 83 EE 10                    sub     rsi, 10h
.text:00007FF7ACDE1137 E2 E4                          loop    loc_7FF7ACDE111D
.text:00007FF7ACDE1139 48 89 FE                       mov     rsi, rdi
.text:00007FF7ACDE113C 48 81 C6 5F 01                 add     rsi, 15Fh     ; Adjusted for BLOCK_SIZE
.text:00007FF7ACDE113C 00 00
.text:00007FF7ACDE1143 B9 60 01 00 00                 mov     ecx, 160h     ; Adjusted for BLOCK_SIZE  
.text:00007FF7ACDE1148 48 31 D2                       xor     rdx, rdx
.text:00007FF7ACDE114B
.text:00007FF7ACDE114B                loc_7FF7ACDE114B:                     ; CODE XREF: .text:00007FF7ACDE1160↓j
.text:00007FF7ACDE114B 8A 06                          mov     al, [rsi]
.text:00007FF7ACDE114D 89 D3                          mov     ebx, edx
.text:00007FF7ACDE114F 83 E3 01                       and     ebx, 1
.text:00007FF7ACDE1152 8A 5C 1C 40                    mov     bl, [rsp+rbx+40h]
.text:00007FF7ACDE1156 30 D8                          xor     al, bl
.text:00007FF7ACDE1158 88 06                          mov     [rsi], al
.text:00007FF7ACDE115A 48 FF CE                       dec     rsi
.text:00007FF7ACDE115D 48 FF C2                       inc     rdx
.text:00007FF7ACDE1160 E2 E9                          loop    loc_7FF7ACDE114B
.text:00007FF7ACDE1162 FF E7                          jmp     rdi
"""

final_asm_code = """
.text:00007FF77D951000 65 48 8B 04 25                 mov     rax, gs:60h
.text:00007FF77D951000 60 00 00 00
.text:00007FF77D951009 48 8B 40 20                    mov     rax, [rax+20h]
.text:00007FF77D95100D 48 8B 48 20                    mov     rcx, [rax+20h]
.text:00007FF77D951011 31 D2                          xor     edx, edx
.text:00007FF77D951013 45 31 C0                       xor     r8d, r8d
.text:00007FF77D951016 45 31 C9                       xor     r9d, r9d
.text:00007FF77D951019 48 8D 44 24 10                 lea     rax, [rsp+arg_0]
.text:00007FF77D95101E 48 89 44 24 20                 mov     [rsp+arg_10], rax
.text:00007FF77D951023 48 8D 05 {offset_end_flag1} 00 lea     rax, end_flag2
.text:00007FF77D951023 00 00
.text:00007FF77D95102A 48 89 44 24 28                 mov     [rsp+arg_18], rax
.text:00007FF77D95102F C7 44 24 30 10                 mov     [rsp+arg_20], 10h
.text:00007FF77D95102F 00 00 00
.text:00007FF77D951037 48 C7 44 24 38                 mov     [rsp+arg_28], 0
.text:00007FF77D951037 00 00 00 00
.text:00007FF77D951040 48 C7 44 24 40                 mov     [rsp+arg_30], 0
.text:00007FF77D951040 00 00 00 00
.text:00007FF77D951049 49 89 CA                       mov     r10, rcx
.text:00007FF77D95104C B8 06 00 00 00                 mov     eax, 6
.text:00007FF77D951051 48 83 EC 08                    sub     rsp, 8
.text:00007FF77D951055 0F 05                          syscall                 ; Low latency system call
.text:00007FF77D951057 48 83 C4 08                    add     rsp, 8
.text:00007FF77D95105B 48 8D 3D {offset_end_flag2} 00 lea     rdi, end_flag2
.text:00007FF77D95105B 00 00
.text:00007FF77D951062 B9 40 00 00 00                 mov     ecx, 40h ; '@'
.text:00007FF77D951067 B0 0D                          mov     al, 0Dh
.text:00007FF77D951069 F2 AE                          repne scasb
.text:00007FF77D95106B 48 FF CF                       dec     rdi
.text:00007FF77D95106E C6 07 00                       mov     byte ptr [rdi], 0
.text:00007FF77D951071 48 8D 3D {offset_end_flag3} 00 lea     rdi, end_flag2
.text:00007FF77D951071 00 00
.text:00007FF77D951078 B9 40 00 00 00                 mov     ecx, 40h ; '@'
.text:00007FF77D95107D B0 0A                          mov     al, 0Ah
.text:00007FF77D95107F F2 AE                          repne scasb
.text:00007FF77D951081 48 FF CF                       dec     rdi
.text:00007FF77D951084 C6 07 00                       mov     byte ptr [rdi], 0
.text:00007FF77D951087 48 8D 35 {offset_end_flag4} 00 lea     rsi, end_flag2
.text:00007FF77D951087 00 00
.text:00007FF77D95108E 48 8D 3D 30 00                 lea     rdi, unk_7FF77D9510C5
.text:00007FF77D95108E 00 00
.text:00007FF77D951095 B9 {len_flag2} 00 00 00        mov     ecx, len_flag2
.text:00007FF77D95109A F3 A6                          repe cmpsb
.text:00007FF77D95109C 74 02                          jz      short loc_7FF77D9510A0
.text:00007FF77D95109E EB 20                          jmp     short loc_7FF77D9510C0
.text:00007FF77D9510A0                ; ---------------------------------------------------------------------------
.text:00007FF77D9510A0
.text:00007FF77D9510A0                loc_7FF77D9510A0:                       ; CODE XREF: start+9C↑j
.text:00007FF77D9510A0 48 B8 08 09 0A                 mov     rax, 0F0E0D0C0B0A0908h
.text:00007FF77D9510A0 0B 0C 0D 0E 0F
.text:00007FF77D9510AA 48 BA 01 01 02                 mov     rdx, 706050403020101h
.text:00007FF77D9510AA 03 04 05 06 07
.text:00007FF77D9510B4 66 48 0F 6E C8                 movq    xmm1, rax
.text:00007FF77D9510B9 66 48 0F 3A 22                 pinsrq  xmm1, rdx, 1
.text:00007FF77D9510B9 CA 01
.text:00007FF77D9510C0
.text:00007FF77D9510C0                loc_7FF77D9510C0:                       ; CODE XREF: start+9E↑j
.text:00007FF77D9510C0 48 83 C4 50                    add     rsp, 50h
.text:00007FF77D9510C4 CB                             retf
.text:00007FF77D9510C4                start           endp ; sp-analysis failed
.text:00007FF77D9510C4
.text:00007FF77D9510C4                ; ---------------------------------------------------------------------------
.text:00007FF77D9510C5 {flag2} 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
"""

asm_code = """
; hg.asm - WoW64 Heaven's Gate: 32-bit entry -> 64-bit syscalls -> back to 32-bit
;
; Build as 32-bit (x86) PE under WoW64. The 64-bit stub is embedded in the same module
; and is reached via a far return (retf) to CS 0x33. Returning to 32-bit uses retf to CS 0x23.
;
; Notes:
; - This relies on the image being mapped below 4GB so RIP target fits in 32-bit.
; - Works only in WoW64 (32-bit process on x64 Windows). Not valid for native x64-only process.

default rel

section .data

section .text align=16

; ------------------------------ 32-bit entry (WoW64) ------------------------------
BITS 32
global start
start:
    ; Far call to 64-bit CS (0x33) -> label x64_start
    db 0x9A                             ; CALL FAR ptr16:32
    dd x64_print_banner                 ; 32-bit offset
    dw 0x0033                           ; 64-bit CS selector
    db 0x9A                             ; CALL FAR ptr16:32
    dd x64_start                        ; 32-bit offset
    dw 0x0033                           ; 64-bit CS selector
    db 0x9A                             ; CALL FAR ptr16:32
    dd x64_print_result                 ; 32-bit offset
    dw 0x0033                           ; 64-bit CS selector

.halt:
    jmp .halt


; ------------------------------ 64-bit stub ------------------------------
BITS 64
x64_start:
sub     rsp, 50h

{byte_code}

x64_print_banner:
    mov     rax, [gs:0x60]
    mov     rax, [rax+0x20]
    mov     rcx, [rax+0x28]
    sub     rsp, 0x50
    xor     edx, edx
    xor     r8d, r8d
    xor     r9d, r9d
    lea     rax, [rsp+0x10]
    mov     [rsp+0x20], rax
    lea     rax, [rel banner]
    mov     [rsp+0x28], rax
    mov     dword [rsp+0x30], banner_len
    mov     qword [rsp+0x38], 0
    mov     qword [rsp+0x40], 0
    mov     r10, rcx
    mov     eax, 8
    sub     rsp, 8
    syscall
    add     rsp, 0x58
    retf
banner:     db "Pass through Heaven or descend into Hell",10,0
banner_len  equ $-banner

x64_print_result:
    ; Check if xmm1 equals 0102030405060708090a0b0c0d0e0f
    mov     rax, 0x0f0e0d0c0b0a0908
    mov     rdx, 0x0706050403020101
    movq    xmm0, rax
    pinsrq  xmm0, rdx, 1
    pcmpeqq xmm0, xmm1
    movmskpd eax, xmm0
    cmp     eax, 3
    jne     .no_print
    ; Print success message
    mov     rax, [gs:0x60]
    mov     rax, [rax+0x20]
    mov     rcx, [rax+0x28]
    sub     rsp, 0x50
    xor     edx, edx
    xor     r8d, r8d
    xor     r9d, r9d
    lea     rax, [rsp+0x10]
    mov     [rsp+0x20], rax
    lea     rax, [rel success]
    mov     [rsp+0x28], rax
    mov     dword [rsp+0x30], success_len
    mov     qword [rsp+0x38], 0
    mov     qword [rsp+0x40], 0
    mov     r10, rcx
    mov     eax, 8
    sub     rsp, 8
    syscall
    add     rsp, 0x58
.no_print:
    retf
success:     db "Congrats, you own both realms!",10,0
success_len  equ $-success
"""

def asm_to_bytearray(asm_str: str) -> bytearray:
    """
    Convert an assembly dump string into a bytearray of machine code.
    Keeps only the hex bytes from the machine code section of each line.
    """
    hex_bytes = []
    for line in asm_str.split('\n'):
        # Skip empty lines and comment-only lines
        if not line.strip() or line.strip().startswith(';'):
            continue
            
        # Look for the pattern: address followed by hex bytes, then instruction
        # Format: .text:00007FF77D9510A0 48 B8 08 09 0A    mov     rax, ...
        parts = line.split()
        if len(parts) >= 2:
            # Find the first part that looks like an address (contains :)
            addr_idx = -1
            for i, part in enumerate(parts):
                if ':' in part:
                    addr_idx = i
                    break
            
            # Extract hex bytes after the address
            if addr_idx >= 0 and addr_idx + 1 < len(parts):
                for part in parts[addr_idx + 1:]:
                    # Stop at the first non-hex part (instruction mnemonic)
                    if not re.match(r'^[0-9A-Fa-f]{2}$', part):
                        break
                    hex_bytes.append(part)
    
    return bytearray(int(b, 16) for b in hex_bytes)

FLAG = 'KMACTF{32bit_heaven_crashed_into_64bit_hellish_syscalls}'

flag1 = FLAG[:30]+'?'*12+FLAG[42:]  # KMACTF{32bit_heaven_crashed_in????????????lish_syscalls}
flag2 = FLAG[30:42]  # to_64bit_hel

num_blocks = len(FLAG)//4

BLOCK_SIZE = 352

byte_code = bytearray()
rol_dx = random.randint(1, 15)
imul_ax = random.randint(1, 15)
byte_code.extend(asm_to_bytearray(block_code.format(rol_dx=f"{rol_dx:02X}", imul_ax=f"{imul_ax:02X}")))

for i in range(num_blocks):
    key_bytes = flag1[i*4:i*4+4].encode('ascii')
    key32 = int.from_bytes(key_bytes, 'little')
    seed = key32 & 0xFFFF
    xor_bytes = (key32 >> 16) & 0xFFFF
    xor_bytes = ((xor_bytes & 0xFF) << 8) | ((xor_bytes >> 8) & 0xFF)
    rk0, rk1, rk2 = derive_round_keys_from_seed(seed)
    gap = compute_gap(seed, rk2, rol_dx=rol_dx, imul_ax=imul_ax)
    padding_bytes = [random.randint(0, 255) for _ in range(gap)]
    byte_code.extend(padding_bytes)
    if i != num_blocks - 1:
        rol_dx = random.randint(1, 15)
        imul_ax = random.randint(1, 15)
        xor_data = asm_to_bytearray(block_code.format(rol_dx=f"{rol_dx:02X}", imul_ax=f"{imul_ax:02X}"))
    else:
        xor_data = asm_to_bytearray(final_asm_code.format(flag2=" ".join(f"{ord(c):02X}" for c in flag2),
                                                        len_flag2=f"{len(flag2):02X}", 
                                                        offset_end_flag1=f"{0x9C+len(flag2):02X}",  # Make lea reg64, end_flag2 point to the end of the flag2 data
                                                        offset_end_flag2=f"{0x64+len(flag2):02X}",  # offset_end_flag should not exceed 0xFF
                                                        offset_end_flag3=f"{0x4E+len(flag2):02X}",
                                                        offset_end_flag4=f"{0x38+len(flag2):02X}"))
        xor_data.extend([random.randint(0, 255) for _ in range(BLOCK_SIZE - len(xor_data))])
    xor_byte0 = xor_bytes & 0xFF
    xor_byte1 = (xor_bytes >> 8) & 0xFF
    for i in range(len(xor_data)):
        if i & 1 == 0:  # even index
            xor_data[i] ^= xor_byte0
        else:  # odd index
            xor_data[i] ^= xor_byte1
    ct = bytearray()

    for j in range(0, BLOCK_SIZE, 16):
        block = xor_data[j:j + 16]
        ct_block = encrypt_block_uc(block, rk0, rk1, rk2)
        ct.extend(ct_block)
    _block_bytes = list(ct)
    byte_code.extend(_block_bytes)


# Convert byte arrays to strings for assembly

asm_code = asm_code.format(byte_code='db ' + ', '.join(hex(b) for b in byte_code))

with open('hg.asm', 'w') as f:
    f.write(asm_code)

