#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Dump asm of exported 'check' (aka _Z5checkPh) from a DLL until first RET.
- Resolve call targets (local export or imported from other DLLs)
- Collect fNN... calls in order and show (index, exporting DLL, function)
- Record MOVABS rax, imm64 (48 B8 ..) immediates in order

Requires: capstone, pefile
    pip install capstone pefile

Usage:
    python dump_check_calls.py path\to\file.dll
"""
import sys, os, re, struct
from typing import Dict, Tuple, List, Optional
import json

try:
    import pefile
except ImportError:
    print("[!] pefile not installed: pip install pefile", file=sys.stderr); sys.exit(1)
try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    from capstone.x86 import *
except ImportError:
    print("[!] capstone not installed: pip install capstone", file=sys.stderr); sys.exit(1)

F_PATTERN = re.compile(r"^f\d+$")
MANGLED_F_PATTERN = re.compile(r"^_Z(\d+)f(\d+)Ph$")  # _Z21f26328791948844762963Ph

def rva_to_off(pe: pefile.PE, rva: int) -> Optional[int]:
    try: return pe.get_offset_from_rva(rva)
    except Exception: return None

def va_to_rva(pe: pefile.PE, va: int) -> int:
    return va - pe.OPTIONAL_HEADER.ImageBase

def va_to_off(pe: pefile.PE, va: int) -> Optional[int]:
    return rva_to_off(pe, va_to_rva(pe, va))

def read_bytes(pe: pefile.PE, start_va: int, size: int) -> bytes:
    off = va_to_off(pe, start_va)
    if off is None: return b""
    end_off = off + size
    data = pe.__data__
    if end_off > len(data) or off < 0: return b""
    return data[off:end_off]

def find_export_va(pe: pefile.PE, names: List[str]) -> Optional[int]:
    if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"): return None
    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if not exp.name: continue
        nm = exp.name.decode(errors="ignore")
        if nm in names and not exp.forwarder:
            return pe.OPTIONAL_HEADER.ImageBase + exp.address
    return None

def build_export_map(pe: pefile.PE) -> Dict[int, str]:
    m = {}
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name and not exp.forwarder:
                m[pe.OPTIONAL_HEADER.ImageBase + exp.address] = exp.name.decode(errors="ignore")
    return m

def build_iat_ranges_and_names(pe: pefile.PE) -> Tuple[List[Tuple[int,int]], Dict[int, Tuple[str,str]]]:
    ranges: List[Tuple[int,int]] = []
    names: Dict[int, Tuple[str,str]] = {}
    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"): return ranges, names

    ptr_size = 8 if pe.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS else 4

    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll = entry.dll.decode(errors="ignore") if getattr(entry, "dll", None) else "unknown"
        first_thunk_rva = getattr(entry.struct, "FirstThunk", 0) or 0
        if first_thunk_rva:
            count = len(entry.imports)
            start_va = pe.OPTIONAL_HEADER.ImageBase + first_thunk_rva
            end_va   = start_va + count * ptr_size
            ranges.append((start_va, end_va))
        for idx, imp in enumerate(entry.imports):
            thunk_va = imp.address
            if not thunk_va and first_thunk_rva:
                thunk_va = pe.OPTIONAL_HEADER.ImageBase + first_thunk_rva + idx * ptr_size
            if not thunk_va: continue
            if imp.name:
                func = imp.name.decode(errors="ignore")
            elif imp.ordinal is not None:
                func = f"ord{imp.ordinal}"
            else:
                func = "unknown"
            names[thunk_va] = (dll, func)
    return ranges, names

def in_any_range(va: int, ranges: List[Tuple[int,int]]) -> bool:
    return any(a <= va < b for a,b in ranges)

def demangle_f_from_mangled(name: str) -> Optional[str]:
    m = MANGLED_F_PATTERN.match(name)
    if not m: return None
    nlen = int(m.group(1)); fnum = m.group(2)
    return f"f{fnum}"

def pretty_bytes(code: bytes) -> str:
    return " ".join(f"{b:02X}" for b in code)

def is_ret(insn) -> bool:
    return insn.id in (X86_INS_RET,)

def insn_is_movabs_rax_imm64(insn) -> Optional[int]:
    """
    Robustly detect 'movabs rax, imm64' regardless of Capstone operand quirks.
    Exact encoding is: 48 B8 <imm64 little-endian>.
    """
    b = insn.bytes or b""
    if len(b) >= 10 and b[0] == 0x48 and b[1] == 0xB8:
        imm = int.from_bytes(b[2:10], byteorder="little", signed=False)
        return imm
    return None

def compute_rel_target(insn) -> Optional[int]:
    ops = insn.operands
    if len(ops) >= 1 and ops[0].type == X86_OP_IMM:
        return ops[0].imm & ((1<<64)-1)
    return None

def compute_ripmem_target(insn) -> Optional[int]:
    for op in insn.operands:
        if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
            return (insn.address + insn.size + op.mem.disp) & ((1<<64)-1)
    return None

def resolve_call(pe: pefile.PE,
                 insn,
                 export_map: Dict[int,str],
                 iat_ranges: List[Tuple[int,int]],
                 iat_names: Dict[int, Tuple[str,str]],
                 cur_dll_name: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Return (dll_name, func_name) if resolvable.
    - Direct call rel32 -> local VA: if matches local export, dll = current DLL.
    - call [rip+disp] -> IAT thunk: dll = imported dll.
    - call [rip+disp] to pointer of local export in .data: dll = current DLL.
    """
    # Direct call rel32
    if insn.id == X86_INS_CALL and insn.operands and insn.operands[0].type == X86_OP_IMM:
        target = compute_rel_target(insn)
        if target is None: return None, None
        if target in export_map:
            return cur_dll_name, export_map[target]
        # not exported: unknown to us
        return None, None

    # Indirect RIP-relative memory
    if insn.id == X86_INS_CALL:
        target_ptr = compute_ripmem_target(insn)
        if target_ptr is not None:
            if in_any_range(target_ptr, iat_ranges):
                dll, func = iat_names.get(target_ptr, ("unknown", "unknown"))
                return dll, func
            data = read_bytes(pe, target_ptr, 8)
            if len(data) == 8:
                q = struct.unpack("<Q", data)[0]
                if q in export_map:
                    return cur_dll_name, export_map[q]
    return None, None

def dump_check_call(path: str):
    pe = pefile.PE(path, fast_load=False)
    cur_dll_name = os.path.basename(path)

    check_va = find_export_va(pe, ["check", "_Z5checkPh"])
    if check_va is None:
        print(f"[!] '{cur_dll_name}' has no exported 'check' or '_Z5checkPh'", file=sys.stderr)
        sys.exit(2)

    export_map = build_export_map(pe)
    iat_ranges, iat_names = build_iat_ranges_and_names(pe)

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    window_size = 0x10000
    code = read_bytes(pe, check_va, window_size)
    if not code:
        print("[!] Could not read code at check()", file=sys.stderr); sys.exit(3)

    # collections
    imm64s: List[int] = []
    f_calls: List[Tuple[int, str, str]] = []  # (index, dll_name, f_name)

    # backtracker: mov rax, [rip+disp] -> call rax
    last_rax_from_rip_target: Optional[int] = None

    # print(f"; DLL: {cur_dll_name}")
    # print(f"; Exported function: check @ 0x{check_va:016X}")
    # print("; ---------------------------------------------------")

    call_index = 0

    for insn in md.disasm(code, check_va):
        bytes_s = pretty_bytes(insn.bytes)
        asm_line = f"{insn.address:016X}  {bytes_s:<32}  {insn.mnemonic} {insn.op_str}".rstrip()
        extra = []

        # MOVABS rax, imm64
        imm = insn_is_movabs_rax_imm64(insn)
        if imm is not None:
            imm64s.append(imm)
            extra.append(f"; movabs imm64=0x{imm:016X}")

        # Track "mov rax, [rip+disp]"
        if insn.id == X86_INS_MOV and len(insn.operands) == 2:
            dst, src = insn.operands
            if dst.type == X86_OP_REG and dst.reg == X86_REG_RAX and src.type == X86_OP_MEM and src.mem.base == X86_REG_RIP:
                last_rax_from_rip_target = (insn.address + insn.size + src.mem.disp) & ((1<<64)-1)
            else:
                if insn.regs_write and X86_REG_RAX in insn.regs_write:
                    last_rax_from_rip_target = None
        else:
            if insn.regs_write and X86_REG_RAX in insn.regs_write:
                last_rax_from_rip_target = None

        # Resolve CALL
        resolved_dll, resolved_name = None, None
        if insn.id == X86_INS_CALL:
            # direct or RIP-mem
            resolved_dll, resolved_name = resolve_call(pe, insn, export_map, iat_ranges, iat_names, cur_dll_name)

            # handle "call rax" just after "mov rax, [rip+disp]"
            if (not resolved_name and len(insn.operands) == 1 and
                insn.operands[0].type == X86_OP_REG and insn.operands[0].reg == X86_REG_RAX and
                last_rax_from_rip_target):
                target_ptr = last_rax_from_rip_target
                if in_any_range(target_ptr, iat_ranges):
                    resolved_dll, resolved_name = iat_names.get(target_ptr, ("unknown", "unknown"))
                else:
                    data = read_bytes(pe, target_ptr, 8)
                    if len(data) == 8:
                        q = struct.unpack("<Q", data)[0]
                        if q in export_map:
                            resolved_dll, resolved_name = cur_dll_name, export_map[q]

            if resolved_name:
                extra.append(f"; call -> {resolved_dll}!{resolved_name}")

                # If it's an f-function, record with counter + dll name
                base_name = resolved_name
                if not F_PATTERN.match(base_name):
                    dm = demangle_f_from_mangled(base_name)
                    if dm: base_name = dm
                if F_PATTERN.match(base_name):
                    call_index += 1
                    f_calls.append((call_index, resolved_dll, base_name))

        # Print line
        if extra:
            # print(f"{asm_line:<90}  {' '.join(extra)}")
            pass
        else:
            # print(asm_line)
            pass

        if is_ret(insn):
            break

    # ---- Summary ----
    # print("\n; ---------------------------------------------------")
    # print("; Summary")
    f_functions = []
    if f_calls:
        # print("; f-functions in call order:")
        for idx, dlln, fname in f_calls:
            f_functions.append(f"{dlln}!{fname}")
    else:
        f_functions.append("(none)")

    imm64_sequence = []
    if imm64s:
        imm64_sequence = [f"0x{x:016X}" for x in imm64s]

    with open(f"check_db/{cur_dll_name.split('.')[0]}.json", "w") as f:
        f.write(json.dumps({
            "f_functions": f_functions,
            "imm64_sequence": imm64_sequence
        }, indent=4))

if __name__ == "__main__":
    os.makedirs("check_db", exist_ok=True)
    for file in os.listdir("dlls"):
        if not file.lower().endswith('.dll'):
            continue
        print(f"Processing {file}")
        try:
            dump_check_call(f"dlls/{file}")
        except Exception as e:
            print(f"Error: {e}")
            continue
