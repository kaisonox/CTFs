#!/usr/bin/env python3
"""Shuffle x64 code ranges into jump-linked instruction slots.

This is a manual payload hardening tool. It is intentionally not wired into
build.bat because the start/end RVAs are chosen by inspection.

Example:
    python tools/obfuscate_payload.py payload.exe payload.obf.exe \
        --range 0x1234:0x12F0 --range 0x1800:0x18A0 --seed 1337

Then extract with the added section included:
    python tools/extract_payload.py payload.obf.exe payload.bin \
        --meta payload.json --sections .data,.mix,.rdata,.text
"""
from __future__ import annotations

import argparse
import random
import struct
from dataclasses import dataclass
from pathlib import Path

Cs = None
CS_ARCH_X86 = 0
CS_GRP_CALL = 0
CS_GRP_JUMP = 0
CS_GRP_RET = 0
CS_MODE_64 = 0
X86_OP_IMM = 0
X86_OP_MEM = 0
X86_REG_RIP = 0

IMAGE_FILE_HEADER_SIZE = 20
IMAGE_SECTION_HEADER_SIZE = 40
IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20B
IMAGE_SCN_CNT_CODE = 0x00000020
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
PE32_PLUS_DATA_DIRECTORY_OFF = 112
IMAGE_DIRECTORY_ENTRY_SECURITY = 4
SECTION_CHARACTERISTICS = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ


def require_capstone() -> None:
    global Cs
    global CS_ARCH_X86
    global CS_GRP_CALL
    global CS_GRP_JUMP
    global CS_GRP_RET
    global CS_MODE_64
    global X86_OP_IMM
    global X86_OP_MEM
    global X86_REG_RIP

    if Cs is not None:
        return
    try:
        from capstone import Cs as cs_class
        from capstone import CS_ARCH_X86 as cs_arch_x86
        from capstone import CS_GRP_CALL as cs_grp_call
        from capstone import CS_GRP_JUMP as cs_grp_jump
        from capstone import CS_GRP_RET as cs_grp_ret
        from capstone import CS_MODE_64 as cs_mode_64
        from capstone.x86 import X86_OP_IMM as x86_op_imm
        from capstone.x86 import X86_OP_MEM as x86_op_mem
        from capstone.x86 import X86_REG_RIP as x86_reg_rip
    except ImportError as exc:
        raise SystemExit('missing dependency: pip install capstone') from exc
    Cs = cs_class
    CS_ARCH_X86 = cs_arch_x86
    CS_GRP_CALL = cs_grp_call
    CS_GRP_JUMP = cs_grp_jump
    CS_GRP_RET = cs_grp_ret
    CS_MODE_64 = cs_mode_64
    X86_OP_IMM = x86_op_imm
    X86_OP_MEM = x86_op_mem
    X86_REG_RIP = x86_reg_rip


@dataclass
class Section:
    off: int
    name: str
    virtual_size: int
    virtual_address: int
    size_of_raw_data: int
    pointer_to_raw_data: int
    characteristics: int


@dataclass
class DecodedInsn:
    insn: object
    rva: int
    data: bytes


@dataclass
class RangePlan:
    start_rva: int
    end_rva: int
    insns: list[DecodedInsn]


def align_up(value: int, alignment: int) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


def u16(buf: bytes | bytearray, off: int) -> int:
    return struct.unpack_from('<H', buf, off)[0]


def u32(buf: bytes | bytearray, off: int) -> int:
    return struct.unpack_from('<I', buf, off)[0]


def u64(buf: bytes | bytearray, off: int) -> int:
    return struct.unpack_from('<Q', buf, off)[0]


def put_u16(buf: bytearray, off: int, value: int) -> None:
    struct.pack_into('<H', buf, off, value)


def put_u32(buf: bytearray, off: int, value: int) -> None:
    struct.pack_into('<I', buf, off, value)


def put_i8(buf: bytearray, off: int, value: int) -> None:
    if value < -0x80 or value > 0x7F:
        raise ValueError(f'rel8 out of range: {value}')
    struct.pack_into('<b', buf, off, value)


def put_i32(buf: bytearray, off: int, value: int) -> None:
    if value < -0x80000000 or value > 0x7FFFFFFF:
        raise ValueError(f'rel32 out of range: {value}')
    struct.pack_into('<i', buf, off, value)


def parse_int(s: str) -> int:
    return int(s, 0)


def parse_range(s: str) -> tuple[int, int]:
    sep = ':' if ':' in s else '-'
    if sep not in s:
        raise argparse.ArgumentTypeError('range must be START:END or START-END')
    a, b = s.split(sep, 1)
    start = parse_int(a)
    end = parse_int(b)
    if start >= end:
        raise argparse.ArgumentTypeError('range start must be below end')
    return start, end


def parse_sections(buf: bytes | bytearray, section_table: int, count: int) -> list[Section]:
    out = []
    for i in range(count):
        off = section_table + i * IMAGE_SECTION_HEADER_SIZE
        name = bytes(buf[off:off + 8]).rstrip(b'\0').decode('ascii', 'replace')
        out.append(Section(
            off=off,
            name=name,
            virtual_size=u32(buf, off + 8),
            virtual_address=u32(buf, off + 12),
            size_of_raw_data=u32(buf, off + 16),
            pointer_to_raw_data=u32(buf, off + 20),
            characteristics=u32(buf, off + 36),
        ))
    return out


def rva_to_file_offset(sections: list[Section], rva: int) -> int | None:
    for s in sections:
        span = max(s.virtual_size, s.size_of_raw_data)
        if s.virtual_address <= rva < s.virtual_address + span:
            delta = rva - s.virtual_address
            if delta >= s.size_of_raw_data:
                return None
            return s.pointer_to_raw_data + delta
    return None


def find_section(sections: list[Section], rva: int) -> Section | None:
    for s in sections:
        span = max(s.virtual_size, s.size_of_raw_data)
        if s.virtual_address <= rva < s.virtual_address + span:
            return s
    return None


def parse_pe(buf: bytearray):
    if len(buf) < 0x100 or buf[:2] != b'MZ':
        raise ValueError('not a PE/MZ file')
    pe_off = u32(buf, 0x3C)
    if buf[pe_off:pe_off + 4] != b'PE\0\0':
        raise ValueError('invalid PE signature')
    file_header = pe_off + 4
    count = u16(buf, file_header + 2)
    optional_size = u16(buf, file_header + 16)
    optional = file_header + IMAGE_FILE_HEADER_SIZE
    if u16(buf, optional) != IMAGE_NT_OPTIONAL_HDR64_MAGIC:
        raise ValueError('only PE32+ x64 is supported')
    section_table = optional + optional_size
    sections = parse_sections(buf, section_table, count)
    return pe_off, file_header, optional, optional_size, section_table, sections


def is_direct(insn: object) -> bool:
    return bool(insn.operands) and insn.operands[0].type == X86_OP_IMM


def direct_target_rva(insn: object, image_base: int) -> int:
    return int(insn.operands[0].imm) - image_base


def is_cond_jcc(insn: object) -> bool:
    b = bytes(insn.bytes)
    if len(b) >= 1 and 0x70 <= b[0] <= 0x7F:
        return True
    if len(b) >= 2 and b[0] == 0x0F and 0x80 <= b[1] <= 0x8F:
        return True
    return False


def jcc_condition(insn: object) -> int:
    b = bytes(insn.bytes)
    if len(b) >= 1 and 0x70 <= b[0] <= 0x7F:
        return b[0] & 0x0F
    if len(b) >= 2 and b[0] == 0x0F and 0x80 <= b[1] <= 0x8F:
        return b[1] & 0x0F
    raise ValueError(f'unsupported conditional jump encoding at 0x{insn.address:X}')


def relocate_rip_relative(code: bytearray, insn: object, new_va: int) -> None:
    for op in insn.operands:
        if op.type != X86_OP_MEM or op.mem.base != X86_REG_RIP:
            continue
        if insn.disp_size != 4:
            raise ValueError(f'unsupported RIP displacement size at 0x{insn.address:X}')
        target_va = insn.address + insn.size + insn.disp
        new_disp = target_va - (new_va + insn.size)
        put_i32(code, insn.disp_offset, new_disp)


def emit_rel_jmp(src_va: int, dst_va: int) -> bytes:
    out = bytearray(b'\xE9\0\0\0\0')
    put_i32(out, 1, dst_va - (src_va + 5))
    return bytes(out)


def emit_rel_call(src_va: int, dst_va: int) -> bytes:
    out = bytearray(b'\xE8\0\0\0\0')
    put_i32(out, 1, dst_va - (src_va + 5))
    return bytes(out)


def emit_near_jcc(cond: int, src_va: int, dst_va: int) -> bytes:
    out = bytearray([0x0F, 0x80 | cond, 0, 0, 0, 0])
    put_i32(out, 2, dst_va - (src_va + 6))
    return bytes(out)


def jump_key(src_va: int, dst_va: int, seed: int) -> int:
    x = (src_va ^ ((dst_va << 7) & 0xFFFFFFFF) ^ seed ^ 0x9E3779B9) & 0xFFFFFFFF
    x ^= (x >> 16)
    x = (x * 0x7FEB352D) & 0xFFFFFFFF
    x ^= (x >> 15)
    x = (x * 0x846CA68B) & 0xFFFFFFFF
    x ^= (x >> 16)
    return x & 0xFFFFFFFF


def emit_encoded_jmp(src_va: int, dst_va: int, seed: int) -> bytes:
    out = bytearray()
    variant = jump_key(src_va, dst_va, seed) % 4
    key = jump_key(src_va ^ 0x13579BDF, dst_va ^ 0x2468ACE0, seed)
    lea_off = 0
    base_va = 0
    delta = 0

    # First reserve the common tail so the target delta is known relative to
    # the actual LEA position selected by each decoder variant.
    def append_tail() -> None:
        nonlocal lea_off
        out.extend(b'\x48\x98')                # cdqe
        out.extend(b'\x50')                    # push rax
        lea_off = len(out)
        out.extend(b'\x48\x8D\x05\x00\x00\x00\x00')  # lea rax, [rip]
        out.extend(b'\x48\x01\x04\x24')        # add qword ptr [rsp], rax
        out.extend(b'\x58')                    # pop rax
        out.extend(b'\x48\x87\x44\x24\x08')    # xchg qword ptr [rsp+8], rax
        out.extend(b'\x9D')                    # popfq
        out.extend(b'\xC3')                    # ret

    # Emit a dummy immediate first; it is patched after delta is computed.
    out.extend(b'\x50')                    # push rax
    out.extend(b'\x9C')                    # pushfq
    imm_off = len(out) + 1
    out.extend(b'\xB8\x00\x00\x00\x00')    # mov eax, encoded_delta
    op_off = len(out)
    if variant == 0:
        out.extend(b'\x35\x00\x00\x00\x00')    # xor eax, key
    elif variant == 1:
        out.extend(b'\x05\x00\x00\x00\x00')    # add eax, key
    elif variant == 2:
        out.extend(b'\x2D\x00\x00\x00\x00')    # sub eax, key
    else:
        out.extend(b'\x35\x00\x00\x00\x00')    # xor eax, key
        out.extend(b'\xC1\xC0\x00')            # rol eax, rot
    append_tail()

    base_va = src_va + lea_off + 7
    delta = dst_va - base_va
    if delta < -0x80000000 or delta > 0x7FFFFFFF:
        raise ValueError(f'encoded jump delta out of range: {delta}')
    delta32 = delta & 0xFFFFFFFF

    if variant == 0:
        encoded = delta32 ^ key
        put_u32(out, imm_off, encoded)
        put_u32(out, op_off + 1, key)
    elif variant == 1:
        encoded = (delta32 - key) & 0xFFFFFFFF
        put_u32(out, imm_off, encoded)
        put_u32(out, op_off + 1, key)
    elif variant == 2:
        encoded = (delta32 + key) & 0xFFFFFFFF
        put_u32(out, imm_off, encoded)
        put_u32(out, op_off + 1, key)
    else:
        rot = ((key >> 27) & 7) + 1
        pre_rot = ((delta32 >> rot) | ((delta32 << (32 - rot)) & 0xFFFFFFFF)) & 0xFFFFFFFF
        encoded = pre_rot ^ key
        put_u32(out, imm_off, encoded)
        put_u32(out, op_off + 1, key)
        out[op_off + 7] = rot
    return bytes(out)


def emit_flow_jmp(src_va: int, dst_va: int, seed: int, direct: bool) -> bytes:
    if direct:
        return emit_rel_jmp(src_va, dst_va)
    return emit_encoded_jmp(src_va, dst_va, seed)


def patch_direct_rel(insn: object, code: bytearray, src_va: int, target_va: int) -> None:
    if insn.imm_offset == 0 or insn.imm_size not in (1, 4):
        raise ValueError(f'unsupported direct immediate at 0x{insn.address:X}')
    rel = target_va - (src_va + insn.size)
    if insn.imm_size == 1:
        put_i8(code, insn.imm_offset, rel)
    else:
        put_i32(code, insn.imm_offset, rel)


def decode_range(buf: bytearray, sections: list[Section], start_rva: int, end_rva: int, image_base: int) -> list[DecodedInsn]:
    start_off = rva_to_file_offset(sections, start_rva)
    end_off = rva_to_file_offset(sections, end_rva - 1)
    if start_off is None or end_off is None:
        raise ValueError('range is not fully file-backed')
    code = bytes(buf[start_off:start_off + (end_rva - start_rva)])
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    out = []
    cur = start_rva
    for insn in md.disasm(code, image_base + start_rva):
        rva = int(insn.address) - image_base
        if rva != cur:
            raise ValueError(f'disassembly gap at RVA 0x{cur:X}')
        out.append(DecodedInsn(insn=insn, rva=rva, data=bytes(insn.bytes)))
        cur += insn.size
        if cur == end_rva:
            break
        if cur > end_rva:
            raise ValueError('range ends inside an instruction')
    if cur != end_rva:
        raise ValueError(f'disassembly stopped at RVA 0x{cur:X}, expected 0x{end_rva:X}')
    return out


def validate_range(insns: list[DecodedInsn], start_rva: int, end_rva: int, image_base: int) -> None:
    boundaries = {x.rva for x in insns}
    for item in insns:
        insn = item.insn
        if insn.group(CS_GRP_JUMP) and not is_direct(insn):
            raise ValueError(f'indirect jump unsupported at RVA 0x{item.rva:X}')
        if insn.group(CS_GRP_CALL) and not is_direct(insn):
            # Indirect calls are position-independent as-is and are safe to copy.
            continue
        if insn.group(CS_GRP_JUMP) or insn.group(CS_GRP_CALL):
            if not is_direct(insn):
                continue
            target = direct_target_rva(insn, image_base)
            if start_rva <= target < end_rva and target not in boundaries:
                raise ValueError(f'branch/call targets middle of instruction RVA 0x{target:X}')


def add_section(buf: bytearray, section_name: str, payload: bytes, file_header: int, optional: int,
                optional_size: int, section_table: int, sections: list[Section]) -> tuple[int, list[Section]]:
    count = u16(buf, file_header + 2)
    section_alignment = u32(buf, optional + 32)
    file_alignment = u32(buf, optional + 36)
    size_of_image_off = optional + 56
    checksum_off = optional + 64
    cert_dir_off = optional + PE32_PLUS_DATA_DIRECTORY_OFF + IMAGE_DIRECTORY_ENTRY_SECURITY * 8

    if len(section_name) > 8:
        raise ValueError('section name must be at most 8 bytes')
    if any(s.name == section_name for s in sections):
        raise ValueError(f'section already exists: {section_name}')

    new_header_off = section_table + count * IMAGE_SECTION_HEADER_SIZE
    first_raw = min(s.pointer_to_raw_data for s in sections if s.pointer_to_raw_data)
    if new_header_off + IMAGE_SECTION_HEADER_SIZE > first_raw:
        raise ValueError('not enough PE header slack for another section header')

    last = max(sections, key=lambda s: s.virtual_address + max(s.virtual_size, s.size_of_raw_data))
    new_rva = align_up(last.virtual_address + max(last.virtual_size, last.size_of_raw_data), section_alignment)
    new_raw = align_up(len(buf), file_alignment)
    raw_size = align_up(len(payload), file_alignment)

    if len(buf) < new_raw:
        buf.extend(b'\0' * (new_raw - len(buf)))
    buf.extend(payload)
    buf.extend(b'\0' * (raw_size - len(payload)))

    header = bytearray(IMAGE_SECTION_HEADER_SIZE)
    header[:8] = section_name.encode('ascii') + b'\0' * (8 - len(section_name))
    put_u32(header, 8, len(payload))
    put_u32(header, 12, new_rva)
    put_u32(header, 16, raw_size)
    put_u32(header, 20, new_raw)
    put_u32(header, 36, SECTION_CHARACTERISTICS)
    buf[new_header_off:new_header_off + IMAGE_SECTION_HEADER_SIZE] = header

    put_u16(buf, file_header + 2, count + 1)
    put_u32(buf, size_of_image_off, align_up(new_rva + len(payload), section_alignment))
    put_u32(buf, checksum_off, 0)
    # Authenticode certificate table uses file offsets; invalidate it after rewriting the image.
    put_u32(buf, cert_dir_off, 0)
    put_u32(buf, cert_dir_off + 4, 0)

    return new_rva, parse_sections(buf, section_table, count + 1)


def mapped_target_va(target_rva: int, mapping: dict[int, int], image_base: int) -> int:
    return image_base + mapping.get(target_rva, target_rva)


def slot_fill_bytes(length: int, mode: str, seed: int) -> bytes:
    if length <= 0:
        return b''
    if mode == 'int3':
        return b'\xCC' * length
    if mode == 'nop':
        return b'\x90' * length
    if mode == 'zero':
        return b'\x00' * length
    if mode == 'random':
        rng = random.Random(seed ^ 0x534C4F54)
        return bytes(rng.randrange(1, 256) for _ in range(length))
    raise ValueError(f'unknown slot fill mode: {mode}')


def build_slots(plans: list[RangePlan], image_base: int, new_section_rva: int,
                slot_size: int, seed: int, direct_jumps: bool, slot_fill: str) -> tuple[bytes, dict[int, int]]:
    items = []
    for range_idx, plan in enumerate(plans):
        for insn_idx, _ in enumerate(plan.insns):
            items.append((range_idx, insn_idx))
    n = len(items)
    order = list(range(n))
    rng = random.Random(seed)
    rng.shuffle(order)
    slot_by_item_index = {idx: slot for slot, idx in enumerate(order)}
    slot_rva_by_item_index = {idx: new_section_rva + slot_by_item_index[idx] * slot_size for idx in range(n)}
    mapping = {}
    for idx, (range_idx, insn_idx) in enumerate(items):
        mapping[plans[range_idx].insns[insn_idx].rva] = slot_rva_by_item_index[idx]
    slots = bytearray(slot_fill_bytes(n * slot_size, slot_fill, seed))

    for item_index, (range_idx, insn_idx) in enumerate(items):
        plan = plans[range_idx]
        item = plan.insns[insn_idx]
        insn = item.insn
        slot_rva = slot_rva_by_item_index[item_index]
        slot_va = image_base + slot_rva
        next_rva = plan.insns[insn_idx + 1].rva if insn_idx + 1 < len(plan.insns) else plan.end_rva
        next_va = mapped_target_va(next_rva, mapping, image_base)
        body = bytearray()

        if insn.group(CS_GRP_RET):
            body.extend(item.data)
        elif insn.group(CS_GRP_JUMP) and is_direct(insn):
            target_va = mapped_target_va(direct_target_rva(insn, image_base), mapping, image_base)
            if is_cond_jcc(insn):
                false_jump = emit_flow_jmp(slot_va + 2, next_va, seed, direct_jumps)
                body.extend(bytes([0x70 | jcc_condition(insn), len(false_jump)]))
                body.extend(false_jump)
                body.extend(emit_flow_jmp(slot_va + len(body), target_va, seed, direct_jumps))
            else:
                body.extend(emit_flow_jmp(slot_va, target_va, seed, direct_jumps))
        elif insn.group(CS_GRP_CALL) and is_direct(insn):
            target_va = mapped_target_va(direct_target_rva(insn, image_base), mapping, image_base)
            body.extend(emit_rel_call(slot_va, target_va))
            body.extend(emit_flow_jmp(slot_va + len(body), next_va, seed, direct_jumps))
        else:
            code = bytearray(item.data)
            relocate_rip_relative(code, insn, slot_va)
            body.extend(code)
            body.extend(emit_flow_jmp(slot_va + len(body), next_va, seed, direct_jumps))

        if len(body) > slot_size:
            raise ValueError(f'slot too small for RVA 0x{item.rva:X}: need {len(body)}, have {slot_size}')
        off = slot_by_item_index[item_index] * slot_size
        slots[off:off + len(body)] = body

    return bytes(slots), mapping


def old_fill_bytes(length: int, mode: str, seed: int) -> bytes:
    if length <= 0:
        return b''
    if mode == 'int3':
        return b'\xCC' * length
    if mode == 'nop':
        return b'\x90' * length
    if mode == 'zero':
        return b'\x00' * length
    if mode == 'random':
        rng = random.Random(seed ^ 0x51504D58)
        return bytes(rng.randrange(1, 256) for _ in range(length))
    raise ValueError(f'unknown old fill mode: {mode}')


def patch_entry(buf: bytearray, sections: list[Section], insns: list[DecodedInsn], image_base: int,
                start_rva: int, end_rva: int, new_entry_rva: int, old_fill: str, seed: int) -> int:
    patch_len = 0
    for item in insns:
        patch_len += item.insn.size
        if patch_len >= 5:
            break
    if patch_len < 5:
        raise ValueError('not enough bytes at start to place rel32 jmp')
    off = rva_to_file_offset(sections, start_rva)
    if off is None:
        raise ValueError('start RVA is not file-backed')
    patch = bytearray(b'\x90' * patch_len)
    patch[:5] = emit_rel_jmp(image_base + start_rva, image_base + new_entry_rva)
    buf[off:off + patch_len] = patch
    fill_off = off + patch_len
    fill_len = (end_rva - start_rva) - patch_len
    buf[fill_off:fill_off + fill_len] = old_fill_bytes(fill_len, old_fill, seed)
    return patch_len


def validate_requested_ranges(ranges: list[tuple[int, int]]) -> None:
    ordered = sorted(ranges)
    for i in range(1, len(ordered)):
        if ordered[i][0] < ordered[i - 1][1]:
            raise ValueError(f'overlapping ranges: 0x{ordered[i - 1][0]:X}:0x{ordered[i - 1][1]:X} and 0x{ordered[i][0]:X}:0x{ordered[i][1]:X}')


def validate_cross_range_targets(plans: list[RangePlan], image_base: int) -> None:
    ranges = [(p.start_rva, p.end_rva) for p in plans]
    boundaries = {item.rva for p in plans for item in p.insns}
    for plan in plans:
        for item in plan.insns:
            insn = item.insn
            if not (insn.group(CS_GRP_JUMP) or insn.group(CS_GRP_CALL)) or not is_direct(insn):
                continue
            target = direct_target_rva(insn, image_base)
            if any(start <= target < end for start, end in ranges) and target not in boundaries:
                raise ValueError(f'branch/call targets middle of obfuscated instruction RVA 0x{target:X}')


def obfuscate(exe: Path, out: Path, ranges: list[tuple[int, int]], section_name: str,
              slot_size: int, seed: int, direct_jumps: bool, old_fill: str, slot_fill: str) -> None:
    require_capstone()
    buf = bytearray(exe.read_bytes())
    _, file_header, optional, optional_size, section_table, sections = parse_pe(buf)
    image_base = u64(buf, optional + 24)

    if not ranges:
        raise ValueError('at least one range is required')
    validate_requested_ranges(ranges)

    plans = []
    for start_rva, end_rva in ranges:
        start_sec = find_section(sections, start_rva)
        end_sec = find_section(sections, end_rva - 1)
        if not start_sec or start_sec != end_sec:
            raise ValueError(f'range 0x{start_rva:X}:0x{end_rva:X} must be inside one section')
        if not (start_sec.characteristics & IMAGE_SCN_MEM_EXECUTE):
            raise ValueError(f'range 0x{start_rva:X}:0x{end_rva:X} must be inside an executable section')
        insns = decode_range(buf, sections, start_rva, end_rva, image_base)
        validate_range(insns, start_rva, end_rva, image_base)
        plans.append(RangePlan(start_rva=start_rva, end_rva=end_rva, insns=insns))
    validate_cross_range_targets(plans, image_base)

    # Reserve deterministic section size first so slot RVAs are known, then fill it.
    total_insns = sum(len(plan.insns) for plan in plans)
    placeholder = slot_fill_bytes(total_insns * slot_size, 'random', seed)
    new_section_rva, sections = add_section(buf, section_name, placeholder, file_header, optional, optional_size, section_table, sections)
    slots, mapping = build_slots(plans, image_base, new_section_rva, slot_size, seed, direct_jumps, slot_fill)
    new_section = next(s for s in sections if s.name == section_name)
    raw_off = new_section.pointer_to_raw_data
    buf[raw_off:raw_off + len(slots)] = slots
    patch_lens = []
    for plan in plans:
        patch_lens.append(patch_entry(buf, sections, plan.insns, image_base, plan.start_rva,
                                      plan.end_rva, mapping[plan.start_rva], old_fill, seed))

    out.write_bytes(buf)
    print(f'wrote: {out}')
    print(f'ranges={len(plans)}')
    print(f'instructions={total_insns}')
    print(f'new_section={section_name} rva=0x{new_section_rva:X} size=0x{len(slots):X}')
    for plan, patch_len in zip(plans, patch_lens):
        print(f'range=0x{plan.start_rva:X}:0x{plan.end_rva:X} entry_patch_len=0x{patch_len:X} new_entry_rva=0x{mapping[plan.start_rva]:X}')
    print(f'flow_jumps={"direct" if direct_jumps else "encoded"}')
    print(f'old_fill={old_fill}')
    print(f'slot_fill={slot_fill}')
    print('extract note: include the new section, e.g. --sections .data,.mix,.rdata,.text')


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('exe', type=Path, help='input payload.exe')
    ap.add_argument('out', type=Path, help='output obfuscated PE')
    ap.add_argument('--range', dest='ranges', action='append', type=parse_range, help='range as START:END; may be repeated')
    ap.add_argument('--start-rva', type=parse_int, help='legacy first instruction RVA for a single range')
    ap.add_argument('--end-rva', type=parse_int, help='legacy RVA immediately after the last instruction')
    ap.add_argument('--section', default='.mix', help='new section name, max 8 bytes')
    ap.add_argument('--slot-size', default=96, type=parse_int, help='bytes reserved for each shuffled instruction slot')
    ap.add_argument('--seed', default=0xC0FFEE, type=parse_int, help='shuffle seed')
    ap.add_argument('--direct-jumps', action='store_true', help='use simple rel32 jumps between slots for debugging')
    ap.add_argument('--old-fill', choices=('int3', 'nop', 'zero', 'random'), default='int3', help='fill mode for displaced original code after the entry jump')
    ap.add_argument('--slot-fill', choices=('random', 'int3', 'nop', 'zero'), default='random', help='fill mode for unused bytes inside shuffled slots')
    args = ap.parse_args()
    ranges = list(args.ranges or [])
    if args.start_rva is not None or args.end_rva is not None:
        if args.start_rva is None or args.end_rva is None:
            ap.error('--start-rva and --end-rva must be used together')
        ranges.append((args.start_rva, args.end_rva))
    if not ranges:
        ap.error('provide at least one --range START:END or --start-rva/--end-rva pair')
    obfuscate(args.exe, args.out, ranges, args.section,
              args.slot_size, args.seed, args.direct_jumps, args.old_fill, args.slot_fill)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
