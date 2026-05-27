#!/usr/bin/env python3
"""Embed a raw x64 payload blob into a PE32+ EXE and redirect entrypoint.

The injected section layout is:
    .nono:
        save flags/registers
        allocate Win64 shadow space
        call payload
        restore registers/flags
        jmp original_entrypoint
        <payload bytes>

The payload is expected to return quickly. For this project, extract_payload.py
builds payload.bin plus metadata containing the payload entry offset.
"""
import argparse
import json
import shutil
import struct
from pathlib import Path

IMAGE_FILE_HEADER_SIZE = 20
IMAGE_SECTION_HEADER_SIZE = 40
IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20B
IMAGE_SCN_CNT_CODE = 0x00000020
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000
IMAGE_DLLCHARACTERISTICS_GUARD_CF = 0x4000
IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG = 10
PE32_PLUS_DATA_DIRECTORY_OFF = 112
LOAD_CONFIG_GUARD_FLAGS_OFF64 = 144
PAYLOAD_ALIGNMENT = 0x1000
SECTION_CHARACTERISTICS = (
    IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE
)


def align_up(value, alignment):
    return (value + alignment - 1) & ~(alignment - 1)


def u16(buf, off):
    return struct.unpack_from('<H', buf, off)[0]


def u32(buf, off):
    return struct.unpack_from('<I', buf, off)[0]


def put_u16(buf, off, value):
    struct.pack_into('<H', buf, off, value)


def put_u32(buf, off, value):
    struct.pack_into('<I', buf, off, value)


def put_i32(buf, off, value):
    if value < -0x80000000 or value > 0x7FFFFFFF:
        raise ValueError(f'rel32 out of range: {value}')
    struct.pack_into('<i', buf, off, value)


def rva_to_file_offset(sections, rva):
    for section in sections:
        va = section['virtual_address']
        span = max(section['virtual_size'], section['size_of_raw_data'])
        if va <= rva < va + span:
            delta = rva - va
            if delta >= section['size_of_raw_data']:
                return None
            return section['pointer_to_raw_data'] + delta
    return None


def clear_guard_cf(buf, optional, sections):
    """Disable CFG metadata after redirecting OEP to a new unregistered stub."""
    dll_characteristics_off = optional + 70
    old_dll_chars = u16(buf, dll_characteristics_off)
    new_dll_chars = old_dll_chars & ~IMAGE_DLLCHARACTERISTICS_GUARD_CF
    put_u16(buf, dll_characteristics_off, new_dll_chars)

    load_config_dir = optional + PE32_PLUS_DATA_DIRECTORY_OFF + IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG * 8
    load_config_rva = u32(buf, load_config_dir)
    load_config_size = u32(buf, load_config_dir + 4)
    old_guard_flags = None
    new_guard_flags = None

    if load_config_rva and load_config_size > LOAD_CONFIG_GUARD_FLAGS_OFF64:
        load_config_off = rva_to_file_offset(sections, load_config_rva)
        if load_config_off is not None:
            guard_flags_off = load_config_off + LOAD_CONFIG_GUARD_FLAGS_OFF64
            if guard_flags_off + 4 <= len(buf):
                old_guard_flags = u32(buf, guard_flags_off)
                new_guard_flags = 0
                put_u32(buf, guard_flags_off, new_guard_flags)

    return {
        'old_dll_characteristics': old_dll_chars,
        'new_dll_characteristics': new_dll_chars,
        'old_guard_flags': old_guard_flags,
        'new_guard_flags': new_guard_flags,
    }


def build_entry_stub(new_rva, payload_entry_rva, old_oep):
    """Build an x64 entrypoint stub that preserves process-start state."""
    stub = bytearray()

    # Preserve the original apphost entry state. The payload uses normal Win64
    # calls and may clobber both volatile registers and flags.
    # stub.extend(b'\x9C')          # pushfq
    # stub.extend(b'\x50')          # push rax
    # stub.extend(b'\x51')          # push rcx
    # stub.extend(b'\x52')          # push rdx
    # stub.extend(b'\x53')          # push rbx
    # stub.extend(b'\x55')          # push rbp
    # stub.extend(b'\x56')          # push rsi
    # stub.extend(b'\x57')          # push rdi
    # stub.extend(b'\x41\x50')      # push r8
    # stub.extend(b'\x41\x51')      # push r9
    # stub.extend(b'\x41\x52')      # push r10
    # stub.extend(b'\x41\x53')      # push r11
    # stub.extend(b'\x41\x54')      # push r12
    # stub.extend(b'\x41\x55')      # push r13
    # stub.extend(b'\x41\x56')      # push r14
    # stub.extend(b'\x41\x57')      # push r15

    # 32-byte shadow space plus the usual 8-byte alignment adjustment before
    # a Win64 call. This matches the normal caller-side ABI contract.
    stub.extend(b'\x48\x83\xEC\x28')  # sub rsp, 28h

    call_off = len(stub)
    stub.extend(b'\xE8\x00\x00\x00\x00')

    stub.extend(b'\x48\x83\xC4\x28')  # add rsp, 28h
    # stub.extend(b'\x41\x5F')          # pop r15
    # stub.extend(b'\x41\x5E')          # pop r14
    # stub.extend(b'\x41\x5D')          # pop r13
    # stub.extend(b'\x41\x5C')          # pop r12
    # stub.extend(b'\x41\x5B')          # pop r11
    # stub.extend(b'\x41\x5A')          # pop r10
    # stub.extend(b'\x41\x59')          # pop r9
    # stub.extend(b'\x41\x58')          # pop r8
    # stub.extend(b'\x5F')              # pop rdi
    # stub.extend(b'\x5E')              # pop rsi
    # stub.extend(b'\x5D')              # pop rbp
    # stub.extend(b'\x5B')              # pop rbx
    # stub.extend(b'\x5A')              # pop rdx
    # stub.extend(b'\x59')              # pop rcx
    # stub.extend(b'\x58')              # pop rax
    # stub.extend(b'\x9D')              # popfq

    jmp_off = len(stub)
    stub.extend(b'\xE9\x00\x00\x00\x00')

    if payload_entry_rva is not None:
        put_i32(stub, call_off + 1, payload_entry_rva - (new_rva + call_off + 5))
    put_i32(stub, jmp_off + 1, old_oep - (new_rva + jmp_off + 5))
    return stub


def parse_sections(buf, section_table, count):
    sections = []
    for i in range(count):
        off = section_table + i * IMAGE_SECTION_HEADER_SIZE
        name = bytes(buf[off:off + 8]).rstrip(b'\0').decode('ascii', 'replace')
        sections.append({
            'off': off,
            'name': name,
            'virtual_size': u32(buf, off + 8),
            'virtual_address': u32(buf, off + 12),
            'size_of_raw_data': u32(buf, off + 16),
            'pointer_to_raw_data': u32(buf, off + 20),
            'characteristics': u32(buf, off + 36),
        })
    return sections


def patch_pe(exe_path, payload_path, out_path, section_name, keep_guard_cf, entry_offset):
    exe = Path(exe_path)
    payload = Path(payload_path).read_bytes()
    if not payload:
        raise ValueError('payload is empty')

    buf = bytearray(exe.read_bytes())
    if len(buf) < 0x100 or buf[0:2] != b'MZ':
        raise ValueError('not a PE/MZ file')

    pe_off = u32(buf, 0x3C)
    if buf[pe_off:pe_off + 4] != b'PE\0\0':
        raise ValueError('invalid PE signature')

    file_header = pe_off + 4
    number_of_sections = u16(buf, file_header + 2)
    size_of_optional_header = u16(buf, file_header + 16)
    optional = file_header + IMAGE_FILE_HEADER_SIZE
    if u16(buf, optional) != IMAGE_NT_OPTIONAL_HDR64_MAGIC:
        raise ValueError('only PE32+ x64 executables are supported')

    address_of_entrypoint_off = optional + 16
    section_alignment = u32(buf, optional + 32)
    file_alignment = u32(buf, optional + 36)
    size_of_image_off = optional + 56
    checksum_off = optional + 64
    old_oep = u32(buf, address_of_entrypoint_off)
    size_of_image = u32(buf, size_of_image_off)

    section_table = optional + size_of_optional_header
    sections = parse_sections(buf, section_table, number_of_sections)
    if any(s['name'] == section_name for s in sections):
        raise ValueError(f'section {section_name!r} already exists')

    new_header_off = section_table + number_of_sections * IMAGE_SECTION_HEADER_SIZE
    first_raw = min(s['pointer_to_raw_data'] for s in sections if s['pointer_to_raw_data'])
    if new_header_off + IMAGE_SECTION_HEADER_SIZE > first_raw:
        raise ValueError('not enough PE header slack for another section header')

    last = max(sections, key=lambda s: s['virtual_address'] + max(s['virtual_size'], s['size_of_raw_data']))
    new_rva = align_up(last['virtual_address'] + max(last['virtual_size'], last['size_of_raw_data']), section_alignment)
    new_raw = align_up(len(buf), file_alignment)

    stub = build_entry_stub(new_rva, None, old_oep)
    payload_rva = align_up(new_rva + len(stub), min(PAYLOAD_ALIGNMENT, section_alignment))
    payload_padding = payload_rva - (new_rva + len(stub))
    payload_entry_rva = payload_rva + entry_offset
    if entry_offset < 0 or entry_offset >= len(payload):
        raise ValueError(f'payload entry offset 0x{entry_offset:X} outside payload size 0x{len(payload):X}')
    stub = build_entry_stub(new_rva, payload_entry_rva, old_oep)

    section_data = bytes(stub) + (b'\xCC' * payload_padding) + payload
    virtual_size = len(section_data)
    raw_size = align_up(virtual_size, file_alignment)

    if len(section_name) > 8:
        raise ValueError('section name must be at most 8 bytes')
    name_bytes = section_name.encode('ascii') + b'\0' * (8 - len(section_name))

    header = bytearray(IMAGE_SECTION_HEADER_SIZE)
    header[0:8] = name_bytes
    put_u32(header, 8, virtual_size)
    put_u32(header, 12, new_rva)
    put_u32(header, 16, raw_size)
    put_u32(header, 20, new_raw)
    put_u32(header, 36, SECTION_CHARACTERISTICS)
    buf[new_header_off:new_header_off + IMAGE_SECTION_HEADER_SIZE] = header

    if len(buf) < new_raw:
        buf.extend(b'\0' * (new_raw - len(buf)))
    buf.extend(section_data)
    buf.extend(b'\0' * (raw_size - len(section_data)))

    put_u16(buf, file_header + 2, number_of_sections + 1)
    put_u32(buf, address_of_entrypoint_off, new_rva)
    put_u32(buf, size_of_image_off, align_up(new_rva + virtual_size, section_alignment))
    put_u32(buf, checksum_off, 0)
    guard_info = None
    if not keep_guard_cf:
        guard_info = clear_guard_cf(buf, optional, sections)

    Path(out_path).write_bytes(buf)
    info = {
        'old_oep': old_oep,
        'new_oep': new_rva,
        'payload_rva': payload_rva,
        'payload_entry_rva': payload_entry_rva,
        'payload_entry_offset': entry_offset,
        'payload_padding': payload_padding,
        'raw_offset': new_raw,
        'payload_size': len(payload),
        'old_size_of_image': size_of_image,
        'new_size_of_image': u32(buf, size_of_image_off),
    }
    if guard_info:
        info.update(guard_info)
    return info


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('exe', help='input Nono.exe')
    ap.add_argument('payload', help='raw payload blob')
    ap.add_argument('-o', '--out', help='output exe path')
    ap.add_argument('--entry-offset', type=lambda x: int(x, 0), default=0,
                    help='entry offset inside payload blob')
    ap.add_argument('--meta', help='payload metadata JSON from extract_payload.py')
    ap.add_argument('--section', default='.nono', help='new section name, max 8 bytes')
    ap.add_argument('--keep-guard-cf', action='store_true',
                    help='do not clear CFG flags; only use if the new OEP is registered in GuardCF metadata')
    ap.add_argument('--in-place', action='store_true', help='patch input exe in place and create .bak')
    args = ap.parse_args()

    exe = Path(args.exe)
    if args.in_place:
        backup = exe.with_suffix(exe.suffix + '.bak')
        shutil.copy2(exe, backup)
        out = exe
    else:
        out = Path(args.out) if args.out else exe.with_name(exe.stem + '.patched' + exe.suffix)

    entry_offset = args.entry_offset
    if args.meta:
        meta = json.loads(Path(args.meta).read_text())
        entry_offset = int(meta['entry_offset'])

    info = patch_pe(exe, args.payload, out, args.section, args.keep_guard_cf, entry_offset)
    print(f'wrote: {out}')
    for k, v in info.items():
        print(f'{k}=0x{v:X}' if isinstance(v, int) else f'{k}={v}')


if __name__ == '__main__':
    main()
