#!/usr/bin/env python3
"""Extract a position-independent virtual payload image from payload.exe.

The output blob preserves source section RVAs relative to the lowest selected RVA.
The companion JSON records the entry offset used by patch_pe_payload.py.
"""
import argparse
import json
import struct
from pathlib import Path

IMAGE_FILE_HEADER_SIZE = 20
IMAGE_SECTION_HEADER_SIZE = 40
IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20B
IMAGE_DIRECTORY_ENTRY_IMPORT = 1
IMAGE_DIRECTORY_ENTRY_BASERELOC = 5
PE32_PLUS_DATA_DIRECTORY_OFF = 112
DEFAULT_SECTIONS = {'.text', '.rdata', '.data'}


def align_up(value, alignment):
    return (value + alignment - 1) & ~(alignment - 1)


def u16(buf, off):
    return struct.unpack_from('<H', buf, off)[0]


def u32(buf, off):
    return struct.unpack_from('<I', buf, off)[0]


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


def rva_ranges_overlap(a_start, a_size, b_start, b_size):
    if not a_start or not a_size or not b_start or not b_size:
        return False
    a_end = a_start + a_size
    b_end = b_start + b_size
    return a_start < b_end and b_start < a_end


def extract_payload(exe_path, out_path, meta_path, section_names, allow_imports, allow_relocs):
    buf = bytearray(Path(exe_path).read_bytes())
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

    entry_rva = u32(buf, optional + 16)
    section_alignment = u32(buf, optional + 32)
    section_table = optional + size_of_optional_header
    sections = parse_sections(buf, section_table, number_of_sections)

    selected = [s for s in sections if s['name'] in section_names]
    if not selected:
        raise ValueError(f'no selected sections found: {sorted(section_names)}')

    min_rva = min(s['virtual_address'] for s in selected)
    max_rva = max(s['virtual_address'] + align_up(max(s['virtual_size'], s['size_of_raw_data']), section_alignment) for s in selected)
    blob = bytearray(max_rva - min_rva)

    for s in selected:
        raw_off = s['pointer_to_raw_data']
        raw_size = s['size_of_raw_data']
        virt_size = max(s['virtual_size'], raw_size)
        dst_off = s['virtual_address'] - min_rva
        if raw_off and raw_size:
            blob[dst_off:dst_off + raw_size] = buf[raw_off:raw_off + raw_size]
        if virt_size > raw_size:
            # bytearray is already zero-filled; this documents BSS behavior.
            pass

    if not (min_rva <= entry_rva < max_rva):
        raise ValueError(f'entry RVA 0x{entry_rva:X} is outside selected virtual image 0x{min_rva:X}..0x{max_rva:X}')

    import_rva = u32(buf, optional + PE32_PLUS_DATA_DIRECTORY_OFF + IMAGE_DIRECTORY_ENTRY_IMPORT * 8)
    import_size = u32(buf, optional + PE32_PLUS_DATA_DIRECTORY_OFF + IMAGE_DIRECTORY_ENTRY_IMPORT * 8 + 4)
    reloc_rva = u32(buf, optional + PE32_PLUS_DATA_DIRECTORY_OFF + IMAGE_DIRECTORY_ENTRY_BASERELOC * 8)
    reloc_size = u32(buf, optional + PE32_PLUS_DATA_DIRECTORY_OFF + IMAGE_DIRECTORY_ENTRY_BASERELOC * 8 + 4)

    warnings = []
    if import_rva and import_size:
        msg = f'import directory present at RVA 0x{import_rva:X}, size 0x{import_size:X}'
        if not allow_imports:
            raise ValueError(msg)
        warnings.append(msg)
    if rva_ranges_overlap(reloc_rva, reloc_size, min_rva, max_rva - min_rva):
        msg = f'relocation directory overlaps payload image at RVA 0x{reloc_rva:X}, size 0x{reloc_size:X}'
        if not allow_relocs:
            raise ValueError(msg)
        warnings.append(msg)

    meta = {
        'entry_rva': entry_rva,
        'base_rva': min_rva,
        'entry_offset': entry_rva - min_rva,
        'image_size': len(blob),
        'sections': [
            {
                'name': s['name'],
                'virtual_address': s['virtual_address'],
                'virtual_size': s['virtual_size'],
                'raw_size': s['size_of_raw_data'],
                'blob_offset': s['virtual_address'] - min_rva,
            }
            for s in selected
        ],
        'warnings': warnings,
    }

    Path(out_path).write_bytes(blob)
    Path(meta_path).write_text(json.dumps(meta, indent=2) + '\n')
    return meta


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('exe', help='input payload.exe')
    ap.add_argument('out', help='output payload.bin')
    ap.add_argument('--meta', help='output payload metadata JSON')
    ap.add_argument('--sections', default=','.join(sorted(DEFAULT_SECTIONS)), help='comma-separated PE section names to preserve as a virtual image')
    ap.add_argument('--allow-imports', action='store_true', help='permit an import directory in the input PE')
    ap.add_argument('--allow-relocs', action='store_true', help='permit a relocation directory inside the extracted virtual image')
    args = ap.parse_args()

    section_names = {s.strip() for s in args.sections.split(',') if s.strip()}
    meta_path = Path(args.meta) if args.meta else Path(args.out).with_suffix(Path(args.out).suffix + '.json')
    meta = extract_payload(args.exe, args.out, meta_path, section_names, args.allow_imports, args.allow_relocs)
    print(f'wrote: {args.out}')
    print(f'wrote: {meta_path}')
    print(f'base_rva=0x{meta["base_rva"]:X}')
    print(f'entry_rva=0x{meta["entry_rva"]:X}')
    print(f'entry_offset=0x{meta["entry_offset"]:X}')
    print(f'image_size=0x{meta["image_size"]:X}')
    for warning in meta['warnings']:
        print(f'warning: {warning}')


if __name__ == '__main__':
    main()
