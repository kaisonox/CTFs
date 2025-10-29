import argparse
import sys
from pathlib import Path
from typing import Tuple

from simulate_aes_asm import encrypt_block_uc


def pslldq(b: bytes, count: int) -> bytes:
    # Shift bytes left within 128-bit lane: insert zeros at low indices
    if count <= 0:
        return b
    if count >= 16:
        return b"\x00" * 16
    return (b"\x00" * count + b[:16 - count])


def psrldq(b: bytes, count: int) -> bytes:
    # Shift bytes right within 128-bit lane: insert zeros at high indices
    if count <= 0:
        return b
    if count >= 16:
        return b"\x00" * 16
    return (b[count:] + b"\x00" * count)


def pxor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def broadcast_u32_to_xmm(val32: int) -> bytes:
    # 4 lanes of the same little-endian dword
    word = val32 & 0xFFFFFFFF
    le = word.to_bytes(4, 'little')
    return le * 4


def derive_round_keys_from_seed(seed16: int) -> Tuple[bytes, bytes, bytes]:
    # Emulate the logic in patch.asm:
    # movd xmm0, eax; pshufd xmm0, xmm0, 0x00; (seed broadcast)
    # xmm1=xmm0; pslldq xmm1,2; pxor xmm0,xmm1; pslldq xmm1,4; pxor xmm0,xmm1
    # C0=0x9E3779B9, C1=0x7F4A7C15 broadcast
    # rk0 = xmm0 ^ C0
    # xmm6 = xmm0; psrldq xmm6,1; rk1 = xmm6 ^ C1
    # rk2 = rk0 ^ rk1
    seed32 = seed16 & 0xFFFF
    xmm0 = broadcast_u32_to_xmm(seed32)
    xmm1 = pslldq(xmm0, 2)
    xmm0 = pxor(xmm0, xmm1)
    xmm1 = pslldq(xmm1, 4)  # shift previous xmm1 by 4 more (total 6 from original)
    xmm0 = pxor(xmm0, xmm1)

    C0 = broadcast_u32_to_xmm(0x9E3779B9)
    C1 = broadcast_u32_to_xmm(0x7F4A7C15)

    rk0 = pxor(xmm0, C0)
    xmm6 = psrldq(xmm0, 1)
    rk1 = pxor(xmm6, C1)
    rk2 = pxor(rk0, rk1)
    return rk0, rk1, rk2


def _rol16(x: int, r: int) -> int:
    r &= 15
    return ((x << r) | (x >> (16 - r))) & 0xFFFF


def compute_gap(seed16: int, rk2: bytes, rol_dx=5, imul_ax=3) -> int:
    """Complex gap function mirrored with asm.

    gap = 0x100 + (((seed ^ rol16(seed,5) ^ rk2_low16) * 3) & 0x1FF)
    """
    s = seed16 & 0xFFFF
    r = _rol16(s, rol_dx)
    rk2_low16 = int.from_bytes(rk2[:2], 'little')
    mixed = (s ^ r ^ rk2_low16) & 0xFFFF
    mixed = (mixed * imul_ax) & 0xFFFF
    return 0x100 + (mixed & 0x1FF)


def to_db_lines(data: bytes, bytes_per_line: int = 16) -> str:
    lines = []
    for i in range(0, len(data), bytes_per_line):
        chunk = data[i:i + bytes_per_line]
        hexes = ", ".join(f"0x{b:02X}" for b in chunk)
        lines.append(f"    db {hexes}")
    return "\n".join(lines)


