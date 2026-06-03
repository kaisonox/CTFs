from typing import List, Union

def _build_index_from_qwords(qwords: List[int]) -> List[int]:
    if len(qwords) != 4:
        raise ValueError("expected 4 QWORDs")
    idx: List[int] = []
    for k in qwords:
        if k < 0 or k > 0xFFFFFFFFFFFFFFFF:
            raise ValueError("qword out of range")
        for j in range(8):
            idx.append((k >> (8 * j)) & 0xFF)
    if len(idx) != 32:
        raise AssertionError("invalid index length")
    return idx

def func_3(data: Union[bytes, bytearray], key_dword: int, index_qwords: List[int]) -> bytes:
    """
    Equivalent of function at 0x7FFE84884CE9:
    - XOR first 4 bytes (LE) with key_dword
    - Permute bytes using 32-byte index table derived from 4 QWORDs (LE)
    """
    if len(data) != 32:
        raise ValueError("expected 32 bytes")

    buf = bytearray(data)
    first = int.from_bytes(buf[0:4], "little") ^ (key_dword & 0xFFFFFFFF)
    buf[0:4] = first.to_bytes(4, "little")

    index = _build_index_from_qwords(index_qwords)
    tmp = bytearray(32)
    for i in range(32):
        tmp[i] = buf[index[i]]

    return bytes(tmp)

def invert_func_3(output: Union[bytes, bytearray], key_dword: int, index_qwords: List[int]) -> bytes:
    """
    Invert of transform_perm_32:
    - Reverse permutation using inverse of index table
    - XOR first 4 bytes (LE) with key_dword
    """
    if len(output) != 32:
        raise ValueError("expected 32 bytes")

    index = _build_index_from_qwords(index_qwords)
    # Build inverse permutation: inv[index[i]] = i
    inv = [0] * 32
    for i, pos in enumerate(index):
        inv[pos] = i

    buf = bytearray(32)
    for pos in range(32):
        buf[pos] = output[inv[pos]]

    first = int.from_bytes(buf[0:4], "little") ^ (key_dword & 0xFFFFFFFF)
    buf[0:4] = first.to_bytes(4, "little")

    return bytes(buf)

if __name__ == "__main__":
    buf = bytes.fromhex("744777CA3A146FFBB421FC2B5E2B018D84746706C07BA3A09F93B19D32CDB2D8")
    qwords = [
        0x1E07141A020D0F00, 0x6041B171D19010C, 0x1F100E0913111503, 0xA12050816181C0B
    ]
    key_dword = 0x00905A4D

    out = func_3(buf, key_dword, qwords)
    print("Output:", out.hex().upper())
    assert(out.hex().upper() == "398D2BE7B1C0FBB25E1D93CDA09D3A6FCA7B7406210184D82B329FA3B41467FC")

    reversed_input = invert_func_3(out, key_dword, qwords)
    print("Reversed input:", reversed_input.hex().upper())
    assert(reversed_input.hex().upper() == buf.hex().upper())