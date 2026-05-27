from typing import List, Union

def _build_sbox_from_qwords(qwords: List[int]) -> List[int]:
    """
    Build 256-byte S-box from 32 QWORDs laid out in little-endian order.
    """
    if len(qwords) != 32:
        raise ValueError("expected 32 QWORDs")
    sbox: List[int] = []
    for k in qwords:
        if k < 0 or k > 0xFFFFFFFFFFFFFFFF:
            raise ValueError("qword out of range")
        for j in range(8):
            sbox.append((k >> (8 * j)) & 0xFF)
    if len(sbox) != 256:
        raise AssertionError("invalid sbox length")
    return sbox

def func_2(data: Union[bytes, bytearray], key_dword: int, qwords: List[int]) -> bytes:
    """
    Equivalent of the function at 0x7FFE8487BF7A.
    - XOR first 4 bytes (little-endian) with key_dword
    - Substitute each byte via a 256-byte S-box
    Returns the transformed 32 bytes.
    """
    if len(data) != 32:
        raise ValueError("expected 32 bytes")

    buf = bytearray(data)

    # XOR the first DWORD (little-endian) with the provided key_dword
    first = int.from_bytes(buf[0:4], "little") ^ (key_dword & 0xFFFFFFFF)
    buf[0:4] = first.to_bytes(4, "little")

    # Build S-box from caller-provided 32 QWORDs (little-endian layout in memory)
    sbox = _build_sbox_from_qwords(qwords)

    # Byte-wise substitution for 32 bytes
    for i in range(32):
        buf[i] = sbox[buf[i]]

    return bytes(buf)

def invert_func_2(output: Union[bytes, bytearray], key_dword: int, qwords: List[int]) -> bytes:
    """
    Inverts func_2: given the 32-byte output, recover original input.
    Steps (reverse order):
    - Apply inverse S-box to all 32 bytes
    - XOR first 4 bytes with key_dword (little-endian)
    """
    if len(output) != 32:
        raise ValueError("expected 32 bytes")

    sbox = _build_sbox_from_qwords(qwords)
    inv = [0] * 256
    for i, v in enumerate(sbox):
        inv[v] = i

    buf = bytearray(output)
    for i in range(32):
        buf[i] = inv[buf[i]]

    first = int.from_bytes(buf[0:4], "little") ^ (key_dword & 0xFFFFFFFF)
    buf[0:4] = first.to_bytes(4, "little")

    return bytes(buf)

if __name__ == "__main__":
    qwords = [
        0x48D4B4B214423E5A, 0xC32B82DA6624C1E3, 0xABEEBC9246E4E87B, 0x90213DF4DB612840,
        0x13D2C4E92A0F1516, 0x3AA9274973D7688D, 0x4FF5019836A6CF22, 0x5862F24A0069C952,
        0x178AD0838C347C8B, 0x093C032C8875C20D, 0x71564B774E729E08, 0x7ACB35530BA7381B,
        0x60D8540A5CD6EB44, 0x11A5F34CFDCA6339, 0x6F899A6CB732E76D, 0x10EFB8AFA82904F6,
        0x9F70F79C125076FF, 0x0E3165F9E2A34DFB, 0x2F1806E1DF99AD91, 0x029B7993C5B3BB20,
        0xD5AE55F8DC6B1CEA, 0x1959CEFC3B9447C7, 0x1F301E25C6DEC06E, 0x7F3395A1861D6A26,
        0x435774BFE5B0D9B5, 0xECBE84FA5EBA7E5F, 0x5D80C87864A2B9A0, 0x6707BDD37D23512D,
        0x059D2ECC0CFEB15B, 0x37F1B6AAEDF0AC87, 0x97411AA4E6D18E85, 0x8FDD96E04581CD3F,
    ]
    buf = bytes.fromhex("88F3C46A2F037788051EAC0ECB0E3528CDC5DF95B1108AD0879CE1E672F90466")
    out = func_2(buf, 0x00905A4D, qwords)
    print("Output:", out.hex().upper())
    assert(out.hex().upper() == "744777CA3A146FFBB421FC2B5E2B018D84746706C07BA3A09F93B19D32CDB2D8")

    reversed_input = invert_func_2(out, 0x00905A4D, qwords)
    print("Reversed input:", reversed_input.hex().upper())
    assert(reversed_input.hex().upper() == "88F3C46A2F037788051EAC0ECB0E3528CDC5DF95B1108AD0879CE1E672F90466")