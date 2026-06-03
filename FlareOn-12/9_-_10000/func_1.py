from typing import List
from struct import pack

def func_1(buf: bytes, key_dword: int, qwords: List[int]) -> bytes:
    """
    Python reimplementation of the reverse-engineered function.
    
    Args:
        buf: Input buffer (must be at least 32 bytes)
        exponent_bytes: 31-byte exponent (little-endian). Default uses original hardcoded value.
        key_dword: 4-byte XOR key. Default uses 0x00905A4D (DLL base key).
    
    Returns:
        32-byte transformed output
    """
    if len(buf) < 32:
        raise ValueError("Input buffer must be at least 32 bytes")
    # Build exponent from qwords
    exponent_bytes = pack('<QQ', qwords[0], qwords[1])[:15] + pack('<QQ', qwords[2], qwords[3])

    E = int.from_bytes(exponent_bytes, 'little')

    # 1. Load little-endian 256-bit integer
    N = int.from_bytes(buf[:32], 'little')

    # 2. XOR low dword with key
    N_prime = (N & ~0xFFFFFFFF) | ((N ^ key_dword) & 0xFFFFFFFF)

    # 3. Record original LSB after XOR
    orig_bit = N_prime & 1

    # 4. Force odd
    Y = N_prime | 1

    # 5. Modular exponentiation mod 2^256
    modulus = 1 << 256
    R = pow(Y, E, modulus)

    # 6. Adjust LSB to restore original bit
    if orig_bit == 0:
        R ^= 1

    # 7. Return 32-byte little-endian
    return R.to_bytes(32, 'little')

def invert_func_1(output: bytes, key_dword: int, qwords: List[int]) -> bytes:
    """
    Inverse function of f38236877289593244403.
    Given the output, this function recovers the original input.
    
    Args:
        output: 32-byte output buffer to reverse
        exponent_bytes: 31-byte exponent (little-endian). Default uses original hardcoded value.
        key_dword: 4-byte XOR key. Default uses 0x00905A4D (DLL base key).
    
    Returns:
        32-byte original input
    
    This works because:
    1. The exponent E and φ(2^256) = 2^255 are coprime
    2. All operations in the original function are deterministic and reversible
    3. The modular exponentiation can be reversed using the modular inverse
    """
    if len(output) != 32:
        raise ValueError("Output buffer must be exactly 32 bytes")
    
    # Build exponent from qwords, convert to bytes, little-endian
    exponent_bytes = pack('<QQ', qwords[0], qwords[1])[:15] + pack('<QQ', qwords[2], qwords[3])

    E = int.from_bytes(exponent_bytes, 'little')
    
    # Calculate modular inverse of E modulo φ(2^256) = 2^255
    phi_modulus = 1 << 255
    E_inv = pow(E, -1, phi_modulus)
    
    # Convert output to integer
    R = int.from_bytes(output, 'little')
    
    # Try both possible LSB values (since the original function adjusts LSB)
    for orig_bit in [0, 1]:
        # Adjust R based on original bit
        if orig_bit == 0:
            R_adjusted = R ^ 1
        else:
            R_adjusted = R
            
        # Reverse the modular exponentiation: Y = R^(E_inv) mod 2^256
        modulus = 1 << 256
        Y = pow(R_adjusted, E_inv, modulus)
        
        # Check if Y is odd (should be since original function forces odd)
        if Y & 1 == 1:
            # Remove the forced odd bit
            N_prime = Y & ~1
            
            # Restore the original LSB
            if orig_bit == 0:
                N_prime = N_prime & ~1
            else:
                N_prime = N_prime | 1
                
            # Reverse the XOR with key: N = N_prime ^ key (only on low dword)
            N = (N_prime & ~0xFFFFFFFF) | ((N_prime ^ key_dword) & 0xFFFFFFFF)
            
            # Convert back to bytes
            result = N.to_bytes(32, 'little')

            return result

    raise ValueError("Could not reverse the function - no valid input found")

if __name__ == "__main__":
    qwords = [
        0x22F130E6FAFE934B, 0x777FD23EB0B83B25, 0xF605C9124BC28C77, 0x59263089104BC46B
    ]
    # Test vector
    buf = bytes.fromhex("00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF")
    out = func_1(buf, 0x00905A4D, qwords)
    print("Output:", out.hex().upper())
    # Expected: F5 F5 C0 6D BA EF 92 23 C9 34 E2 64 DC 3D F1 E1 FE AF D4 3B A4 19 0A 85 58 E4 A5 D4 70 85 52 14
    assert(out.hex().upper() == "F5F5C06DBAEF9223C934E264DC3DF1E1FEAFD43BA4190A8558E4A5D470855214")

    reversed_input = invert_func_1(out, 0x00905A4D, qwords)
    print("Reversed input:", reversed_input.hex().upper())
    assert(reversed_input.hex().upper() == "00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF")
