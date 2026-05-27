# We'll compute the inverse-exponent trick to recover the 32-byte input,
# then verify by running the original check.

from math import prod, gcd
from typing import List

def fe_add(a: int, b: int, P: int) -> int: 
    return (a + b) % P

def fe_mul(a: int, b: int, P: int) -> int: 
    return (a * b) % P

def mat4_mul(A: List[int], B: List[int], P: int) -> List[int]:
    C = [0]*16
    for r in range(4):
        for c in range(4):
            acc = 0
            for k in range(4):
                acc = fe_add(acc, fe_mul(A[4*r+k], B[4*k+c], P), P)
            C[4*r+c] = acc
    return C

def mat4_pow_generic(M: List[int], e: int, P: int) -> List[int]:
    # Generic binary exponentiation (works for large e)
    I = [0]*16
    for i in range(4): I[5*i] = 1
    acc, base = I[:], M[:]
    while e > 0:
        if e & 1:
            acc = mat4_mul(acc, base, P)
        base = mat4_mul(base, base, P)
        e >>= 1
    return acc

def compose128(pairs_lo_hi: List[int]) -> List[int]:
    assert len(pairs_lo_hi) % 2 == 0
    out = []
    for i in range(0, len(pairs_lo_hi), 2):
        lo = pairs_lo_hi[i]; hi = pairs_lo_hi[i+1]
        out.append((hi << 64) | lo)
    return out

def solve_post_f_func_call(P: int, E: int, base_seed_pairs: List[int], target_pairs: List[int]) -> dict:
    """
    Solve the post-f function call to recover the 32-byte input.
    
    Args:
        P: Prime modulus
        E: Exponent
        base_seed_pairs: List of base seed pairs (lo, hi values)
        target_pairs: List of target pairs (lo, hi values)
    
    Returns:
        Dictionary containing:
        - inv_exists: Whether inverse exists
        - gcd_value: GCD of E and order
        - lanes_hex: Recovered lanes in hex
        - input_hex: Input in hex format
        - ok: Verification result
        - input32: Raw 32-byte input
    """
    
    BASE_SEED = compose128(base_seed_pairs)
    TARGET = compose128(target_pairs)
    
    # --- Step 1: compute |GL(4, P)| and modular inverse of E ---
    q = P
    # |GL(4, q)| = (q^4 - 1)(q^4 - q)(q^4 - q^2)(q^4 - q^3)
    q4 = q**4
    order = (q4 - 1) * (q4 - q) * (q4 - q*q) * (q4 - q*q*q)
    
    # ensure gcd(E, order) == 1 and compute inverse
    g = gcd(E, order)
    inv_exists = (g == 1)
    d = pow(E, -1, order) if inv_exists else None
    
    if not inv_exists:
        return {
            'inv_exists': inv_exists,
            'gcd_value': g,
            'lanes_hex': None,
            'input_hex': None,
            'ok': False,
            'input32': None
        }
    
    # --- Step 2: compute M = TARGET^d ---
    M = mat4_pow_generic(TARGET, d, P)
    
    # --- Step 3: recover lanes via XOR with base seed (use the four indices per lane) ---
    lanes = [None]*4
    for j in range(4):
        # grab positions i where i%4 == j
        indices = [i for i in range(16) if i % 4 == j]
        candidates = { M[i] ^ BASE_SEED[i] for i in indices }
        if len(candidates) != 1:
            raise ValueError(f"lane {j} inconsistent: {candidates}")
        lanes[j] = candidates.pop()
    
    # Pack lanes to 32-byte input (little-endian per lane)
    input32 = b''.join(int(x & ((1<<64)-1)).to_bytes(8, 'little') for x in lanes)
    
    # --- Verify by re-running the original check ---
    def absorb(input32: bytes, base_seed: List[int], P: int) -> List[int]:
        lanes_local = [int.from_bytes(input32[i*8:(i+1)*8], 'little') for i in range(4)]
        M_local = base_seed[:]
        for i in range(16):
            x = M_local[i] ^ lanes_local[i % 4]
            if x >= P:
                raise ValueError("range check failed")
            M_local[i] = x
        return M_local
    
    def check(input32: bytes, base_seed: List[int], target: List[int], P: int, E: int) -> bool:
        M_check = absorb(input32, base_seed, P)
        out = mat4_pow_generic(M_check, E, P)
        return out == target
    
    ok = check(input32, BASE_SEED, TARGET, P, E)
    
    lanes_hex = [hex(x) for x in lanes]
    input_hex = input32.hex()
    
    return {
        'inv_exists': inv_exists,
        'gcd_value': g,
        'lanes_hex': lanes_hex,
        'input_hex': input_hex,
        'ok': ok,
        'input32': input32
    }

# Example usage with default values
if __name__ == "__main__":
    P = 0x0DC37C0E304978087
    E = 0x594B7F91F11228E5
    
    base_seed_pairs = [
        0x264F1C2A310E43AA, 0x0,
        0x06F62577DDB8F7C8, 0x0,
        0x2F5EEF5C62186C64, 0x0,
        0x3B278B1EA0E08E88, 0x0,
        0x030B6B0678E48AEE, 0x0,
        0x5857A70651B71BD1, 0x0,
        0x11328681BBF8806A, 0x0,
        0x46A52DF6F08B2685, 0x0,
        0x5B5746A4910CA7FD, 0x0,
        0x04FCE2F265662E21, 0x0,
        0x32A013DC0E0F538A, 0x0,
        0xFFFEC7AE2C6F8F79, 0x0,
        0x3B0AD6E24BE21F00, 0x0,
        0xD285721394B26B6F, 0x0,
        0x49FF24112A0C1A2E, 0x0,
        0xF3A55FBBC4837E78, 0x0,
    ]
    
    target_pairs = [
        0x65DE31EF76B34C5E, 0x0,
        0xBF9224AA780960BA, 0x0,
        0x944C61FE664D8A46, 0x0,
        0x85FFAACD31F816D1, 0x0,
        0x5FE739DE69B61B49, 0x0,
        0x4362AB9DFD8274E5, 0x0,
        0xC90B9E6AC29A84EC, 0x0,
        0x661807122A7615D7, 0x0,
        0x2367A1BF2B936D7C, 0x0,
        0x289E160527983DEF, 0x0,
        0xB0E4B274464C4BFD, 0x0,
        0x5222046DFEF7B826, 0x0,
        0x6158769ED8530622, 0x0,
        0x056EABD584B51A70, 0x0,
        0xA5B7C08151FFACE8, 0x0,
        0xC7B8D0A6D71A6E00, 0x0,
    ]
    
    result = solve_post_f_func_call(P, E, base_seed_pairs, target_pairs)
    
    print("Inverse exists:", result['inv_exists'])
    print("GCD(E, order):", result['gcd_value'])
    print("Recovered lanes (hex):", result['lanes_hex'])
    print("Input (hex):", result['input_hex'])
    print("Check result:", result['ok'])