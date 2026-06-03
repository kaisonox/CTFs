import hashlib
import itertools

# Target hashes (after transformation)
TARGET_H1 = "53578cc8c5c0a6a19c571a1fa6bcab85"  # 8 digits
TARGET_H2 = "8c6e0b255bc7528b7063da96258281a8"  # 4 alphanum
TARGET_H3 = "d974e538cf501afdfc3986041c5a3993"  # 6 alphanum

def md5(s):
    return hashlib.md5(s.encode()).hexdigest()

def crack_component(target, charset, length, name):
    """Brute force a component."""
    print(f"[*] Cracking {name} ({length} chars, charset size: {len(charset)})...")
    for combo in itertools.product(charset, repeat=length):
        candidate = ''.join(combo)
        if md5(candidate) == target:
            print(f"[+] Found {name}: {candidate}")
            return candidate
    return None

def reconstruct_password(h1, h2, h3):
    """Reconstruct password from components using nl array positions."""
    password = [
        h1[1], h3[3], h1[4], h1[5], h1[6], h1[0], h1[2], h1[3],
        h3[5], h1[7], h2[2], h2[3], h3[2], h3[0], h3[4], h3[1],
        h2[0], h2[1]
    ]
    return ''.join(password)

def main():
    print("=" * 60)
    print("Zambia C4 CSG CTF Solver")
    print("=" * 60)
    
    # Crack h2 (smallest search space)
    h2 = crack_component(TARGET_H2, 
        "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        4, "h2")
    
    # Crack h1 (8 digits)
    h1 = crack_component(TARGET_H1, "0123456789", 8, "h1")
    
    # For h3: Use hashcat or provide known value
    # hashcat -m 0 -a 3 hash.txt ?1?1?1?1?1?1 -1 ?u?l?d
    h3 = "Dec0d3"  # Known from hashcat
    print(f"[+] Using h3: {h3}")
    
    # Verify h3
    if md5(h3) != TARGET_H3:
        print("[-] h3 verification failed!")
        return
    
    print("\n" + "=" * 60)
    print("Components:")
    print(f"  h1: {h1}")
    print(f"  h2: {h2}")
    print(f"  h3: {h3}")
    
    # Reconstruct password
    password = reconstruct_password(h1, h2, h3)
    
    print("\n" + "=" * 60)
    print(f"Password: {password}")
    print(f"Flag: CSG_FLAG{{{password}}}")
    print("=" * 60)

if __name__ == "__main__":
    main()
