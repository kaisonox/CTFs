# Zambia C4 CSG CTF - Writeup

## Challenge
**File:** `C4_csg_ctf.HTA` - HTML Application password crackme.

### Mechanism
1. JavaScript validation using MD5 hashing
2. Password split into 3 components (h1, h2, h3) via character rearrangement
3. Each component hashed with MD5, reversed, and compared with obfuscated values

### Key Variables
```javascript
nl = [0, 6, 17, 14, 1, 18, 16, 7, 11, 13, 8, 12, 2, 3, 0, 15, 4, 0, 9, 5, 0, 0, 10, 0, 0]
ko = "58b4cb64f141e5c914640c5c8cc8e5d5"  // h1: 8 digits
ka = "8a1828526galf607b8257cb552b0e6c8"  // h2: 4 alphanum
kq = "z99za5c140689zc2d2a1052c8z5e4b9d"  // h3: 6 alphanum
```

## Solution

### Step 1: Reverse the Transformation
```python
# Apply character substitutions then reverse string
target_h1 = ko.replace('4','a').replace('d','3').replace('e','7')[::-1]
target_h2 = ka.replace('f','3').replace('l','d').replace('g','9')[::-1]
target_h3 = kq.replace('2','f').replace('b','7').replace('z','3')[::-1]
```

Target MD5 hashes:
- h1: `53578cc8c5c0a6a19c571a1fa6bcab85`
- h2: `8c6e0b255bc7528b7063da96258281a8`
- h3: `d974e538cf501afdfc3986041c5a3993`

### Step 2: Crack the Hashes

**Python brute force** (for h1 & h2):
```python
import hashlib, itertools

def md5(s): return hashlib.md5(s.encode()).hexdigest()

# h1: 8 digits - found 20231114
# h2: 4 alphanum - found fL46
```

**Hashcat** (for h3):
```bash
hashcat -m 0 -a 3 hash.txt ?1?1?1?1?1?1 -1 ?u?l?d
# Result: Dec0d3
```

### Step 3: Reconstruct Password

Using the `nl` array position map:
```
Position  1: h1[1]=0  |  Position  2: h3[3]=0  |  Position  3: h1[4]=1
Position  4: h1[5]=1  |  Position  5: h1[6]=1  |  Position  6: h1[0]=2
Position  7: h1[2]=2  |  Position  8: h1[3]=3  |  Position  9: h3[5]=3
Position 10: h1[7]=4  |  Position 11: h2[2]=4  |  Position 12: h2[3]=6
Position 13: h3[2]=c  |  Position 14: h3[0]=D  |  Position 15: h3[4]=d
Position 16: h3[1]=e  |  Position 17: h2[0]=f  |  Position 18: h2[1]=L
```

**Components:**
- h1 = `20231114`
- h2 = `fL46`
- h3 = `Dec0d3`

**Password:** `001112233446cDdefL`

## Flag
```
CSG_FLAG{001112233446cDdefL}
```

## Tools Used
- Python 3 (brute force for h1, h2)
- Hashcat (cracking for h3)
