import pefile
from Crypto.Cipher import AES
import re

PE_PATH = "packed.exe"
PAYLOAD_RVA = 0xF370
PAYLOAD_SIZE = 0x19A00
KEY = bytes([0x49,0x6D,0x6C,0x39,0x43,0x90,0xAF,0x04,0xDD,0x0A,0xBF,0xD8,0xDF,0xF1,0x9F,0xB9])

pe = pefile.PE(PE_PATH, fast_load=False)
fo = pe.get_offset_from_rva(PAYLOAD_RVA)

with open(PE_PATH, "rb") as f:
    f.seek(fo)
    enc = f.read(PAYLOAD_SIZE)

cipher = AES.new(KEY, AES.MODE_ECB)
dec = cipher.decrypt(enc)

# quick sanity checks
assert dec[:2] == b"MZ", f"Not MZ at start, got {dec[:2]!r}"
e_lfanew = int.from_bytes(dec[0x3C:0x40], "little")
assert dec[e_lfanew:e_lfanew+4] == b"PE\x00\x00", "PE signature not found"

# write decrypted DLL
out_path = "payload.dll"
with open(out_path, "wb") as f:
    f.write(dec)
print(f"Wrote {out_path} ({len(dec)} bytes)")

# Try to find a flag-like string
cands = set()
for m in re.finditer(rb'(flag|FLAG|Flag|CTF|Greece)\{[^}\r\n]{6,200}\}', dec):
    try:
        cands.add(m.group(0).decode("utf-8", "ignore"))
    except:
        cands.add(m.group(0).decode("latin-1", "ignore"))

if cands:
    print("Possible flag(s):")
    for s in sorted(cands):
        print("  ", s)
else:
    print("No obvious flag strings found.")