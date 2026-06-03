# Greece R2 - Packer

`packed.exe` (PE32+) is a custom packer that carries an encrypted payload.

## Solution

Reversing the stub shows it decrypts an embedded blob with **AES-128 ECB** using a
hardcoded key, then loads the result as a DLL. The relevant constants pulled from the
binary:

- Payload location: RVA `0xF370`, size `0x19A00`
- AES key: `49 6D 6C 39 43 90 AF 04 DD 0A BF D8 DF F1 9F B9`

`decrypt_payload.py` reproduces it: read the blob at that RVA, AES-ECB decrypt, and
verify the output is a valid PE (`MZ` / `PE\0\0`). It writes `payload.dll` and greps it
for the flag.

```bash
python3 decrypt_payload.py      # needs: pefile, pycryptodome
# Wrote payload.dll (104960 bytes)
strings payload.dll | grep CSG
```

The flag is a plain string in the decrypted DLL.

## Flag

```
CSG_FLAG{packer_daisuki}
```
