# Simple DRM Solution

Simple DRM is a Tauri app that encrypts files but has a significant security flaw. I analyzed the app to understand its encryption method and bypass its protection.

1. I used tauri-dumper to extract the app's assets (https://crates.io/crates/tauri-dumper)
2. By examining the JavaScript and WebAssembly code, I discovered:
   - The app uses SHA-256 to hash the user's email
   - This hash becomes the key for XOR encryption
   - The encrypted file includes the key in its header

The encrypted files follow this format:
- Magic number: "SDRM" (0x53 0x44 0x52 0x4D)
- Data length: 4 bytes
- Key length: 4 bytes
- Key data: The SHA-256 hash
- Encrypted data: XOR-encrypted content

The critical flaw is that the encryption key is stored within the encrypted file itself, making it trivial to decrypt any file.

Script to decrypt the files:

```python
import sys
import struct

def xor_decrypt(data, key):
    """Decrypt data using XOR with the provided key"""
    result = bytearray(len(data))
    for i in range(len(data)):
        result[i] = data[i] ^ key[i % len(key)]
    return result

def decrypt_sdrm_file(input_file, output_file):
    """Decrypt an SDRM file"""
    with open(input_file, 'rb') as f:
        # Read header
        if f.read(4) != b'SDRM':
            print("Error: Not a valid SDRM file")
            return False
        
        # Read data length and key length
        data_length = struct.unpack('<I', f.read(4))[0]
        key_length = struct.unpack('<I', f.read(4))[0]
        
        # Handle unreasonable key length
        if key_length > 1000:
            print(f"Warning: Using default key length (32)")
            key_length = 32
        
        # Read key and encrypted data
        key = f.read(key_length)
        encrypted_data = f.read()
    
    # Decrypt and write to file
    decrypted_data = xor_decrypt(encrypted_data, key)
    with open(output_file, 'wb') as f:
        f.write(decrypted_data)
    
    print(f"Decrypted {input_file} to {output_file}")
    return True

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python simple_drm_decrypt.py <input_file> <output_file>")
        sys.exit(1)
    
    decrypt_sdrm_file(sys.argv[1], sys.argv[2]) 
```
