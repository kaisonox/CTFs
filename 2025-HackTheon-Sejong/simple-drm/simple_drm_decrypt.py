import sys
import struct

def xor_encrypt(data, key):
    """Encrypt/decrypt data using XOR with the provided key"""
    result = bytearray(len(data))
    for i in range(len(data)):
        result[i] = data[i] ^ key[i % len(key)]
    return result

def decrypt_sdrm_file(input_file, output_file):
    """Decrypt an SDRM file"""
    try:
        with open(input_file, 'rb') as f:
            # Read the header
            magic = f.read(4)
            if magic != b'SDRM':
                print(f"Error: Not a valid SDRM file (magic: {magic})")
                return False
            
            # Read data length and key length
            data_length = struct.unpack('<I', f.read(4))[0]
            key_length = struct.unpack('<I', f.read(4))[0]
            
            # Sanity check for key length
            if key_length > 1000:
                print(f"Warning: Key length {key_length} is unreasonably large. Assuming SHA-256 key (32 bytes).")
                key_length = 32
            
            # Read the key
            key = f.read(key_length)
            
            # Read the encrypted data
            encrypted_data = f.read()
        
        # Decrypt the data
        decrypted_data = xor_encrypt(encrypted_data, key)
        
        # Check if data_length is reasonable
        if data_length > len(decrypted_data) or data_length > 100000000:
            print(f"Warning: Data length {data_length} is unreasonable. Using full decrypted data.")
            data_length = len(decrypted_data)
        
        # Write decrypted data
        with open(output_file, 'wb') as f:
            f.write(decrypted_data[:data_length])
        
        print(f"Successfully decrypted {input_file} to {output_file}")
        return True
    
    except Exception as e:
        print(f"Error: {e}")
        return False

def main():
    if len(sys.argv) != 3:
        print("Usage: python simple_drm_decrypt.py <input_file> <output_file>")
        return
    
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    
    decrypt_sdrm_file(input_file, output_file)

if __name__ == "__main__":
    main() 