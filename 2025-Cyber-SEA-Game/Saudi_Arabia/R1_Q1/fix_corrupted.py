def fix_corrupted_exe(input_file, output_file):
    """
    Remove first 10 bytes from file and set first byte to 'M'
    
    Args:
        input_file: Path to corrupted.exe
        output_file: Path to save the restored file
    """
    # Read the corrupted file
    with open(input_file, 'rb') as f:
        data = f.read()
    
    print(f"Original file size: {len(data)} bytes")
    print(f"First 20 bytes (hex): {data[:20].hex()}")
    
    # Remove first 10 bytes
    data = data[10:]
    
    print(f"\nAfter removing 10 bytes:")
    print(f"New file size: {len(data)} bytes")
    print(f"First 20 bytes (hex): {data[:20].hex()}")
    
    # Set first byte to ASCII 'M' (0x4D)
    data = b'M' + data[1:]
    
    print(f"\nAfter setting first byte to 'M':")
    print(f"First 20 bytes (hex): {data[:20].hex()}")
    print(f"First 2 bytes as ASCII: {data[:2]}")
    
    # Write the restored file
    with open(output_file, 'wb') as f:
        f.write(data)
    
    print(f"\nRestored file saved as: {output_file}")

if __name__ == "__main__":
    input_file = "corrupted.exe"
    output_file = "restored.exe"
    
    fix_corrupted_exe(input_file, output_file)
    print("\nDone! You can now try to run the restored.exe")
