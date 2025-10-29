import pefile
import sys

def make_section_rwx(exe_path):
    """
    Modify a PE file to make the .text section writable (RWX)
    """
    try:
        # Load the PE file
        pe = pefile.PE(exe_path)
        
        print(f"Original sections in {exe_path}:")
        print("-" * 60)
        
        # Find the .text section
        text_section = None
        for section in pe.sections:
            name = section.Name.decode('utf-8').rstrip('\x00')
            characteristics = section.Characteristics
            
            # Parse characteristics
            readable = bool(characteristics & 0x40000000)  # IMAGE_SCN_MEM_READ
            writable = bool(characteristics & 0x80000000)  # IMAGE_SCN_MEM_WRITE
            executable = bool(characteristics & 0x20000000)  # IMAGE_SCN_MEM_EXECUTE
            
            perms = []
            if readable:
                perms.append("R")
            if writable:
                perms.append("W")
            if executable:
                perms.append("X")
            
            perm_str = "".join(perms) if perms else "None"
            
            print(f"Section: {name:12} | Permissions: {perm_str:3} | Characteristics: 0x{characteristics:08X}")
            
            if name == '.text' or name == '.code':
                text_section = section
        
        if text_section is None:
            print("Error: .text or .code section not found!")
            return False
        
        print(f"\nModifying {text_section.Name.decode('utf-8').rstrip('\x00')} section...")
        
        # Set the characteristics to make it readable, writable, and executable
        # IMAGE_SCN_MEM_READ (0x40000000) | IMAGE_SCN_MEM_WRITE (0x80000000) | IMAGE_SCN_MEM_EXECUTE (0x20000000)
        new_characteristics = 0x40000000 | 0x80000000 | 0x20000000
        
        # Preserve other important characteristics
        # IMAGE_SCN_CNT_CODE (0x00000020) - contains executable code
        # IMAGE_SCN_ALIGN_16BYTES (0x00500000) - 16-byte alignment
        new_characteristics |= 0x00000020  # IMAGE_SCN_CNT_CODE
        new_characteristics |= 0x00500000  # IMAGE_SCN_ALIGN_16BYTES
        
        text_section.Characteristics = new_characteristics
        
        print(f"New characteristics: 0x{new_characteristics:08X}")
        
        # Write the modified PE file
        output_path = exe_path.replace('.exe', '_rwx.exe')
        pe.write(output_path)
        pe.close()
        
        print(f"\nModified PE file saved as: {output_path}")
        
        # Verify the changes
        print(f"\nVerifying changes in {output_path}:")
        print("-" * 60)
        
        pe_verify = pefile.PE(output_path)
        for section in pe_verify.sections:
            name = section.Name.decode('utf-8').rstrip('\x00')
            characteristics = section.Characteristics
            
            # Parse characteristics
            readable = bool(characteristics & 0x40000000)
            writable = bool(characteristics & 0x80000000)
            executable = bool(characteristics & 0x20000000)
            
            perms = []
            if readable:
                perms.append("R")
            if writable:
                perms.append("W")
            if executable:
                perms.append("X")
            
            perm_str = "".join(perms) if perms else "None"
            
            print(f"Section: {name:12} | Permissions: {perm_str:3} | Characteristics: 0x{characteristics:08X}")
        
        pe_verify.close()
        
        return True
        
    except Exception as e:
        print(f"Error: {e}")
        return False

if __name__ == "__main__":
    exe_path = "hg.exe"
    if len(sys.argv) > 1:
        exe_path = sys.argv[1]
    
    success = make_section_rwx(exe_path)
    if success:
        print("\n✓ Successfully made .text section RWX!")
    else:
        print("\n✗ Failed to modify section permissions")
