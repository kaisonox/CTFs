# PE Stub Component

The stub component is responsible for loading and executing packed executables. It implements various anti-analysis, anti-debugging, and anti-VM techniques to protect the unpacked binary.

## Features

### Core Unpacking
- PE header decompression
- Section unpacking and decryption
- Import table resolution
- Relocation processing
- Memory protection management

### Anti-Analysis
- Import redirection with intermediate functions
- Safe DLL redirection
- Zeroing out sensitive data
- Obfuscated workflow stages
- Encoded entry point

### Anti-Debugging
- Debugger presence detection
- Hardware breakpoint detection
- Remote debugger detection
- Anti-debugging entry point protection

### Anti-VM
- CPUID-based VM detection
- Process/DLL-based VM detection
- System resource analysis
- Multiple VM vendor detection

## Architecture

### Stage-Based Workflow
1. **Initialization Stage**
   - Decompresses minimal PE headers
   - Validates binary integrity
   - Sets up initial memory protections

2. **Loading Stage**
   - Decompresses and loads the PE image
   - Allocates memory with appropriate permissions
   - Copies sections to their proper locations

3. **Fixup Stage**
   - Processes import table
   - Applies relocations
   - Restores PE headers
   - Creates intermediate functions for imports

4. **Protection Stage**
   - Sets proper memory protections
   - Applies section-specific permissions
   - Enables execute protection where needed

5. **Execution Stage**
   - Decodes entry point
   - Performs final integrity checks
   - Transfers control to the original program

## Technical Details

### Memory Protection
- Initial allocation with READWRITE permissions
- Section-specific protection based on characteristics
- Execute protection for code sections
- Write protection for data sections

### Import Protection
- Safe DLL redirection list
- Intermediate function generation
- Function name and hint zeroing
- Import directory zeroing

### Anti-Analysis Techniques
- Obfuscated state transitions
- Encoded entry point
- Zeroed sensitive data
- Protected memory regions

### Anti-VM Detection
- CPUID vendor string analysis
- Hypervisor bit detection
- VM process/DLL detection
- System resource analysis

## Implementation Details

### Memory Management
```cpp
DWORD get_section_protection(DWORD characteristics) {
    // Returns appropriate memory protection flags
    // based on section characteristics
}

void set_section_protections(std::uint8_t *base, const MinimalHeaders &headers) {
    // Sets memory protections for each section
    // based on their characteristics
}
```

### Import Handling
```cpp
bool is_safe_to_redirect(const char* dll_name) {
    // Checks if a DLL is safe for import redirection
}

std::uint8_t* create_intermediate_function(std::uint8_t* base, std::uint8_t* target_function) {
    // Creates an intermediate function for import redirection
}
```

### Anti-Analysis
```cpp
bool is_debugger_present() {
    // Detects debugger presence
}

bool has_hardware_breakpoints() {
    // Checks for hardware breakpoints
}

bool is_running_in_vm() {
    // Detects virtual machine environment
}
```

## Limitations

- 64-bit Windows executables only
- Requires Windows 7 or later
- May not work with all PE formats
- May not work with multi-threaded targets
- Some anti-VM features may trigger on real hardware

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.
