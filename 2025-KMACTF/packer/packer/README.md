# PE Packer

A PE (Portable Executable) packer with anti-analysis, anti-debugging, and anti-VM capabilities. This packer implements multiple layers of protection to secure Windows executables.

## Features

### Core Packing Features
- PE header compression and encryption
- Section packing and encryption
- Import table obfuscation
- Relocation table protection
- Memory protection management

### Anti-Analysis Features
- Import redirection with intermediate functions
- Safe DLL redirection list
- Zeroing out sensitive data after use
- Obfuscated workflow stages
- Encoded entry point

### Anti-Debugging Features
- Debugger presence detection
- Hardware breakpoint detection
- Remote debugger detection
- Anti-debugging entry point protection

### Anti-VM Features
- CPUID-based VM detection
- Process/DLL-based VM detection
- System resource analysis
- Multiple VM vendor detection

## Architecture

### Stage-Based Workflow
The packer uses a multi-stage approach to load and execute the packed binary:

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

## Usage

### Building
1. Clone the repository
2. Open the solution in Visual Studio
3. Build the project

### Packing an Executable
1. Run the packer with the target executable:
   ```
   packer.exe target.exe
   ```
2. The packed executable will be created with "_packed" suffix

### Unpacking
The unpacking process is automatic and happens at runtime:
1. The stub decompresses and loads the original binary
2. Memory protections are set appropriately
3. Imports are resolved and protected
4. Control is transferred to the original entry point

## Security Features

### Anti-Debugging
- Detects debugger presence
- Checks for hardware breakpoints
- Verifies remote debugging
- Protects against analysis tools

### Anti-VM
- CPUID-based detection
- Process/DLL-based detection
- System resource analysis
- Multiple VM vendor detection

### Memory Protection
- Section-specific permissions
- Execute protection
- Write protection
- Read protection

### Import Protection
- Safe DLL redirection
- Intermediate functions
- Zeroed sensitive data
- Protected import table

## Technical Details

### PE Header Compression
- Minimal headers stored in .pack0 section
- Compressed using MSZIP algorithm
- Encrypted for additional protection

### Section Packing
- Original sections compressed in .pack1
- Encrypted for security
- Decompressed at runtime

### Import Table Protection
- Safe DLL redirection list
- Intermediate function generation
- Function name and hint zeroing
- Import directory zeroing

### Memory Protection
- Initial READWRITE allocation
- Section-specific protection
- Execute protection for code
- Write protection for data

## Limitations

- 64-bit Windows executables only
- Requires Windows 7 or later
- May not work with all PE formats
- May not work with target that uses multi-threading
- Some anti-VM features may trigger on real hardware

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Windows PE/COFF specification
- Microsoft documentation
- Various anti-analysis research papers
- Open-source packer implementations
