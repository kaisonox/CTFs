#!/usr/bin/env python3
"""
Build database of f functions from all DLLs.

This script scans all DLLs in the ./dlls folder, extracts exported f functions,
matches them against patterns, and builds a JSON database for quick lookup.
"""

import os
import json
import re
import struct
import mmap
from typing import List, Dict, Any, Optional
from pathlib import Path
from patterns import PATTERNS

# Import pefile with fallback
try:
    import pefile
except ImportError:
    print("Error: pefile module not found")
    print("Install with: pip install pefile")
    pefile = None

class FFunctionDatabaseBuilder:
    def __init__(self, dll_folder: str = 'dlls', db_folder: str = 'db'):
        self.dll_folder = dll_folder
        self.db_folder = db_folder
        self.patterns = PATTERNS
        
        # Precompile all patterns once (optimization #1)
        self.compiled_patterns = {
            name: self._hex_pattern_to_regex(hexpat)
            for name, hexpat in self.patterns.items()
        }
        
        # Calculate max pattern length (optimization #5)
        self.max_pattern_len = max(
            self._pattern_len(pattern_str) for pattern_str in self.patterns.values()
        )
        
        # Create db folder if it doesn't exist
        os.makedirs(db_folder, exist_ok=True)
    
    def _pattern_len(self, pattern_str: str) -> int:
        """Calculate the length of a pattern in bytes."""
        return len(pattern_str.split())
    
    def _hex_pattern_to_regex(self, pattern_str: str) -> re.Pattern:
        """Convert hex pattern to regex for matching."""
        tokens = pattern_str.split()
        regex_parts = []
        i = 0
        group_index = 1

        while i < len(tokens):
            if tokens[i] == "__":
                # Count consecutive wildcards
                count = 1
                while i + count < len(tokens) and tokens[i + count] == "__":
                    count += 1
                regex_parts.append(f"(.{{{count}}})")
                i += count
                group_index += 1
            else:
                # Regular hex byte
                regex_parts.append(rf"\x{tokens[i]}")
                i += 1

        regex_str = "".join(regex_parts)
        return re.compile(regex_str.encode(), re.DOTALL)

    def _match_pattern_with_wildcards(self, data: bytes, pattern_name: str) -> tuple[int, re.Match]:
        """Match hex pattern with wildcards against byte data starting at offset 0."""
        regex = self.compiled_patterns[pattern_name]
        m = regex.match(data)
        if not m:
            return -1, None
        return 0, m

    def _extract_constants_from_match(self, mm: mmap.mmap, pe: pefile.PE, pattern_type: str, match_obj: re.Match = None) -> Optional[Dict[str, Any]]:
        """Extract constants based on pattern type using memory map."""
        try:
            if pattern_type == 'pattern_1_1':
                qwords = [int.from_bytes(match_obj.group(i + 1), 'little') for i in range(1, 5)]
                return {
                    'offset': 0,
                    'qwords': qwords,
                    'pattern_type': pattern_type
                }
            elif pattern_type == 'pattern_1_2':
                # Extract the instruction bytes to determine if it's add or sub
                instruction_bytes = match_obj.group(2)
                if instruction_bytes[0] == 0xC0:  # add rax, imm8
                    # Extract the 8-bit immediate value
                    imm8 = instruction_bytes[1]
                    # Calculate offset: rax + imm8
                    offset = imm8
                elif instruction_bytes[0] == 0xE8:  # sub rax, imm8  
                    # Extract the 8-bit immediate value
                    imm8 = instruction_bytes[1]
                    # Calculate offset: rax - imm8 (but imm8 is signed, so handle as subtraction)
                    # For sub rax, 0x80, it's actually adding 128 (0x80 = -128 in signed 8-bit)
                    offset = 0x100 - imm8  # Convert to unsigned
                else:
                    # Unknown instruction, use the immediate value directly
                    raise ValueError(f"Unknown instruction: {instruction_bytes.hex()}")
            
                qwords = [int.from_bytes(match_obj.group(i + 1), 'little') for i in range(2, 6)]
                return {
                    'offset': offset,
                    'qwords': qwords,
                    'pattern_type': pattern_type
                }
            elif pattern_type == 'pattern_1_3':
                # Extract the instruction bytes to determine if it's add or sub
                instruction_bytes = match_obj.group(2)
                if instruction_bytes[0] == 0x05:  # add rax, imm32
                    # Extract the 32-bit immediate value
                    imm32 = int.from_bytes(instruction_bytes[1:5], 'little')
                    # Calculate the offset: rax + imm32
                    offset = imm32
                elif instruction_bytes[0] == 0x2D:  # sub rax, imm32
                    # Extract the 32-bit immediate value
                    imm32 = int.from_bytes(instruction_bytes[1:5], 'little')
                    # Calculate the offset: rax - imm32 (handle as subtraction)
                    offset = 0x100000000 - imm32  # Convert to unsigned offset
                else:
                    # Fallback to original logic
                    raise ValueError(f"Unknown instruction: {instruction_bytes.hex()}")
                
                qwords = [int.from_bytes(match_obj.group(i + 1), 'little') for i in range(2, 6)]
                return {
                    'offset': offset,
                    'qwords': qwords,
                    'pattern_type': pattern_type
                }
            elif pattern_type == 'pattern_2_1':
                qwords = [int.from_bytes(match_obj.group(i + 1), 'little') for i in range(1, 33)]
                return {
                    'offset': 0,
                    'qwords': qwords,
                    'pattern_type': pattern_type
                }
            elif pattern_type == 'pattern_2_2':
                # Extract the instruction bytes to determine if it's add or sub
                instruction_bytes = match_obj.group(2)
                if instruction_bytes[0] == 0xC0:  # add rax, imm8
                    # Extract the 8-bit immediate value
                    imm8 = instruction_bytes[1]
                    # Calculate the offset: rax + imm8
                    offset = imm8
                elif instruction_bytes[0] == 0xE8:  # sub rax, imm8  
                    # Extract the 8-bit immediate value
                    imm8 = instruction_bytes[1]
                    # Calculate the offset: rax - imm8 (but imm8 is signed, so handle as subtraction)
                    # For sub rax, 0x80, it's actually adding 128 (0x80 = -128 in signed 8-bit)
                    offset = 0x100 - imm8  # Convert to unsigned offset
                else:
                    # Fallback to original logic
                    raise ValueError(f"Unknown instruction: {instruction_bytes.hex()}")
                
                qwords = [int.from_bytes(match_obj.group(i + 1), 'little') for i in range(2, 34)]
                return {
                    'offset': offset,
                    'qwords': qwords,
                    'pattern_type': pattern_type
                }
            elif pattern_type == 'pattern_2_3':
                # Extract the instruction bytes to determine if it's add or sub
                instruction_bytes = match_obj.group(2)
                if instruction_bytes[0] == 0x05:  # add rax, imm32
                    # Extract the 32-bit immediate value
                    imm32 = int.from_bytes(instruction_bytes[1:5], 'little')
                    # Calculate the offset: rax + imm32
                    offset = imm32
                elif instruction_bytes[0] == 0x2D:  # sub rax, imm32
                    # Extract the 32-bit immediate value
                    imm32 = int.from_bytes(instruction_bytes[1:5], 'little')
                    # Calculate the offset: rax - imm32 (handle as subtraction)
                    offset = 0x100000000 - imm32  # Convert to unsigned offset
                else:
                    # Fallback to original logic
                    raise ValueError(f"Unknown instruction: {instruction_bytes.hex()}")
                
                qwords = [int.from_bytes(match_obj.group(i + 1), 'little') for i in range(2, 34)]
                return {
                    'offset': offset,
                    'qwords': qwords,
                    'pattern_type': pattern_type
                }
            elif pattern_type == 'pattern_3_1':
                qwords = [int.from_bytes(match_obj.group(i + 1), 'little') for i in range(1, 5)]
                return {
                    'offset': 0,
                    'qwords': qwords,
                    'pattern_type': pattern_type
                }
            elif pattern_type == 'pattern_3_2':
                # Extract the instruction bytes to determine if it's add or sub
                instruction_bytes = match_obj.group(2)
                if instruction_bytes[0] == 0xC0:  # add rax, imm8
                    # Extract the 8-bit immediate value
                    imm8 = instruction_bytes[1]
                    # Calculate the offset: rax + imm8
                    offset = imm8
                elif instruction_bytes[0] == 0xE8:  # sub rax, imm8
                    # Extract the 8-bit immediate value
                    imm8 = instruction_bytes[1]
                    # Calculate the offset: rax - imm8 (but imm8 is signed, so handle as subtraction)
                    # For sub rax, 0x80, it's actually adding 128 (0x80 = -128 in signed 8-bit)
                    offset = 0x100 - imm8  # Convert to unsigned offset
                else:
                    # Fallback to original logic
                    raise ValueError(f"Unknown instruction: {instruction_bytes.hex()}")

                qwords = [int.from_bytes(match_obj.group(i + 1), 'little') for i in range(2, 6)]
                return {
                    'offset': offset,
                    'qwords': qwords,
                    'pattern_type': pattern_type
                }
            elif pattern_type == 'pattern_3_3':
                # Extract the instruction bytes to determine if it's add or sub
                instruction_bytes = match_obj.group(2)
                if instruction_bytes[0] == 0x05:  # add rax, imm32
                    # Extract the 32-bit immediate value
                    imm32 = int.from_bytes(instruction_bytes[1:5], 'little')
                    # Calculate the offset: rax + imm32
                    offset = imm32
                elif instruction_bytes[0] == 0x2D:  # sub rax, imm32
                    # Extract the 32-bit immediate value
                    imm32 = int.from_bytes(instruction_bytes[1:5], 'little')
                    # Calculate the offset: rax - imm32 (handle as subtraction)
                    offset = 0x100000000 - imm32  # Convert to unsigned offset
                else:
                    # Fallback to original logic
                    raise ValueError(f"Unknown instruction: {instruction_bytes.hex()}")

                qwords = [int.from_bytes(match_obj.group(i + 1), 'little') for i in range(2, 6)]
                return {
                    'offset': offset,
                    'qwords': qwords,
                    'pattern_type': pattern_type
                }
        except Exception as e:
            print(f"Error extracting constants: {e}")
            return None
        return None


    def build_database(self) -> Dict[str, Any]:
        """Build complete database from all DLLs."""
        if pefile is None:
            print("Error: pefile module not available")
            print("Install with: pip install pefile")
            return {}
        
        print(f"Building f function database from {self.dll_folder}...")
        
        if not os.path.exists(self.dll_folder):
            print(f"Error: DLL folder {self.dll_folder} does not exist")
            return {}
        
        dll_files = [f for f in os.listdir(self.dll_folder) if f.lower().endswith('.dll')]
        print(f"Found {len(dll_files)} DLL files")
        
        database = {
            'dll_folder': self.dll_folder,
            'db_folder': self.db_folder,
            'total_dlls': len(dll_files),
            'processed_dlls': 0,
            'total_f_functions': 0,
            'matched_f_functions': 0,
            'dlls': {}
        }
        
        for i, dll_file in enumerate(dll_files, 1):
            print(f"\n[{i}/{len(dll_files)}] Processing {dll_file}...")
            
            dll_path = os.path.join(self.dll_folder, dll_file)
            dll_name = os.path.basename(dll_path)
            
            # Initialize results for this DLL
            dll_results = {
                'dll_path': dll_path,
                'dll_name': dll_name,
                'f_functions': {},
                'total_functions': 0,
                'matched_functions': 0
            }
            
            try:
                # Optimized pefile loading (optimization #4)
                pe = pefile.PE(dll_path, fast_load=True)
                pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']])
                
                # Check if DLL has exports
                if not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                    print(f"  No exports in {dll_name}")
                    database['dlls'][dll_file] = dll_results
                    database['processed_dlls'] += 1
                    continue
                
                # Memory map the DLL file (optimization #2)
                with open(dll_path, 'rb') as fh:
                    mm = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
                    
                    # Find all f functions
                    f_functions = []
                    for export in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                        if export.name:
                            export_name = export.name.decode()
                            # Match _Z21f...Ph pattern
                            if export_name.startswith('_Z21f') and export_name.endswith('Ph'):
                                # Extract function number
                                func_match = re.match(r'_Z21f(\d+)Ph', export_name)
                                if func_match:
                                    func_number = func_match.group(1)
                                    f_functions.append({
                                        'mangled_name': export_name,
                                        'function_name': f'f{func_number}',
                                        'export_address': export.address
                                    })
                    
                    print(f"  Found {len(f_functions)} f functions")
                    dll_results['total_functions'] = len(f_functions)
                    
                    # Process each f function
                    for func_info in f_functions:
                        func_name = func_info['function_name']
                        export_address = func_info['export_address']
                        
                        # Use pefile's built-in RVA to offset conversion (optimization #3)
                        file_offset = pe.get_offset_from_rva(export_address)
                        if file_offset is None:
                            continue
                        
                        # Read only as many bytes as needed (optimization #5)
                        function_code = mm[file_offset:file_offset + self.max_pattern_len]
                        
                        # Try to match against each pattern using precompiled regexes
                        matched = False
                        pattern_attempts = []
                        
                        for pattern_name in self.compiled_patterns.keys():
                            match_pos, match_obj = self._match_pattern_with_wildcards(function_code, pattern_name)
                            pattern_attempts.append({
                                'pattern_name': pattern_name,
                                'match_pos': match_pos,
                                'matched': match_pos != -1
                            })
                            
                            if match_pos != -1:
                                constants = self._extract_constants_from_match(
                                    mm, pe, pattern_name, match_obj
                                )
                                
                                if constants:
                                    # Determine function type from pattern
                                    if pattern_name.startswith('pattern_1_'):
                                        function_type = 'func_1'
                                    elif pattern_name.startswith('pattern_2_'):
                                        function_type = 'func_2'
                                    elif pattern_name.startswith('pattern_3_'):
                                        function_type = 'func_3'
                                    else:
                                        function_type = 'unknown'
                                    
                                    dll_results['f_functions'][func_name] = {
                                        'mangled_name': func_info['mangled_name'],
                                        'export_address': export_address,
                                        'function_type': function_type,
                                        'pattern_type': pattern_name,
                                        'offset': constants['offset'],
                                        'qwords': constants['qwords']
                                    }
                                    matched = True
                                    dll_results['matched_functions'] += 1
                                    break
                        
                        if not matched:
                            # Fast fail: log detailed mismatch information and exit
                            print(f"  ERROR: Function {func_name} ({func_info['mangled_name']}) does not match any pattern!")
                            print(f"  Function code (first 128 bytes): {function_code[:128].hex()}")
                            print(f"  Export address: 0x{export_address:08X}")
                            print(f"  File offset: 0x{file_offset:08X}")
                            print(f"  DLL: {dll_name}")
                            print(f"  Function code length: {len(function_code)} bytes")
                            print(f"  Max pattern length: {self.max_pattern_len} bytes")
                            
                            # Log pattern matching attempts
                            print(f"  Pattern matching attempts:")
                            for attempt in pattern_attempts:
                                status = "MATCH" if attempt['matched'] else "NO MATCH"
                                print(f"    {attempt['pattern_name']}: {status} (pos: {attempt['match_pos']})")
                            
                            # Show first few bytes of function code in detail
                            print(f"  Function code analysis:")
                            print(f"    First 32 bytes: {function_code[:32].hex()}")
                            print(f"    Bytes 32-64:    {function_code[32:64].hex() if len(function_code) > 32 else 'N/A'}")
                            print(f"    Bytes 64-96:    {function_code[64:96].hex() if len(function_code) > 64 else 'N/A'}")
                            
                            # Show pattern details for comparison
                            print(f"  Pattern details for comparison:")
                            for pattern_name, pattern_hex in self.patterns.items():
                                pattern_bytes = bytes.fromhex(pattern_hex.replace(' ', '').replace('__', '00'))
                                print(f"    {pattern_name}: {pattern_bytes[:32].hex()}")
                            
                            print(f"  Stopping database build due to unmatched function.")
                            return None
                
            except Exception as e:
                print(f"  Error scanning {dll_name}: {e}")
            
            # Save individual DLL database
            dll_db_file = os.path.join(self.db_folder, f"{dll_file.replace('.dll', '')}.json")
            with open(dll_db_file, 'w') as f:
                json.dump(dll_results, f, indent=2)
            
            # Update main database
            database['dlls'][dll_file] = dll_results
            database['processed_dlls'] += 1
            database['total_f_functions'] += dll_results['total_functions']
            database['matched_f_functions'] += dll_results['matched_functions']
            
            print(f"  Saved to: {dll_db_file}")
            print(f"  F functions: {dll_results['total_functions']} total, {dll_results['matched_functions']} matched")
        
        # Save main database
        # main_db_file = os.path.join(self.db_folder, 'database.json')
        # with open(main_db_file, 'w') as f:
        #     json.dump(database, f, indent=2)
        
        print(f"\nDatabase complete!")
        # print(f"  Main database: {main_db_file}")
        print(f"  Total DLLs processed: {database['processed_dlls']}")
        print(f"  Total f functions: {database['total_f_functions']}")
        print(f"  Matched f functions: {database['matched_f_functions']}")
        
        return database


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Build f function database from DLLs')
    parser.add_argument('--dll-folder', default='dlls', help='Folder containing DLLs (default: dlls)')
    parser.add_argument('--db-folder', default='f_db', help='Database output folder (default: db)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    try:
        builder = FFunctionDatabaseBuilder(args.dll_folder, args.db_folder)
        database = builder.build_database()
        
        if database:
            print(f"\nDatabase building completed successfully!")
        else:
            print(f"\nDatabase building failed due to unmatched function!")
            return 1
        
    except Exception as e:
        print(f"Error: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())
