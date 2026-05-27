#!/usr/bin/env python3
"""
Solver for series of f function calls.

This script automatically scans DLLs for f function implementations,
extracts their constants, and solves for the original input from the final output.
"""

import os
import argparse
from typing import List, Dict, Any, Union, Optional
from func_1 import invert_func_1
from func_2 import invert_func_2
from func_3 import invert_func_3


def solve_f_func_calls(series_functions: List[Dict[str, Any]], accumulator: bytearray, final_result: Union[bytes, str]) -> Optional[bytes]:
    """
    Solve for a series of f function calls by inverting them in reverse order.
    
    Args:
        series_functions: List of function dictionaries, each containing:
            - 'function_type': 'func_1', 'func_2', or 'func_3'
            - 'offset': key_dword = accumulator[offset:offset+4] as DWORD (little-endian)
            - 'qwords': List of QWORDs for the function
        final_result: Final output bytes (as bytes or hex string)
    
    Returns:
        Recovered original input bytes, or None if solving fails
    
    Example:
        series = [
            {
                'function_type': 'func_1',
                'offset': 0,
                'qwords': [0x22F130E6FAFE934B, 0x777FD23EB0B83B25, 0xF605C9124BC28C77, 0x59263089104BC46B]
            },
            {
                'function_type': 'func_2',
                'offset': 4,
                'qwords': [0x48D4B4B214423E5A, 0xC32B82DA6624C1E3, ...]  # 32 QWORDs
            }
        ]
        result = solve_f_func_calls(series, bytearray(40000), "F5F5C06DBAEF9223...")
    """
    
    # Convert hex string to bytes if needed
    if isinstance(final_result, str):
        try:
            current_data = bytes.fromhex(final_result.replace(' ', ''))
        except ValueError:
            print(f"Error: Invalid hex string: {final_result}")
            return None
    else:
        current_data = final_result
    
    if len(current_data) != 32:
        print(f"Error: Expected 32 bytes, got {len(current_data)} bytes")
        return None
    
    # print(f"Starting with final result: {current_data.hex().upper()}")
    
    # Process functions in reverse order
    for i, func_info in enumerate(reversed(series_functions)):
        step_num = len(series_functions) - i
        # print(f"\nStep {step_num}: Inverting {func_info['f_function']}, type: {func_info['function_type']}")
        
        try:
            # Validate function info
            if 'function_type' not in func_info:
                print(f"Error: Missing 'function_type' in function {step_num}")
                return None
            
            if 'offset' not in func_info:
                print(f"Error: Missing 'offset' in function {step_num}")
                return None
                
            if 'qwords' not in func_info:
                print(f"Error: Missing 'qwords' in function {step_num}")
                return None
            
            # Apply the appropriate inverse function
            if func_info['function_type'] == 'func_1':
                if len(func_info['qwords']) != 4:
                    print(f"Error: func_1 expects 4 QWORDs, got {len(func_info['qwords'])}")
                    return None
                current_data = invert_func_1(
                    current_data,
                    int.from_bytes(accumulator[func_info['offset']:func_info['offset']+4], 'little'),
                    func_info['qwords']
                )
                
            elif func_info['function_type'] == 'func_2':
                if len(func_info['qwords']) != 32:
                    print(f"Error: func_2 expects 32 QWORDs, got {len(func_info['qwords'])}")
                    return None
                current_data = invert_func_2(
                    current_data,
                    int.from_bytes(accumulator[func_info['offset']:func_info['offset']+4], 'little'),
                    func_info['qwords']
                )
                
            elif func_info['function_type'] == 'func_3':
                if len(func_info['qwords']) != 4:
                    print(f"Error: func_3 expects 4 QWORDs, got {len(func_info['qwords'])}")
                    return None
                current_data = invert_func_3(
                    current_data,
                    int.from_bytes(accumulator[func_info['offset']:func_info['offset']+4], 'little'),
                    func_info['qwords']
                )
            else:
                print(f"Error: Unknown function type: {func_info['function_type']}")
                return None
            
            # print(f"  After inversion: {current_data.hex().upper()}")
            
        except Exception as e:
            print(f"Error inverting function {step_num}: {e}")
            return None
    
    # print(f"\nFinal recovered input: {current_data.hex().upper()}")
    return current_data

