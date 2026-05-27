# apply_deobf_patches.py
# IDAPython script to apply deobfuscation patches
#
# This script:
# 1. Loads deobfuscation results from JSON file
# 2. Replaces obfuscated jump patterns with equivalent conditional jumps
# 3. Calculates relative jump offsets
# 4. Fills remaining space with NOPs

import json
import struct
import os
from datetime import datetime

import idaapi
import idc
import ida_bytes
import ida_segment


class DeobfuscationPatcher:
    def __init__(self, json_file=None):
        self.json_file = json_file
        self.patch_data = None
        self.applied_patches = []
        self.failed_patches = []
    
    def load_patch_data(self, json_file=None):
        """Load deobfuscation data from JSON file."""
        if json_file:
            self.json_file = json_file
        
        if not self.json_file:
            print("[-] No JSON file specified")
            return False
        
        if not os.path.exists(self.json_file):
            print(f"[-] JSON file not found: {self.json_file}")
            return False
        
        try:
            with open(self.json_file, 'r') as f:
                self.patch_data = json.load(f)
            
            print(f"[+] Loaded patch data from: {self.json_file}")
            print(f"[*] Found {len(self.patch_data.get('patches', []))} patterns to patch")
            return True
            
        except Exception as e:
            print(f"[-] Failed to load JSON file: {e}")
            return False
    
    def calculate_relative_offset(self, from_addr, to_addr, instruction_size):
        """
        Calculate relative offset for jump instruction.
        
        Args:
            from_addr: Address of the jump instruction
            to_addr: Target address to jump to
            instruction_size: Size of the jump instruction in bytes
        
        Returns:
            Relative offset as signed integer
        """
        # Relative offset = target - (current_addr + instruction_size)
        offset = to_addr - (from_addr + instruction_size)
        return offset
    
    def encode_conditional_jump(self, condition, offset):
        """
        Encode a conditional jump instruction.
        
        Args:
            condition: Jump condition (je, jne, jge, jl, etc.)
            offset: Relative offset (signed)
        
        Returns:
            Bytes for the instruction, or None if encoding fails
        """
        # Map condition names to opcodes
        condition_opcodes = {
            'je': 0x74,   # Jump if equal (ZF=1)
            'jz': 0x74,   # Jump if zero (same as je)
            'jne': 0x75,  # Jump if not equal (ZF=0)
            'jnz': 0x75,  # Jump if not zero (same as jne)
            'jl': 0x7C,   # Jump if less (SF!=OF)
            'jnge': 0x7C, # Jump if not greater or equal (same as jl)
            'jge': 0x7D,  # Jump if greater or equal (SF=OF)
            'jnl': 0x7D,  # Jump if not less (same as jge)
            'jg': 0x7F,   # Jump if greater (ZF=0 and SF=OF)
            'jle': 0x7E,  # Jump if less or equal (ZF=1 or SF!=OF)
        }
        
        condition_lower = condition.lower()
        if condition_lower not in condition_opcodes:
            print(f"[-] Unknown condition: {condition}")
            return None
        
        opcode = condition_opcodes[condition_lower]
        
        # Check if offset fits in 8-bit signed range (-128 to +127)
        if -128 <= offset <= 127:
            # Short jump (2 bytes): opcode + 8-bit offset
            return struct.pack('<Bb', opcode, offset)
        
        # Check if offset fits in 32-bit signed range
        elif -2147483648 <= offset <= 2147483647:
            # Near jump (6 bytes): 0x0F + opcode + 32-bit offset
            # For conditional jumps, add 0x10 to the opcode for the 0x0F prefix version
            near_opcode = opcode + 0x10
            return struct.pack('<BBi', 0x0F, near_opcode, offset)
        
        else:
            print(f"[-] Offset too large for relative jump: {offset}")
            return None
    
    def encode_unconditional_jump(self, offset):
        """
        Encode an unconditional jump instruction.
        
        Args:
            offset: Relative offset (signed)
        
        Returns:
            Bytes for the instruction, or None if encoding fails
        """
        # Check if offset fits in 8-bit signed range (-128 to +127)
        if -128 <= offset <= 127:
            # Short jump (2 bytes): 0xEB + 8-bit offset
            return struct.pack('<Bb', 0xEB, offset)
        
        # Check if offset fits in 32-bit signed range
        elif -2147483648 <= offset <= 2147483647:
            # Near jump (5 bytes): 0xE9 + 32-bit offset
            return struct.pack('<Bi', 0xE9, offset)
        
        else:
            print(f"[-] Offset too large for relative jump: {offset}")
            return None
    
    def create_nop_bytes(self, count):
        """Create NOP bytes to fill remaining space."""
        if count <= 0:
            return b''
        
        # Use single-byte NOPs (0x90)
        return b'\x90' * count
    
    def encode_comparison(self, reg1, reg2):
        """
        Encode a comparison instruction (cmp reg1, reg2).
        
        Args:
            reg1: First register (rax, eax, etc.)
            reg2: Second register (rcx, ecx, etc.)
        
        Returns:
            Bytes for the cmp instruction
        """
        reg1_lower = reg1.lower()
        reg2_lower = reg2.lower()
        
        # cmp rax, rcx = 48 39 C8
        if reg1_lower == "rax" and reg2_lower == "rcx":
            return b'\x48\x39\xC8'
        # cmp eax, ecx = 39 C8  
        elif reg1_lower == "eax" and reg2_lower == "ecx":
            return b'\x39\xC8'
        else:
            print(f"[-] Unsupported register combination: {reg1}, {reg2}")
            return None

    def patch_pattern(self, patch_info):
        """
        Apply patch to a single obfuscated jump pattern.
        
        Args:
            patch_info: Dictionary containing patch information
        
        Returns:
            True if patch was successful, False otherwise
        """
        try:
            start_addr = int(patch_info['address'], 16)
            end_addr = int(patch_info['end_address'], 16)
            original_size = patch_info['original_size']
            equivalent_jumps = patch_info['equivalent_jumps']
            setz_type = patch_info.get('setz_type', 'unknown')
            
            print(f"\n[*] Patching pattern at 0x{start_addr:X} - 0x{end_addr:X}")
            print(f"    Original size: {original_size} bytes")
            print(f"    Condition type: {setz_type}")
            
            if not equivalent_jumps:
                print(f"[-] No equivalent jumps found for pattern at 0x{start_addr:X}")
                return False
            
            # Start building the patch bytes
            patch_bytes = b''
            current_patch_addr = start_addr
            
            # First, add the comparison instruction
            # Determine register size based on original pattern
            # Check the original instruction to see if it was rax/rcx or eax/ecx
            original_mnem = idc.print_insn_mnem(start_addr)
            original_op1 = idc.print_operand(start_addr, 0)
            original_op2 = idc.print_operand(start_addr, 1)
            
            if original_op1 and original_op2:
                cmp_bytes = self.encode_comparison(original_op1, original_op2)
                if cmp_bytes:
                    patch_bytes += cmp_bytes
                    current_patch_addr += len(cmp_bytes)
                    print(f"    Added comparison: cmp {original_op1}, {original_op2} ({len(cmp_bytes)} bytes)")
                else:
                    # Fallback to rax, rcx
                    cmp_bytes = self.encode_comparison("rax", "rcx")
                    patch_bytes += cmp_bytes
                    current_patch_addr += len(cmp_bytes)
                    print(f"    Added comparison: cmp rax, rcx ({len(cmp_bytes)} bytes)")
            else:
                # Default fallback
                cmp_bytes = self.encode_comparison("rax", "rcx")
                patch_bytes += cmp_bytes
                current_patch_addr += len(cmp_bytes)
                print(f"    Added comparison: cmp rax, rcx ({len(cmp_bytes)} bytes)")
            
            for i, jump_info in enumerate(equivalent_jumps):
                jump_type = jump_info.get('type', 'unknown')
                
                if jump_type == 'unconditional':
                    # Simple unconditional jump
                    target = jump_info['target']
                    
                    # Calculate offset for unconditional jump
                    jmp_size = 5  # Assume near jump initially
                    offset = self.calculate_relative_offset(current_patch_addr, target, jmp_size)
                    
                    # Encode the jump
                    jmp_bytes = self.encode_unconditional_jump(offset)
                    if not jmp_bytes:
                        print(f"[-] Failed to encode unconditional jump to 0x{target:X}")
                        return False
                    
                    # Update if we used a short jump instead
                    if len(jmp_bytes) == 2:
                        offset = self.calculate_relative_offset(current_patch_addr, target, 2)
                        jmp_bytes = self.encode_unconditional_jump(offset)
                    
                    patch_bytes += jmp_bytes
                    current_patch_addr += len(jmp_bytes)
                    
                    print(f"    Added unconditional jump to 0x{target:X} ({len(jmp_bytes)} bytes)")
                
                elif jump_type == 'conditional':
                    # Conditional jump + fallback jump
                    condition = jump_info['condition']
                    target_true = jump_info['target_true']
                    target_false = jump_info['target_false']
                    
                    # First, add the conditional jump
                    cond_jmp_size = 6  # Assume near conditional jump initially
                    cond_offset = self.calculate_relative_offset(current_patch_addr, target_true, cond_jmp_size)
                    
                    cond_jmp_bytes = self.encode_conditional_jump(condition, cond_offset)
                    if not cond_jmp_bytes:
                        print(f"[-] Failed to encode conditional jump {condition} to 0x{target_true:X}")
                        return False
                    
                    # Update if we used a short jump instead
                    if len(cond_jmp_bytes) == 2:
                        cond_offset = self.calculate_relative_offset(current_patch_addr, target_true, 2)
                        cond_jmp_bytes = self.encode_conditional_jump(condition, cond_offset)
                    
                    patch_bytes += cond_jmp_bytes
                    current_patch_addr += len(cond_jmp_bytes)
                    
                    print(f"    Added conditional jump {condition} to 0x{target_true:X} ({len(cond_jmp_bytes)} bytes)")
                    
                    # Then, add the fallback unconditional jump
                    fallback_jmp_size = 5  # Assume near jump initially
                    fallback_offset = self.calculate_relative_offset(current_patch_addr, target_false, fallback_jmp_size)
                    
                    fallback_jmp_bytes = self.encode_unconditional_jump(fallback_offset)
                    if not fallback_jmp_bytes:
                        print(f"[-] Failed to encode fallback jump to 0x{target_false:X}")
                        return False
                    
                    # Update if we used a short jump instead
                    if len(fallback_jmp_bytes) == 2:
                        fallback_offset = self.calculate_relative_offset(current_patch_addr, target_false, 2)
                        fallback_jmp_bytes = self.encode_unconditional_jump(fallback_offset)
                    
                    patch_bytes += fallback_jmp_bytes
                    current_patch_addr += len(fallback_jmp_bytes)
                    
                    print(f"    Added fallback jump to 0x{target_false:X} ({len(fallback_jmp_bytes)} bytes)")
                
                else:
                    print(f"[-] Unknown jump type: {jump_type}")
                    return False
            
            # Fill remaining space with NOPs
            remaining_space = original_size - len(patch_bytes)
            if remaining_space > 0:
                nop_bytes = self.create_nop_bytes(remaining_space)
                patch_bytes += nop_bytes
                print(f"    Added {remaining_space} NOP bytes")
            elif remaining_space < 0:
                print(f"[-] Patch too large! Need {len(patch_bytes)} bytes but only have {original_size}")
                return False
            
            # Apply the patch
            print(f"[*] Applying {len(patch_bytes)} bytes of patch data...")
            
            # Backup original bytes
            original_bytes = ida_bytes.get_bytes(start_addr, original_size)
            if not original_bytes:
                print(f"[-] Failed to read original bytes at 0x{start_addr:X}")
                return False
            
            print(f"[*] Original bytes: {original_bytes.hex()}")
            print(f"[*] Patch bytes: {patch_bytes.hex()}")
            
            # Check if the address is in a writable segment
            seg = ida_segment.getseg(start_addr)
            if not seg:
                print(f"[-] Address 0x{start_addr:X} is not in any segment")
                return False
            
            print(f"[*] Segment: {idc.get_segm_name(seg.start_ea)} (0x{seg.start_ea:X}-0x{seg.end_ea:X})")
            print(f"[*] Segment permissions: 0x{seg.perm:X}")
            
            # Try multiple patching methods
            success = False
            
            # Method 1: Use ida_bytes.patch_bytes (most reliable)
            try:
                if ida_bytes.patch_bytes(start_addr, patch_bytes):
                    print(f"[+] Successfully applied patch using patch_bytes")
                    success = True
                else:
                    print(f"[*] patch_bytes failed, trying individual byte patching...")
            except Exception as e:
                print(f"[*] patch_bytes exception: {e}")
            
            # Method 2: Try individual byte patching with put_byte
            if not success:
                try:
                    success = True
                    for i, byte_val in enumerate(patch_bytes):
                        addr = start_addr + i
                        # Try put_byte instead of patch_byte
                        ida_bytes.put_byte(addr, byte_val)
                        # Verify the byte was written
                        if ida_bytes.get_byte(addr) != byte_val:
                            print(f"[-] Failed to write byte at offset {i} (address 0x{addr:X})")
                            success = False
                            break
                    
                    if success:
                        print(f"[+] Successfully applied patch using put_byte")
                    else:
                        print(f"[*] put_byte method failed, trying patch_byte...")
                except Exception as e:
                    print(f"[*] put_byte exception: {e}")
                    success = False
            
            # Method 3: Try patch_byte as fallback
            if not success:
                try:
                    success = True
                    for i, byte_val in enumerate(patch_bytes):
                        addr = start_addr + i
                        if not ida_bytes.patch_byte(addr, byte_val):
                            print(f"[-] Failed to patch byte at offset {i} (address 0x{addr:X})")
                            success = False
                            break
                    
                    if success:
                        print(f"[+] Successfully applied patch using patch_byte")
                except Exception as e:
                    print(f"[*] patch_byte exception: {e}")
                    success = False
            
            if not success:
                print(f"[-] All patching methods failed at 0x{start_addr:X}")
                print(f"[*] This might be due to segment permissions or IDA protection")
                print(f"[*] Try manually editing the bytes in IDA's hex view")
                return False
            
            # Add comment
            comment = f"[PATCHED] Deobfuscated jump pattern - was {original_size} bytes"
            idc.set_cmt(start_addr, comment, 0)
            
            # Store patch info for rollback if needed
            patch_record = {
                'address': start_addr,
                'original_bytes': original_bytes,
                'patch_bytes': patch_bytes,
                'size': original_size
            }
            self.applied_patches.append(patch_record)
            
            print(f"[+] Successfully patched pattern at 0x{start_addr:X}")
            return True
            
        except Exception as e:
            print(f"[-] Error patching pattern: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def apply_all_patches(self):
        """Apply all patches from the loaded JSON data."""
        if not self.patch_data:
            print("[-] No patch data loaded")
            return False
        
        patches = self.patch_data.get('patches', [])
        if not patches:
            print("[-] No patches found in data")
            return False
        
        print(f"[*] Applying {len(patches)} patches...")
        
        successful = 0
        failed = 0
        
        for i, patch_info in enumerate(patches, 1):
            print(f"\n{'='*60}")
            print(f"Processing patch {i}/{len(patches)}")
            print(f"{'='*60}")
            
            if self.patch_pattern(patch_info):
                successful += 1
            else:
                failed += 1
                self.failed_patches.append(patch_info)
        
        print(f"\n{'='*60}")
        print("PATCHING SUMMARY")
        print(f"{'='*60}")
        print(f"[+] Successfully applied: {successful}/{len(patches)} patches")
        if failed > 0:
            print(f"[-] Failed patches: {failed}")
        
        return successful > 0
    
    def save_patch_log(self):
        """Save a log of applied patches."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_filename = f"patch_conditional_jumps_log_{timestamp}.json"
        
        log_data = {
            "timestamp": timestamp,
            "source_json": self.json_file,
            "applied_patches": len(self.applied_patches),
            "failed_patches": len(self.failed_patches),
            "patches": []
        }
        
        for patch in self.applied_patches:
            log_data["patches"].append({
                "address": f"0x{patch['address']:X}",
                "size": patch['size'],
                "original_bytes": patch['original_bytes'].hex(),
                "patch_bytes": patch['patch_bytes'].hex()
            })
        
        with open(log_filename, 'w') as f:
            json.dump(log_data, f, indent=2)
        
        print(f"[+] Patch log saved to: {log_filename}")
        return log_filename


def test_single_patch():
    """Test a single patch for debugging."""
    print("="*70)
    print("Single Patch Test")
    print("="*70)
    
    # Find the most recent deobfuscation JSON file
    json_files = [f for f in os.listdir('.') if f.startswith('patch_deobf_conditional_jumps_') and f.endswith('.json')]
    
    if not json_files:
        print("[-] No deobfuscation JSON files found")
        return
    
    json_files.sort(reverse=True)
    latest_json = json_files[0]
    
    patcher = DeobfuscationPatcher(latest_json)
    if not patcher.load_patch_data():
        return
    
    patches = patcher.patch_data.get('patches', [])
    if not patches:
        return
    
    # Test the first patch
    print(f"[*] Testing first patch...")
    result = patcher.patch_pattern(patches[0])
    print(f"[*] Test result: {'SUCCESS' if result else 'FAILED'}")


def main():
    """Main function to apply deobfuscation patches."""
    print("="*70)
    print("Deobfuscation Patch Application")
    print("="*70)
    
    # Find the most recent deobfuscation JSON file
    json_files = [f for f in os.listdir('.') if f.startswith('patch_deobf_conditional_jumps_') and f.endswith('.json')]
    
    if not json_files:
        print("[-] No deobfuscation JSON files found in current directory")
        print("[-] Please run deobfuscate_conditional_jumps.py first to generate patch data")
        return
    
    # Use the most recent file
    json_files.sort(reverse=True)
    latest_json = json_files[0]
    
    print(f"[*] Using latest deobfuscation file: {latest_json}")
    
    # Create patcher and apply patches
    patcher = DeobfuscationPatcher(latest_json)
    
    if not patcher.load_patch_data():
        return
    
    # Ask what to do
    patches_count = len(patcher.patch_data.get('patches', []))
    print(f"[*] Found {patches_count} patches to apply")
    print("[1] Test single patch (for debugging)")
    print("[2] Apply all patches")
    print("[3] Cancel")
    
    choice = idaapi.ask_long(1, "Choose option (1-3):")
    
    if choice == 1:
        # Test single patch
        if patches_count > 0:
            print(f"[*] Testing first patch...")
            result = patcher.patch_pattern(patcher.patch_data['patches'][0])
            print(f"[*] Test result: {'SUCCESS' if result else 'FAILED'}")
        return
        
    elif choice == 2:
        # Apply all patches
        response = idc.ask_yn(1, f"Apply {patches_count} deobfuscation patches to the database?")
        
        if response != 1:  # User said no or cancelled
            print("[-] Patching cancelled by user")
            return
        
        # Apply patches
        if patcher.apply_all_patches():
            # Save log
            patcher.save_patch_log()
            print("\n[+] Patching complete! Check the patched instructions in IDA.")
            print("[*] Tip: Use 'Edit -> Patch program -> Apply patches to input file' to save changes")
        else:
            print("\n[-] Patching failed or partially failed")
    
    else:
        print("[-] Cancelled by user")


if __name__ == "__main__":
    main()
