# apply_deobf_unconditional_jumps_patches.py
# IDAPython script to apply unconditional jump deobfuscation patches
#
# This script:
# 1. Loads unconditional jump deobfuscation results from JSON file
# 2. Replaces obfuscated jump patterns with simple unconditional jumps
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


class UnconditionalJumpPatcher:
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
    
    def patch_pattern(self, patch_info):
        """
        Apply patch to a single unconditional obfuscated jump pattern.
        
        Args:
            patch_info: Dictionary containing patch information
        
        Returns:
            True if patch was successful, False otherwise
        """
        try:
            start_addr = int(patch_info['address'], 16)
            end_addr = int(patch_info['end_address'], 16)
            original_size = patch_info['original_size']
            target = int(patch_info['target'], 16)
            
            print(f"\n[*] Patching unconditional pattern at 0x{start_addr:X} - 0x{end_addr:X}")
            print(f"    Original size: {original_size} bytes")
            print(f"    Target: 0x{target:X}")
            
            # Build the patch: single unconditional jump + NOPs
            patch_bytes = b''
            
            # Calculate offset for the jump (assume 5-byte near jump initially)
            jmp_size = 5
            offset = self.calculate_relative_offset(start_addr, target, jmp_size)
            
            # Encode the jump
            jmp_bytes = self.encode_unconditional_jump(offset)
            if not jmp_bytes:
                print(f"[-] Failed to encode jump to 0x{target:X}")
                return False
            
            # If we got a short jump instead, recalculate
            if len(jmp_bytes) == 2:
                offset = self.calculate_relative_offset(start_addr, target, 2)
                jmp_bytes = self.encode_unconditional_jump(offset)
                if not jmp_bytes:
                    print(f"[-] Failed to encode short jump to 0x{target:X}")
                    return False
            
            patch_bytes += jmp_bytes
            print(f"    Added jump to 0x{target:X} ({len(jmp_bytes)} bytes)")
            
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
            
            # Check if the address is in a segment
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
            comment = f"[PATCHED] Unconditional jump to 0x{target:X} - was {original_size} bytes"
            idc.set_cmt(start_addr, comment, 0)
            
            # Store patch info for rollback if needed
            patch_record = {
                'address': start_addr,
                'original_bytes': original_bytes,
                'patch_bytes': patch_bytes,
                'size': original_size,
                'target': target
            }
            self.applied_patches.append(patch_record)
            
            print(f"[+] Successfully patched unconditional pattern at 0x{start_addr:X}")
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
        
        print(f"[*] Applying {len(patches)} unconditional jump patches...")
        
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
        log_filename = f"patch_log_unconditional_{timestamp}.json"
        
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
                "target": f"0x{patch['target']:X}",
                "size": patch['size'],
                "original_bytes": patch['original_bytes'].hex(),
                "patch_bytes": patch['patch_bytes'].hex()
            })
        
        with open(log_filename, 'w') as f:
            json.dump(log_data, f, indent=2)
        
        print(f"[+] Patch log saved to: {log_filename}")
        return log_filename


def main():
    """Main function to apply unconditional jump deobfuscation patches."""
    print("="*70)
    print("Unconditional Jump Deobfuscation Patch Application")
    print("="*70)
    
    # Find the most recent unconditional jump deobfuscation JSON file
    json_files = [f for f in os.listdir('.') if f.startswith('patch_deobf_unconditional_jumps_') and f.endswith('.json')]
    
    if not json_files:
        print("[-] No unconditional jump deobfuscation JSON files found in current directory")
        print("[-] Please run deobfuscate_unconditional_jumps.py first to generate patch data")
        return
    
    # Use the most recent file
    json_files.sort(reverse=True)
    latest_json = json_files[0]
    
    print(f"[*] Using latest deobfuscation file: {latest_json}")
    
    # Create patcher and apply patches
    patcher = UnconditionalJumpPatcher(latest_json)
    
    if not patcher.load_patch_data():
        return
    
    # Ask what to do
    patches_count = len(patcher.patch_data.get('patches', []))
    print(f"[*] Found {patches_count} unconditional jump patches to apply")
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
        response = idc.ask_yn(1, f"Apply {patches_count} unconditional jump patches to the database?")
        
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
