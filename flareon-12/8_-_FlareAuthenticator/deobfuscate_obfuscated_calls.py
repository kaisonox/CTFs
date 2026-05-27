# deobfuscate_obfuscated_calls.py
# IDAPython script to deobfuscate obfuscated call patterns
#
# This script:
# 1. Finds obfuscated call patterns (mov rax,cs:off_; add rax,reg; ...; call rax)
# 2. Emulates each pattern to determine the actual call target
# 3. Builds equivalent direct call instructions

import sys
import os
import json
from datetime import datetime

# Add flare-emu to path
script_dir = os.path.dirname(os.path.abspath(__file__))
flare_emu_path = os.path.join(script_dir, "flare-emu")
if flare_emu_path not in sys.path:
    sys.path.insert(0, flare_emu_path)

import flare_emu
import idaapi
import idc
import ida_bytes
import ida_search
import ida_segment
import ida_funcs
import ida_ua
import ida_name


class ObfuscatedCallDeobfuscator:
    def __init__(self):
        self.patterns = []
        self.deobfuscated_calls = []
        self.eh = None
    
    def find_next_instruction(self, ea):
        """Find the next instruction after the given address."""
        next_ea = idc.next_head(ea)
        if next_ea == idc.BADADDR:
            return None
        return next_ea
    
    def instruction_writes_to_rax(self, ea):
        """Check if instruction writes to rax register."""
        mnem = idc.print_insn_mnem(ea)
        if not mnem:
            return False
        
        # Get the first operand (destination for most instructions)
        op1 = idc.print_operand(ea, 0)
        if not op1:
            return False
        
        # Check if rax or eax is the destination
        op1_lower = op1.lower()
        if 'rax' in op1_lower or 'eax' in op1_lower:
            # Check if it's actually being written to (not just read)
            # For most instructions, first operand is destination
            if mnem.lower() in ['mov', 'add', 'sub', 'xor', 'or', 'and', 'lea', 
                               'imul', 'mul', 'div', 'idiv', 'neg', 'not',
                               'shl', 'shr', 'sal', 'sar', 'rol', 'ror',
                               'inc', 'dec', 'movzx', 'movsx', 'movsxd']:
                return True
        
        return False
    
    def check_obfuscated_call_pattern(self, start_ea):
        """Check if the given address starts an obfuscated call pattern."""
        current_ea = start_ea
        
        # Check instruction 1: mov rax, cs:off_...
        mnem = idc.print_insn_mnem(current_ea)
        op1 = idc.print_operand(current_ea, 0)
        op2 = idc.print_operand(current_ea, 1)
        
        if not (mnem and mnem.lower() == "mov" and op1 and op1.lower() == "rax"):
            return None
        
        # Must be cs:off_... reference
        if not op2 or not ("cs:off_" in op2 or ("cs:" in op2 and "off_" in op2)):
            return None
        
        pattern_start = current_ea
        data_ref = idc.get_operand_value(current_ea, 1)
        
        current_ea = self.find_next_instruction(current_ea)
        if not current_ea:
            return None
        
        # Check instruction 2: mov reg, imm (load constant)
        mnem = idc.print_insn_mnem(current_ea)
        op1 = idc.print_operand(current_ea, 0)
        
        if not (mnem and mnem.lower() == "mov" and op1):
            return None
        
        # Should be a register (not rax)
        if op1.lower() in ['rax', 'eax']:
            return None
        
        # Should load an immediate value
        op_type = idc.get_operand_type(current_ea, 1)
        if op_type != idc.o_imm:
            return None
        
        loaded_register = op1.lower()
        
        current_ea = self.find_next_instruction(current_ea)
        if not current_ea:
            return None
        
        # Check instruction 3: add rax, reg or sub rax, reg
        mnem = idc.print_insn_mnem(current_ea)
        op1 = idc.print_operand(current_ea, 0)
        op2 = idc.print_operand(current_ea, 1)
        
        if not (mnem and mnem.lower() in ["add", "sub"] and 
                op1 and op1.lower() == "rax" and
                op2 and op2.lower() == loaded_register):
            return None
        
        # Store the operation type for later use
        operation_type = mnem.lower()
        
        # Now look for middle instructions and call rax
        middle_start = self.find_next_instruction(current_ea)
        if not middle_start:
            return None
        
        current_ea = middle_start
        middle_instructions = []
        max_middle_instructions = 20
        instruction_count = 0
        call_rax_ea = None
        
        while current_ea and instruction_count < max_middle_instructions:
            mnem = idc.print_insn_mnem(current_ea)
            op1 = idc.print_operand(current_ea, 0)
            
            # Check if this is "call rax"
            if (mnem and op1 and 
                mnem.lower() == "call" and 
                op1.lower() == "rax"):
                call_rax_ea = current_ea
                break
            
            # Check if this instruction writes to rax (should not)
            if self.instruction_writes_to_rax(current_ea):
                # Instruction writes to rax - pattern broken
                return None
            
            # Reject patterns with other control flow
            if mnem and mnem.lower() in ['call', 'jmp', 'je', 'jne', 'jz', 'jnz', 
                                          'jl', 'jg', 'jle', 'jge', 'ja', 'jb', 
                                          'jae', 'jbe', 'ret']:
                return None
            
            middle_instructions.append(current_ea)
            instruction_count += 1
            current_ea = self.find_next_instruction(current_ea)
        
        # Verify we found call rax
        if not call_rax_ea:
            return None
        
        return {
            "start_ea": pattern_start,
            "end_ea": call_rax_ea,
            "middle_start": middle_start if middle_instructions else call_rax_ea,
            "middle_instructions": middle_instructions,
            "middle_count": len(middle_instructions),
            "data_ref": data_ref,
            "loaded_register": loaded_register,
            "operation_type": operation_type,
            "total_size": call_rax_ea - pattern_start + idc.get_item_size(call_rax_ea)
        }
    
    def search_all_patterns(self):
        """Search for all instances of obfuscated call patterns."""
        patterns = []
        
        print("[*] Searching for obfuscated call patterns...")
        print("[*] Pattern: mov rax,cs:off_; mov reg,imm; add/sub rax,reg; <middle>; call rax")
        
        # Get all segments
        seg_qty = ida_segment.get_segm_qty()
        for seg_idx in range(seg_qty):
            seg = ida_segment.getnseg(seg_idx)
            if not seg:
                continue
            
            # Only search in code segments
            if seg.type != ida_segment.SEG_CODE:
                continue
            
            print(f"[*] Searching in segment: {idc.get_segm_name(seg.start_ea)}")
            
            # Search for "mov rax, cs:off_" instructions
            current_ea = seg.start_ea
            
            while current_ea < seg.end_ea:
                # Find next "mov" instruction
                current_ea = ida_search.find_text(current_ea, 0, 0, "mov", ida_search.SEARCH_DOWN)
                if current_ea == idc.BADADDR or current_ea >= seg.end_ea:
                    break
                
                # Check if this is "mov rax, cs:off_..."
                mnem = idc.print_insn_mnem(current_ea)
                op1 = idc.print_operand(current_ea, 0)
                op2 = idc.print_operand(current_ea, 1)
                
                if (mnem and mnem.lower() == "mov" and 
                    op1 and op1.lower() == "rax" and
                    op2 and ("cs:off_" in op2 or ("cs:" in op2 and "off_" in op2))):
                    pattern = self.check_obfuscated_call_pattern(current_ea)
                    if pattern:
                        patterns.append(pattern)
                        op_type = pattern.get('operation_type', 'add')
                        print(f"[+] Found {op_type} pattern at 0x{pattern['start_ea']:X} ({pattern['middle_count']} middle instructions)")
                
                # Move to next instruction
                current_ea = self.find_next_instruction(current_ea)
                if not current_ea:
                    break
        
        self.patterns = patterns
        return patterns
    
    def emulate_call_target(self, start_addr, end_addr, verbose=False):
        """Emulate the obfuscated call and return the target address."""
        if not self.eh:
            self.eh = flare_emu.EmuHelper()
        
        if verbose:
            print(f"[*] Emulating 0x{start_addr:X} to 0x{end_addr:X}")
        
        try:
            # Emulate the range
            self.eh.emulateRange(
                start_addr, 
                endAddr=end_addr,
                skipCalls=True,
                count=100
            )
            
            # Get final rax value (the call target)
            final_rax = self.eh.getRegVal("rax")
            
            if verbose:
                print(f"[+] Call target: 0x{final_rax:X}")
            
            return final_rax
            
        except Exception as e:
            if verbose:
                print(f"[-] Emulation failed: {e}")
            return None
    
    def get_function_name(self, ea):
        """Get the function name at the given address."""
        # Try to get the function name
        func_name = ida_name.get_name(ea)
        if func_name:
            return func_name
        
        # Try to get demangled name
        func_name = idc.get_func_name(ea)
        if func_name:
            return func_name
        
        return None
    
    def deobfuscate_pattern(self, pattern):
        """Deobfuscate a single call pattern by emulating it."""
        start_ea = pattern['start_ea']
        end_ea = pattern['end_ea']
        operation_type = pattern.get('operation_type', 'add')
        
        print(f"\n[*] Deobfuscating {operation_type} call pattern at 0x{start_ea:X}")
        
        # Emulate to get the target
        target = self.emulate_call_target(start_ea, end_ea, verbose=True)
        
        if target is None:
            print(f"[-] Failed to emulate pattern at 0x{start_ea:X}")
            return None
        
        # Try to get function name
        func_name = self.get_function_name(target)
        if func_name:
            print(f"[+] Target function: {func_name}")
        else:
            print(f"[+] Target: 0x{target:X} (no symbol)")
        
        deobf_info = {
            "pattern": pattern,
            "target": target,
            "function_name": func_name,
            "equivalent_call": {
                "type": "direct_call",
                "instruction": f"call {func_name if func_name else f'0x{target:X}'}",
                "target": target,
                "offset": target - end_ea
            }
        }
        
        return deobf_info
    
    def generate_patch_data(self):
        """Generate patch data for all deobfuscated calls."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        patch_filename = f"patch_deobf_calls_{timestamp}.json"
        
        patch_data = {
            "timestamp": timestamp,
            "description": "Deobfuscated call patterns",
            "patches": []
        }
        
        for deobf in self.deobfuscated_calls:
            if not deobf:
                continue
                
            pattern = deobf["pattern"]
            equivalent_call = deobf["equivalent_call"]
            
            patch_entry = {
                "address": f"0x{pattern['start_ea']:X}",
                "end_address": f"0x{pattern['end_ea']:X}",
                "middle_start": f"0x{pattern['middle_start']:X}",
                "middle_count": pattern["middle_count"],
                "original_size": pattern["total_size"],
                "pattern_type": "obfuscated_call",
                "operation_type": pattern.get("operation_type", "add"),
                "target": f"0x{deobf['target']:X}",
                "function_name": deobf.get("function_name"),
                "equivalent_call": equivalent_call,
                "comment": f"Call to {deobf.get('function_name', f'0x{deobf['target']:X}')}"
            }
            
            patch_data["patches"].append(patch_entry)
        
        # Save patch data
        with open(patch_filename, 'w') as f:
            json.dump(patch_data, f, indent=2)
        
        print(f"[+] Patch data saved to: {patch_filename}")
        return patch_filename
    
    def add_comments(self):
        """Add comments to the deobfuscated patterns."""
        for deobf in self.deobfuscated_calls:
            if not deobf:
                continue
                
            pattern = deobf["pattern"]
            start_ea = pattern["start_ea"]
            end_ea = pattern["end_ea"]
            target = deobf["target"]
            func_name = deobf.get("function_name")
            operation_type = pattern.get("operation_type", "add")
            
            # Add comment at the start of the pattern
            if func_name:
                start_comment = f"[DEOBFUSCATED] {operation_type.upper()} call to {func_name} (0x{target:X})"
            else:
                start_comment = f"[DEOBFUSCATED] {operation_type.upper()} call to 0x{target:X}"
            idc.set_cmt(start_ea, start_comment, 0)
            
            # Add comment at the call rax instruction
            if func_name:
                end_comment = f"[DEOBFUSCATED] Equivalent: call {func_name}"
            else:
                end_comment = f"[DEOBFUSCATED] Equivalent: call 0x{target:X}"
            idc.set_cmt(end_ea, end_comment, 0)
    
    def run_deobfuscation(self):
        """Main function to run the complete deobfuscation process."""
        print("="*70)
        print("Obfuscated Call Deobfuscation")
        print("="*70)
        
        # Step 1: Search for patterns
        patterns = self.search_all_patterns()
        
        if not patterns:
            print("[-] No obfuscated call patterns found.")
            return
        
        print(f"[+] Found {len(patterns)} obfuscated call pattern(s)")
        
        # Step 2: Deobfuscate each pattern
        print("\n[*] Starting deobfuscation process...")
        
        for i, pattern in enumerate(patterns, 1):
            print(f"\n{'='*50}")
            print(f"Processing pattern {i}/{len(patterns)}")
            print(f"{'='*50}")
            
            deobf_result = self.deobfuscate_pattern(pattern)
            self.deobfuscated_calls.append(deobf_result)
        
        # Step 3: Generate patch data
        print(f"\n[*] Generating patch data...")
        patch_file = self.generate_patch_data()
        
        # Step 4: Add comments
        print(f"[*] Adding comments...")
        self.add_comments()
        
        # Step 5: Summary
        print("\n" + "="*70)
        print("DEOBFUSCATION SUMMARY")
        print("="*70)
        
        successful = sum(1 for d in self.deobfuscated_calls if d is not None)
        print(f"[+] Successfully deobfuscated: {successful}/{len(patterns)} patterns")
        print(f"[+] Patch data saved to: {patch_file}")
        
        return self.deobfuscated_calls


def main():
    """Main entry point."""
    deobfuscator = ObfuscatedCallDeobfuscator()
    return deobfuscator.run_deobfuscation()


if __name__ == "__main__":
    main()