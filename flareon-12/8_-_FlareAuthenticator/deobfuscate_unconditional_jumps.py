# deobfuscate_unconditional_jumps.py
# IDAPython script to deobfuscate unconditional obfuscated jump patterns
#
# This script:
# 1. Finds unconditional obfuscated jump patterns (mov rax,cs:off_...; <arithmetic>; jmp rax)
# 2. Emulates each pattern to determine the single jump target
# 3. Builds equivalent unconditional jump instructions

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


class UnconditionalJumpDeobfuscator:
    def __init__(self):
        self.patterns = []
        self.deobfuscated_jumps = []
        self.eh = None
    
    def is_instruction_match(self, ea, expected_mnem, expected_op1=None, expected_op2=None):
        """Check if instruction at ea matches expected mnemonic and operands."""
        mnem = idc.print_insn_mnem(ea)
        if not mnem or mnem.lower() != expected_mnem.lower():
            return False
        
        if expected_op1:
            op1 = idc.print_operand(ea, 0)
            if not op1 or op1.lower() != expected_op1.lower():
                return False
        
        if expected_op2:
            op2 = idc.print_operand(ea, 1)
            if not op2 or op2.lower() != expected_op2.lower():
                return False
        
        return True
    
    def find_next_instruction(self, ea):
        """Find the next instruction after the given address."""
        next_ea = idc.next_head(ea)
        if next_ea == idc.BADADDR:
            return None
        return next_ea
    
    def is_arithmetic_instruction(self, ea):
        """Check if instruction is an arithmetic/logic operation (not call/jmp/etc)."""
        mnem = idc.print_insn_mnem(ea)
        if not mnem:
            return False
        
        # List of arithmetic/logic instructions commonly used in obfuscation
        arithmetic_mnems = {
            'add', 'sub', 'mul', 'imul', 'div', 'idiv',
            'and', 'or', 'xor', 'not', 'neg', 'shl', 'shr', 'sal', 'sar',
            'mov', 'lea', 'movzx', 'movsx', 'movsxd',
            'inc', 'dec', 'adc', 'sbb', 'rol', 'ror', 'rcl', 'rcr',
            'test', 'cmp', 'cmov', 'cmova', 'cmovae', 'cmovb', 'cmovbe',
            'cmovc', 'cmove', 'cmovg', 'cmovge', 'cmovl', 'cmovle',
            'cmovna', 'cmovnae', 'cmovnb', 'cmovnbe', 'cmovnc', 'cmovne',
            'cmovng', 'cmovnge', 'cmovnl', 'cmovnle', 'cmovno', 'cmovnp',
            'cmovns', 'cmovnz', 'cmovo', 'cmovp', 'cmovpe', 'cmovpo',
            'cmovs', 'cmovz'
        }
        
        return mnem.lower() in arithmetic_mnems
    
    def check_unconditional_jump_pattern(self, start_ea):
        """Check if the given address starts an unconditional obfuscated jump pattern."""
        current_ea = start_ea
        
        # Check instruction 1: mov reg, cs:off_... (must be cs: segment reference)
        # Can be mov rax, cs:off_... or mov rcx, cs:off_... or other registers
        mnem = idc.print_insn_mnem(current_ea)
        op1 = idc.print_operand(current_ea, 0)
        op2 = idc.print_operand(current_ea, 1)
        
        if not (mnem and mnem.lower() == "mov" and op1):
            return None
        
        # Must be cs:off_... reference, not just any memory reference
        if not op2 or not ("cs:off_" in op2 or ("cs:" in op2 and "off_" in op2)):
            return None
        
        # Store the register that was loaded (rax, rcx, etc.)
        loaded_register = op1.lower()
        
        pattern_start = current_ea
        data_ref = idc.get_operand_value(current_ea, 1)
        
        # Look for arithmetic instructions followed by jmp rax
        instruction_count = 0
        max_instructions = 30
        
        current_ea = self.find_next_instruction(current_ea)
        jmp_rax_ea = None
        has_arithmetic = False
        
        while current_ea and instruction_count < max_instructions:
            mnem = idc.print_insn_mnem(current_ea)
            op1 = idc.print_operand(current_ea, 0)
            
            # Check if this is "jmp rax"
            if (mnem and op1 and 
                mnem.lower() == "jmp" and 
                op1.lower() == "rax"):
                jmp_rax_ea = current_ea
                break
            
            # Check if this is an arithmetic instruction
            if self.is_arithmetic_instruction(current_ea):
                has_arithmetic = True
            
            # Reject patterns with calls, conditional jumps, or other control flow (but allow unconditional jmp to rax at the end)
            if mnem and mnem.lower() in ['call', 'je', 'jne', 'jz', 'jnz', 'jl', 'jg', 'jle', 'jge', 'ja', 'jb', 'jae', 'jbe', 'ret']:
                return None
            
            # Reject unconditional jmp to anything other than rax
            if mnem and mnem.lower() == 'jmp' and op1 and op1.lower() != 'rax':
                return None
            
            instruction_count += 1
            current_ea = self.find_next_instruction(current_ea)
        
        # Verify we found jmp rax and have arithmetic instructions
        if not jmp_rax_ea or not has_arithmetic or instruction_count < 3 or instruction_count > 25:
            return None
        
        return {
            "start_ea": pattern_start,
            "end_ea": jmp_rax_ea,
            "data_ref": data_ref,
            "loaded_register": loaded_register,
            "instruction_count": instruction_count,
            "total_size": jmp_rax_ea - pattern_start + idc.get_item_size(jmp_rax_ea)
        }
    
    def search_all_patterns(self):
        """Search for all instances of unconditional obfuscated jump patterns."""
        patterns = []
        
        print("[*] Searching for unconditional obfuscated jump patterns...")
        print("[*] Pattern: mov reg,cs:off_...; <3-25 arithmetic instrs, no calls>; jmp rax")
        
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
            
            # Search for "mov rax" instructions
            current_ea = seg.start_ea
            
            while current_ea < seg.end_ea:
                # Find next "mov" instruction
                current_ea = ida_search.find_text(current_ea, 0, 0, "mov", ida_search.SEARCH_DOWN)
                if current_ea == idc.BADADDR or current_ea >= seg.end_ea:
                    break
                
                # Check if this is "mov reg, cs:off_..." (any register)
                mnem = idc.print_insn_mnem(current_ea)
                op1 = idc.print_operand(current_ea, 0)
                op2 = idc.print_operand(current_ea, 1)
                
                if (mnem and mnem.lower() == "mov" and 
                    op1 and  # Any register is fine
                    op2 and ("cs:off_" in op2 or ("cs:" in op2 and "off_" in op2))):
                    pattern = self.check_unconditional_jump_pattern(current_ea)
                    if pattern:
                        patterns.append(pattern)
                        print(f"[+] Found pattern at 0x{pattern['start_ea']:X} (starts with mov {op1}, ...)")
                
                # Move to next instruction
                current_ea = self.find_next_instruction(current_ea)
                if not current_ea:
                    break
        
        self.patterns = patterns
        return patterns
    
    def emulate_jump_target(self, start_addr, end_addr, verbose=False):
        """Emulate the unconditional obfuscated jump and return the target address."""
        if not self.eh:
            self.eh = flare_emu.EmuHelper()
        
        if verbose:
            print(f"[*] Emulating 0x{start_addr:X} to 0x{end_addr:X}")
        
        try:
            # Emulate the range with minimal initial state
            self.eh.emulateRange(
                start_addr, 
                endAddr=end_addr,
                skipCalls=True,
                count=100
            )
            
            # Get final rax value (the jump target)
            final_rax = self.eh.getRegVal("rax")
            
            if verbose:
                print(f"[+] Jump target: 0x{final_rax:X}")
            
            return final_rax
            
        except Exception as e:
            if verbose:
                print(f"[-] Emulation failed: {e}")
            return None
    
    def deobfuscate_pattern(self, pattern):
        """Deobfuscate a single unconditional pattern by emulating it."""
        start_ea = pattern['start_ea']
        end_ea = pattern['end_ea']
        loaded_register = pattern.get('loaded_register', 'unknown')
        
        print(f"\n[*] Deobfuscating unconditional pattern at 0x{start_ea:X}")
        print(f"    Initial register: {loaded_register}")
        
        # Emulate to get the target
        target = self.emulate_jump_target(start_ea, end_ea, verbose=True)
        
        if target is None:
            print(f"[-] Failed to emulate pattern at 0x{start_ea:X}")
            return None
        
        print(f"[+] Target: 0x{target:X}")
        
        deobf_info = {
            "pattern": pattern,
            "target": target,
            "equivalent_jump": {
                "type": "unconditional",
                "instruction": f"jmp 0x{target:X}",
                "target": target,
                "offset": target - end_ea
            }
        }
        
        return deobf_info
    
    def generate_patch_data(self):
        """Generate patch data for all deobfuscated jumps."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        patch_filename = f"patch_deobf_unconditional_jumps_{timestamp}.json"
        
        patch_data = {
            "timestamp": timestamp,
            "description": "Deobfuscated unconditional jump patterns",
            "patches": []
        }
        
        for deobf in self.deobfuscated_jumps:
            if not deobf:
                continue
                
            pattern = deobf["pattern"]
            equivalent_jump = deobf["equivalent_jump"]
            
            patch_entry = {
                "address": f"0x{pattern['start_ea']:X}",
                "end_address": f"0x{pattern['end_ea']:X}",
                "original_size": pattern["total_size"],
                "pattern_type": "unconditional_obfuscated_jump",
                "target": f"0x{deobf['target']:X}",
                "equivalent_jump": equivalent_jump,
                "comment": f"Unconditional jump to 0x{deobf['target']:X}"
            }
            
            patch_data["patches"].append(patch_entry)
        
        # Save patch data
        with open(patch_filename, 'w') as f:
            json.dump(patch_data, f, indent=2)
        
        print(f"[+] Patch data saved to: {patch_filename}")
        return patch_filename
    
    def add_comments(self):
        """Add comments to the deobfuscated patterns."""
        for deobf in self.deobfuscated_jumps:
            if not deobf:
                continue
                
            pattern = deobf["pattern"]
            start_ea = pattern["start_ea"]
            end_ea = pattern["end_ea"]
            target = deobf["target"]
            
            # Add comment at the start of the pattern
            start_comment = f"[DEOBFUSCATED] Unconditional jump to 0x{target:X}"
            idc.set_cmt(start_ea, start_comment, 0)
            
            # Add comment at the jmp rax instruction
            end_comment = f"[DEOBFUSCATED] Equivalent: jmp 0x{target:X}"
            idc.set_cmt(end_ea, end_comment, 0)
    
    def run_deobfuscation(self):
        """Main function to run the complete deobfuscation process."""
        print("="*70)
        print("Unconditional Jump Deobfuscation")
        print("="*70)
        
        # Step 1: Search for patterns
        patterns = self.search_all_patterns()
        
        if not patterns:
            print("[-] No unconditional obfuscated jump patterns found.")
            return
        
        print(f"[+] Found {len(patterns)} unconditional obfuscated jump pattern(s)")
        
        # Step 2: Deobfuscate each pattern
        print("\n[*] Starting deobfuscation process...")
        
        for i, pattern in enumerate(patterns, 1):
            print(f"\n{'='*50}")
            print(f"Processing pattern {i}/{len(patterns)}")
            print(f"{'='*50}")
            
            deobf_result = self.deobfuscate_pattern(pattern)
            self.deobfuscated_jumps.append(deobf_result)
        
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
        
        successful = sum(1 for d in self.deobfuscated_jumps if d is not None)
        print(f"[+] Successfully deobfuscated: {successful}/{len(patterns)} patterns")
        print(f"[+] Patch data saved to: {patch_file}")
        
        return self.deobfuscated_jumps


def main():
    """Main entry point."""
    deobfuscator = UnconditionalJumpDeobfuscator()
    return deobfuscator.run_deobfuscation()


if __name__ == "__main__":
    main()
