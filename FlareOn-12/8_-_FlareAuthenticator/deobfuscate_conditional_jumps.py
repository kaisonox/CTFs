# deobfuscate_jumps.py
# IDAPython script to automatically deobfuscate obfuscated jump patterns
#
# This script:
# 1. Finds all obfuscated jump patterns (sub rax,rcx/sub eax,ecx; setz/setnz/setnl cl/al; <obfuscation>; jmp rax)
# 2. Emulates each pattern with three test cases (rax > rcx, rax < rcx, rax = rcx)
# 3. Determines the actual jump targets for each condition
# 4. Builds equivalent conditional jump instructions

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


class ObfuscatedJumpDeobfuscator:
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
    
    def check_obfuscated_jump_pattern(self, start_ea):
        """Check if the given address starts an obfuscated jump pattern."""
        current_ea = start_ea
        
        # Check instruction 1: sub rax, rcx or sub eax, ecx
        mnem = idc.print_insn_mnem(current_ea)
        op1 = idc.print_operand(current_ea, 0)
        op2 = idc.print_operand(current_ea, 1)
        
        if not (mnem and mnem.lower() == "sub" and
                ((op1.lower() == "rax" and op2.lower() == "rcx") or
                 (op1.lower() == "eax" and op2.lower() == "ecx"))):
            return None
        
        pattern_start = current_ea
        current_ea = self.find_next_instruction(current_ea)
        if not current_ea:
            return None
        
        # Check instruction 2: setz/setnz/setnl with cl or al
        mnem = idc.print_insn_mnem(current_ea)
        op1 = idc.print_operand(current_ea, 0)
        if not (mnem and op1 and 
                mnem.lower() in ["setz", "setnz", "setnl"] and 
                op1.lower() in ["cl", "al"]):
            return None
        
        setz_type = mnem.lower()
        current_ea = self.find_next_instruction(current_ea)
        if not current_ea:
            return None
        
        # Skip the strict mov rax, cs:off_... check
        # Just continue from the setz/setnz/setnl instruction
        mov_rax_ea = current_ea  # Keep track for compatibility
        data_ref = 0  # Will be determined during emulation
        
        # Count the next instructions to find jmp rax
        instruction_count = 0
        max_instructions = 50  # Increased range for more flexible patterns
        
        jmp_rax_ea = None
        
        while current_ea and instruction_count < max_instructions:
            mnem = idc.print_insn_mnem(current_ea)
            op1 = idc.print_operand(current_ea, 0)
            
            # Check if this is "jmp rax"
            if (mnem and op1 and 
                mnem.lower() == "jmp" and 
                op1.lower() == "rax"):
                jmp_rax_ea = current_ea
                break
            
            instruction_count += 1
            current_ea = self.find_next_instruction(current_ea)
        
        # Verify we found jmp rax within reasonable instruction count
        # Relaxed constraints: allow 5-50 instructions
        if not jmp_rax_ea or instruction_count < 5 or instruction_count > 45:
            return None
        
        return {
            "start_ea": pattern_start,
            "end_ea": jmp_rax_ea,
            "setz_type": setz_type,
            "mov_rax_ea": mov_rax_ea,
            "data_ref": data_ref,
            "instruction_count": instruction_count,
            "total_size": jmp_rax_ea - pattern_start + idc.get_item_size(jmp_rax_ea)
        }
    
    def search_all_patterns(self):
        """Search for all instances of the obfuscated jump pattern."""
        patterns = []
        
        print("[*] Searching for obfuscated jump patterns...")
        print("[*] Pattern: sub rax,rcx/sub eax,ecx; setz/setnz/setnl cl/al; <5-45 instrs>; jmp rax")
        
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
            
            # Search for "sub rax, rcx" instructions
            current_ea = seg.start_ea
            
            while current_ea < seg.end_ea:
                # Find next "sub" instruction
                current_ea = ida_search.find_text(current_ea, 0, 0, "sub", ida_search.SEARCH_DOWN)
                if current_ea == idc.BADADDR or current_ea >= seg.end_ea:
                    break
                
                # Check if this is "sub rax, rcx" or "sub eax, ecx"
                mnem = idc.print_insn_mnem(current_ea)
                op1 = idc.print_operand(current_ea, 0)
                op2 = idc.print_operand(current_ea, 1)
                
                if (mnem and mnem.lower() == "sub" and
                    ((op1.lower() == "rax" and op2.lower() == "rcx") or
                     (op1.lower() == "eax" and op2.lower() == "ecx"))):
                    pattern = self.check_obfuscated_jump_pattern(current_ea)
                    if pattern:
                        patterns.append(pattern)
                        print(f"[+] Found pattern at 0x{pattern['start_ea']:X}")
                
                # Move to next instruction
                current_ea = self.find_next_instruction(current_ea)
                if not current_ea:
                    break
        
        self.patterns = patterns
        return patterns
    
    def emulate_jump_target(self, start_addr, end_addr, rax_val, rcx_val, verbose=False):
        """Emulate the obfuscated jump and return the target address."""
        if not self.eh:
            self.eh = flare_emu.EmuHelper()
        
        initial_regs = {
            "rax": rax_val,
            "rcx": rcx_val,
        }
        
        if verbose:
            print(f"[*] Emulating 0x{start_addr:X} with rax=0x{rax_val:X}, rcx=0x{rcx_val:X}")
        
        try:
            # Emulate the range
            self.eh.emulateRange(
                start_addr, 
                endAddr=end_addr,
                registers=initial_regs,
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
        """Deobfuscate a single pattern by emulating all three cases."""
        start_ea = pattern['start_ea']
        end_ea = pattern['end_ea']
        setz_type = pattern['setz_type']
        
        print(f"\n[*] Deobfuscating pattern at 0x{start_ea:X}")
        print(f"    Condition type: {setz_type}")
        
        # Test values for the three cases
        test_base = 0x1000000000000000
        
        # Case 1: rax == rcx (ZF = 1)
        rax_eq = test_base
        rcx_eq = test_base
        target_eq = self.emulate_jump_target(start_ea, end_ea, rax_eq, rcx_eq)
        
        # Case 2: rax > rcx (ZF = 0, rax - rcx > 0)
        rax_gt = test_base + 0x1000
        rcx_gt = test_base
        target_gt = self.emulate_jump_target(start_ea, end_ea, rax_gt, rcx_gt)
        
        # Case 3: rax < rcx (ZF = 0, rax - rcx < 0)
        rax_lt = test_base
        rcx_lt = test_base + 0x1000
        target_lt = self.emulate_jump_target(start_ea, end_ea, rax_lt, rcx_lt)
        
        if not all([target_eq is not None, target_gt is not None, target_lt is not None]):
            print(f"[-] Failed to emulate all cases for pattern at 0x{start_ea:X}")
            return None
        
        print(f"[+] Results:")
        print(f"    rax == rcx (ZF=1): 0x{target_eq:X}")
        print(f"    rax > rcx  (ZF=0): 0x{target_gt:X}")
        print(f"    rax < rcx  (ZF=0): 0x{target_lt:X}")
        
        # Analyze the results to determine the conditional jump logic
        deobf_info = {
            "pattern": pattern,
            "targets": {
                "equal": target_eq,
                "greater": target_gt,
                "less": target_lt
            },
            "setz_type": setz_type
        }
        
        # Determine the equivalent conditional jumps
        equivalent_jumps = self.build_conditional_jumps(deobf_info)
        deobf_info["equivalent_jumps"] = equivalent_jumps
        
        return deobf_info
    
    def build_conditional_jumps(self, deobf_info):
        """Build equivalent conditional jump instructions from emulation results."""
        targets = deobf_info["targets"]
        setz_type = deobf_info["setz_type"]
        start_ea = deobf_info["pattern"]["start_ea"]
        end_ea = deobf_info["pattern"]["end_ea"]
        
        # Group targets by their values
        unique_targets = {}
        for condition, target in targets.items():
            if target not in unique_targets:
                unique_targets[target] = []
            unique_targets[target].append(condition)
        
        print(f"[*] Building conditional jumps:")
        
        equivalent_jumps = []
        
        # Condition flag behavior after "sub rax, rcx":
        # - If setz_type is "setz": cl/al=1 when ZF=1 (rax==rcx), cl/al=0 when ZF=0 (rax!=rcx)
        # - If setz_type is "setnz": cl/al=0 when ZF=1 (rax==rcx), cl/al=1 when ZF=0 (rax!=rcx)  
        # - If setz_type is "setnl": cl/al=1 when SF==OF (rax>=rcx), cl/al=0 when SF!=OF (rax<rcx)
        
        if len(unique_targets) == 1:
            # All cases jump to the same target - this is just an unconditional jump
            target = list(unique_targets.keys())[0]
            jump_type = "jmp"
            equivalent_jumps.append({
                "type": "unconditional",
                "instruction": f"jmp 0x{target:X}",
                "target": target,
                "offset": target - end_ea
            })
            print(f"    Unconditional: jmp 0x{target:X}")
            
        elif len(unique_targets) == 2:
            # Two different targets - conditional jump
            targets_list = list(unique_targets.keys())
            target1, target2 = targets_list[0], targets_list[1]
            
            # Determine which conditions go to which target
            conditions1 = unique_targets[target1]
            conditions2 = unique_targets[target2]
            
            # Build the conditional logic based on the original comparison (sub rax, rcx)
            # and the setz/setnz instruction
            
            if "equal" in conditions1:
                # Equal case goes to target1
                if setz_type == "setz":
                    # setz cl means cl=1 when ZF=1 (equal), cl=0 when ZF=0 (not equal)
                    # So when equal, we go to target1; when not equal, we go to target2
                    jump_condition = "je"  # Jump if equal
                elif setz_type == "setnz":
                    # setnz cl means cl=0 when ZF=1 (equal), cl=1 when ZF=0 (not equal)
                    # This is inverted logic
                    jump_condition = "jne"  # Jump if not equal (but target is swapped)
                    target1, target2 = target2, target1  # Swap targets
                else:  # setnl
                    # setnl cl means cl=1 when SF==OF (rax>=rcx), cl=0 when SF!=OF (rax<rcx)
                    # Equal case goes to target1, so this is likely jge (jump if greater or equal)
                    jump_condition = "jge"  # Jump if greater or equal
                
                equivalent_jumps.append({
                    "type": "conditional",
                    "condition": jump_condition,
                    "instruction": f"{jump_condition} 0x{target1:X}",
                    "target_true": target1,
                    "target_false": target2,
                    "offset_true": target1 - end_ea,
                    "offset_false": target2 - end_ea
                })
                
                print(f"    Conditional: {jump_condition} 0x{target1:X}")
                print(f"    Fallthrough: jmp 0x{target2:X}")
                
            elif setz_type == "setnl":
                # For setnl, check if greater and equal go to the same target (>=)
                # or if less goes to one target and greater+equal go to another
                if "greater" in conditions1 and "equal" in conditions1:
                    # greater and equal both go to target1, less goes to target2
                    jump_condition = "jge"  # Jump if greater or equal
                elif "less" in conditions1:
                    # less goes to target1, greater+equal go to target2
                    jump_condition = "jl"   # Jump if less
                else:
                    # Fallback - treat as complex
                    equivalent_jumps.append({
                        "type": "complex_conditional",
                        "targets": unique_targets,
                        "note": "Complex setnl conditional - manual analysis required"
                    })
                    print(f"    Complex setnl conditional detected - manual analysis required")
                    return equivalent_jumps
                
                equivalent_jumps.append({
                    "type": "conditional",
                    "condition": jump_condition,
                    "instruction": f"{jump_condition} 0x{target1:X}",
                    "target_true": target1,
                    "target_false": target2,
                    "offset_true": target1 - end_ea,
                    "offset_false": target2 - end_ea
                })
                
                print(f"    Conditional: {jump_condition} 0x{target1:X}")
                print(f"    Fallthrough: jmp 0x{target2:X}")
                
            else:
                # More complex case - might need to check greater/less conditions
                # For now, create a generic conditional based on the pattern
                equivalent_jumps.append({
                    "type": "complex_conditional",
                    "targets": unique_targets,
                    "note": "Complex conditional - manual analysis required"
                })
                print(f"    Complex conditional detected - manual analysis required")
        
        return equivalent_jumps
    
    def generate_patch_data(self):
        """Generate patch data for all deobfuscated jumps."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        patch_filename = f"patch_deobf_conditional_jumps_{timestamp}.json"
        
        patch_data = {
            "timestamp": timestamp,
            "description": "Deobfuscated jump patterns",
            "patches": []
        }
        
        for deobf in self.deobfuscated_jumps:
            if not deobf:
                continue
                
            pattern = deobf["pattern"]
            equivalent_jumps = deobf["equivalent_jumps"]
            
            patch_entry = {
                "address": f"0x{pattern['start_ea']:X}",
                "end_address": f"0x{pattern['end_ea']:X}",
                "original_size": pattern["total_size"],
                "pattern_type": "obfuscated_jump",
                "setz_type": deobf["setz_type"],
                "targets": {k: f"0x{v:X}" for k, v in deobf["targets"].items()},
                "equivalent_jumps": equivalent_jumps,
                "comment": f"Deobfuscated jump pattern - {len(equivalent_jumps)} equivalent instruction(s)"
            }
            
            patch_data["patches"].append(patch_entry)
        
        # Save patch data
        with open(patch_filename, 'w') as f:
            json.dump(patch_data, f, indent=2)
        
        print(f"[+] Patch data saved to: {patch_filename}")
        return patch_filename
    
    def add_comments(self):
        """Add comments to the deobfuscated patterns (no coloring)."""
        for deobf in self.deobfuscated_jumps:
            if not deobf:
                continue
                
            pattern = deobf["pattern"]
            start_ea = pattern["start_ea"]
            end_ea = pattern["end_ea"]
            equivalent_jumps = deobf["equivalent_jumps"]
            
            # Add comment at the start of the pattern
            start_comment = f"[DEOBFUSCATED] Pattern: {deobf['setz_type']}"
            for jump in equivalent_jumps:
                if jump["type"] == "unconditional":
                    start_comment += f" -> jmp 0x{jump['target']:X}"
                elif jump["type"] == "conditional":
                    start_comment += f" -> {jump['condition']} 0x{jump['target_true']:X}"
            
            idc.set_cmt(start_ea, start_comment, 0)
            
            # Add comment at the jmp rax instruction
            end_comment = "[DEOBFUSCATED] Equivalent: "
            for i, jump in enumerate(equivalent_jumps):
                if i > 0:
                    end_comment += "; "
                end_comment += jump.get("instruction", "complex")
            
            idc.set_cmt(end_ea, end_comment, 0)
    
    def run_deobfuscation(self):
        """Main function to run the complete deobfuscation process."""
        print("="*70)
        print("Obfuscated Jump Deobfuscation")
        print("="*70)
        
        # Step 1: Search for patterns
        patterns = self.search_all_patterns()
        
        if not patterns:
            print("[-] No obfuscated jump patterns found.")
            return
        
        print(f"[+] Found {len(patterns)} obfuscated jump pattern(s)")
        
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
        
        # Step 4: Add comments only (no drawing/coloring)
        print(f"[*] Adding comments (no coloring)...")
        self.add_comments()
        
        # Step 5: Summary
        print("\n" + "="*70)
        print("DEOBFUSCATION SUMMARY")
        print("="*70)
        
        successful = sum(1 for d in self.deobfuscated_jumps if d is not None)
        print(f"[+] Successfully deobfuscated: {successful}/{len(patterns)} patterns")
        print(f"[+] Patch data saved to: {patch_file}")
        print(f"[+] Check green-colored instructions and comments in IDA")
        
        return self.deobfuscated_jumps


def main():
    """Main entry point."""
    deobfuscator = ObfuscatedJumpDeobfuscator()
    return deobfuscator.run_deobfuscation()


if __name__ == "__main__":
    main()
