# deobfuscate_obfuscated_mem_access.py
# IDAPython script to deobfuscate obfuscated memory access patterns
#
# Pattern handled:
#   mov rax/rcx, cs:off_XXXX
#   mov reg64, imm64
#   sub rax/rcx, reg64  OR  add rax/rcx, reg64
#   <zero or more instructions that DO NOT write to rax/rcx and no control flow>
#   mov [rax/rcx], another_reg64    OR    mov another_reg64, [rax/rcx]
#
# Alternative pattern (register+register addressing):
#   mov rax/rcx, cs:off_XXXX
#   mov reg64, imm64
#   <zero or more instructions that DO NOT write to rax/rcx and no control flow>
#   mov [rax/rcx + reg64], another_reg64    OR    mov another_reg64, [rax/rcx + reg64]
#
# This script finds the above sequences, emulates them to compute the concrete
# address placed in rax/rcx, and emits a JSON describing the resolved memory address
# and the equivalent direct memory operation. It also annotates the database.

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
import ida_ua
import ida_name


class ObfuscatedMemAccessDeobfuscator:
    def __init__(self):
        self.patterns = []
        self.results = []
        self.eh = None

    def find_next_instruction(self, ea):
        next_ea = idc.next_head(ea)
        if next_ea == idc.BADADDR:
            return None
        return next_ea

    def instruction_writes_to_register(self, ea, target_reg):
        mnem = idc.print_insn_mnem(ea)
        if not mnem:
            return False
        op1 = idc.print_operand(ea, 0)
        if not op1:
            return False
        op1l = op1.lower()
        if target_reg.lower() in op1l:
            if mnem.lower() in [
                'mov', 'add', 'sub', 'xor', 'or', 'and', 'lea', 'imul', 'mul', 'div', 'idiv',
                'neg', 'not', 'shl', 'shr', 'sal', 'sar', 'rol', 'ror', 'inc', 'dec',
                'movzx', 'movsx', 'movsxd'
            ]:
                return True
        return False

    def check_pattern(self, start_ea):
        # Instruction 1: mov rax/rcx, cs:off_...
        mnem = idc.print_insn_mnem(start_ea)
        op1 = idc.print_operand(start_ea, 0)
        op2 = idc.print_operand(start_ea, 1)
        if not (mnem and mnem.lower() == 'mov' and op1):
            return None
        if not (op1.lower() in ['rax', 'rcx']):
            return None
        if not (op2 and ("cs:off_" in op2 or ("cs:" in op2 and "off_" in op2))):
            return None
        
        # Store the base register (rax or rcx)
        base_reg = op1.lower()

        pattern_start = start_ea
        current_ea = self.find_next_instruction(start_ea)
        if not current_ea:
            return None

        # Instruction 2: mov reg64, imm
        mnem = idc.print_insn_mnem(current_ea)
        mov2_op1 = idc.print_operand(current_ea, 0)
        if not (mnem and mnem.lower() == 'mov' and mov2_op1):
            return None
        if mov2_op1.lower() in [base_reg, base_reg.replace('x', 'x')]:  # Don't use the same register as base
            return None
        if idc.get_operand_type(current_ea, 1) != idc.o_imm:
            return None
        loaded_reg = mov2_op1.lower()

        current_ea = self.find_next_instruction(current_ea)
        if not current_ea:
            return None

        # Instruction 3: sub base_reg, loaded_reg OR add base_reg, loaded_reg
        mnem = idc.print_insn_mnem(current_ea)
        op1 = idc.print_operand(current_ea, 0)
        op2 = idc.print_operand(current_ea, 1)
        if not (mnem and mnem.lower() in ['sub', 'add'] and op1 and op1.lower() == base_reg and op2 and op2.lower() == loaded_reg):
            return None
        
        # Store the operation type for later use
        operation_type = mnem.lower()  # 'sub' or 'add'

        # Walk middle instructions until a terminal mov [base_reg],reg OR mov reg,[base_reg]
        middle_start = self.find_next_instruction(current_ea)
        if not middle_start:
            return None
        middle_instructions = []
        max_middle_instructions = 20
        current_ea = middle_start
        terminal_ea = None
        terminal_kind = None  # 'store' or 'load'
        terminal_reg = None

        while current_ea and len(middle_instructions) <= max_middle_instructions:
            mnem = idc.print_insn_mnem(current_ea)
            op1 = idc.print_operand(current_ea, 0) or ''
            op2 = idc.print_operand(current_ea, 1) or ''

            # Terminal checks
            # mov [base_reg], reg64
            if mnem and mnem.lower() == 'mov' and (op1.lower().startswith(f'qword ptr [{base_reg}]') or op1.lower().startswith(f'[{base_reg}]')):
                # store
                terminal_ea = current_ea
                terminal_kind = 'store'
                terminal_reg = op2.lower()
                break
            # mov reg64, [base_reg]
            if mnem and mnem.lower() == 'mov' and f'[{base_reg}]' in op2.lower():
                terminal_ea = current_ea
                terminal_kind = 'load'
                terminal_reg = op1.lower()
                break

            # Reject if base_reg is modified or control flow occurs
            if self.instruction_writes_to_register(current_ea, base_reg):
                return None
            if mnem and mnem.lower() in ['call', 'jmp', 'je', 'jne', 'jz', 'jnz', 'jl', 'jg', 'jle', 'jge', 'ja', 'jb', 'jae', 'jbe', 'ret']:
                return None

            middle_instructions.append(current_ea)
            current_ea = self.find_next_instruction(current_ea)

        if not terminal_ea or not terminal_kind:
            return None

        total_size = terminal_ea - pattern_start + idc.get_item_size(terminal_ea)
        return {
            'start_ea': pattern_start,
            'end_ea': terminal_ea,
            'middle_start': middle_start if middle_instructions else terminal_ea,
            'middle_instructions': middle_instructions,
            'middle_count': len(middle_instructions),
            'loaded_register': loaded_reg,
            'base_register': base_reg,  # 'rax' or 'rcx'
            'operation_type': f'{operation_type}_mem_{terminal_kind}',  # sub/add + mem load/store
            'arithmetic_operation': operation_type,  # 'sub' or 'add'
            'addressing_mode': 'arithmetic',  # 'arithmetic' for sub/add patterns
            'terminal_kind': terminal_kind,
            'terminal_reg': terminal_reg,
            'total_size': total_size,
        }

    def check_register_plus_register_pattern(self, start_ea):
        # Pattern: mov rax/rcx, cs:off_...; mov reg64, imm; <middle>; mov [rax/rcx + reg64], reg | mov reg, [rax/rcx + reg64]
        
        # Instruction 1: mov rax/rcx, cs:off_...
        mnem = idc.print_insn_mnem(start_ea)
        op1 = idc.print_operand(start_ea, 0)
        op2 = idc.print_operand(start_ea, 1)
        if not (mnem and mnem.lower() == 'mov' and op1):
            return None
        if not (op1.lower() in ['rax', 'rcx']):
            return None
        if not (op2 and ("cs:off_" in op2 or ("cs:" in op2 and "off_" in op2))):
            return None
        
        # Store the base register (rax or rcx)
        base_reg = op1.lower()
        pattern_start = start_ea
        current_ea = self.find_next_instruction(start_ea)
        if not current_ea:
            return None

        # Instruction 2: mov reg64, imm
        mnem = idc.print_insn_mnem(current_ea)
        mov2_op1 = idc.print_operand(current_ea, 0)
        if not (mnem and mnem.lower() == 'mov' and mov2_op1):
            return None
        if mov2_op1.lower() in [base_reg, base_reg.replace('x', 'x')]:  # Don't use the same register as base
            return None
        if idc.get_operand_type(current_ea, 1) != idc.o_imm:
            return None
        loaded_reg = mov2_op1.lower()

        # Walk middle instructions until a terminal mov [base_reg + loaded_reg], reg OR mov reg, [base_reg + loaded_reg]
        middle_start = self.find_next_instruction(current_ea)
        if not middle_start:
            return None
        middle_instructions = []
        max_middle_instructions = 20
        current_ea = middle_start
        terminal_ea = None
        terminal_kind = None  # 'store' or 'load'
        terminal_reg = None

        while current_ea and len(middle_instructions) <= max_middle_instructions:
            mnem = idc.print_insn_mnem(current_ea)
            op1 = idc.print_operand(current_ea, 0) or ''
            op2 = idc.print_operand(current_ea, 1) or ''

            # Terminal checks for [base_reg + loaded_reg] addressing
            # mov [base_reg + loaded_reg], reg64
            if mnem and mnem.lower() == 'mov':
                # Check for various forms: [rax+reg], [rax + reg], qword ptr [rax+reg], etc.
                op1_lower = op1.lower()
                if (f'[{base_reg}+{loaded_reg}]' in op1_lower or 
                    f'[{base_reg} + {loaded_reg}]' in op1_lower or
                    f'qword ptr [{base_reg}+{loaded_reg}]' in op1_lower or
                    f'qword ptr [{base_reg} + {loaded_reg}]' in op1_lower):
                    terminal_ea = current_ea
                    terminal_kind = 'store'
                    terminal_reg = op2.lower()
                    break
            
            # mov reg64, [base_reg + loaded_reg]
            if mnem and mnem.lower() == 'mov':
                op2_lower = op2.lower()
                if (f'[{base_reg}+{loaded_reg}]' in op2_lower or 
                    f'[{base_reg} + {loaded_reg}]' in op2_lower or
                    f'qword ptr [{base_reg}+{loaded_reg}]' in op2_lower or
                    f'qword ptr [{base_reg} + {loaded_reg}]' in op2_lower):
                    terminal_ea = current_ea
                    terminal_kind = 'load'
                    terminal_reg = op1.lower()
                    break

            # Reject if base_reg or loaded_reg is modified or control flow occurs
            if self.instruction_writes_to_register(current_ea, base_reg) or self.instruction_writes_to_register(current_ea, loaded_reg):
                return None
            if mnem and mnem.lower() in ['call', 'jmp', 'je', 'jne', 'jz', 'jnz', 'jl', 'jg', 'jle', 'jge', 'ja', 'jb', 'jae', 'jbe', 'ret']:
                return None

            middle_instructions.append(current_ea)
            current_ea = self.find_next_instruction(current_ea)

        if not terminal_ea or not terminal_kind:
            return None

        total_size = terminal_ea - pattern_start + idc.get_item_size(terminal_ea)
        return {
            'start_ea': pattern_start,
            'end_ea': terminal_ea,
            'middle_start': middle_start if middle_instructions else terminal_ea,
            'middle_instructions': middle_instructions,
            'middle_count': len(middle_instructions),
            'loaded_register': loaded_reg,
            'base_register': base_reg,  # 'rax' or 'rcx'
            'operation_type': f'reg_plus_reg_mem_{terminal_kind}',  # reg+reg + mem load/store
            'arithmetic_operation': None,  # No arithmetic operation in this pattern
            'addressing_mode': 'register_plus_register',  # 'register_plus_register' for [reg+reg] patterns
            'terminal_kind': terminal_kind,
            'terminal_reg': terminal_reg,
            'total_size': total_size,
        }

    def search_all_patterns(self):
        patterns = []
        print("[*] Searching for obfuscated memory access patterns...")
        print("[*] Pattern 1: mov rax/rcx,cs:off_; mov reg,imm; sub/add rax/rcx,reg; <middle>; mov [rax/rcx],reg | mov reg,[rax/rcx]")
        print("[*] Pattern 2: mov rax/rcx,cs:off_; mov reg,imm; <middle>; mov [rax/rcx + reg],reg | mov reg,[rax/rcx + reg]")

        seg_qty = ida_segment.get_segm_qty()
        for seg_idx in range(seg_qty):
            seg = ida_segment.getnseg(seg_idx)
            if not seg or seg.type != ida_segment.SEG_CODE:
                continue
            print(f"[*] Searching in segment: {idc.get_segm_name(seg.start_ea)}")

            current_ea = seg.start_ea
            while current_ea < seg.end_ea:
                current_ea = ida_search.find_text(current_ea, 0, 0, 'mov', ida_search.SEARCH_DOWN)
                if current_ea == idc.BADADDR or current_ea >= seg.end_ea:
                    break

                mnem = idc.print_insn_mnem(current_ea)
                op1 = idc.print_operand(current_ea, 0)
                op2 = idc.print_operand(current_ea, 1)
                if (mnem and mnem.lower() == 'mov' and op1 and op1.lower() in ['rax', 'rcx'] and op2 and ("cs:off_" in op2 or ("cs:" in op2 and "off_" in op2))):
                    # Try arithmetic pattern first (sub/add)
                    pat = self.check_pattern(current_ea)
                    if pat:
                        patterns.append(pat)
                        print(f"[+] Found {pat['base_register']}-based {pat['addressing_mode']} pattern at 0x{pat['start_ea']:X} ({pat['terminal_kind']}) with {pat['middle_count']} middle insn(s)")
                    else:
                        # Try register+register pattern
                        pat = self.check_register_plus_register_pattern(current_ea)
                        if pat:
                            patterns.append(pat)
                            print(f"[+] Found {pat['base_register']}-based {pat['addressing_mode']} pattern at 0x{pat['start_ea']:X} ({pat['terminal_kind']}) with {pat['middle_count']} middle insn(s)")

                nxt = self.find_next_instruction(current_ea)
                if not nxt:
                    break
                current_ea = nxt

        self.patterns = patterns
        return patterns

    def emulate_and_resolve(self, start_addr, end_addr, base_reg, loaded_reg=None, addressing_mode='arithmetic', verbose=False):
        if not self.eh:
            self.eh = flare_emu.EmuHelper()
        if verbose:
            print(f"[*] Emulating 0x{start_addr:X} to 0x{end_addr:X}")
        try:
            self.eh.emulateRange(start_addr, endAddr=end_addr, skipCalls=True, count=200)
            
            if addressing_mode == 'register_plus_register':
                # For [base_reg + loaded_reg] addressing, we need to add the values
                base_val = self.eh.getRegVal(base_reg)
                loaded_val = self.eh.getRegVal(loaded_reg)
                
                # Handle potential None values from getRegVal
                if base_val is None or loaded_val is None:
                    if verbose:
                        print(f"[-] Failed to get register values: {base_reg}={base_val}, {loaded_reg}={loaded_val}")
                    return None
                    
                final_addr = (base_val + loaded_val) & 0xFFFFFFFFFFFFFFFF  # Mask to 64 bits
                if verbose:
                    print(f"[+] Resolved [{base_reg}] + [{loaded_reg}] = 0x{base_val:X} + 0x{loaded_val:X} = 0x{final_addr:X}")
            else:
                # For arithmetic addressing (sub/add), just use the base register
                final_addr = self.eh.getRegVal(base_reg)
                
                # Handle potential None value from getRegVal
                if final_addr is None:
                    if verbose:
                        print(f"[-] Failed to get register value: {base_reg}={final_addr}")
                    return None
                
                # Mask to 64 bits to handle potential overflow
                final_addr = final_addr & 0xFFFFFFFFFFFFFFFF
                    
                if verbose:
                    print(f"[+] Resolved [{base_reg}] address: 0x{final_addr:X}")
            
            # Ensure the address is a valid integer (range is already handled by masking)
            if not isinstance(final_addr, int):
                if verbose:
                    print(f"[-] Invalid address type: {final_addr} (type: {type(final_addr)})")
                return None
                
            return final_addr
        except Exception as e:
            if verbose:
                print(f"[-] Emulation failed: {e}")
            return None

    def deobfuscate_pattern(self, pattern):
        start_ea = pattern['start_ea']
        end_ea = pattern['end_ea']
        term = pattern['terminal_kind']
        arith_op = pattern.get('arithmetic_operation')
        base_reg = pattern['base_register']
        loaded_reg = pattern.get('loaded_register')
        addressing_mode = pattern.get('addressing_mode', 'arithmetic')
        
        if addressing_mode == 'register_plus_register':
            print(f"\n[*] Deobfuscating {addressing_mode} mem {term} at 0x{start_ea:X} (using [{base_reg} + {loaded_reg}])")
        else:
            print(f"\n[*] Deobfuscating {arith_op}-based mem {term} at 0x{start_ea:X} (using {base_reg})")

        addr = self.emulate_and_resolve(start_ea, end_ea, base_reg, loaded_reg, addressing_mode, verbose=True)
        if addr is None:
            print(f"[-] Failed to emulate pattern at 0x{start_ea:X}")
            return None

        # Try to name the address if it points into a named item
        name = None
        try:
            # Convert to proper address type and check if it's a valid address
            if addr and isinstance(addr, int) and addr >= 0:
                name = ida_name.get_name(addr)
        except (TypeError, ValueError, OverflowError):
            # If get_name fails, just continue without a name
            name = None

        if term == 'store':
            eq = {
                'type': 'mem_store',
                'instruction': f"mov [0x{addr:X}], <reg64>",
                'address': addr,
            }
        else:
            eq = {
                'type': 'mem_load',
                'instruction': f"mov <reg64>, [0x{addr:X}]",
                'address': addr,
            }

        info = {
            'pattern': pattern,
            'resolved_address': addr,
            'resolved_name': name if name else None,
            'equivalent': eq,
        }
        return info

    def add_comments(self):
        for res in self.results:
            if not res:
                continue
            pat = res['pattern']
            start_ea = pat['start_ea']
            end_ea = pat['end_ea']
            addr = res['resolved_address']
            name = res.get('resolved_name')
            term = pat['terminal_kind']

            arith_op = pat.get('arithmetic_operation')
            base_reg = pat['base_register']
            addressing_mode = pat.get('addressing_mode', 'arithmetic')
            
            if addressing_mode == 'register_plus_register':
                loaded_reg = pat.get('loaded_register', 'reg')
                start_comment = f"[DEOBF MEM] {addressing_mode} {term}: [{base_reg}+{loaded_reg}]=0x{addr:X}" if term == 'store' else f"[DEOBF MEM] {addressing_mode} {term}: loads from 0x{addr:X}"
            else:
                start_comment = f"[DEOBF MEM] {arith_op}-based {term}: [{base_reg}]=0x{addr:X}" if term == 'store' else f"[DEOBF MEM] {arith_op}-based {term}: loads from 0x{addr:X}"
            if name:
                start_comment += f" ({name})"
            idc.set_cmt(start_ea, start_comment, 0)

            end_comment = res['equivalent']['instruction']
            idc.set_cmt(end_ea, f"[DEOBF MEM] Equivalent: {end_comment}", 0)

    def generate_patch_data(self):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        fname = f"patch_deobf_mem_{timestamp}.json"
        data = {
            'timestamp': timestamp,
            'description': 'Deobfuscated memory access patterns (sub/add rax/rcx, reg and [rax/rcx + reg] addressing)',
            'patches': []
        }
        for res in self.results:
            if not res:
                continue
            pat = res['pattern']
            entry = {
                'address': f"0x{pat['start_ea']:X}",
                'end_address': f"0x{pat['end_ea']:X}",
                'middle_start': f"0x{pat['middle_start']:X}",
                'middle_count': pat['middle_count'],
                'original_size': pat['total_size'],
                'pattern_type': 'obfuscated_mem_access',
                'operation_type': pat['operation_type'],
                'arithmetic_operation': pat.get('arithmetic_operation'),
                'base_register': pat['base_register'],
                'loaded_register': pat.get('loaded_register'),
                'addressing_mode': pat.get('addressing_mode', 'arithmetic'),
                'terminal_kind': pat['terminal_kind'],
                'terminal_reg': pat.get('terminal_reg'),
                'resolved_address': f"0x{res['resolved_address']:X}",
                'resolved_name': res.get('resolved_name'),
                'equivalent': res['equivalent'],
                'comment': f"{pat['base_register']}-based {pat.get('addressing_mode', 'arithmetic')} {pat['terminal_kind']} at [0x{res['resolved_address']:X}]"
            }
            data['patches'].append(entry)

        with open(fname, 'w') as f:
            json.dump(data, f, indent=2)
        print(f"[+] Patch data saved to: {fname}")
        return fname

    def run(self):
        print("=" * 70)
        print("Obfuscated Memory Access Deobfuscation")
        print("=" * 70)

        pats = self.search_all_patterns()
        if not pats:
            print("[-] No matching patterns found.")
            return

        print(f"[+] Found {len(pats)} pattern(s)")
        print("\n[*] Starting deobfuscation...")
        for i, p in enumerate(pats, 1):
            print("\n" + "=" * 50)
            print(f"Processing pattern {i}/{len(pats)}")
            print("=" * 50)
            r = self.deobfuscate_pattern(p)
            self.results.append(r)

        print("\n[*] Generating patch data...")
        patch_file = self.generate_patch_data()

        print("[*] Adding comments...")
        self.add_comments()

        ok = sum(1 for r in self.results if r)
        print("\n" + "=" * 70)
        print("DEOBFUSCATION SUMMARY")
        print("=" * 70)
        print(f"[+] Successfully deobfuscated: {ok}/{len(pats)} patterns")
        print(f"[+] Patch data saved to: {patch_file}")
        return self.results


def main():
    deobf = ObfuscatedMemAccessDeobfuscator()
    return deobf.run()


if __name__ == '__main__':
    main()


