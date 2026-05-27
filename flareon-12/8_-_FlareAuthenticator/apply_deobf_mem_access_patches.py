# apply_deobf_mem_access_patches.py
# IDAPython script to apply patches for deobfuscated memory access patterns
#
# Reads patch_deobf_mem_*.json produced by deobfuscate_obfuscated_mem_access.py
# and rewrites sequences into direct memory loads/stores where possible, while
# preserving allowed middle instructions and filling remaining space with NOPs.

import json
import os
import struct
from datetime import datetime

import idaapi
import idc
import ida_bytes
import ida_segment


class MemAccessPatcher:
    def __init__(self, json_file=None):
        self.json_file = json_file
        self.patch_data = None
        self.applied_patches = []
        self.failed_patches = []

    def load_patch_data(self, json_file=None):
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

    def create_nop_bytes(self, count):
        if count <= 0:
            return b''
        return b'\x90' * count

    def encode_mov_rip_relative_load(self, from_addr, target_addr, dst_reg):
        # mov dst_reg, qword ptr [rip+disp32] ; disp32 = target - (next_ip)
        reg_map = {
            'rax': 0, 'rcx': 1, 'rdx': 2, 'rbx': 3,
            'rsp': 4, 'rbp': 5, 'rsi': 6, 'rdi': 7,
            'r8': 8, 'r9': 9, 'r10': 10, 'r11': 11,
            'r12': 12, 'r13': 13, 'r14': 14, 'r15': 15,
        }
        r = reg_map.get(dst_reg.lower())
        if r is None:
            return None
        rex = 0x48 | (0x04 if r >= 8 else 0x00)
        opcode = 0x8B  # MOV r64, r/m64
        modrm = 0x05 | ((r & 7) << 3)  # mod=00 r/m=101 for RIP-relative
        next_ip = from_addr + 7  # 1(REX)+1(opcode)+1(modrm)+4(disp)
        disp = target_addr - next_ip
        if disp < -2147483648 or disp > 2147483647:
            return None
        return bytes([rex, opcode, modrm]) + struct.pack('<i', disp)

    def encode_mov_rip_relative_store(self, from_addr, target_addr, src_reg):
        # mov qword ptr [rip+disp32], src_reg
        reg_map = {
            'rax': 0, 'rcx': 1, 'rdx': 2, 'rbx': 3,
            'rsp': 4, 'rbp': 5, 'rsi': 6, 'rdi': 7,
            'r8': 8, 'r9': 9, 'r10': 10, 'r11': 11,
            'r12': 12, 'r13': 13, 'r14': 14, 'r15': 15,
        }
        r = reg_map.get(src_reg.lower())
        if r is None:
            return None
        rex = 0x48 | (0x04 if r >= 8 else 0x00)
        opcode = 0x89  # MOV r/m64, r64
        modrm = 0x05 | ((r & 7) << 3)  # mod=00 r/m=101 for RIP-relative
        next_ip = from_addr + 7
        disp = target_addr - next_ip
        if disp < -2147483648 or disp > 2147483647:
            return None
        return bytes([rex, opcode, modrm]) + struct.pack('<i', disp)

    def patch_one(self, patch_info):
        try:
            start_addr = int(patch_info['address'], 16)
            end_addr = int(patch_info['end_address'], 16)
            middle_start = int(patch_info['middle_start'], 16)
            middle_count = patch_info['middle_count']
            original_size = patch_info['original_size']
            terminal_kind = patch_info['terminal_kind']  # 'store' or 'load'
            terminal_reg = (patch_info.get('terminal_reg') or '').lower()
            target_addr = int(patch_info['resolved_address'], 16)
            arith_op = patch_info.get('arithmetic_operation', 'sub')  # 'sub' or 'add'
            base_reg = patch_info.get('base_register', 'rax')  # 'rax' or 'rcx'
            addressing_mode = patch_info.get('addressing_mode', 'arithmetic')  # 'arithmetic' or 'register_plus_register'

            if addressing_mode == 'register_plus_register':
                print(f"\n[*] Patching {base_reg}-based {addressing_mode} mem {terminal_kind} at 0x{start_addr:X} - 0x{end_addr:X}")
            else:
                print(f"\n[*] Patching {base_reg}-based {arith_op} mem {terminal_kind} at 0x{start_addr:X} - 0x{end_addr:X}")
            print(f"    Original size: {original_size} bytes")
            print(f"    Middle instructions: {middle_count}")
            print(f"    Resolved address: 0x{target_addr:X}")

            patch_bytes = b''
            current_patch_addr = start_addr

            # Preserve middle instructions
            if middle_count > 0:
                middle_size = end_addr - middle_start
                middle_bytes = ida_bytes.get_bytes(middle_start, middle_size)
                if not middle_bytes:
                    print(f"[-] Failed to read middle instructions at 0x{middle_start:X}")
                    return False
                patch_bytes += middle_bytes
                current_patch_addr += len(middle_bytes)
                print(f"    Preserved {middle_count} middle instruction(s) ({len(middle_bytes)} bytes)")

            # Encode terminal direct memory op at current_patch_addr
            encoded = None
            if terminal_kind == 'load':
                # mov reg, [rip+disp]
                encoded = self.encode_mov_rip_relative_load(current_patch_addr, target_addr, terminal_reg)
            else:
                # store: mov [rip+disp], reg
                encoded = self.encode_mov_rip_relative_store(current_patch_addr, target_addr, terminal_reg)

            if not encoded:
                print("[-] Failed to encode RIP-relative mov; target too far or bad reg")
                return False

            patch_bytes += encoded
            current_patch_addr += len(encoded)
            print(f"    Added {len(encoded)}-byte direct memory {'load' if terminal_kind=='load' else 'store'}")

            # Fill with NOPs
            remaining = original_size - len(patch_bytes)
            if remaining < 0:
                print(f"[-] Patch too large! Need {len(patch_bytes)} bytes, have {original_size}")
                return False
            if remaining > 0:
                patch_bytes += self.create_nop_bytes(remaining)
                print(f"    Added {remaining} NOP bytes")

            # Backup original bytes
            original_bytes = ida_bytes.get_bytes(start_addr, original_size)
            if not original_bytes:
                print(f"[-] Failed to read original bytes at 0x{start_addr:X}")
                return False

            # Apply patch
            success = False
            try:
                if ida_bytes.patch_bytes(start_addr, patch_bytes):
                    success = True
                    print("[+] Applied patch via patch_bytes")
            except Exception as e:
                print(f"[*] patch_bytes exception: {e}")

            if not success:
                try:
                    success = True
                    for i, b in enumerate(patch_bytes):
                        ida_bytes.put_byte(start_addr + i, b)
                        if ida_bytes.get_byte(start_addr + i) != b:
                            print(f"[-] Failed put_byte at offset {i}")
                            success = False
                            break
                    if success:
                        print("[+] Applied patch via put_byte")
                except Exception as e:
                    print(f"[*] put_byte exception: {e}")
                    success = False

            if not success:
                try:
                    success = True
                    for i, b in enumerate(patch_bytes):
                        if not ida_bytes.patch_byte(start_addr + i, b):
                            print(f"[-] Failed patch_byte at offset {i}")
                            success = False
                            break
                    if success:
                        print("[+] Applied patch via patch_byte")
                except Exception as e:
                    print(f"[*] patch_byte exception: {e}")
                    success = False

            if not success:
                print(f"[-] All patching methods failed at 0x{start_addr:X}")
                return False

            # Comment
            if addressing_mode == 'register_plus_register':
                if terminal_kind == 'load':
                    comment = f"[PATCHED MEM] {base_reg}-based {addressing_mode}: mov {terminal_reg}, [0x{target_addr:X}]"
                else:
                    comment = f"[PATCHED MEM] {base_reg}-based {addressing_mode}: mov [0x{target_addr:X}], {terminal_reg}"
            else:
                if terminal_kind == 'load':
                    comment = f"[PATCHED MEM] {base_reg}-based {arith_op}: mov {terminal_reg}, [0x{target_addr:X}]"
                else:
                    comment = f"[PATCHED MEM] {base_reg}-based {arith_op}: mov [0x{target_addr:X}], {terminal_reg}"
            idc.set_cmt(start_addr, comment, 0)

            self.applied_patches.append({
                'address': start_addr,
                'size': original_size,
                'original_bytes': original_bytes,
                'patch_bytes': patch_bytes,
                'terminal_kind': terminal_kind,
                'terminal_reg': terminal_reg,
                'resolved_address': target_addr,
                'arithmetic_operation': arith_op,
                'base_register': base_reg,
                'addressing_mode': addressing_mode,
            })
            print(f"[+] Successfully patched at 0x{start_addr:X}")
            return True
        except Exception as e:
            print(f"[-] Error patching pattern: {e}")
            import traceback
            traceback.print_exc()
            return False

    def apply_all_patches(self):
        if not self.patch_data:
            print("[-] No patch data loaded")
            return False
        patches = self.patch_data.get('patches', [])
        if not patches:
            print("[-] No patches in file")
            return False
        print(f"[*] Applying {len(patches)} memory patches...")

        ok = 0
        for i, p in enumerate(patches, 1):
            print("\n" + "=" * 60)
            print(f"Processing patch {i}/{len(patches)}")
            print("=" * 60)
            if self.patch_one(p):
                ok += 1
            else:
                self.failed_patches.append(p)

        print("\n" + "=" * 60)
        print("PATCHING SUMMARY")
        print("=" * 60)
        print(f"[+] Successfully applied: {ok}/{len(patches)} patches")
        if len(patches) - ok:
            print(f"[-] Failed patches: {len(patches) - ok}")
        return ok > 0

    def save_patch_log(self):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_name = f"patch_log_mem_{timestamp}.json"
        data = {
            'timestamp': timestamp,
            'source_json': self.json_file,
            'applied_patches': len(self.applied_patches),
            'failed_patches': len(self.failed_patches),
            'patches': []
        }
        for p in self.applied_patches:
            data['patches'].append({
                'address': f"0x{p['address']:X}",
                'size': p['size'],
                'resolved_address': f"0x{p['resolved_address']:X}",
                'terminal_kind': p['terminal_kind'],
                'terminal_reg': p['terminal_reg'],
                'arithmetic_operation': p['arithmetic_operation'],
                'base_register': p['base_register'],
                'addressing_mode': p['addressing_mode'],
                'original_bytes': p['original_bytes'].hex(),
                'patch_bytes': p['patch_bytes'].hex(),
            })
        with open(log_name, 'w') as f:
            json.dump(data, f, indent=2)
        print(f"[+] Patch log saved to: {log_name}")
        return log_name


def main():
    print("=" * 70)
    print("Obfuscated Memory Access Patch Application")
    print("=" * 70)

    json_files = [f for f in os.listdir('.') if f.startswith('patch_deobf_mem_') and f.endswith('.json')]
    if not json_files:
        print("[-] No memory deobfuscation JSON files found in current directory")
        print("[-] Please run deobfuscate_obfuscated_mem_access.py first to generate patch data")
        return

    json_files.sort(reverse=True)
    latest = json_files[0]
    print(f"[*] Using latest deobfuscation file: {latest}")

    patcher = MemAccessPatcher(latest)
    if not patcher.load_patch_data():
        return

    patches_count = len(patcher.patch_data.get('patches', []))
    print(f"[*] Found {patches_count} memory patches to apply")
    print("[1] Test single patch (for debugging)")
    print("[2] Apply all patches")
    print("[3] Cancel")

    choice = idaapi.ask_long(1, "Choose option (1-3):")
    if choice == 1:
        if patches_count > 0:
            print("[*] Testing first patch...")
            result = patcher.patch_one(patcher.patch_data['patches'][0])
            print(f"[*] Test result: {'SUCCESS' if result else 'FAILED'}")
        return
    elif choice == 2:
        response = idc.ask_yn(1, f"Apply {patches_count} memory patches to the database?")
        if response != 1:
            print("[-] Patching cancelled by user")
            return
        if patcher.apply_all_patches():
            patcher.save_patch_log()
            print("\n[+] Patching complete! Check the patched instructions in IDA.")
            print("[*] Tip: Use 'Edit -> Patch program -> Apply patches to input file' to save changes")
        else:
            print("\n[-] Patching failed or partially failed")
    else:
        print("[-] Cancelled by user")


if __name__ == '__main__':
    main()


