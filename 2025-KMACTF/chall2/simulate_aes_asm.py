import struct
from typing import Tuple

from unicorn import Uc, UC_ARCH_X86, UC_MODE_64
from unicorn.x86_const import (
	UC_X86_REG_RIP,
	UC_X86_REG_RSP,
	UC_X86_REG_RSI,
	UC_X86_REG_XMM0,
	UC_X86_REG_XMM1,
	UC_X86_REG_XMM2,
	UC_X86_REG_XMM3,
	UC_X86_REG_XMM4,
)

from capstone import Cs, CS_ARCH_X86, CS_MODE_64


def u64le(x: int) -> bytes:
	return struct.pack('<Q', x & 0xFFFFFFFFFFFFFFFF)

def bytes_to_u128_le(b: bytes) -> int:
	if len(b) != 16:
		raise ValueError("Expected 16 bytes")
	return int.from_bytes(b, "little")


def u128_to_bytes_le(x: int) -> bytes:
	return x.to_bytes(16, "little")


def build_code() -> bytes:
	"""Return machine code for the aes.asm core logic (encrypt + decrypt)."""
	# Instruction sequence:
	#   pxor       xmm1, xmm0
	#   aesenc     xmm1, xmm2
	#   aesenclast xmm1, xmm3
	#   movdqa     xmm4, xmm2
	#   aesimc     xmm4, xmm4
	#   pxor       xmm1, xmm3
	#   aesdec     xmm1, xmm4
	#   aesdeclast xmm1, xmm0
	#   movdqu     [rsi], xmm1   ; store result
	return bytes([
		0x66, 0x0F, 0xEF, 0xC8,       # pxor xmm1, xmm0
		0x66, 0x0F, 0x38, 0xDC, 0xCA, # aesenc xmm1, xmm2
		0x66, 0x0F, 0x38, 0xDD, 0xCB, # aesenclast xmm1, xmm3
		0x66, 0x0F, 0x6F, 0xE2,       # movdqa xmm4, xmm2
		0x66, 0x0F, 0x38, 0xDB, 0xE4, # aesimc xmm4, xmm4
		0x66, 0x0F, 0xEF, 0xCB,       # pxor xmm1, xmm3
		0x66, 0x0F, 0x38, 0xDE, 0xCC, # aesdec xmm1, xmm4
		0x66, 0x0F, 0x38, 0xDF, 0xC8, # aesdeclast xmm1, xmm0
		0xF3, 0x0F, 0x7F, 0x0E,       # movdqu [rsi], xmm1
	])


def build_encrypt_code() -> bytes:
	"""Return machine code to encrypt: pxor; aesenc; aesenclast; store."""
	return bytes([
		0x66, 0x0F, 0xEF, 0xC8,       # pxor xmm1, xmm0
		0x66, 0x0F, 0x38, 0xDC, 0xCA, # aesenc xmm1, xmm2
		0x66, 0x0F, 0x38, 0xDD, 0xCB, # aesenclast xmm1, xmm3
		0xF3, 0x0F, 0x7F, 0x0E,       # movdqu [rsi], xmm1
	])


def build_decrypt_code() -> bytes:
	"""Return machine code to decrypt per aes.asm sequence."""
	return bytes([
		0x66, 0x0F, 0x6F, 0xE2,       # movdqa xmm4, xmm2
		0x66, 0x0F, 0x38, 0xDB, 0xE4, # aesimc xmm4, xmm4
		0x66, 0x0F, 0xEF, 0xCB,       # pxor xmm1, xmm3
		0x66, 0x0F, 0x38, 0xDE, 0xCC, # aesdec xmm1, xmm4
		0x66, 0x0F, 0x38, 0xDF, 0xC8, # aesdeclast xmm1, xmm0
		0xF3, 0x0F, 0x7F, 0x0E,       # movdqu [rsi], xmm1
	])


def _run_uc_block(xmm1_in: bytes, rk0: bytes, rk1: bytes, rk2: bytes, code: bytes) -> bytes:
	BASE = 0x10000000
	CODE_ADDR = BASE + 0x1000
	STACK_ADDR = BASE + 0x8000
	DATA_ADDR = BASE + 0x2000

	uc = Uc(UC_ARCH_X86, UC_MODE_64)
	uc.mem_map(BASE, 0x10000)
	uc.mem_write(CODE_ADDR, code)
	uc.mem_write(DATA_ADDR, b"\x00" * 16)

	uc.reg_write(UC_X86_REG_RIP, CODE_ADDR)
	uc.reg_write(UC_X86_REG_RSP, STACK_ADDR + 0x400)
	uc.reg_write(UC_X86_REG_RSI, DATA_ADDR)

	uc.reg_write(UC_X86_REG_XMM1, bytes_to_u128_le(xmm1_in))
	uc.reg_write(UC_X86_REG_XMM0, bytes_to_u128_le(rk0))
	uc.reg_write(UC_X86_REG_XMM2, bytes_to_u128_le(rk1))
	uc.reg_write(UC_X86_REG_XMM3, bytes_to_u128_le(rk2))

	uc.emu_start(CODE_ADDR, CODE_ADDR + len(code))
	return bytes(uc.mem_read(DATA_ADDR, 16))


def encrypt_block_uc(plaintext16: bytes, rk0: bytes, rk1: bytes, rk2: bytes) -> bytes:
	"""Encrypt a single 16-byte block using Unicorn AES-NI."""
	if len(plaintext16) != 16:
		raise ValueError("plaintext must be 16 bytes")
	for k in (rk0, rk1, rk2):
		if len(k) != 16:
			raise ValueError("round keys must be 16 bytes each")
	return _run_uc_block(plaintext16, rk0, rk1, rk2, build_encrypt_code())


def decrypt_block_uc(ciphertext16: bytes, rk0: bytes, rk1: bytes, rk2: bytes) -> bytes:
	"""Decrypt a single 16-byte block using Unicorn AES-NI (inverse sequence)."""
	if len(ciphertext16) != 16:
		raise ValueError("ciphertext must be 16 bytes")
	for k in (rk0, rk1, rk2):
		if len(k) != 16:
			raise ValueError("round keys must be 16 bytes each")
	return _run_uc_block(ciphertext16, rk0, rk1, rk2, build_decrypt_code())


def disassemble(code: bytes, addr: int) -> str:
	md = Cs(CS_ARCH_X86, CS_MODE_64)
	lines = []
	for i in md.disasm(code, addr):
		lines.append(f"0x{i.address:016x}: {i.mnemonic}\t{i.op_str}")
	return "\n".join(lines)


def emulate_and_check(plaintext: bytes, rk0: bytes, rk1: bytes, rk2: bytes) -> Tuple[bool, bytes]:
	if len(plaintext) != 16:
		raise ValueError("plaintext must be 16 bytes")
	for k in (rk0, rk1, rk2):
		if len(k) != 16:
			raise ValueError("round keys must be 16 bytes each")
	ct = encrypt_block_uc(plaintext, rk0, rk1, rk2)
	pt2 = decrypt_block_uc(ct, rk0, rk1, rk2)
	return pt2 == plaintext, pt2



if __name__ == "__main__":
	TEST_DATA = u64le(0x0123456789ABCDEF) + u64le(0xFEDCBA9876543210)
	ROUND_KEY0 = u64le(0x2B28AB097EAEF7CF) + u64le(0x15D2154F16A6883C)
	ROUND_KEY1 = u64le(0xA6C5F4031E30AE23) + u64le(0x7C924F6A8B6D5F37)
	ROUND_KEY2 = u64le(0x9F4E2BA7D83A1057) + u64le(0x4D8C91F2A7B3E8C6)

	print("Disassembly (encrypt):")
	print(disassemble(build_encrypt_code(), 0x10000000 + 0x1000))
	print("Disassembly (decrypt):")
	print(disassemble(build_decrypt_code(), 0x10000000 + 0x2000))

	ct = encrypt_block_uc(TEST_DATA, ROUND_KEY0, ROUND_KEY1, ROUND_KEY2)
	pt2 = decrypt_block_uc(ct, ROUND_KEY0, ROUND_KEY1, ROUND_KEY2)
	print("Ciphertext:", ct.hex())
	print("Round-trip ok:", pt2 == TEST_DATA)
	print("Decrypted bytes:", pt2.hex())
