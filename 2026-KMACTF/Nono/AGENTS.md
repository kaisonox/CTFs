## Project Overview

KMACTF 2025 reverse-engineering challenge. A 37x37 nonogram game (Raylib-cs, .NET 8, Windows x64) whose correct clue values are injected at runtime by a native JIT patch payload. The IL source contains decoy clue values.

## Build Commands

### Full Build And Injection (Windows)

Run from the repository root in a VS x64 Native Tools Command Prompt:

```
build.bat release
build.bat debug
```

The single build file performs the complete release/debug pipeline:

1. `dotnet build Nono\\Nono.csproj -c <Config> -p:Platform=x64 -o Nono\\bin\\x64\\<Config>\\net8.0` builds the managed x64 game.
2. `cl/link` builds `payload.exe` next to the managed apphost.
3. `tools\extract_payload.py` extracts `.text`, `.rdata`, and `.data` into `payload.bin` plus `payload.json` metadata in the same output directory.
4. `tools\patch_pe_payload.py` injects the payload blob into `Nono.exe` and writes `Nono.patched.exe` in the same output directory.

Before the managed build, `tools\inject_prompt_bait.py` regenerates `Nono.cs` and `Program.cs` from `Nono.org.cs` and `Program.org.cs`, injecting harmless prompt-bait strings that are visible in dnSpy. The `.org.cs` files are excluded from compilation.

Optional partial targets:

```
build.bat release managed
build.bat release payload   # native payload PE + converted payload blob
build.bat debug all
```

Manual binary-level payload obfuscation is handled outside `build.bat` because the target ranges are chosen by inspection. Use `tools\obfuscate_payload.py` after `payload.exe` is linked and before `extract_payload.py`. It requires Python `capstone`, accepts repeated `--range start:end` pairs inside functions, emits an obfuscated PE with a new `.mix` section, wipes displaced original bytes after each entry jump, and prints the `extract_payload.py --sections` reminder. Slot-to-slot transfers randomly choose among several encoded PIC-safe `ret` jump decoders by default; pass `--direct-jumps` only for debugging. Unused bytes inside each slot are random by default; use `--slot-fill int3` only when debugging. Default slot size is 96 bytes; increase `--slot-size` if a copied instruction plus encoded transfer exceeds the slot.

Requirements:

- VS x64 Native Tools Command Prompt for `cl/link`.
- Python available as `python`.

### Managed Debug Run

For local non-injected development only:

```
dotnet run --project Nono/Nono.csproj
dotnet run --project Nono/Nono.csproj -- flags/real_flag.txt
```

Without PE injection, the managed app uses decoy clues.

## Native Payload Source Layout

Native payload code lives under `Nono/payload/`:

- `payload.c`: JIT hook, runtime scan, trampoline patching, anti-debug, EXE payload entrypoint.
- `correct_data.h`: encoded packed clue data plus the `clue_value(index)` decoder for the real QR/nonogram solution.
- `log.h`: optional debug logging helpers. Logging compiles to no-op macros unless `DEBUG` is defined.

The payload EXE is linked with `/FIXED /DYNAMICBASE:NO`; the extractor preserves selected sections as a virtual image and records `ShellMain` as an entry offset.

The payload resolves Windows APIs itself by walking the PEB loader list, finding modules by case-insensitive hashes, parsing exports by case-insensitive hashes, and following forwarded exports into loaded modules such as `kernelbase.dll`. Payload code should call WinAPI only through `g_api`; the payload link step intentionally does not link `kernel32.lib`. Do not add new cleartext API-name literals.
`tools\extract_payload.py` should fail the build if the payload PE still has imports or selected relocations. Do not bypass this unless the entry injection logic is changed to perform loader-style import binding or relocation fixups.

Enable hook logs via `build.bat debug`, which compiles the payload with `/DDEBUG`.

## Architecture

### The Two-Layer Trick

`GetRegionClues()` in `Nono.cs` is the JIT target. It returns a `Dictionary<Region, (rowClues, colClues)>` for 4 overlapping 20x20 regions of the 37x37 grid. The IL contains decoy values. The native payload patches the JIT-compiled native code before `GetRegionClues()` is executed by game logic.

The managed `Utils.cs`/`LoadLibraryA` loader path has been removed. Final startup is through PE entrypoint redirection in the patched `Nono.exe`.

### Payload Install Process

Entry point: `ShellMain -> payload_start()`.

`payload_start()` creates a worker thread and returns immediately. The worker waits until `clrjit.dll` is loaded, then calls `hook_install()`. This is required because the payload can run before CLR/JIT modules are loaded.

1. `hook_install()` finds `clrjit.dll` and resolves `getJit()`.
2. It calls `getJit()` and reads the `ICorJitCompiler` vtable.
3. It saves `vtable[0]` as the original `compileMethod`.
4. It overwrites `vtable[0]` with `hook_compile_method`.
5. If anti-debug checks trigger, `g_ctx.skip = 1`; the hook later unhooks without patching.

`hook_compile_method` must exactly match `compileMethod_t`. Do not change calling convention or arguments.

### Deferred Runtime Patching

.NET 8 uses W^X dual-mapped JIT code. The executable view may not contain the finalized bytes until after `compileMethod` returns. The hook uses a deferred-scan strategy:

1. Before calling the original JIT compiler, it checks whether a previous large method was saved.
2. If present, it scans and patches that previous method.
3. It calls the original `compileMethod`.
4. If the newly compiled method is large enough (`native_size >= 0x800`), it saves `native_entry` and `native_size` for the next hook invocation.
5. Once `CLUE_BLOCK_COUNT` (`1600`) blocks are patched, it restores the original vtable entry and unhooks.

### Runtime Scan Pattern

The proven scan target is the first 1600 single add-blocks in scan order matching:

```
BA xx xx xx xx  mov edx, value
39 09           cmp dword ptr [rcx], ecx
FF 15 xx xx xx  call qword ptr [rip+disp32]
```

Scanner details:

- Collect `BA` positions where `BA imm32 39 09 FF 15 disp32` matches.
- Advance `p += 13` after each hit to avoid overlapping false positives.
- Do not require fixed 17-byte adjacency.
- Do not require groups to be physically contiguous without gaps.

The first 1600 hits in scan order correspond to `clue_value(0..1599)`. `correct_data.h` intentionally avoids storing final `u32` clue values directly; it stores packed encoded nibbles and derives each value on demand.

### Real Block Shape

Each add-block starts before the `BA` with a `mov rcx, [...]` reload for the `List<int>` instance. The reload length varies:

```
48 8B 4D xx              mov rcx, qword ptr [rbp+disp8]      ; 4 bytes
48 8B 4C 24 xx           mov rcx, qword ptr [rsp+disp8]      ; 5 bytes
48 8B 8D xx xx xx xx     mov rcx, qword ptr [rbp+disp32]     ; 7 bytes
48 8B 8C 24 xx xx xx xx  mov rcx, qword ptr [rsp+disp32]     ; 8 bytes
```

The copied payload length is therefore `mov_len + 13`, not a fixed 17 bytes.

Empirically for the current build:

- 1600 add-blocks total.
- 40 use 4-byte `mov rcx`.
- 1560 use 7-byte `mov rcx`.
- Intra-group add-blocks have a 1-byte `90` gap between copied blocks.
- Inter-group gaps contain normal JIT code and must be preserved by jumping back after the 10th copied block.

### Trampoline Patching Process

`apply_replay_plan()` collects the 1600 candidate positions with a staged opcode check, then attempts `emit_replay_chain()`. If the trampoline path fails validation/allocation/range checks, it leaves the method untouched and keeps waiting rather than applying a direct immediate patch.

`emit_replay_chain()` process:

1. For every candidate position, use `locate_replay_start()` to identify the real block start and `mov_len`.
2. Validate `block_len = mov_len + 13` fits in `TRAMP_SLOT_SIZE` after appending a 13-byte absolute jump.
3. Allocate one RWX trampoline buffer near the JIT code via `VirtualAlloc` hints within about +/-1.5 GB.
4. Use 160 groups x 10 slots.
5. For each block:
   - Fill the slot with `90`.
   - Copy the original `mov rcx` reload.
   - Materialize the correct `edx` value using small arithmetic operations rather than a direct `mov edx, imm32`.
   - Copy `cmp [rcx], ecx` and the `FF 15` call opcode.
   - Rebase the copied `FF 15 disp32`.
   - Append an absolute `mov r11, imm64; jmp r11`.
6. Chain slots 0 -> 1 -> ... -> 9 inside each group.
7. Slot 9 jumps back to original JIT code at `pos[group*10 + 9] + 13`, preserving normal code between list initializers.
8. Patch only original block 0 of each group with an absolute jump to that group's trampoline.
9. Original blocks 1..9 are left untouched for safer behavior; execution reaches them only if the trampoline path is not used.

### Near Allocation Requirement

Near allocation is mandatory because the copied call remains `FF 15 disp32`, which uses a signed 32-bit RIP-relative displacement. If the trampoline buffer is more than +/-2 GB from the original call thunk, rebasing overflows.

Always range-check the rebased displacement before writing it. The current code uses `fits_s32()` and aborts the trampoline attempt on failure.

Absolute jumps are used for trampoline chaining and entry redirection:

```
49 BB imm64      mov r11, imm64
41 FF E3         jmp r11
```

These jumps do not require near targets, but the copied `FF 15` call still does.

### Failure Behavior

If trampoline patching fails, do not add a simpler backup patch path. A secondary path tends to become the easiest one to recover from quick decompilation.

## PE Injection

`tools/patch_pe_payload.py` injects the virtual payload image from `payload.bin` into a new `.nono` section and redirects the apphost entrypoint there. Use `payload.json` so the stub calls the recorded `ShellMain` offset inside that image rather than assuming offset zero. The payload image start is page-aligned inside `.nono`; do not place it directly after the entry stub, because MSVC may emit aligned SIMD loads for constants in the extracted image.

The injected entry stub:

1. Saves flags and all GPRs.
2. Allocates Win64 shadow space.
3. Calls the payload blob.
4. Restores registers and flags.
5. Jumps to the original apphost entrypoint.

The patcher clears `IMAGE_DLLCHARACTERISTICS_GUARD_CF` and load-config `GuardFlags` by default. Do not keep CFG enabled unless the new entrypoint RVA is also registered in the GuardCF function table; otherwise Windows can fail fast with `C0000409` before the stub's first instruction executes.

## Grid / Validation

- 37x37 main grid split into 4 overlapping 20x20 regions (A, B, C, D).
- Region offsets: A `(0,0)`, B `(0,17)`, C `(17,0)`, D `(17,17)`.
- `ValidateRegion` checks each region's rows and columns against the JIT-patched clues.
- Win condition: all 4 regions solved, then the grid renders as a scannable QR code.
- Debug mode: pass a `.txt` file as argument (37 lines of 37 `0`/`1` chars) to pre-fill the grid.

## Native Payload Constraints

- No CRT: `/NODEFAULTLIB /Zl`.
- Keep large arrays static to avoid `__chkstk`.
- Avoid compiler-generated CRT helpers; a local `memset` shim exists because MSVC may emit `memset` even for simple fill loops.
- Keep C89-style declarations at the top of blocks.
- Do not change `hook_compile_method` signature or calling convention.
- Do not silently cast pointer deltas to `s32`; validate with `fits_s32()` first.

## Anti-Debug

`anti_debug()` checks:

- `IsDebuggerPresent()`.
- PEB `NtGlobalFlag & 0x70` at `PEB+0xBC`.
- Heap `ForceFlags` at `heap+0x74`.
- RDTSC timing threshold over 3,000,000 cycles.

If debugged, `g_ctx.skip = 1`; the hook leaves decoy values and unhooks silently.
