# Nono

KMACTF 2025 reverse-engineering challenge. The managed .NET game contains decoy nonogram clues. The real clues are patched into the JIT-compiled `GetRegionClues()` method by a native payload embedded into the final `Nono.exe`.

## Build

Run from the repository root in a VS x64 Native Tools Command Prompt:

```bat
build.bat release
build.bat debug
```

The build writes outputs under `Nono\bin\x64\<Config>\net8.0\`:

- `payload.exe`: native payload PE.
- `payload.bin`: virtual payload image extracted by `tools\extract_payload.py`.
- `payload.json`: payload base/entry metadata consumed by `tools\patch_pe_payload.py`.
- `Nono.patched.exe`: final game executable with the payload injected.

The managed build pins MSBuild `Platform` to `x64` and forces the output directory to `Nono\bin\x64\<Config>\net8.0`.
Before the managed build, `tools\inject_prompt_bait.py` regenerates `Nono.cs` and `Program.cs` from their `.org.cs` originals and injects harmless prompt-bait strings that are visible in dnSpy.

Partial targets are available:

```bat
build.bat release managed
build.bat release payload   # native payload PE + converted payload blob
build.bat debug all
```

## Runtime Design

`Nono.patched.exe` starts at an injected `.nono` section. The entry stub saves process-start state, calls the payload, restores state, then jumps to the original apphost entrypoint.
The payload image is page-aligned inside `.nono` so constants keep the alignment assumptions MSVC made when compiling `payload.exe`.

The payload starts a worker thread, waits for `clrjit.dll`, hooks `ICorJitCompiler::compileMethod`, and patches matching add-blocks in `GetRegionClues()` with decoded clue data.

The native payload resolves required Windows APIs by walking the PEB and parsing module exports. The payload build does not link `kernel32.lib`; all WinAPI usage goes through the runtime `g_api` table.
The payload extractor fails if the PE still has an import directory or selected relocation directory, because the injected virtual image is expected to be position-independent and self-resolving.

The old managed `LoadLibraryA` loader has been removed; `Nono/Utils.cs` is no longer part of the project.

## Debug Input

The game can pre-fill the grid from a text file:

```bat
Nono.patched.exe images\real_flag.txt
```

The input file must contain 37 lines of 37 `0`/`1` characters.
