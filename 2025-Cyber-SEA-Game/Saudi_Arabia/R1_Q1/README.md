# Saudi Arabia R1 Q1 - Corrupted

We get `corrupted.exe`, which won't run. Restore it and run it (no options) to get the flag.

## Solution

The file is a PE with a tampered header. Looking at the start:

```
corrupted: 00 04 99 01 40 01 b1 a3 00 00 5a 5a 90 00 03 00 ...
restored:  4d 5a 90 00 03 00 00 00 04 00 ...   -> "MZ"
```

Two things are wrong: there are **10 junk bytes prepended**, and the `MZ` magic is
broken. `fix_corrupted.py` fixes both — drop the first 10 bytes, then force the first
byte back to `'M'` — giving a valid PE32 console executable.

```bash
python3 fix_corrupted.py      # corrupted.exe -> restored.exe
```

Running `restored.exe` with no arguments prints the flag. In the disassembly, `main`
builds it from a format string:

```c
printf("CSG_FLAG{%sing_%s_%s_%s!}\n", "find", "the", "magic", "now");
```

`%sing` = `find` + `ing` = `finding`, so the result is:

## Flag

```
CSG_FLAG{finding_the_magic_now!}
```