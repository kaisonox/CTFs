# chall2

Build the executable:

```bash
python gen_asm.py
nasm -f win32 hg.asm -o hg.obj
link.exe /SUBSYSTEM:CONSOLE /MACHINE:X86 /ENTRY:start hg.obj
python make_rwx.py hg.exe
```
