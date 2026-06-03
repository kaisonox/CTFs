# Angola C2 - Do You Think I'm Fragile

## Solution

`kimpampara.txt` is double Base64. Decoding twice yields a sequence of `U+HHHH` Unicode codepoints which form a Windows [batch script](command.txt)

The batch reconstructs strings using `%VAR:~offset,1%` lookups and derives several alphabets; the final `echo` indexes into those alphabets to build the password.

## Flag

```
F1r3NIc3$4Lyfe
```
