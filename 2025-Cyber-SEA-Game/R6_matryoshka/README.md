# R6 Matryoshka

A multi-layer ("matryoshka") obfuscated PHP script. Each layer, when executed, just
decodes and `eval`s the next layer — nested dolls all the way down to the flag.

## Files

- The outermost layer is **~130 MB** (one giant `eval(hex2bin("…"))`).
- `final.php` — a much smaller intermediate/final layer (146 bytes) that contains the flag.

## Obfuscation pattern

Every layer is the next layer wrapped in one or more reversible PHP transforms, then
`eval`'d. Peeling the first layers shows the building blocks:

```
eval(hex2bin("6261736536345f6465636f6465..."))      # hex2bin -> ASCII
   -> base64_decode("aGV4MmJpbigiNjc3YTY5...")       # base64  -> ASCII
      -> hex2bin("677a696e666c617465286865...")      # "gzinflate(hex..."
         -> gzinflate(hex2bin("..."))                # decompress
            -> eval(... next layer ...)
```

So the alphabet of wrappers is:

`hex2bin(...)` -> hex decode

`base64_decode` -> base64 decode

`gzinflate(...)` -> raw DEFLATE inflate

`eval(...)` -> run the result

## Final layer / flag

The innermost script is a small decoy + flag:

```php
<?php $s='print("I have a flag!\n"); /* CSG_FLAG{A_Matryoshka_Obfuscated_Script} */ print("Congrats!!\n");';
$s=substr($s, 0, 27); eval($s); ?>
```

Note the trick: `$s` is truncated to 27 chars before `eval`, so the code that actually
runs is only `print("I have a flag!\n")`. The flag itself sits in the comment inside
the original string.

## Flag

```
CSG_FLAG{A_Matryoshka_Obfuscated_Script}
```
