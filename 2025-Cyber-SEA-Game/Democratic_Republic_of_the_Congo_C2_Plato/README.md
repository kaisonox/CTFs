# Democratic Republic of the Congo C2 — Plato

**Category:** forensics / stego

## Solution

**1. Carve the embedded archive.** The provided JPEG (`C2_Plato.jpg`) has an
appended ZIP. `binwalk` extracts it; the archive is password-protected and
unpacks into 12 image tiles of Jacques-Louis David's *The Death of Socrates*.

**2. Recover the fragments.** Running `strings` over each of the 12 tiles yields
a short scrambled text fragment per image:

```
q-pvothd   ef!-Ooas   g-aeq-sh   eeq-cvbh   rd-iaeiq   ocressgl
uemthdag   guoae!!}   {Ynk!==Yb   qd-Iugrz   OST_RLNS   yk-drooq
```

**3. Order the tiles.** Reassembling the painting puts the tiles (and therefore
their fragments) in the correct order:

```
11 - 9 - 3 - 6 - 12 - 10 - 4 - 5 - 1 - 2 - 7 - 8
```

Concatenating the fragments in that order gives:

```
OST_RLNS{Ynk!==Ybg-aeq-shocressglyk-drooqqd-Iugrzeeq-cvbhrd-iaeiqq-pvothdef!-Ooasuemthdagguoae!!}
```

**4. Vigenère.** The result is a **Vigenère ciphertext**; decrypting it produces
readable text and the flag.

## Flag

```
CSG_FLAG{Yay!==You-are-successfully-decoded-Vigenere-cipher-inside-pictures!-Congratulations!!}
```
