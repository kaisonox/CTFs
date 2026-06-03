# China C1

We get example (ciphertext, plaintext) pairs and one ciphertext to decrypt into the flag.

## Solution

Structure of each ciphertext: two halves of equal length.

- The **second half** is the raw keystream (key).
- The **first half** is `base64(plaintext) XOR key`.

To decrypt:

```
first_half XOR second_half  ->  base64  ->  plaintext
```

Verified against the known pairs (`Great Scott!`, `Hello? Hello? Anybody home?`), then applied to the flag ciphertext.

```bash
python3 solve.py
```

## Flag

```
CSG_FLAG{Wont_U_make_Lemonade}
```
