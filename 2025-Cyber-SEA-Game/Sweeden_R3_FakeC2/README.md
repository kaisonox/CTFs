# Fake C2 (Go implant)

- **Goal**: Analyze the binary and extract the flag.
- **Binary**: `fakeC2.exe` (Go binary)

## High-level behavior

- Entry transfers to `main.main`, which calls `main.startServer` (registers `/check` and `/post`) and then `main.runClient`.
- Client does an HTTP check to `http://127.0.0.1:5555/check`, prompts for a decrypt key, then POSTs JSON `{ "decryptkey": <key> }` to `/post` and prints the server response.

## Server `/post` handler (main.startServer.func2)

- Decodes JSON and extracts `decryptkey`.
- Compares against embedded expected key global `main.expectedKey`.
- If it matches, RC4-decrypts an embedded ciphertext buffer and returns the plaintext; otherwise returns an error message.

## Key and ciphertext

- `main.expectedKey` → "RC4JsonMarshalLocalC2"
- `main.flag` → 73-byte ciphertext (global byte buffer)

## Decryption

- Algorithm: RC4 stream cipher, key = `RC4JsonMarshalLocalC2`
- Decrypting the 73-byte `main.flag` yields JSON containing the flag.

## Flag

- `CSG_FLAG{go_rev_startingpoint}`
