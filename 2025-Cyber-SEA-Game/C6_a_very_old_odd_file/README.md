# Central African Republic C6 — A Very Old Odd File

**Category:** misc / encoding

## Challenge

A text file of `.` and `-` characters. The description hints at "telegraph /
Morse" — but that is a red herring.

## Solution

**1. It isn't Morse.** A long, uniform `.-` stream that doesn't split cleanly
into A–Z by letter/word gaps is a tell. The "older than Morse" teleprinter code
is **Baudot / ITA2**, a fixed 5-bit code.

**2. Decode as ITA2.** Strip everything except `.` and `-`, map the two symbols
to bits, slice into 5-bit groups, and look up the ITA2 *letters* table. Because
the orientation is ambiguous, try four variants — `. -> 1 / - -> 0` and its
inverse, each with and without reversing the bits inside every 5-bit group. One
variant produces clean words.

**3. Swedish spelling alphabet.** The decoded text is a sequence of Swedish radio
spelling-alphabet words — `ADAM=A, BERTIL=B, CAESAR=C, DAVID=D, ERIK=E, …,
SIGURD=S, GUSTAV=G, …`. Mapping each word to its initial letter yields:

```
CSG UNDERSCORE FLAG OPENING BRACE PUNCH CARDS ARE DEAD NOW CLOSING BRACE
```

**4. Normalize tokens** (`UNDERSCORE -> _`, `OPENINGBRACE -> {`,
`CLOSINGBRACE -> }`) to assemble the flag. `solve.py` runs the full pipeline
(it auto-selects the correct bit variant).

## Flag

```
CSG_FLAG{PUNCHCARDSAREDEADNOW}
```
