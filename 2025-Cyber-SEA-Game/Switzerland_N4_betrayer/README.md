# Switzerland N4 — Betrayer

**Category:** forensics / network

## Challenge

An "inside job" is suspected on `192.168.56.104`; credentials may have leaked
from `192.168.56.33`. Analyze the PCAP, identify the attack, recover the leaked
credentials, and build the flag.

Flag format:
`CSG_FLAG{<user>::<domain>:<16 hex>:<32 hex>:<620 hex>}`

## Solution

The capture contains NBNS/NetBIOS name traffic followed by SMB with NTLMSSP —
the classic signature of an **NTLMv2 credential capture** (LLMNR/NBT-NS
poisoning / SMB relay). The flag format maps exactly onto the fields of an NTLMv2
authentication exchange:

- `server challenge` — from the NTLMSSP **Type 2** (CHALLENGE) message
- `NT proof` + `blob` — from the NTLMSSP **Type 3** (AUTHENTICATE) message
  (`NTProofStr` is the first 16 bytes of the NTLMv2 response, the blob is the rest)

Extract the fields with `tshark`:

```bash
# Server challenge (Type 2)
tshark -r betrayer.pcap -Y "ntlmssp.ntlmserverchallenge" \
       -T fields -e ntlmssp.ntlmserverchallenge | head -n1
# -> 46f422cd882b169d

# User, domain, NTLMv2 response (Type 3)
tshark -r betrayer.pcap \
       -Y "ntlmssp.auth.username && ntlmssp.auth.ntresponse" \
       -T fields -e ntlmssp.auth.username -e ntlmssp.auth.domain \
       -e ntlmssp.auth.ntresponse
# -> bob   WINDOMAIN   4837e8d2...
```

Then split the NTLMv2 response: `ntresponse[0:32]` is the NT proof (32 hex),
`ntresponse[32:]` is the blob (620 hex). `analyze_pcap.py` automates the whole
extraction and prints both the flag and a hashcat `-m 5600` line.

Recovered values:

- **User / domain:** `bob` / `WINDOMAIN`
- **Server challenge:** `46f422cd882b169d`
- **NT proof:** `4837e8d20080f19cc2762798c9373a8e`
- **Blob:** `0101000000000000934f159ee807dc01...0000000000` (620 hex)

## Flag

```
CSG_FLAG{bob::WINDOMAIN:46f422cd882b169d:4837e8d20080f19cc2762798c9373a8e:0101000000000000934f159ee807dc01c70a33e89710d3140000000002001200570049004e0044004f004d00410049004e0001000e00570049004e00310030002d00320004001e00770069006e0064006f006d00610069006e002e006c006f00630061006c0003002e00770069006e00310030002d0032002e00770069006e0064006f006d00610069006e002e006c006f00630061006c0005001e00770069006e0064006f006d00610069006e002e006c006f00630061006c0007000800934f159ee807dc0106000400020000000800300030000000000000000000000000200000d680c970ffd7be19f29a3b7d61c7d3353ee63fdfa4fd83344a83f7681a6b65980a001000000000000000000000000000000000000900140063006900660073002f00640063006300300032000000000000000000}
```

The traitor: `WINDOMAIN\bob`, whose NTLMv2 credentials were captured over NBNS/SMB.
