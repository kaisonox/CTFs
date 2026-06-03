# The Boss Needs Help

## Overview
This program collects system information (username, hostname, memory, architecture, cores, OS version, build, timestamp) and sends it to a server. Both the program and C2 server use this information to generate a shared secret key for encrypting transmitted data.

## System Configuration
Based on initial traffic analysis, the target machine has:
- Architecture: x64, Cores: 2
- OS: Windows 6.2 (Build 9200)
- Memory: 6143 MB
- Hostname: THUNDERNODE
- Username: TheBoss
- Timestamp: around 6h on 20/08/2025

## Solution Approach
1. Use Frida hooks to modify system values and monitor memcpy function to capture plaintext
2. Write Python server to replay traffic from C2 to client
3. Since symmetric encryption is used, the client can decrypt the replayed traffic to reveal plaintext

## Important Files
The following files were discovered through Frida hooks:
- `C:\Users\%USERNAME%\Documents\boss_tech_notes.txt`
- `C:\Users\TheBoss\Documents\Personal_Stuff\passwords.txt`
- `C:\Users\TheBoss\Documents\Studio_Masters_Vault\The_Vault\rocknroll.zip`

All files are base64 encoded, then encrypted and sent to the server. By replaying this traffic from C2 to client, the client decrypts it and reveals the plaintext.

## Flag Recovery
Extract the `rocknroll.zip` file using the password found in `passwords.txt` to get the flag.

## Recovered Passwords
- Email: BornToRun!75
- Bank: TheRiver##1980
- ComputerLogin: TheBossMan
- Other: TheBigM@n1942!