# Australia M1

The goal is to shut down the machine.

## Solution

The EC2 user-data script (`linpeas.txt`) leaks the whole setup:

- A local `user` exists with password `IamTheUser!`, and SSH password auth is enabled.
- `/etc/pam.d/su` gets a `pam_succeed_if` rule so that when `user` runs `su shutdown`, auth succeeds **without a password**.
- The `shutdown` user's login shell is `/sbin/system/shutdown.sh`, which just runs `sudo poweroff -i`.
- sudoers grants `shutdown ALL=NOPASSWD: /usr/sbin/poweroff -i`.

So the chain is: log in as `user`, switch to `shutdown`, and its shell powers the box off.

```bash
ssh user@<target>          # password: IamTheUser!
su shutdown                # passwordless via PAM -> runs shutdown.sh -> sudo poweroff -i
```

The machine shuts down.
