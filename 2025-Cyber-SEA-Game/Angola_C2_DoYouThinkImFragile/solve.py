import base64
import re

KIMPAMPARA = "kimpampara.txt"


def decode_kimpampara(b64_blob: str) -> str:
    """base64 x2 -> 'U+HHHH' code points -> batch script text."""
    inner = base64.b64decode(base64.b64decode(b64_blob))
    cps = re.findall(rb"U\+([0-9A-Fa-f]{4})", inner)
    return "".join(chr(int(cp, 16)) for cp in cps)


def emulate_batch(script: str) -> str:
    # Base substitution alphabets defined at the top of the .bat
    env = {
        "HPOJs": "YXSWCJUBLPNZGIAHDMKRVFTEQO",
        "BeoPl": "clpadkuxztisfnerygwobmhqvj",
        "kufzE": "8394265017",
    }

    def expand(line: str) -> str:
        # %VAR:~OFF,1%  ->  single char from VAR at index OFF
        def repl(m):
            var, off = m.group(1), int(m.group(2))
            return env[var][off] if var in env else m.group(0)
        return re.sub(r"%([A-Za-z]+):~(\d+),1%", repl, line)

    # The script derives three more alphabets (set NAME=...) then builds the
    # final `echo` line referencing them. Resolve `set` lines first.
    for line in script.splitlines():
        s = expand(line.strip())
        m = re.match(r"^set\s+([A-Za-z]+)=(\S+)$", s, re.IGNORECASE)
        if m:
            env[m.group(1)] = m.group(2)

    # Expand the final echo line. It uses %%VAR:~i,1%% (doubled %) which,
    # after one round of expansion above, are written with single % at runtime.
    echo_line = next(l for l in script.splitlines() if "=echo " in l)
    template = expand(echo_line.split("=echo ", 1)[1])
    message = expand(template)
    # In cmd.exe the leftover `%x%` wrappers are undefined-variable references
    # that expand to nothing, leaving only the bare characters. 
    # Drop every `%` (no message/password character is ever a literal `%`).
    message = message.replace("%", "")

    return message

def main():
    blob = KIMPAMPARA.read_text().strip()
    script = decode_kimpampara(blob)
    print(script)
    for line in script.splitlines()[:6]:
        print("    " + line)
    message = emulate_batch(script)
    print(f"{message}")


if __name__ == "__main__":
    main()
