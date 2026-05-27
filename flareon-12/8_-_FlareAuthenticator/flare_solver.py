# flare_solver.py
import re
from pathlib import Path
from typing import Dict, List, Tuple

TARGET = 0x0BC42D5779FEC401
RESULTS_FILE = Path("obf_transform_test_results.txt")

line_re = re.compile(r"value=0x([0-9a-fA-F]+),\s*return=0x([0-9a-fA-F]+)")

def parse_results(path: Path) -> Dict[int, int]:
    """
    Parse lines like: value=0x1, return=0x279342f
    Returns dict[value] = return (as ints).
    """
    mp: Dict[int, int] = {}
    with path.open("r", encoding="utf-8") as f:
        for ln in f:
            m = line_re.search(ln)
            if not m:
                continue
            v = int(m.group(1), 16)
            r = int(m.group(2), 16) & 0xFFFFFFFF  # 32-bit output
            mp[v] = r
    return mp

def build_contribs(mp: Dict[int, int]) -> List[List[int]]:
    """
    Build 25x10 contribution table C[i-1][d] = uint64(ret[i]) * uint64(ret[(i<<8) | (0x30+d)])
    """
    C: List[List[int]] = [[0]*10 for _ in range(25)]
    for i in range(1, 26):
        if i not in mp:
            raise KeyError(f"Missing return for value=0x{i:x}")
        t1 = mp[i]
        for d in range(10):
            mix = (i << 8) | (0x30 + d)
            if mix not in mp:
                raise KeyError(f"Missing return for value=0x{mix:x} (i={i}, d={d})")
            t2 = mp[mix]
            c = (t1 * t2) & 0xFFFFFFFFFFFFFFFF  # 64-bit contribution
            C[i-1][d] = c
    return C

def prefix_bounds(C: List[List[int]]) -> Tuple[List[int], List[int]]:
    """
    Compute Rmin/Rmax bounds from position k to end.
    """
    n = len(C)
    S = [min(row) for row in C]
    L = [max(row) for row in C]
    Rmin = [0]*(n+1)
    Rmax = [0]*(n+1)
    for k in range(n-1, -1, -1):
        Rmin[k] = Rmin[k+1] + S[k]
        Rmax[k] = Rmax[k+1] + L[k]
    return Rmin, Rmax

def solve(C: List[List[int]], target: int) -> str:
    n = 25
    Rmin, Rmax = prefix_bounds(C)
    digits = [-1]*n
    answer = [""]
    found = [False]

    # Try digits in ascending contribution order per position to prune faster
    order = [sorted(range(10), key=lambda d: C[i][d]) for i in range(n)]

    def dfs(i: int, acc: int) -> None:
        if found[0]:
            return
        if i == n:
            if acc == target:
                answer[0] = "".join(str(d) for d in digits)
                found[0] = True
            return
        # Prune by remaining bounds
        if acc + Rmin[i] > target or acc + Rmax[i] < target:
            return
        for d in order[i]:
            c = C[i][d]
            acc2 = (acc + c) & 0xFFFFFFFFFFFFFFFF
            # Remaining feasibility check
            if acc2 + Rmin[i+1] > target or acc2 + Rmax[i+1] < target:
                continue
            digits[i] = d
            dfs(i+1, acc2)
            if found[0]:
                return
        digits[i] = -1

    dfs(0, 0)
    if not found[0]:
        raise RuntimeError("No solution found; verify the test results are from the same ctx/binary.")
    return answer[0]

def main():
    mp = parse_results(RESULTS_FILE)
    C = build_contribs(mp)
    code = solve(C, TARGET)
    # Verify by recomputing the sum
    acc = 0
    for i, ch in enumerate(code, start=1):
        d = ord(ch) - ord('0')
        acc = (acc + C[i-1][d]) & 0xFFFFFFFFFFFFFFFF
    print(f"Code: {code}")
    print(f"Accumulator: 0x{acc:016X} (target 0x{TARGET:016X})")

if __name__ == "__main__":
    main()