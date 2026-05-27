import os
import sys
import json
import glob
import struct
from typing import Dict, Set, List, Tuple, Optional
from concurrent.futures import ProcessPoolExecutor, as_completed

try:
    import pefile
except ImportError:
    print("Missing dependency: pefile. Install with: pip install pefile", file=sys.stderr)
    raise

from solve import solve  # your existing solver

DLLS_DIR = os.path.join(os.path.dirname(__file__), "dlls")
TOTAL_MODULES = 10000
RECORD_SIZE = 2 + 32
EXPECTED_SIZE = TOTAL_MODULES * RECORD_SIZE
DEPS_CACHE_PATH = os.path.join(os.path.dirname(__file__), "deps_cache.json")


def _leading_digit_prefix(s: str) -> str:
    j = 0
    while j < len(s) and s[j].isdigit():
        j += 1
    return s[:j]


def parse_numeric_imports_for_id(rc_id: int) -> Tuple[int, List[int]]:
    dll_path = os.path.join(DLLS_DIR, f"{rc_id:04}.dll")
    if not os.path.isfile(dll_path):
        return rc_id, []
    try:
        pe = pefile.PE(dll_path, fast_load=True)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']]
        )
    except Exception:
        return rc_id, []

    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        return rc_id, []

    deps: List[int] = []
    for desc in pe.DIRECTORY_ENTRY_IMPORT:
        name = desc.dll
        if isinstance(name, bytes):
            try:
                name = name.decode("ascii", "ignore")
            except Exception:
                continue
        # Gate: first 4 chars are digits, then atoi leading run
        if len(name) >= 4 and name[:4].isdigit():
            pref = _leading_digit_prefix(name)
            if pref:
                try:
                    val = int(pref)
                except ValueError:
                    continue
                if 0 <= val < TOTAL_MODULES:
                    deps.append(val)
    return rc_id, deps


def load_deps_cache() -> Dict[str, List[int]]:
    if os.path.isfile(DEPS_CACHE_PATH):
        try:
            with open(DEPS_CACHE_PATH, "r") as f:
                data = json.load(f)
            if isinstance(data, dict):
                return data
        except Exception:
            pass
    return {}


def save_deps_cache(deps: Dict[str, List[int]]) -> None:
    tmp = DEPS_CACHE_PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump(deps, f, separators=(",", ":"))
    os.replace(tmp, DEPS_CACHE_PATH)


def build_or_update_deps_cache() -> Dict[str, List[int]]:
    deps_cache = load_deps_cache()
    missing: List[int] = []
    for i in range(TOTAL_MODULES):
        k = f"{i:04}"
        if k not in deps_cache:
            dll_path = os.path.join(DLLS_DIR, f"{k}.dll")
            if os.path.isfile(dll_path):
                missing.append(i)
            else:
                deps_cache[k] = []

    if missing:
        print(f"[deps] Parsing imports for {len(missing)} DLLs in parallel...")
        workers = min(8, max(2, (os.cpu_count() or 4) - 1))
        with ProcessPoolExecutor(max_workers=workers) as ex:
            futures = [ex.submit(parse_numeric_imports_for_id, i) for i in missing]
            for fut in as_completed(futures):
                rc_id, deps = fut.result()
                deps_cache[f"{rc_id:04}"] = deps
        save_deps_cache(deps_cache)
        print(f"[deps] Cache updated: {DEPS_CACHE_PATH}")

    return deps_cache


class Resolver:
    def __init__(self, deps_cache: Dict[str, List[int]]) -> None:
        self.adj: Dict[int, List[int]] = {int(k): v for k, v in deps_cache.items()}
        self._closure_cache: Dict[int, Set[int]] = {}

    def closure(self, rc: int) -> Set[int]:
        if rc in self._closure_cache:
            return self._closure_cache[rc]
        visited: Set[int] = set()
        stack = [rc]
        while stack:
            cur = stack.pop()
            if cur in visited:
                continue
            visited.add(cur)
            for dep in self.adj.get(cur, []):
                if dep not in visited:
                    stack.append(dep)
        self._closure_cache[rc] = visited
        return visited


def add_to_accumulation(acc: bytearray, idx: int, value: int) -> None:
    off = idx * 4
    cur = struct.unpack_from("<I", acc, off)[0]
    struct.pack_into("<I", acc, off, (cur + value) & 0xFFFFFFFF)


def read_accumulation_target(path: Optional[str] = None) -> List[int]:
    """
    Accepts:
      - a single .bin file containing 10000 uint32 little-endian
      - a single .txt file with one integer per line (dec or hex '0x..')
      - or autodetect accumulation*.txt files and concatenate their numbers in name-sorted order.
    """
    def parse_txt(fp: str) -> List[int]:
        vals: List[int] = []
        with open(fp, "r") as f:
            for line in f:
                s = line.strip()
                if not s:
                    continue
                if s.lower().startswith("0x"):
                    vals.append(int(s, 16) & 0xFFFFFFFF)
                else:
                    vals.append(int(s) & 0xFFFFFFFF)
        return vals

    if path:
        if path.lower().endswith(".bin"):
            with open(path, "rb") as f:
                data = f.read()
            if len(data) != TOTAL_MODULES * 4:
                raise ValueError(f"bin size {len(data)} != {TOTAL_MODULES*4}")
            return list(struct.unpack("<" + "I"*TOTAL_MODULES, data))
        elif path.lower().endswith(".txt"):
            vals = parse_txt(path)
            if len(vals) != TOTAL_MODULES:
                raise ValueError(f"txt count {len(vals)} != {TOTAL_MODULES}")
            return vals
        else:
            raise ValueError("Unsupported target file type (use .bin or .txt)")

    # Auto-detect
    txts = sorted(glob.glob(os.path.join(os.path.dirname(__file__), "accumulation*.txt")))
    if txts:
        vals: List[int] = []
        for fp in txts:
            vals.extend(parse_txt(fp))
        if len(vals) != TOTAL_MODULES:
            raise ValueError(f"Concatenated txt count {len(vals)} != {TOTAL_MODULES}")
        return vals

    # Try default bin file name
    bin_fp = os.path.join(os.path.dirname(__file__), "accumulation_target.bin")
    if os.path.isfile(bin_fp):
        with open(bin_fp, "rb") as f:
            data = f.read()
        if len(data) != TOTAL_MODULES * 4:
            raise ValueError(f"bin size {len(data)} != {TOTAL_MODULES*4}")
        return list(struct.unpack("<" + "I"*TOTAL_MODULES, data))

    raise FileNotFoundError("No accumulation target found. Provide a path or add accumulation*.txt or accumulation_target.bin")


def recover_order(accum_target: List[int], resolver: Resolver) -> List[int]:
    """
    Solve for a permutation positions: pos[rc] in 0..9999 such that:
      For each module k: sum_{rc : k in closure(rc)} pos[rc] == accum_target[k]
    Greedy peeling: pick k with coverage count==1 to determine a unique rc and its position.
    Returns order O of rc_ids where O[i] = rc assigned to iteration i.
    """
    # Precompute closures and module->rc coverage
    closures: Dict[int, Set[int]] = {}
    covered_by: List[Set[int]] = [set() for _ in range(TOTAL_MODULES)]
    for rc in range(TOTAL_MODULES):
        S = resolver.closure(rc)
        closures[rc] = S
        for k in S:
            covered_by[k].add(rc)

    remaining_target = accum_target[:]  # mutable copy
    coverage_count = [len(covered_by[k]) for k in range(TOTAL_MODULES)]
    # Map rc -> assigned position (None if unassigned)
    pos: List[Optional[int]] = [None] * TOTAL_MODULES
    used_positions: Set[int] = set()

    # Initialize queue with all k having unique coverage
    from collections import deque
    q = deque([k for k, c in enumerate(coverage_count) if c == 1])

    steps = 0
    while q:
        k = q.popleft()
        if coverage_count[k] != 1:
            continue
        # Find the only rc that still covers k and is unassigned
        candidates = [rc for rc in covered_by[k] if pos[rc] is None]
        if not candidates:
            # Already accounted via earlier removals
            continue
        rc = candidates[0]
        # Deduce position for rc from the equation at k
        p = remaining_target[k]
        if p < 0 or p >= TOTAL_MODULES or p in used_positions:
            raise RuntimeError(f"Invalid/duplicate position deduced: rc={rc}, pos={p}")
        pos[rc] = p
        used_positions.add(p)
        steps += 1
        if steps % 1000 == 0:
            print(f"[order] Assigned {steps} positions...")

        # Remove rc's contribution from all modules in its closure
        for u in closures[rc]:
            remaining_target[u] -= p
            # Remove rc from coverage
            if rc in covered_by[u]:
                covered_by[u].remove(rc)
                coverage_count[u] -= 1
                if coverage_count[u] == 1:
                    q.append(u)

    # Validate solution
    if any(p is None for p in pos):
        missing = sum(1 for p in pos if p is None)
        raise RuntimeError(f"Could not determine full order, {missing} rc_ids unassigned")

    if len(used_positions) != TOTAL_MODULES:
        raise RuntimeError("Positions are not a permutation of 0..9999")

    # Build order O: O[i] = rc such that pos[rc] == i
    O = [0] * TOTAL_MODULES
    for rc, p in enumerate(pos):
        O[p] = rc
    return O


def build_license_with_order(output_path: str = "license.bin", target_path: Optional[str] = None) -> None:
    # Load deps (or build) and create resolver
    deps_cache = build_or_update_deps_cache()
    resolver = Resolver(deps_cache)

    # Read accumulation target
    accum_target = read_accumulation_target(target_path)

    # Recover order
    print("[order] Recovering rc_id order from accumulation_target...")
    order = recover_order(accum_target, resolver)
    print("[order] Order recovered.")
    with open("recovered_order.json", "w") as f:
        json.dump(order, f)
    print("[order] Wrote recovered_order.json")

    # Generate license by following recovered order
    accumulation = bytearray(TOTAL_MODULES * 4)
    out = bytearray(EXPECTED_SIZE)
    write_off = 0

    for i, rc_id in enumerate(order):
        res = solve(rc_id, accumulation)
        if not isinstance(res, dict) or "result" not in res:
            raise RuntimeError(f"solve({rc_id}) failed or returned unexpected data: {res}")

        payload_hex = res["result"]
        try:
            payload = bytes.fromhex(payload_hex)
        except Exception as e:
            raise ValueError(f"solve({rc_id}) produced invalid hex: {payload_hex}") from e

        if len(payload) != 32:
            raise ValueError(f"solve({rc_id}) payload length {len(payload)} != 32 bytes")

        out[write_off:write_off+2] = rc_id.to_bytes(2, "little", signed=False)
        out[write_off+2:write_off+34] = payload
        write_off += RECORD_SIZE

        # Accumulate using rc closure with weight i
        for k in resolver.closure(rc_id):
            add_to_accumulation(accumulation, k, i)

        if (i % 100) == 0:
            print(f"[+] {i:5d}/9999 rc={rc_id}")

    if write_off != EXPECTED_SIZE:
        raise RuntimeError(f"Output size {write_off} != expected {EXPECTED_SIZE}")

    # Optional: verify final accumulation matches target
    # Compare accumulation (bytearray) vs accum_target (list of ints)
    diff = []
    for idx in range(TOTAL_MODULES):
        cur = struct.unpack_from("<I", accumulation, idx*4)[0]
        if cur != (accum_target[idx] & 0xFFFFFFFF):
            diff.append(idx)
            if len(diff) <= 10:
                print(f"[verify] mismatch at {idx:04d}: built={cur} target={accum_target[idx]}")
    if diff:
        print(f"[verify] WARNING: {len(diff)} mismatches in accumulation vs target")
    else:
        print("[verify] Accumulation matches target!")

    with open(output_path, "wb") as f:
        f.write(out)
    print(f"[+] Wrote {output_path} ({len(out)} bytes)")

    with open("accumulation.bin", "wb") as f:
        f.write(accumulation)
    print("[+] Wrote accumulation.bin (final state snapshot)")
    

if __name__ == "__main__":
    # Usage:
    #   python build_license_with_order.py [license.bin] [accum_target_path]
    out_path = sys.argv[1] if len(sys.argv) > 1 else "license.bin"
    target_path = sys.argv[2] if len(sys.argv) > 2 else "accumulation_target.bin"
    build_license_with_order(out_path, target_path)