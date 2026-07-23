#!/usr/bin/env python3
"""Rank dhat-heap program points by retained bytes at t-end (leak candidates).

Usage: dhat_analyze.py <dhat-heap.json> [--top N] [--min-kb K]
"""
import json
import sys


def main() -> None:
    path = sys.argv[1]
    top_n = 20
    min_kb = 512
    if "--top" in sys.argv:
        top_n = int(sys.argv[sys.argv.index("--top") + 1])
    if "--min-kb" in sys.argv:
        min_kb = int(sys.argv[sys.argv.index("--min-kb") + 1])

    d = json.load(open(path))
    pps = d.get("pps", [])
    ftbl = d.get("ftbl", [])

    def frames(pp):
        out = []
        for i in pp.get("fs", []):
            if isinstance(i, int) and i < len(ftbl):
                out.append(ftbl[i])
        return out

    # Candidate end-of-run live fields (dhat rust-heap: 'teb' = total bytes
    # at t-end). Fall back to 'tb' (total allocated) if absent.
    def end_bytes(pp):
        for k in ("teb", "eb", "leb"):
            if k in pp:
                return pp[k]
        return pp.get("tb", 0)

    def gmax_bytes(pp):
        for k in ("tgb", "gb"):
            if k in pp:
                return pp[k]
        return 0

    rows = sorted(pps, key=lambda p: -end_bytes(p))
    total_end = sum(end_bytes(p) for p in pps)
    total_tb = sum(p.get("tb", 0) for p in pps)
    print(f"file: {path}")
    print(f"program points: {len(pps)}  total-alloc: {total_tb/1e6:.1f} MB  "
          f"live-at-end: {total_end/1e6:.1f} MB")
    print(f"pp keys sample: {sorted(pps[0].keys()) if pps else 'none'}")
    shown = 0
    for pp in rows:
        eb = end_bytes(pp)
        if eb < min_kb * 1024 or shown >= top_n:
            continue
        shown += 1
        fr = frames(pp)
        short = " <- ".join(f.split("/")[-1] for f in fr[:7])
        print(f"{eb/1024:>10.0f} KB end | {gmax_bytes(pp)/1024:>10.0f} KB gmax | {short}")


if __name__ == "__main__":
    main()
