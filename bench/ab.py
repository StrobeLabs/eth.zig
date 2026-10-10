#!/usr/bin/env python3
"""Interleaved A/B comparison of eth.zig benchmark binaries.

Runs every binary once per round, in a shuffled order, so drift in machine
load or clock speed lands on all of them equally. For each binary and
benchmark it keeps the fastest per-run median across rounds: interference
(another process, a run migrated to efficiency cores) only ever slows a run
down, so the best round is the closest estimate of what the code can do.
Changes are relative to the first binary (the baseline).

    python3 bench/ab.py --rounds 5 BASELINE_BIN CANDIDATE_BIN [MORE_BINS...]

Build a binary for any ref with `zig build bench-install --prefix DIR` in a
checkout of that ref; it lands at DIR/bin/bench (see bench/README.md).
"""
import argparse
import json
import random
import statistics
import subprocess
import sys


def run(binary, samples, flt):
    cmd = [binary, "--json", "--samples", str(samples)]
    if flt:
        cmd += ["--filter", flt]
    out = subprocess.run(cmd, check=True, capture_output=True, text=True).stdout
    return {r["name"]: r["median_ns"] for r in json.loads(out)["results"]}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("binaries", nargs="+", help="first one is the baseline")
    ap.add_argument("--rounds", type=int, default=5)
    ap.add_argument("--samples", type=int, default=15)
    ap.add_argument("--filter", default=None)
    ap.add_argument("--threshold", type=float, default=5.0, help="percent change to flag")
    args = ap.parse_args()

    runs = {b: [] for b in args.binaries}
    for r in range(args.rounds):
        order = list(args.binaries)
        random.shuffle(order)
        for b in order:
            runs[b].append(run(b, args.samples, args.filter))
        print(f"round {r + 1}/{args.rounds} done", file=sys.stderr)

    base = args.binaries[0]
    names = list(runs[base][0].keys())
    for b in args.binaries[1:]:
        for n in runs[b][0]:
            if n not in names:
                names.append(n)

    def med(b, n):
        vals = [r[n] for r in runs[b] if n in r]
        return (min(vals), (statistics.median(vals) - min(vals)) / min(vals) * 100) if vals else (None, None)

    labels = [b.rsplit("/", 1)[-1] for b in args.binaries]
    print(f"\n{'benchmark':<30}" + "".join(f"{l[:20]:>22}" for l in labels))
    for n in names:
        row = f"{n:<30}"
        b0, _ = med(base, n)
        for i, b in enumerate(args.binaries):
            m, spread = med(b, n)
            if m is None:
                row += f"{'-':>22}"
                continue
            cell = f"{m:.2f}ns"
            if i > 0 and b0:
                ch = (m - b0) / b0 * 100
                mark = " !" if ch > args.threshold else (" +" if ch < -args.threshold else "")
                cell += f" {ch:+.1f}%{mark}"
            row += f"{cell:>22}"
        print(row)
    print(f"\n{args.rounds} interleaved rounds; '!' = slower than baseline by >{args.threshold:g}%, '+' = faster.")


if __name__ == "__main__":
    main()
