"""Whole-program pass: which functions of a PE32+ image can this lifter lift *and link*?

A function is liftable if its own instructions are in the supported subset AND every direct
call it makes goes to another liftable function. That closure is computed to a fixpoint, so a
function that calls an unsupported function is reported as unsupported too — no silent
half-lifted code.

Modes:
  --analyze            coverage statistics over the whole image (fast, no output)
  --emit DIR --max N   write N liftable functions as one C file + prototypes header

The emitted C is derived from the game and never leaves the private workspace.
"""
import argparse
import collections
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pe64 import PE64  # noqa: E402
from lift64 import Lifter, Unsupported  # noqa: E402
from capstone.x86 import X86_OP_IMM  # noqa: E402


def analyze_all(pe, funcs, progress=False):
    lif = Lifter(pe)
    self_ok = {}
    callees = {}
    reason = {}
    for n, (begin, end, _u) in enumerate(funcs):
        if progress and n and n % 20000 == 0:
            print(f"  {n}/{len(funcs)}", file=sys.stderr, flush=True)
        try:
            blocks = lif.cfg(begin, end)
        except Unsupported as e:
            self_ok[begin] = False
            reason[begin] = str(e)
            callees[begin] = ()
            continue
        calls = list(getattr(lif, "last_tails", ()))
        why = None
        for addr in sorted(blocks):
            for ins in blocks[addr]:
                m = ins.mnemonic
                if m == "call":
                    if ins.operands and ins.operands[0].type == X86_OP_IMM:
                        calls.append(ins.operands[0].imm)
                    else:
                        why = "indirect call"
                    continue
                if m == "jmp" and not (ins.operands and ins.operands[0].type == X86_OP_IMM):
                    why = "indirect jmp"
                    continue
                if why:
                    continue
                if m.endswith("ret"):
                    m = "ret"
                try:
                    lif._emit([], ins, m)
                except Unsupported as e:
                    why = str(e)
        self_ok[begin] = why is None
        reason[begin] = why or ""
        callees[begin] = tuple(calls)
    return self_ok, callees, reason


def fixpoint(funcs, self_ok, callees):
    """Greatest fixpoint: start from everything whose own code is supported and prune any
    function whose direct callee is not liftable (or is outside the analysed set). Pruning,
    not growing, is what makes cycles safe."""
    ok = {f for f, v in self_ok.items() if v}
    known = {b for b, _e, _u in funcs}
    while True:
        drop = {f for f in ok
                if any((c not in ok) or (c not in known) for c in callees[f])}
        if not drop:
            return ok
        ok -= drop


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("exe")
    ap.add_argument("--analyze", action="store_true")
    ap.add_argument("--emit")
    ap.add_argument("--max", type=int, default=0)
    ap.add_argument("--only", type=int, default=0, help="analyze only the first N functions")
    ap.add_argument("--report", default=None)
    args = ap.parse_args()

    pe = PE64(open(args.exe, "rb").read())
    funcs = pe.exceptions()
    if args.only:
        funcs = funcs[:args.only]
    t0 = time.time()
    self_ok, callees, reason = analyze_all(pe, funcs, progress=True)
    ok = fixpoint(funcs, self_ok, callees)
    stats = {
        "functions": len(funcs),
        "supported_self": sum(1 for v in self_ok.values() if v),
        "liftable_closure": len(ok),
        "seconds": round(time.time() - t0, 1),
        "unsupported_reasons": collections.Counter(r for r in reason.values() if r).most_common(15),
        "direct_call_targets": sum(len(c) for c in callees.values()),
    }
    if args.report:
        json.dump(stats, open(args.report, "w"), indent=1)
    print(json.dumps({k: v for k, v in stats.items() if k != "unsupported_reasons"}, indent=1))
    if not args.emit:
        return

    end_by_addr = {b: e for b, e, _u in funcs}
    chosen = sorted(ok)
    if args.max:
        # Smallest functions are fast to test and exercise the same opcodes. Keep the set
        # closed under direct calls, otherwise the link would miss a callee.
        by_size = sorted((a for a in ok if a in end_by_addr), key=lambda a: (end_by_addr[a] - a, a))
        seeds = by_size[:args.max]
        sel = set(seeds)
        while True:
            drop = {f for f in sel if any(c not in sel for c in callees[f])}
            if not drop:
                break
            sel -= drop
        chosen = sorted(sel)
    os.makedirs(args.emit, exist_ok=True)
    hdr = os.path.join(args.emit, "lifted.h")
    with open(hdr, "w") as f:
        f.write("/* generated: do not commit */\n#include \"x64rt.h\"\n")
        for a in chosen:
            f.write(f"void f_{a:x}(X64Ctx *c);\n")
    lif = Lifter(pe)
    out = os.path.join(args.emit, "lifted.c")
    n = 0
    with open(out, "w") as f:
        f.write('#include "lifted.h"\n')
        for a in chosen:
            try:
                f.write(lif.lift(a, end_by_addr[a]))
            except Unsupported:
                continue
            f.write("\n")
            n += 1
    print(json.dumps({"emitted_functions": n, "file": out, "bytes": os.path.getsize(out)}, indent=1))


if __name__ == "__main__":
    main()
