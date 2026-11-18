"""Selects functions for the differential test and writes harness/tests.h.

Criteria (all checked, nothing assumed):
  - every instruction is in the lifter's supported subset;
  - no call (a call would need its callee to be lifted and deterministic too);
  - every memory operand is stack-based ([rsp/rbp +/- disp]) or RIP-relative, so a test
    case never reads or writes global mutable state;
  - the function ends in `ret` and is under 2 KB (keeps the run fast).

This deliberately throws away most functions. The point of the test is to prove the
semantics of the lifted instruction subset, not to maximise the function count.
"""
import argparse
import json
import os
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import (X86_OP_MEM, X86_OP_REG, X86_OP_IMM, X86_REG_RIP, X86_REG_RSP,
                          X86_REG_RBP, X86_REG_ESP, X86_REG_EBP)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pe64 import PE64  # noqa: E402
from lift64 import Lifter, Unsupported  # noqa: E402

STACK_REGS = {X86_REG_RSP, X86_REG_RBP, X86_REG_ESP, X86_REG_EBP}
RSP_REGS = {X86_REG_RSP, X86_REG_ESP}


def _writes_rsp(ins):
    ops = ins.operands
    if not ops or ops[0].type != X86_OP_REG or ops[0].reg not in RSP_REGS:
        return False
    return ins.mnemonic not in ("push", "pop", "add", "sub")


def stack_balanced(blocks):
    """True if every path enters and leaves the function with the same RSP.

    Fragments that .pdata declares as functions but that are really the epilogue of
    another function (`add rsp, 0x40; pop r15; ret`) are not callable on their own: in
    the original they would pop their caller's frame and jump somewhere random. Those
    are rejected here, not "tested" and excused."""
    deltas = {min(blocks): 0}
    work = [min(blocks)]
    exits = []
    while work:
        a = work.pop()
        d = deltas[a]
        for ins in blocks[a]:
            m = ins.mnemonic
            if m == "push":
                d -= 8
            elif m == "pop":
                d += 8
            elif (m in ("add", "sub") and ins.operands[0].type == X86_OP_REG
                  and ins.operands[0].reg in RSP_REGS and ins.operands[1].type == X86_OP_IMM):
                d += ins.operands[1].imm if m == "add" else -ins.operands[1].imm
            elif m == "leave":
                return False
            elif _writes_rsp(ins):
                return False
            elif m == "ret":
                exits.append(d)
                break
        last = blocks[a][-1]
        m = last.mnemonic
        succ = []
        if m == "ret":
            pass
        elif m == "jmp" and last.operands and last.operands[0].type == X86_OP_IMM:
            succ = [last.operands[0].imm]
        else:
            nxt = last.address + last.size
            if m != "jmp":
                succ = [nxt]
            if m.startswith("j") and last.operands and last.operands[0].type == X86_OP_IMM:
                succ.append(last.operands[0].imm)
        for s2 in succ:
            if s2 not in blocks:
                continue
            if s2 in deltas:
                if deltas[s2] != d:
                    return False
            else:
                deltas[s2] = d
                work.append(s2)
    return bool(exits) and all(x == 0 for x in exits)


def safe_memory(ins):
    """No write outside the stack.

    Reads may use any register: the harness points every general register at a scratch
    arena, so an indirect read lands in mapped, deterministic memory instead of faulting.
    Writes are only allowed on the stack, because the two runs share one image and one
    arena: a global or arena write would make the second run see different input.
    """
    for n, op in enumerate(ins.operands):
        if op.type != X86_OP_MEM:
            continue
        m = op.mem
        if m.base == X86_REG_RIP:
            if n == 0 and ins.mnemonic not in ("cmp", "test", "lea", "push"):
                return False
            continue
        if n != 0:
            continue
        if ins.mnemonic in ("cmp", "test", "lea"):
            continue
        if m.base in STACK_REGS and (m.index == 0 or m.index in STACK_REGS):
            continue
        return False
    return True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("exe")
    ap.add_argument("--out", default="harness/tests.h")
    ap.add_argument("--max", type=int, default=400)
    ap.add_argument("--cases", type=int, default=8)
    ap.add_argument("--from", dest="from_header", default=None,
                    help="only pick functions declared in this generated lifted.h")
    args = ap.parse_args()

    allowed = None
    if args.from_header:
        import re as _re
        allowed = {int(m, 16) for m in _re.findall(r"void f_([0-9a-f]+)\(", open(args.from_header).read())}

    pe = PE64(open(args.exe, "rb").read())
    lif = Lifter(pe)
    picked = []
    checked = 0
    for begin, end, _u in pe.exceptions():
        if end - begin > 2048 or end <= begin:
            continue
        if allowed is not None and begin not in allowed:
            continue
        checked += 1
        try:
            blocks = lif.cfg(begin, end)
        except Unsupported:
            continue
        bad = False
        for a in sorted(blocks):
            for ins in blocks[a]:
                if ins.mnemonic == "call" or not safe_memory(ins):
                    bad = True
                    break
                # a branch out of the .pdata range is a tail call: the original would run
                # the following bytes as a function, the lifted code calls a lifted one
                if (ins.mnemonic == "jmp" or (ins.mnemonic.startswith("j") and ins.mnemonic != "jmp")) \
                        and ins.operands and ins.operands[0].type == X86_OP_IMM \
                        and not (begin <= ins.operands[0].imm < end):
                    bad = True
                    break
            if bad:
                break
        if bad or not stack_balanced(blocks):
            continue
        try:
            src = lif.lift(begin, end)
        except Unsupported:
            continue
        picked.append((end - begin, begin, end))
    picked.sort()
    picked = picked[:args.max]
    picked.sort(key=lambda t: t[1])

    with open(args.out, "w") as f:
        f.write("/* generated by tools/select_tests.py: do not commit */\n")
        f.write("typedef struct { unsigned long long addr, end; void (*lifted)(X64Ctx *); } TestFn;\n")
        f.write("static const TestFn kTests[] = {\n")
        for _, b, e in picked:
            f.write(f"    {{{b:#x}ull, {e:#x}ull, f_{b:x}}},\n")
        f.write("};\n#define TEST_COUNT (sizeof kTests / sizeof kTests[0])\n")
    print(json.dumps({"candidates_checked": checked, "selected": len(picked),
                      "max_size": picked[-1][0] if picked else 0}, indent=1))


if __name__ == "__main__":
    main()
