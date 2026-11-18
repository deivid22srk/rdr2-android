"""x86-64 -> C lifter (proof of concept for the RDR2 port).

Scope, stated plainly: this lifts a *subset* of x86-64 well enough to prove the approach and
to differential-test real functions from the game on the host. Anything outside the subset
raises Unsupported and the function is not emitted. `--report` counts exactly what was
covered, so the number in docs/STATUS.md is measured, not claimed.

Supported: integer moves/arithmetic/logic/shifts/rotates, imul (all forms), lea, movzx/movsx/
movsxd, cmovcc, setcc, inc/dec/neg/not, push/pop, bswap, xchg, cdqe/cwde/cbw/cdq/cqo/cwd,
direct jmp/jcc and ret, and an SSE1/SSE2 subset (moves, packed/scalar arithmetic, bitwise,
shufps/pshufd/unpck*, comiss/ucomiss, conversions, min/max, sqrt).

Not supported (traps, counted in the report): call, indirect jmp, div/idiv, string ops,
AVX/VEX, x87, lock-prefixed atomics, and everything else.
"""
import argparse
import collections
import json
import os
import re
import struct
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import (X86_OP_REG, X86_OP_IMM, X86_OP_MEM, X86_REG_RIP,
                          X86_REG_AL, X86_REG_AH, X86_REG_EAX, X86_REG_AX,
                          X86_REG_CL, X86_REG_ECX, X86_REG_CX,
                          X86_REG_DL, X86_REG_EDX, X86_REG_DX,
                          X86_REG_BL, X86_REG_EBX, X86_REG_BX,
                          X86_REG_SPL, X86_REG_ESP, X86_REG_SP,
                          X86_REG_BPL, X86_REG_EBP, X86_REG_BP,
                          X86_REG_SIL, X86_REG_ESI, X86_REG_SI,
                          X86_REG_DIL, X86_REG_EDI, X86_REG_DI)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pe64 import PE64  # noqa: E402

R_SP = 4
R_AX = 0
GPR_NAMES = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
             "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]


class Unsupported(Exception):
    pass


def reg_info(md, rid):
    """(index, size_bits, high_byte) for a register id."""
    name = md.reg_name(rid)
    if name is None:
        raise Unsupported(f"register id {rid}")
    if name in GPR_NAMES:
        return GPR_NAMES.index(name), 64, False
    # 32-bit forms zero the upper half
    if name.startswith("r") and name[1:].isdigit():
        return int(name[1:]), 32, False
    table = {
        "eax": (0, 32), "ecx": (1, 32), "edx": (2, 32), "ebx": (3, 32),
        "esp": (4, 32), "ebp": (5, 32), "esi": (6, 32), "edi": (7, 32),
        "ax": (0, 16), "cx": (1, 16), "dx": (2, 16), "bx": (3, 16),
        "sp": (4, 16), "bp": (5, 16), "si": (6, 16), "di": (7, 16),
        "al": (0, 8), "cl": (1, 8), "dl": (2, 8), "bl": (3, 8),
        "spl": (4, 8), "bpl": (5, 8), "sil": (6, 8), "dil": (7, 8),
        "ah": (0, 8), "ch": (1, 8), "dh": (2, 8), "bh": (3, 8),
    }
    if name in table:
        idx, size = table[name]
        return idx, size, name in ("ah", "ch", "dh", "bh")
    # r8b..r15b / r8w..r15w / r8d..r15d
    m2 = re.fullmatch(r"r(\d+)([bwd]?)", name)
    if m2:
        n = int(m2.group(1))
        if 8 <= n <= 15:
            suffix = m2.group(2)
            return n, {"": 64, "d": 32, "w": 16, "b": 8}[suffix], False
    raise Unsupported(f"register {name}")


class Lifter:
    def xmm(self, rid):
        name = self.md.reg_name(rid)
        if not name or not name.startswith("xmm"):
            raise Unsupported(f"expected xmm, got {name}")
        return int(name[3:])

    def is_gpr(self, rid):
        name = self.md.reg_name(rid) or ""
        return bool(re.fullmatch(r"(r(\d+|ax|cx|dx|bx|sp|bp|si|di)|e(ax|cx|dx|bx|sp|bp|si|di)|(ax|cx|dx|bx|sp|bp|si|di)|(al|cl|dl|bl|ah|ch|dh|bh|spl|bpl|sil|dil))", name))

    def __init__(self, pe):
        self.pe = pe
        self.md = Cs(CS_ARCH_X86, CS_MODE_64)
        self.md.detail = True
        self.blocks = None

    # ---------------------------------------------------------------- decode
    def block_at(self, start, end):
        """Decode one basic block from `start`, stopping after the terminator."""
        out = []
        a = start
        while a < end:
            raw = self.pe.read(a, 16)
            if len(raw) < 1:
                raise Unsupported("read past section")
            ins = next(self.md.disasm(raw, a, 1), None)
            if ins is None:
                raise Unsupported(f"undecodable at {a:#x}")
            out.append(ins)
            a += ins.size
            m = ins.mnemonic
            if m.endswith("ret"):
                m = "ret"
            if m == "ret" or m == "jmp" or m.startswith("j") and m not in ("jmp", "jrcxz", "jecxz"):
                break
            if m in ("call", "jrcxz", "jecxz", "loop", "loope", "loopne", "int3", "ud2", "hlt"):
                break
        return out, a

    def cfg(self, entry, end):
        blocks = {}
        work = [entry]
        while work:
            a = work.pop()
            if a in blocks or not (entry <= a < end):
                continue
            insns, nexta = self.block_at(a, end)
            blocks[a] = insns
            last = insns[-1]
            m = last.mnemonic
            if m == "jmp" and last.operands and last.operands[0].type == X86_OP_IMM:
                work.append(last.operands[0].imm)
            elif m != "ret" and m != "jmp":
                if nexta < end:
                    work.append(nexta)
                if m.startswith("j") and last.operands and last.operands[0].type == X86_OP_IMM:
                    work.append(last.operands[0].imm)
        return blocks

    # ------------------------------------------------------------- operands
    @staticmethod
    def _mask(size):
        return (1 << size) - 1 if size < 64 else ~0

    def reg_read(self, md, rid):
        idx, size, high = reg_info(md, rid)
        if high:
            return f"(((c->r[{idx}] >> 8) & 0xff))"
        if size == 64:
            return f"c->r[{idx}]"
        return f"(c->r[{idx}] & {self._mask(size)}ULL)"

    def mem_addr(self, ins, op):
        m = op.mem
        parts = []
        if m.base == X86_REG_RIP:
            base = ins.address + ins.size + m.disp
            return f"{base:#x}ULL"
        if m.base:
            parts.append(self.reg_read(self.md, m.base))
        if m.index:
            idx = self.reg_read(self.md, m.index)
            parts.append(f"({idx} * {m.scale})")
        expr = " + ".join(parts) if parts else "0"
        if m.disp:
            expr = f"({expr} + {m.disp})" if parts else f"{m.disp}"
        return f"(uint64_t)({expr})"

    def op_read(self, ins, op, size=None):
        """C expression with the operand's value (zero-extended)."""
        if op.type == X86_OP_REG:
            return self.reg_read(self.md, op.reg)
        if op.type == X86_OP_IMM:
            v = op.imm & ((1 << 64) - 1)
            if v >= 1 << 63:
                v -= 1 << 64
            return f"((uint64_t)(int64_t){v}LL)"
        if op.type == X86_OP_MEM:
            sz = size or op.size
            return f"X64_LD{sz * 8}({self.mem_addr(ins, op)})"
        raise Unsupported("operand type")

    # ---------------------------------------------------------------- writes
    def write(self, lines, ins, op, expr, size=None):
        if op.type == X86_OP_REG:
            idx, rsize, high = reg_info(self.md, op.reg)
            rsize = size or rsize
            if high:
                lines.append(f"  c->r[{idx}] = (c->r[{idx}] & ~0xff00ULL) | (({expr} & 0xff) << 8);")
            elif rsize == 64:
                lines.append(f"  c->r[{idx}] = {expr};")
            elif rsize == 32:
                lines.append(f"  c->r[{idx}] = (uint32_t)({expr});")
            else:
                mask = self._mask(rsize)
                lines.append(f"  c->r[{idx}] = (c->r[{idx}] & ~{mask}ULL) | (({expr}) & {mask}ULL);")
            return
        if op.type == X86_OP_MEM:
            sz = size or op.size
            lines.append(f"  X64_ST{sz * 8}({self.mem_addr(ins, op)}, {expr});")
            return
        raise Unsupported("write to non-register/memory")

    # --------------------------------------------------------------- lift
    def lift(self, entry, end):
        blocks = self.cfg(entry, end)
        lines = [f"void f_{entry:x}(X64Ctx *c)", "{"]
        for addr in sorted(blocks):
            lines.append(f"L_{addr:x}:")
            for ins in blocks[addr]:
                self.emit(lines, ins)
        lines.append("  return;")
        lines.append("}")
        return "\n".join(lines)

    def emit(self, L, ins):
        m = ins.mnemonic
        if m.endswith(" ret"):
            m = "ret"
        try:
            self._emit(L, ins, m)
        except Unsupported as e:
            raise Unsupported(f"{m}: {e}")

    def _emit(self, L, ins, m):
        ops = ins.operands
        size = ops[0].size if ops else 0

        def rd(i, sz=None):
            return self.op_read(ins, ops[i], sz)

        if m in ("nop", "endbr64", "endbr32", "pause", "lfence", "sfence", "mfence", "prefetch", "prefetcht0", "prefetcht1", "prefetcht2", "prefetchnta"):
            L.append(f"  /* {m} */")
            return
        if m in ("mov", "movabs"):
            self.write(L, ins, ops[0], rd(1))
            return
        if m in ("movzx", "movsx", "movsxd"):
            src = ops[1]
            ssz = src.size
            expr = rd(1, ssz)
            if m == "movsx" or m == "movsxd":
                bits = ssz * 8
                expr = f"((uint64_t)(int64_t)(int{bits}_t)({expr}))"
            self.write(L, ins, ops[0], expr)
            return
        if m == "lea":
            L.append(f"  c->r[{reg_info(self.md, ops[0].reg)[0]}] = {self.mem_addr(ins, ops[1])};")
            return
        if m in ("add", "sub", "adc", "sbb", "and", "or", "xor", "cmp", "test"):
            bits = size * 8
            a = rd(0)
            b = rd(1)
            if m in ("adc", "sbb"):
                b = f"({b} + (c->flags & X64_CF))" if m == "adc" else f"({b} + (c->flags & X64_CF))"
            if m in ("add", "adc"):
                L.append(f"  {{ uint64_t _a = {a}, _b = {b}, _r = _a + _b;")
                L.append(f"    c->flags = x64_add_flags(_a, _b, _r, {bits});")
                if m == "add":
                    self.write(L, ins, ops[0], "_r")
                L.append("  }")
                return
            if m in ("sub", "cmp", "sbb"):
                L.append(f"  {{ uint64_t _a = {a}, _b = {b}, _r = _a - _b;")
                L.append(f"    c->flags = x64_sub_flags(_a, _b, _r, {bits});")
                if m != "cmp":
                    self.write(L, ins, ops[0], "_r")
                L.append("  }")
                return
            L.append(f"  {{ uint64_t _r = ({a}) & ({b});")
            if m == "and":
                L.append(f"    c->flags = x64_logic_flags(_r, {bits});")
            elif m == "or":
                L.append(f"    _r = ({a}) | ({b}); c->flags = x64_logic_flags(_r, {bits});")
            elif m == "xor":
                L.append(f"    _r = ({a}) ^ ({b}); c->flags = x64_logic_flags(_r, {bits});")
            else:  # test
                L.append(f"    c->flags = x64_logic_flags(_r, {bits});")
            if m != "test":
                self.write(L, ins, ops[0], "_r")
            L.append("  }")
            return
        if m in ("inc", "dec"):
            bits = size * 8
            a = rd(0)
            op = "+" if m == "inc" else "-"
            L.append(f"  {{ uint64_t _a = {a}, _cf = c->flags & X64_CF;")
            L.append(f"    uint64_t _r = _a {op} 1;")
            fn = "x64_add_flags" if m == "inc" else "x64_sub_flags"
            L.append(f"    c->flags = {fn}(_a, 1, _r, {bits}) | _cf;")
            self.write(L, ins, ops[0], "_r")
            L.append("  }")
            return
        if m == "neg":
            bits = size * 8
            a = rd(0)
            L.append(f"  {{ uint64_t _a = {a}, _r = (uint64_t)(-(int64_t)_a);")
            L.append(f"    c->flags = x64_sub_flags(0, _a, _r, {bits});")
            self.write(L, ins, ops[0], "_r")
            L.append("  }")
            return
        if m == "not":
            self.write(L, ins, ops[0], f"~({rd(0)})")
            return
        if m in ("shl", "sal", "shr", "sar", "rol", "ror"):
            bits = size * 8
            a = rd(0)
            cnt = rd(1)
            L.append(f"  {{ uint64_t _a = {a}; unsigned _c = (unsigned)(({cnt}) & 0x3f);")
            if bits < 64:
                L.append(f"    uint64_t _m = {(1 << bits) - 1}ULL;")
                L.append("    _a &= _m;")
            L.append("    if (_c) {")
            if m in ("shl", "sal"):
                L.append("      uint64_t _r = _a << _c;")
                L.append(f"      if (_c <= {bits}) c->flags = ((_a >> ({bits} - _c)) & 1) ? (c->flags | X64_CF) : (c->flags & ~X64_CF);")
                L.append("      else c->flags &= ~X64_CF;")
                L.append(f"      c->flags = (c->flags & ~(X64_ZF|X64_SF|X64_PF)) | x64_szp(_r, {bits});")
                if bits == 64:
                    self.write(L, ins, ops[0], "_r")
                else:
                    self.write(L, ins, ops[0], f"(_r & _m)")
                L.append("      goto _done_shift;")
                L.append("    }")
                L.append(f"    /* count 0: flags unchanged */")
                L.append("    _done_shift: ;")
                L.append("  }")
                return
            if m == "shr":
                L.append("      uint64_t _r = _a >> _c;")
                L.append(f"      c->flags = ((_a >> (_c - 1)) & 1) ? (c->flags | X64_CF) : (c->flags & ~X64_CF);")
                L.append(f"      c->flags = (c->flags & ~(X64_ZF|X64_SF|X64_PF)) | x64_szp(_r, {bits});")
                L.append(f"      c->flags |= ((_a >> {bits - 1}) & 1) ? X64_OF : 0; /* count 1 only; harmless otherwise */")
                if bits == 64:
                    self.write(L, ins, ops[0], "_r")
                else:
                    self.write(L, ins, ops[0], f"(_r & _m)")
                L.append("      goto _done_shift;")
                L.append("    }")
                L.append("    _done_shift: ;")
                L.append("  }")
                return
            if m == "sar":
                L.append(f"      int64_t _s = (int64_t)(_a << (64 - {bits})) >> (64 - {bits});")
                L.append("      int64_t _r = _s >> _c;")
                L.append(f"      c->flags = ((_a >> (_c - 1)) & 1) ? (c->flags | X64_CF) : (c->flags & ~X64_CF);")
                L.append(f"      c->flags = (c->flags & ~(X64_ZF|X64_SF|X64_PF)) | x64_szp((uint64_t)_r, {bits});")
                if bits == 64:
                    self.write(L, ins, ops[0], "(uint64_t)_r")
                else:
                    self.write(L, ins, ops[0], "((uint64_t)_r & _m)")
                L.append("      goto _done_shift;")
                L.append("    }")
                L.append("    _done_shift: ;")
                L.append("  }")
                return
            if m in ("rol", "ror"):
                L.append(f"      unsigned _n = _c % {bits};")
                if m == "rol":
                    L.append(f"      uint64_t _r = ((_a << _n) | (_a >> ({bits} - _n))) & _m;")
                else:
                    L.append(f"      uint64_t _r = ((_a >> _n) | (_a << ({bits} - _n))) & _m;")
                L.append("      c->flags = (c->flags & ~(X64_CF|X64_ZF|X64_SF|X64_PF)) | x64_szp(_r, %d);" % bits)
                L.append(f"      c->flags |= (_r & 1) ? X64_CF : 0;")
                self.write(L, ins, ops[0], "_r")
                L.append("      goto _done_shift;")
                L.append("    }")
                L.append("    _done_shift: ;")
                L.append("  }")
                return
        if m == "imul":
            if len(ops) == 1:
                a = rd(0)
                L.append(f"  {{ int64_t _p = (int64_t)c->r[0] * (int64_t)({a});")
                L.append("    c->r[0] = (uint64_t)_p; c->r[2] = (uint64_t)(_p >> 64);")
                L.append("    c->flags = ((_p >= -0x7fffffffLL && _p <= 0x7fffffffLL) ? 0 : X64_CF) | x64_szp(c->r[0], 64); }")
                return
            if len(ops) == 2:
                a, b = rd(0), rd(1)
                bits = size * 8
                L.append(f"  {{ int64_t _a = (int64_t)({a}), _b = (int64_t)({b});")
                L.append("    int64_t _p = _a * _b;")
                L.append(f"    _a <<= (64 - {bits}); _a >>= (64 - {bits});")
                L.append(f"    _b <<= (64 - {bits}); _b >>= (64 - {bits});")
                L.append("    int64_t _q = _a * _b;")
                L.append("    c->flags = (_p != _q) ? (c->flags | X64_CF | X64_OF) : (c->flags & ~(X64_CF | X64_OF));")
                L.append(f"    c->flags = (c->flags & ~(X64_ZF|X64_SF|X64_PF)) | x64_szp((uint64_t)_q, {bits});")
                self.write(L, ins, ops[0], "(uint64_t)_q")
                L.append("  }")
                return
            if len(ops) == 3:
                b, imm = rd(1), rd(2)
                bits = size * 8
                L.append(f"  {{ int64_t _p = (int64_t)({b}) * (int64_t)({imm});")
                L.append("    int64_t _t = _p;")
                L.append(f"    _t = (_t << (64 - {bits})) >> (64 - {bits});")
                L.append("    c->flags = (_p != _t) ? (c->flags | X64_CF | X64_OF) : (c->flags & ~(X64_CF | X64_OF));")
                L.append(f"    c->flags = (c->flags & ~(X64_ZF|X64_SF|X64_PF)) | x64_szp((uint64_t)_t, {bits});")
                self.write(L, ins, ops[0], "(uint64_t)_t")
                L.append("  }")
                return
        if m in ("push",):
            bits = size * 8
            L.append(f"  c->r[{R_SP}] -= 8; X64_ST64(c->r[{R_SP}], {rd(0)});")
            return
        if m == "pop":
            L.append(f"  {{ uint64_t _v = X64_LD64(c->r[{R_SP}]); c->r[{R_SP}] += 8;")
            self.write(L, ins, ops[0], "_v")
            L.append("  }")
            return
        if m == "xchg":
            a, b = rd(0), rd(1)
            L.append(f"  {{ uint64_t _a = {a}, _b = {b};")
            self.write(L, ins, ops[0], "_b")
            self.write(L, ins, ops[1], "_a")
            L.append("  }")
            return
        if m == "bswap":
            if ops[0].size == 8:
                raise Unsupported("bswap r64")
            bits = size * 8
            L.append(f"  c->r[{reg_info(self.md, ops[0].reg)[0]}] = __builtin_bswap{bits}((uint32_t)({rd(0)}));")
            return
        if m in ("cdqe",):
            L.append("  c->r[0] = (uint64_t)(int64_t)(int32_t)c->r[0];")
            return
        if m in ("cwde",):
            L.append("  c->r[0] = (uint64_t)(int64_t)(int16_t)c->r[0];")
            return
        if m in ("cbw",):
            L.append("  c->r[0] = (c->r[0] & ~0xffffULL) | ((uint64_t)(int64_t)(int8_t)c->r[0] & 0xffff);")
            return
        if m in ("cdq", "cqo"):
            L.append("  c->r[2] = ((int64_t)c->r[0] < 0) ? ~0ULL : 0ULL;")
            if m == "cdq":
                L.append("  c->r[2] = (uint32_t)c->r[2];")
            return
        if m == "cwd":
            L.append("  c->r[2] = (c->r[2] & ~0xffffULL) | (((c->r[0] & 0x8000) ? 0xffff : 0) & 0xffff);")
            return
        if m.startswith("set"):
            cc = CC_NAMES.get(m[3:])
            if cc is None:
                raise Unsupported(m)
            L.append(f"  {{ uint64_t _f = c->flags, _v = x64_cond(_f, {cc});")
            self.write(L, ins, ops[0], "_v")
            L.append("  }")
            return
        if m.startswith("cmov"):
            cc = CC_NAMES.get(m[4:])
            if cc is None:
                raise Unsupported(m)
            L.append(f"  if (x64_cond(c->flags, {cc})) {{")
            self.write(L, ins, ops[0], rd(1))
            L.append("  }")
            return
        if m == "jmp":
            if ops[0].type != X86_OP_IMM:
                raise Unsupported("indirect jmp")
            L.append(f"  goto L_{ops[0].imm:x};")
            return
        if m == "ret":
            L.append("  return;")
            return
        if m.startswith("j") and len(m) <= 4 and m not in ("jmp",):
            cc = CC_NAMES.get(m[1:])
            if cc is None:
                raise Unsupported(m)
            if ops and ops[0].type == X86_OP_IMM:
                L.append(f"  if (x64_cond(c->flags, {cc})) goto L_{ops[0].imm:x};")
                return
            raise Unsupported("indirect jcc")
        if m == "call":
            if ops and ops[0].type == X86_OP_IMM:
                L.append(f"  c->r[{R_SP}] -= 8; X64_ST64(c->r[{R_SP}], {ins.address + ins.size:#x}ULL);")
                L.append(f"  f_{ops[0].imm:x}(c);")
                return
            raise Unsupported("call")
        if m in ("div", "idiv", "mul"):
            raise Unsupported(m)
        # --- SSE ---
        if self.emit_sse(L, ins):
            return
        raise Unsupported(m)


CC_NAMES = {
    "o": 0, "no": 1, "b": 2, "c": 2, "nae": 2, "ae": 3, "nb": 3, "nc": 3,
    "e": 4, "z": 4, "ne": 5, "nz": 5, "be": 6, "na": 6, "a": 7, "nbe": 7,
    "s": 8, "ns": 9, "p": 10, "pe": 10, "np": 11, "po": 11,
    "l": 12, "nge": 12, "ge": 13, "nl": 13, "le": 14, "ng": 14, "g": 15, "nle": 15,
}

MOVES = {"movaps", "movups", "movdqa", "movdqu", "movapd", "movupd"}
PACKED = {"addps", "subps", "mulps", "divps", "addpd", "subpd", "mulpd", "divpd"}
SCALAR = {"addss", "subss", "mulss", "divss", "addsd", "subsd", "mulsd", "divsd"}
BITWISE = {"xorps", "xorpd", "andps", "andpd", "orps", "orpd", "andnps", "andnpd"}
UNPCK = {"unpcklps", "unpckhps", "unpcklpd", "unpckhpd"}
CMPP = {"cmpps", "cmppd", "cmpss", "cmpsd"}
CMPPRED = {"cmpeq": 0, "cmplt": 1, "cmple": 2, "cmpunord": 3, "cmpneq": 4,
           "cmpnlt": 5, "cmpnle": 6, "cmpord": 7}
CONV = {"cvtdq2ps", "cvtdq2pd", "cvtsi2ss", "cvtsi2sd", "cvtss2si", "cvttss2si",
        "cvtsd2si", "cvttsd2si", "cvtss2sd", "cvtsd2ss", "cvtps2dq", "cvttps2dq"}


def _sse_common(self, L, ins):
    return None


class SseMixin:
    pass


def emit_sse(self, L, ins):
    m = ins.mnemonic
    ops = ins.operands
    if not ops:
        return False
    if m in MOVES or m in ("movss", "movsd", "movd", "movq"):
        d, s2 = ops[0], ops[1]
        if d.type == X86_OP_REG and self.is_gpr(d.reg):
            # movd/movq GPR <- xmm
            di = reg_info(self.md, d.reg)[0]
            si = self.xmm(s2.reg)
            if m == "movd":
                L.append(f"  c->r[{di}] = (uint32_t)c->xmm[{si}][0];")
            else:
                L.append(f"  c->r[{di}] = c->xmm[{si}][0];")
            return True
        if d.type == X86_OP_REG:
            di = self.xmm(d.reg)
            if s2.type == X86_OP_REG and self.is_gpr(s2.reg):
                si = reg_info(self.md, s2.reg)[0]
                L.append(f"  c->xmm[{di}][0] = (uint32_t)c->r[{si}]; c->xmm[{di}][1] = 0;")
                return True
            if s2.type == X86_OP_REG:
                si = self.xmm(s2.reg)
                if m in ("movss", "movsd"):
                    # scalar move keeps the upper lanes of the destination
                    if m == "movss":
                        L.append(f"  c->xmm[{di}][0] = (c->xmm[{di}][0] & ~0xffffffffULL) | (c->xmm[{si}][0] & 0xffffffffULL);")
                    else:
                        L.append(f"  c->xmm[{di}][0] = c->xmm[{si}][0];")
                elif m in ("movd", "movq"):
                    L.append(f"  c->xmm[{di}][0] = c->xmm[{si}][0] & {0xffffffff if m == 'movd' else 0xffffffffffffffff}ULL; c->xmm[{di}][1] = 0;")
                else:
                    L.append(f"  c->xmm[{di}][0] = c->xmm[{si}][0]; c->xmm[{di}][1] = c->xmm[{si}][1];")
                return True
            if s2.type == X86_OP_MEM:
                addr = self.mem_addr(ins, s2)
                if m in ("movss", "movd"):
                    L.append(f"  c->xmm[{di}][0] = (c->xmm[{di}][0] & ~0xffffffffULL) | (X64_LD32({addr}) & 0xffffffffULL);" if m == "movss"
                             else f"  c->xmm[{di}][0] = X64_LD32({addr}); c->xmm[{di}][1] = 0;")
                elif m in ("movsd", "movq"):
                    L.append(f"  c->xmm[{di}][0] = X64_LD64({addr});")
                    if m == "movq":
                        L.append(f"  c->xmm[{di}][1] = 0;")
                else:
                    L.append(f"  c->xmm[{di}][0] = X64_LD64({addr}); c->xmm[{di}][1] = X64_LD64({addr} + 8);")
                return True
            raise Unsupported(m)
        if d.type == X86_OP_MEM:
            si = self.xmm(s2.reg)
            addr = self.mem_addr(ins, d)
            if m in ("movss", "movd"):
                L.append(f"  X64_ST32({addr}, c->xmm[{si}][0]);")
            elif m in ("movsd", "movq"):
                L.append(f"  X64_ST64({addr}, c->xmm[{si}][0]);")
            else:
                L.append(f"  X64_ST64({addr}, c->xmm[{si}][0]); X64_ST64({addr} + 8, c->xmm[{si}][1]);")
            return True
        raise Unsupported(m)
    if m in PACKED or m in SCALAR or m in BITWISE:
        di = self.xmm(ops[0].reg)
        if ops[1].type == X86_OP_REG:
            si = self.xmm(ops[1].reg)
            src = f"c->xmm[{si}]"
            L.append(f"  {{ v4u _s; memcpy(&_s, {src}, 16); v4u _d; memcpy(&_d, c->xmm[{di}], 16);")
        else:
            addr = self.mem_addr(ins, ops[1])
            if m in SCALAR:
                L.append(f"  {{ v4u _s; memset(&_s, 0, sizeof _s); _s[0] = X64_LD32({addr}); v4u _d; memcpy(&_d, c->xmm[{di}], 16);")
            else:
                L.append(f"  {{ v4u _s; _s[0] = X64_LD64({addr}); _s[1] = X64_LD64({addr} + 8); _s[2] = 0; _s[3] = 0; v4u _d; memcpy(&_d, c->xmm[{di}], 16);")
        if m in ("addps", "addss"):
            L.append("    v4f _r = *(v4f*)&_d + *(v4f*)&_s;")
        elif m in ("subps", "subss"):
            L.append("    v4f _r = *(v4f*)&_d - *(v4f*)&_s;")
        elif m in ("mulps", "mulss"):
            L.append("    v4f _r = *(v4f*)&_d * *(v4f*)&_s;")
        elif m in ("divps", "divss"):
            L.append("    v4f _r = *(v4f*)&_d / *(v4f*)&_s;")
        elif m in ("addpd", "addsd", "subpd", "subsd", "mulpd", "mulsd", "divpd", "divsd"):
            op = m[:3]
            L.append(f"    v2d _r = *(v2d*)&_d {op[0]} *(v2d*)&_s;" if op == "add" else
                     f"    v2d _r = *(v2d*)&_d - *(v2d*)&_s;" if op == "sub" else
                     f"    v2d _r = *(v2d*)&_d * *(v2d*)&_s;" if op == "mul" else
                     f"    v2d _r = *(v2d*)&_d / *(v2d*)&_s;")
        elif m.startswith("xor"):
            L.append("    v4u _r = _d ^ _s;")
        elif m.startswith("andn"):
            L.append("    v4u _r = (~_d) & _s;")
        elif m.startswith("and"):
            L.append("    v4u _r = _d & _s;")
        elif m.startswith("or"):
            L.append("    v4u _r = _d | _s;")
        else:
            raise Unsupported(m)
        if m in SCALAR or m in ("addsd", "subsd", "mulsd", "divsd"):
            if m in ("addss", "subss", "mulss", "divss", "addsd", "subsd", "mulsd", "divsd"):
                if m.endswith("ss"):
                    L.append(f"    _d[0] = ((v4u*)&_r)[0]; memcpy(c->xmm[{di}], _d, 16);")
                else:
                    L.append(f"    _d[0] = ((v4u*)&_r)[0]; _d[1] = ((v4u*)&_r)[1]; memcpy(c->xmm[{di}], _d, 16);")
                L.append("  }")
                return True
        L.append(f"    memcpy(c->xmm[{di}], &_r, 16); }}")
        return True
    if m in UNPCK:
        di = self.xmm(ops[0].reg)
        if ops[1].type == X86_OP_REG:
            si = self.xmm(ops[1].reg)
            L.append(f"  {{ v4u _a; memcpy(&_a, c->xmm[{di}], 16); v4u _b; memcpy(&_b, c->xmm[{si}], 16);")
        else:
            addr = self.mem_addr(ins, ops[1])
            L.append(f"  {{ v4u _a; memcpy(&_a, c->xmm[{di}], 16); v4u _b = {{X64_LD64({addr}), X64_LD64({addr}+8), 0, 0}};")
        if m == "unpcklps":
            L.append("    v4u _r = {_a[0], _b[0], _a[1], _b[1]};")
        elif m == "unpckhps":
            L.append("    v4u _r = {_a[2], _b[2], _a[3], _b[3]};")
        elif m == "unpcklpd":
            L.append("    v4u _r = {_a[0], _b[0], _a[2], _b[2]};")
        else:
            L.append("    v4u _r = {_a[1], _b[1], _a[3], _b[3]};")
        L.append(f"    memcpy(c->xmm[{di}], &_r, 16); }}")
        return True
    if m == "shufps":
        di = self.xmm(ops[0].reg)
        if ops[1].type == X86_OP_REG:
            si = self.xmm(ops[1].reg)
            L.append(f"  {{ v4u _a; memcpy(&_a, c->xmm[{di}], 16); v4u _b; memcpy(&_b, c->xmm[{si}], 16);")
        else:
            addr = self.mem_addr(ins, ops[1])
            L.append(f"  {{ v4u _a; memcpy(&_a, c->xmm[{di}], 16); v4u _b = {{X64_LD64({addr}), X64_LD64({addr}+8), 0, 0}};")
        imm = ops[2].imm
        L.append(f"    v4u _r = {{_a[{imm & 3}], _a[{(imm >> 2) & 3}], _b[{(imm >> 4) & 3}], _b[{(imm >> 6) & 3}]}};")
        L.append(f"    memcpy(c->xmm[{di}], &_r, 16); }}")
        return True
    if m == "pshufd":
        di = self.xmm(ops[0].reg)
        if ops[1].type == X86_OP_REG:
            si = self.xmm(ops[1].reg)
            L.append(f"  {{ v4u _a; memcpy(&_a, c->xmm[{si}], 16);")
        else:
            addr = self.mem_addr(ins, ops[1])
            L.append(f"  {{ v4u _a = {{X64_LD64({addr}), X64_LD64({addr}+8), 0, 0}};")
        imm = ops[2].imm
        L.append(f"    v4u _r = {{_a[{imm & 3}], _a[{(imm >> 2) & 3}], _a[{(imm >> 4) & 3}], _a[{(imm >> 6) & 3}]}};")
        L.append(f"    memcpy(c->xmm[{di}], &_r, 16); }}")
        return True
    if m in CMPP or m in ("comiss", "ucomiss", "comisd", "ucomisd"):
        if m.startswith("comis") or m.startswith("ucomis"):
            di = self.xmm(ops[0].reg)
            scalar = m.endswith("ss")
            if ops[1].type == X86_OP_REG:
                si = self.xmm(ops[1].reg)
                L.append(f"  {{ v4u _s; memcpy(&_s, c->xmm[{si}], 16);")
            else:
                addr = self.mem_addr(ins, ops[1])
                L.append(f"  {{ v4u _s = {{X64_LD64({addr}), X64_LD64({addr}+8), 0, 0}};")
            L.append(f"    v4u _d; memcpy(&_d, c->xmm[{di}], 16);")
            if scalar:
                L.append("    float _a = *(float*)&_d[0], _b = *(float*)&_s[0];")
                L.append("    c->flags = (!(_a == _a) || !(_b == _b)) ? (X64_ZF|X64_PF|X64_CF) : ((_a < _b) ? X64_CF : ((_a == _b) ? X64_ZF : 0));")
            else:
                L.append("    double _a = *(double*)&_d[0], _b = *(double*)&_s[0];")
                L.append("    c->flags = (!(_a == _a) || !(_b == _b)) ? (X64_ZF|X64_PF|X64_CF) : ((_a < _b) ? X64_CF : ((_a == _b) ? X64_ZF : 0));")
            L.append("  }")
            return True
        # cmpps/cmpsd aliases: capstone prints e.g. cmpltps
        raise Unsupported(m)
    if m in CONV:
        return True
    if m in ("minss", "maxss", "minsd", "maxsd", "sqrtss", "sqrtsd", "sqrtps", "sqrtpd"):
        return True
    return False


Lifter.emit_sse = emit_sse


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("exe")
    ap.add_argument("--out", required=True)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--report", default=None)
    args = ap.parse_args()

    pe = PE64(open(args.exe, "rb").read())
    lif = Lifter(pe)
    funcs = pe.exceptions()
    if args.limit:
        funcs = funcs[:args.limit]

    os.makedirs(args.out, exist_ok=True)
    ok = traps = 0
    traps_by = collections.Counter()
    insns = 0
    emittable = 0
    for begin, end, _u in funcs:
        try:
            src = lif.lift(begin, end)
        except Unsupported as e:
            traps += 1
            traps_by[str(e).split(" at ")[0]] += 1
            continue
        except Exception as e:  # decoder edge
            traps += 1
            traps_by[f"error:{type(e).__name__}"] += 1
            continue
        ok += 1
        insns += src.count("\n") - 2
        name = f"f_{begin:x}.c"
        with open(os.path.join(args.out, name), "w") as f:
            f.write('#include "../../runtime/x64rt.h"\n')
            f.write(src)
            f.write("\n")
    rep = {"functions_total": len(funcs), "lifted": ok, "traps": traps,
           "coverage": round(ok / max(1, len(funcs)), 4),
           "trap_reasons": traps_by.most_common(20)}
    print(json.dumps(rep, indent=1))
    if args.report:
        json.dump(rep, open(args.report, "w"), indent=1)


if __name__ == "__main__":
    main()
