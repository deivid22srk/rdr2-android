#!/usr/bin/env python3
"""Instruction census + .pdata function inventory for a PE32+ image.

Linear sweep over the code section with capstone, seeded at every .pdata
RUNTIME_FUNCTION begin address (a real, authoritative function list on x64).
Reports mnemonic frequencies, REX/AVX usage and decoding failures.
"""
import sys, json, collections
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_OPT_DETAIL

def main(path, limit_funcs=0):
    pe = pefile.PE(path, fast_load=True)
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXCEPTION']])
    base = pe.OPTIONAL_HEADER.ImageBase
    text = None
    for s in pe.sections:
        if s.Name.rstrip(b'\0') == b'.text':
            text = s; break
    tva = text.VirtualAddress; tdata = text.get_data()
    funcs = []
    if hasattr(pe, 'DIRECTORY_ENTRY_EXCEPTION'):
        for e in pe.DIRECTORY_ENTRY_EXCEPTION:
            funcs.append((e.struct.BeginAddress, e.struct.EndAddress, e.struct.UnwindData))
    ents = len(funcs)
    if limit_funcs: funcs = funcs[:limit_funcs]
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    mn = collections.Counter(); insns = 0; bad = 0; bytes_dec = 0
    regs = collections.Counter()
    for b, e, u in funcs:
        if not (tva <= b < tva + len(tdata)): continue
        start = b - tva; end = min(e - tva, len(tdata))
        off = start
        while off < end:
            got = False
            for i in md.disasm(tdata[off:end], base + b + (off - start)):
                mn[i.mnemonic] += 1; insns += 1; bytes_dec += i.size
                for op in i.operands:
                    if op.type == 1:  # REG
                        regs[i.reg_name(op.reg)] += 1
                off += i.size; got = True
            if not got:
                bad += 1; off += 1
    print(json.dumps({'path': path, 'pdata_functions': ents, 'scanned_functions': len(funcs),
                      'instructions': insns, 'bytes_decoded': bytes_dec, 'decode_gaps': bad,
                      'text_vsize': text.Misc_VirtualSize,
                      'mnemonics': mn.most_common(60),
                      'distinct_mnemonics': len(mn),
                      'top_regs': regs.most_common(20)}, indent=1))

if __name__ == '__main__':
    main(sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else 0)
