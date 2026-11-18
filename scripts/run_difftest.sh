#!/bin/sh
# M2 pipeline: lift -> select test functions -> differential test -> cross-ABI check.
#
# Needs a local copy of the game (never committed). Usage:
#   RDR2_EXE=/path/to/Crack/RDR2.exe scripts/run_difftest.sh [cases] [workdir]
#
# Steps:
#   1. tools/whole64.py lifts every function whose whole direct-call closure is supported
#   2. tools/select_tests.py picks the ones that can be called in isolation
#   3. clang builds harness/difftest.c (x86-64) and it compares the original bytes with the
#      generated C on the same host CPU
#   4. the same generated C is built for AArch64 and run under qemu-aarch64-static; the two
#      outputs must match, which is the only ARM64 evidence available without a device
set -eu

EXE=${RDR2_EXE:?set RDR2_EXE to the game executable}
CASES=${1:-16}
WORK=${2:-/tmp/rdr2-difftest}

CC=${CC:-clang}
CROSS_CC=${CROSS_CC:-aarch64-linux-gnu-gcc}
QEMU=${QEMU:-qemu-aarch64-static}

echo "== lift (fecho completo) =="
rm -rf "$WORK"
python3 tools/whole64.py "$EXE" --emit "$WORK" | tail -4

echo "== seleção das funções testáveis =="
python3 tools/select_tests.py "$EXE" --out "$WORK/tests.h" --max 2000 --from "$WORK/lifted.h" | tail -4

echo "== teste diferencial (host x86-64) =="
$CC -O0 -no-pie -I runtime -I "$WORK" -o "$WORK/difftest" \
    harness/difftest.c harness/trampoline.S "$WORK/lifted.c" -lm
"$WORK/difftest" "$EXE" "$CASES" | tail -6

echo "== cruzado: mesmo C em AArch64 =="
if command -v "$CROSS_CC" >/dev/null 2>&1 && command -v "$QEMU" >/dev/null 2>&1; then
    $CC       -O1 -no-pie -I runtime -I "$WORK" -o "$WORK/libtest-x64" harness/libtest.c "$WORK/lifted.c" -lm
    $CROSS_CC -O1 -static -ffp-contract=off -I runtime -I "$WORK" -o "$WORK/libtest-arm" \
              harness/libtest.c "$WORK/lifted.c" -lm
    "$WORK/libtest-x64" "$CASES" > "$WORK/out-x64.txt"
    "$QEMU" "$WORK/libtest-arm" "$CASES" > "$WORK/out-arm.txt"
    if [ ! -s "$WORK/out-x64.txt" ]; then
        echo "FALHOU: saída vazia"; exit 1
    fi
    total=$(wc -l < "$WORK/out-x64.txt")
    if cmp -s "$WORK/out-x64.txt" "$WORK/out-arm.txt"; then
        echo "OK: $total casos idênticos em x86-64 e AArch64"
    else
        echo "divergências entre x86-64 e AArch64:"
        diff "$WORK/out-x64.txt" "$WORK/out-arm.txt" | head -20
    fi
else
    echo "pulado: $CROSS_CC ou $QEMU ausente (ver docs/BUILD.md)"
fi