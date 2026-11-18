#!/bin/sh
# Full M2 pipeline: lift -> select test functions -> differential test -> cross-ABI check.
#
# Needs a local copy of the game (never committed). Usage:
#   RDR2_EXE=/path/to/Crack/RDR2.exe scripts/run_difftest.sh [functions] [cases] [workdir]
#
# Steps:
#   1. tools/whole64.py   lifts the loadable closure of the image to C
#   2. tools/select_tests.py picks functions that are safe to call in isolation
#   3. clang builds harness/difftest.c (x86-64) and it compares the original bytes
#      against the generated C on the same host CPU
#   4. the same generated C is built for AArch64 and run under qemu-aarch64-static;
#      the hashes must match the x86-64 run, which proves the C does not depend on
#      the host (it is the ARM64 side of the port that actually ships)
set -eu

EXE=${RDR2_EXE:?set RDR2_EXE to the game executable}
FUNCS=${1:-3000}
CASES=${2:-16}
WORK=${3:-/tmp/rdr2-difftest}

CC=${CC:-clang}
CROSS_CC=${CROSS_CC:-aarch64-linux-gnu-gcc}
QEMU=${QEMU:-qemu-aarch64-static}

echo "== lift ($FUNCS functions) =="
rm -rf "$WORK"
python3 tools/whole64.py "$EXE" --emit "$WORK" --max "$FUNCS" | tail -4

echo "== select =="
python3 tools/select_tests.py "$EXE" --out "$WORK/tests.h" --max 2000 --from "$WORK/lifted.h" | tail -4

echo "== differential test (x86-64 host) =="
$CC -O0 -no-pie -I runtime -I "$WORK" -o "$WORK/difftest" \
    harness/difftest.c harness/trampoline.S "$WORK/lifted.c"
"$WORK/difftest" "$EXE" "$CASES" | tail -6

echo "== cross-ABI: same C on AArch64 =="
if command -v "$CROSS_CC" >/dev/null 2>&1 && command -v "$QEMU" >/dev/null 2>&1; then
    $CC       -O1 -I runtime -I "$WORK" -o "$WORK/libtest-x64"  harness/libtest.c "$WORK/lifted.c" 2>/dev/null
    $CROSS_CC -O1 -static -I runtime -I "$WORK" -o "$WORK/libtest-arm" harness/libtest.c "$WORK/lifted.c"
    "$WORK/libtest-x64" "$CASES" > "$WORK/out-x64.txt"
    "$QEMU" "$WORK/libtest-arm" "$CASES" > "$WORK/out-arm.txt"
    if cmp -s "$WORK/out-x64.txt" "$WORK/out-arm.txt"; then
        echo "OK: $(wc -l < "$WORK/out-x64.txt") cases identical on x86-64 and AArch64"
    else
        echo "FALHOU: x86-64 e AArch64 divergem"
        diff "$WORK/out-x64.txt" "$WORK/out-arm.txt" | head -20
        exit 1
    fi
else
    echo "pulado: $CROSS_CC ou $QEMU ausente (ver docs/BUILD.md)"
fi
