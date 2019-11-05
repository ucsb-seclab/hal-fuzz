#!/bin/bash
DIR="$(dirname "$(readlink -f "$0")")"

BINARY=./tests/csaw_esc19_csa/csaw_esc19_csa.yml
INPUTS=./tests/csaw_esc19_csa/inputs
OUTPUTS=./tests/csaw_esc19_csa/output/
HARNESS="python3 -m hal_fuzz.harness -n --native-lib=$DIR/hal_fuzz/hal_fuzz/native/native_hooks.so -c $BINARY"
#./afl-fuzz -U -m none -i $INPUTS -o $OUTPUTS -- $HARNESS @@
$HARNESS $1
