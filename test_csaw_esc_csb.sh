#!/bin/bash
DIR="$(dirname "$(readlink -f "$0")")"

BINARY=./tests/csaw_esc19_csb/csaw_esc19_csb.yml
INPUTS=./tests/csaw_esc19_csb/inputs
OUTPUTS=./tests/csaw_esc19_csb/output/
HARNESS="python3 -m hal_fuzz.harness -n --native-lib=$DIR/hal_fuzz/hal_fuzz/native/native_hooks.so -c $BINARY"
#./afl-fuzz -U -m none -i $INPUTS -o $OUTPUTS -- $HARNESS @@
$HARNESS $1
