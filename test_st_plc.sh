#!/bin/bash
DIR="$(dirname "$(readlink -f "$0")")"

BINARY=./tests/st-plc/st-plc.yml
INPUTS=./tests/st-plc/inputs
OUTPUTS=./tests/st-plc/output/
HARNESS="python3 -m hal_fuzz.harness -n --native-lib=$DIR/hal_fuzz/hal_fuzz/native/native_hooks.so -c $BINARY"
#./afl-fuzz -U -m none -i $INPUTS -o $OUTPUTS -- $HARNESS @@
$HARNESS $INPUTS/input1
