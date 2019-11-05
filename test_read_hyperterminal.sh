#!/bin/bash
DIR="$(dirname "$(readlink -f "$0")")"

BINARY=./tests/read_hyperterminal/Nucleo_read_hyperterminal.yml
INPUTS=./tests/read_hyperterminal/inputs
OUTPUTS=./tests/read_hyperterminal/output/
HARNESS="python3 -m hal_fuzz.harness  -d -t -n --native-lib=$DIR/hal_fuzz/native/native_hooks.so -c $BINARY"
#./afl-fuzz -U -m none -i $INPUTS -o $OUTPUTS -- $HARNESS @@
$HARNESS $INPUTS/input1
