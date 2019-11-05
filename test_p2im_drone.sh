#!/bin/bash
DIR="$(dirname "$(readlink -f "$0")")"

BINARY=./tests/p2im_drone/p2im_drone.yml
INPUTS=./tests/p2im_drone/inputs
OUTPUTS=./tests/p2im_drone/output/
HARNESS="python3 -m hal_fuzz.harness -t -n --native-lib=$DIR/hal_fuzz/hal_fuzz/native/native_hooks.so -c $BINARY"
#./afl-fuzz -U -m none -i $INPUTS -o $OUTPUTS -- $HARNESS @@
$HARNESS $INPUTS/input1
