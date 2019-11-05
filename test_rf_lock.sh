#!/bin/bash
DIR="$(dirname "$(readlink -f "$0")")"

BINARY=./tests/rf_door_lock/rf_door_lock.yml
INPUTS=./tests/rf_door_lock/inputs
OUTPUTS=./tests/rf_door_lock/output/
HARNESS="python3 -m hal_fuzz.harness -d -t -n --native-lib=$DIR/hal_fuzz/native/native_hooks.so -c $BINARY"
#./afl-fuzz -U -m none -i $INPUTS -o $OUTPUTS -- $HARNESS @@
$HARNESS $INPUTS/input1
