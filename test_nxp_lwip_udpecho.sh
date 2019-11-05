#!/bin/bash
DIR="$(dirname "$(readlink -f "$0")")"

BINARY=./tests/nxp_lwip_udpecho/nxp_lwip_udpecho.yml
INPUTS=./tests/nxp_lwip_udpecho/inputs
OUTPUTS=./tests/nxp_lwip_udpecho/output/
HARNESS="python3 -m hal_fuzz.harness  -t -n --native-lib=$DIR/hal_fuzz/native/native_hooks.so -c $BINARY"
#./afl-fuzz -U -m none -i $INPUTS -o $OUTPUTS -- $HARNESS @@
$HARNESS $INPUTS/input1
