#!/bin/bash
DIR="$(dirname "$(readlink -f "$0")")"

BINARY=./tests/nxp_uart_polling/uart_polling.yml
INPUTS=./tests/nxp_uart_polling/inputs
OUTPUTS=./tests/nxp_uart_polling/output/
HARNESS="python3 -m hal_fuzz.harness -t -n --native-lib=$DIR/hal_fuzz/native/native_hooks.so -c $BINARY"
#./afl-fuzz -U -m none -i $INPUTS -o $OUTPUTS -- $HARNESS @@
$HARNESS $INPUTS/input1
