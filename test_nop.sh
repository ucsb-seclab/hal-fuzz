#!/bin/bash

BINARY=./tests/nop/Nucleo_nop.yml
INPUTS=./tests/nop/inputs
OUTPUTS=./tests/nop/output/
HARNESS="python -m hal_fuzz.harness -l 1000000 -c $BINARY"
./afl-fuzz -t 1000 -U -m none -i $INPUTS -o $OUTPUTS -- $HARNESS @@
#$HARNESS $INPUTS/input1
