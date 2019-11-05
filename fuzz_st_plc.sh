#!/bin/bash

BINARY=./tests/st-plc/st-plc.yml
INPUTS=./tests/st-plc/inputs
OUTPUTS=./tests/st-plc/output/
HARNESS="python -m hal_fuzz.harness -c $BINARY"
./afl-fuzz -U -m none -i $INPUTS -o $OUTPUTS -- $HARNESS @@
#$HARNESS $INPUTS/input1
