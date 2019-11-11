#!/bin/bash

BINARY=./tests/read_hyperterminal/Nucleo_read_hyperterminal.yml
INPUTS=./tests/read_hyperterminal/inputs
OUTPUTS=./tests/read_hyperterminal/output/
HARNESS="python -m hal_fuzz.harness -c $BINARY"
#./afl-fuzz -U -m none -i $INPUTS -o $OUTPUTS -- $HARNESS @@
$HARNESS $INPUTS/input1
