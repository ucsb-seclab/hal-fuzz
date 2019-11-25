#!/bin/bash

BINARY=./tests/chad_blink/blink.ino.yml
INPUTS=./tests/chad_blink/inputs
OUTPUTS=./tests/chad_blink/output/
HARNESS="python3 -m hal_fuzz.harness -c $BINARY"
#./afl-fuzz -t 500 -U -m none -i $INPUTS -o $OUTPUTS -- $HARNESS @@
$HARNESS $INPUTS/input1
#$HARNESS $INPUTS/id:000001,sig:11,src:000000,op:havoc,rep:8
