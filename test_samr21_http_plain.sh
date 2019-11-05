#!/bin/bash

BINARY=./tests/samr21_http/samr21_http_plain.yml
INPUTS=./tests/samr21_http/inputs_plain
OUTPUTS=./tests/samr21_http/output/
HARNESS="python3 -m hal_fuzz.harness -c $BINARY"
./afl-fuzz -t 500 -U -m none -i $INPUTS -o $OUTPUTS -- $HARNESS @@
#$HARNESS $INPUTS/input1
