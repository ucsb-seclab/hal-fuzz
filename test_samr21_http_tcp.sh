#!/bin/bash

BINARY=./tests/samr21_http/samr21_http_tcp.yml
INPUTS=./tests/samr21_http/inputs_tcp
OUTPUTS=./tests/samr21_http/output/
HARNESS="python -m hal_fuzz.harness -n -c $BINARY"
./afl-fuzz -t 10000 -U -m none -i $INPUTS -o $OUTPUTS -- $HARNESS @@
#$HARNESS $INPUTS/input1
