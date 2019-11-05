#!/bin/bash

BINARY=./tests/samr21_http/samr21_http.yml
INPUTS=./tests/samr21_http//inputs
OUTPUTS=./tests/samr21_http/output/
HARNESS="python -m hal_fuzz.harness -d -c $BINARY"
#./afl-fuzz -t 10000 -U -m none -i $INPUTS -o $OUTPUTS -- $HARNESS @@
$HARNESS $1
