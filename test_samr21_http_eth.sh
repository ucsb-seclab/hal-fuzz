#!/bin/bash

BINARY=./tests/samr21_http/samr21_http_eth.yml
INPUTS=./tests/samr21_http/inputs_eth
OUTPUTS=./tests/samr21_http/output/
HARNESS="python -m hal_fuzz.harness -n -c $BINARY"
./afl-fuzz -t 10000 -U -m none -i $INPUTS -o $OUTPUTS -- $HARNESS @@
#$HARNESS $INPUTS/wget_192.168.0.100.pcapng.input
