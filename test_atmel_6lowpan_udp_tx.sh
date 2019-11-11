#!/bin/bash

BINARY=./tests/atmel_6lowpan_udp_tx/atmel_6lowpan_udp_tx.yml
INPUTS=./tests/atmel_6lowpan_udp_tx/inputs
OUTPUTS=./tests/atmel_6lowpan_udp_tx/output/
HARNESS="python3 -m hal_fuzz.harness -c $BINARY"
#./afl-fuzz -t 10000 -U -m none -i $INPUTS -o $OUTPUTS -- $HARNESS @@
$HARNESS $INPUTS/*
