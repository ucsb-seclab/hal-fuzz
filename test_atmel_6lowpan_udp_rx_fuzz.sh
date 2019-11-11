#!/bin/bash

BINARY=./tests/atmel_6lowpan_udp_rx/atmel_6lowpan_udp_rx.yml
INPUTS=./tests/atmel_6lowpan_udp_rx/inputs
OUTPUTS=./tests/atmel_6lowpan_udp_rx/output/
HARNESS="python3 -m hal_fuzz.harness -c $BINARY"
./afl-fuzz -t 10000 -U -m none -i $INPUTS -o $OUTPUTS -- $HARNESS @@
#$HARNESS $INPUTS/input1
