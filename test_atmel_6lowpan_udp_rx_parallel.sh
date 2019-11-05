#!/bin/bash

BINARY=./tests/atmel_6lowpan_udp_rx/atmel_6lowpan_udp_rx.yml
INPUTS=./tests/atmel_6lowpan_udp_rx/inputs
OUTPUTS=./tests/atmel_6lowpan_udp_rx/output/
HARNESS="python3 -m hal_fuzz.harness -c $BINARY"
nprocs=35
for i in `seq 2 $nprocs`; do
    ./afl-fuzz -t 10000 -S slave$i -U -m none -i $INPUTS -o $OUTPUTS -- $HARNESS @@ >/dev/null 2>&1 &
done
./afl-fuzz -t 10000+ -M master -U -m none -i $INPUTS -o $OUTPUTS -- $HARNESS @@
pkill afl-fuzz

