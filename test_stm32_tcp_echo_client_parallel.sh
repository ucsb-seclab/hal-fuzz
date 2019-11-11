#!/bin/bash

BINARY=./tests/stm32_tcp_echo_client/stm32_tcp_echo_client.yml
INPUTS=./tests/stm32_tcp_echo_client/inputs
OUTPUTS=./tests/stm32_tcp_echo_client/output/
HARNESS="python -m hal_fuzz.harness -c $BINARY"
nprocs=18
for i in `seq 2 $nprocs`; do
    ./afl-fuzz -t 2000 -S slave$i -U -m none -i $INPUTS -o $OUTPUTS -- $HARNESS @@ >/dev/null 2>&1 &
done
./afl-fuzz -t 1000+ -M master -U -m none -i $INPUTS -o $OUTPUTS -- $HARNESS @@
pkill afl-fuzz

