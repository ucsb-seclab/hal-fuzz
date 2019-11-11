#!/bin/bash
nprocs=20
BINARY=./tests/read_hyperterminal/Nucleo_read_hyperterminal.yml
INPUTS=./tests/read_hyperterminal/inputs
OUTPUTS=./tests/read_hyperterminal/output/
HARNESS="python -m hal_fuzz.harness -c $BINARY"
for i in `seq 2 $nprocs`; do
    ./afl-fuzz -S slave$i -U -m none -i $INPUTS -o $OUTPUTS -- $HARNESS @@ >/dev/null 2>&1 &
done
./afl-fuzz -M master -U -m none -i $INPUTS -o $OUTPUTS -- $HARNESS @@
pkill afl-fuzz

