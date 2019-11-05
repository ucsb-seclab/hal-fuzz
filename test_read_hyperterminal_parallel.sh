#!/bin/bash

BINARY=./tests/read_hyperterminal/Nucleo_read_hyperterminal.yml
INPUTS=./tests/read_hyperterminal/inputs_plain
OUTPUTS=./tests/read_hyperterminal/output/
HARNESS="python3 -m hal_fuzz.harness -m -c $BINARY"
nprocs=6

for i in `seq 2 $nprocs`; do
	./afl-fuzz -t 500 -M master$i:$i/$nprocs -U -m none -i $INPUTS -o $OUTPUTS -- $HARNESS @@ >/dev/null 2>&1 &
done
./afl-fuzz -t 500+ -M master1:1/$nprocs -U -m none -i $INPUTS -o $OUTPUTS -- $HARNESS @@
pkill afl-fuzz

