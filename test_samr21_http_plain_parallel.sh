#!/bin/bash

BINARY=./tests/samr21_http/samr21_http_plain.yml
INPUTS=./tests/samr21_http/inputs_plain
OUTPUTS=./tests/samr21_http/output/
HARNESS="python3 -m hal_fuzz.harness -c $BINARY"
nprocs=7

for i in `seq 2 $nprocs`; do
	./afl-fuzz -t 500 -M master$i:$i/$nprocs -U -m none -i $INPUTS -o $OUTPUTS -- $HARNESS @@ >/dev/null 2>&1 &
done
./afl-fuzz -t 500+ -M master1:1/$nprocs -U -m none -i $INPUTS -o $OUTPUTS -- $HARNESS @@
pkill afl-fuzz

