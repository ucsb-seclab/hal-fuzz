#!/bin/bash
DIR="$(dirname "$(readlink -f "$0")")"

BINARY=./tests/nxp_lwip_http/nxp_lwip_http.yml
INPUTS=./tests/nxp_lwip_http/inputs
OUTPUTS=./tests/nxp_lwip_http/output/
HARNESS="python -m hal_fuzz.harness -n --native-lib=$DIR/hal_fuzz/native/native_hooks.so -c $BINARY"
nprocs=32
for i in `seq 2 $nprocs`; do
    ./afl-fuzz -t 2000 -S slave$i -U -m none -i $INPUTS -o $OUTPUTS -- $HARNESS @@ >/dev/null 2>&1 &
done
./afl-fuzz -t 1000+ -M master -U -m none -i $INPUTS -o $OUTPUTS -- $HARNESS @@
pkill afl-fuzz

