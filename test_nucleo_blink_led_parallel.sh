#!/bin/bash

BINARY=./tests/blink_led/Nucleo_blink_led.yml
INPUTS=./tests/blink_led/inputs
#OUTPUTS=./tests/blink_led/output/
OUTPUTS=/tmp/blink_led_fuzz_output_preseeded
HARNESS="python3 -m hal_fuzz.harness -c $BINARY"
nprocs=8
for i in `seq 2 $nprocs`; do
    #./afl-fuzz -t 200 -S slave$i -U -m none -i $INPUTS -o $OUTPUTS -- $HARNESS @@ >/dev/null 2>&1 &
    ./afl-fuzz -t 200 -M master$i:$i/$nprocs -U -m none -i $INPUTS -o $OUTPUTS -- $HARNESS @@ >/dev/null 2>&1 &

    #./afl-fuzz -t 200 -S slave$i -U -m none -i- -o $OUTPUTS -- $HARNESS @@ >/dev/null 2>&1 &
done
#./afl-fuzz -t 200+ -M master -U -m none -i $INPUTS -o $OUTPUTS -- $HARNESS @@
./afl-fuzz -t 200+ -M master1:1/$nprocs -U -m none -i $INPUTS -o $OUTPUTS -- $HARNESS @@

#./afl-fuzz -t 200+ -M master -U -m none -i- -o $OUTPUTS -- $HARNESS @@

pkill afl-fuzz

