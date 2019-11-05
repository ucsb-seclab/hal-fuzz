#!/bin/bash

BINARY=./tests/blink_led/Nucleo_blink_led.yml
INPUTS=./tests/blink_led/inputs
OUTPUTS=./tests/blink_led/output/
HARNESS="python3 -m hal_fuzz.harness -t -c $BINARY"
#./afl-fuzz -t 200 -U -m none -i $INPUTS -o $OUTPUTS -- $HARNESS @@
#./afl-fuzz -t 200 -U -m none -i- -o $OUTPUTS -- $HARNESS @@
$HARNESS $INPUTS/input1
