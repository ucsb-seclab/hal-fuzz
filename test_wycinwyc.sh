#!/bin/bash
DIR="$(dirname "$(readlink -f "$0")")"

BINARY=./tests/wycinwyc/expat_panda.yml
INPUTS=./tests/wycinwyc/inputs
OUTPUTS=./tests/wycinwyc/output_new
HARNESS="python -m hal_fuzz.harness -n --native-lib=$DIR/hal_fuzz/native/native_hooks.so -c $BINARY"
./afl-fuzz -U -x ./dictionaries/xml.dict -m none -i $INPUTS -o $OUTPUTS -- $HARNESS @@
#$HARNESS $INPUTS/../sample_trigger/05_*
