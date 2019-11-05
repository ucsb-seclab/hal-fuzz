#!/bin/bash

DIR="$(dirname "$(readlink -f "$0")")"

if [ $# -lt 2 ]; then
    echo "Usage: $0 <myconf.yml> <input_file> [<extra_harness_args>]"
    exit 1
fi

config="$1"
input_file="$2"

native_lib_path=$DIR/../hal_fuzz/native/native_hooks.so
if [ ! -f "$native_lib_path" ]; then
    echo "error: could not find native library at $native_lib_path"; exit 1
fi

if [ ! -f "$config" ]; then
    echo "error: could not find config at $config"; exit 1
fi

if [ ! -f "$input_file" ]; then
    echo "error: could not find input file at $input_file"; exit 1
fi

shift
shift

INSTR_LIMIT=1000000
HARNESS="python3 -m hal_fuzz.harness -l $INSTR_LIMIT -m -n --native-lib=$native_lib_path -c $config"
$HARNESS $@ "$input_file"

#$DIR/../afl-showmap -U -m none -t 10000 -o ./test_showmap_out.bin -i "$input_file" -- $HARNESS @@