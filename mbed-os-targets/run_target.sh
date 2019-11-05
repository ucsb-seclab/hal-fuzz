#!/bin/bash
DIR="$(dirname "$(readlink -f "$0")")"

if [ ! $# -ge 2 ]; then
    echo "Usage: $0 <target_name> <input_file> [<add_harness_args> ...]"; exit 1
fi

target=targets/$1
input_file="$2"

if [ ! -f $input_file ]; then
	input_file="$target/output/$2"
fi

if [ ! -d "$target" ]; then
    echo "ERROR: directory $target does not exist"; exit 1
fi

if [ ! -f "$input_file" ]; then
    echo "ERROR: input file $input_file does not exist"; exit 1
fi

shift
shift

MAX_INSTRS=1000000

BINARY="$target/config.yml"
HARNESS="python3 -m hal_fuzz.harness -l $MAX_INSTRS -m -n --native-lib=$DIR/../hal_fuzz/native/native_hooks.so $@ -c $BINARY"

$HARNESS "$input_file"
