#!/bin/bash

DIR="$(dirname "$(readlink -f "$0")")"

if [ ! $# -eq 3 ]; then
    echo "Usage: $0 <myconf.yml> <input_file> <out_file>"
    exit 1
fi

config=$1
input_file=$2
out_file=$3

native_lib_path=$DIR/../hal_fuzz/native/native_hooks.so
if [ ! -f "$native_lib_path" ]; then
    echo "error: could not find native library at $native_lib_path"; exit 1
fi

if [ ! -f "$config" ]; then
    echo "error: could not find config at $config"; exit 1
fi

if [ ! -f "$input_file" ]; then
    echo "error: could not find input file $input_file"; exit 1
fi

python3 -m hal_fuzz.harness -m -l 1000000 --state-out=$out_file -n --native-lib=$native_lib_path -c $config $input_file || exit -1

echo "done!"