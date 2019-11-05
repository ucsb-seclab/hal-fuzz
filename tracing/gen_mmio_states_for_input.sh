#!/bin/bash

DIR="$(dirname "$(readlink -f "$0")")"

if [ ! $# -eq 3 ]; then
    echo "Usage: $0 <myconf.yml> <input_file> <states_outdir>"
    exit 1
fi

config=$1
input_file=$2
out_dir=$3

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

if [ ! -e "$out_dir" ]; then
    echo "WARN: creating non-existant output directory: $out_dir"
    mkdir -p "$out_dir" | exit 1
elif [ ! -d "$out_dir" ]; then
    echo "error: output target '$out_dir' is no directory"; exit 1
fi

python3 -m hal_fuzz.harness --state-out=$out_dir --dump-mmio-states -m -n --native-lib=$native_lib_path -c $config $input_file || exit -1

echo "done!"