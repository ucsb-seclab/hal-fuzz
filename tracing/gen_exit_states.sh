#!/bin/bash

DIR="$(dirname "$(readlink -f "$0")")"

if [ ! $# -eq 3 ]; then
    echo "Usage: $0 <myconf.yml> <input_dir> <out_dir>"
    exit 1
fi

config=$1
input_dir=$2
out_dir=$3

native_lib_path=$DIR/../hal_fuzz/native/native_hooks.so
if [ ! -f "$native_lib_path" ]; then
    echo "error: could not find native library at $native_lib_path"; exit 1
fi

if [ ! -f "$config" ]; then
    echo "error: could not find config at $config"; exit 1
fi

if [ ! -d "$input_dir" ]; then
    echo "error: could not find input dir at $input_dir"; exit 1
fi

mkdir -p "$out_dir"

for filepath in $input_dir/*; do
    filename="$(basename "$filepath")"
    python3 -m hal_fuzz.harness -m -l 150000 --state-out=$out_dir/state_$filename -n --native-lib=$native_lib_path -c $config $filepath || exit -1
done

echo "done!"