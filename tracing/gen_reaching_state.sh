#!/bin/bash

DIR="$(dirname "$(readlink -f "$0")")"

if [ $# -ne 4 ]; then
    echo "Given an input directory, find an input reaching bbl_addr and generate state file to out_file"
    echo "Usage: $0 <myconf.yml> <bbl_addr> <input_dir> <out_file>"
    exit 1
fi

config="$1"
bbl_addr="$2"
input_dir="$3"
out_file="$4"

native_lib_path=$DIR/../hal_fuzz/native/native_hooks.so
if [ ! -f "$native_lib_path" ]; then
    echo "error: could not find native library at $native_lib_path"; exit 1
fi

if [ ! -f "$config" ]; then
    echo "error: could not find config at $config"; exit 1
fi

if [ ! -d "$input_dir" ]; then
    echo "error: could not find input dir '$input_dir'"; exit 1
fi

for input_file in "$input_dir/"*; do
    echo "Trying input file: $input_file"

    $DIR/run_image.sh "$config" "$input_file" --exit-at="$bbl_addr" > /dev/null
    # For now, return status 5 says: hit exit bbl
    if [ $? -eq 5 ]; then
        echo "found reaching input file: '$input_file'"
        $DIR/run_image.sh "$config" "$input_file" --exit-at=$bbl_addr --state-out="$out_file"
        echo "Generated entry state: '$out_file'"
        exit 0
    fi

done

echo "No input generating state at given address found"
exit 1