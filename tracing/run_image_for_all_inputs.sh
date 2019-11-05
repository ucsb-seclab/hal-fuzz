#!/bin/bash
DIR="$(dirname "$(readlink -f "$0")")"

if [ ! $# -ge 2 ]; then
    echo "Usage: $0 <config_file> <input_dir> [<add_harness_args> ...]"; exit 1
fi

config_file=$1
input_dir="$2"

if [ ! -d $input_dir ]; then
    echo "ERROR: input directory not found"; exit 1
fi

if [ ! -f "$config_file" ]; then
    echo "ERROR: config file $config_file does not exist"; exit 1
fi

shift
shift

for input_file in $input_dir/*; do
    $DIR/run_image.sh "$config_file" "$input_file" $@
    if [ "$?" -ne 0 ]; then
        echo "Got non-zero exit status for input file: '$input_file'"
        break
    fi
done
