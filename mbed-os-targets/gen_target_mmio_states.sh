#!/bin/bash
DIR="$(dirname "$(readlink -f "$0")")"

if [ $# -lt 1 ]; then
    echo "Usage: $0 <target> [<output_subdir> [<targets_base_dir>]]"; exit 1
fi

if [ $# -lt 3 ]; then
    targets_dir="$DIR/targets"
else
    targets_dir="$3"
fi

if [ $# -lt 2 ]; then
    output_subdir="output"
else
    output_subdir="$2"
fi

target="$1"
target_dir="$targets_dir/$target"
if [ ! -d "$target_dir" ]; then
    echo "ERROR: directory $target_dir does not exist"; exit 1
fi

config="$target_dir/config.yml"
outdir="$target_dir/$output_subdir"

input_dir=$outdir/queue_min
state_out_dir="$outdir/mmio_states"

if [ ! -f "$config" ]; then
    echo "Could not find config file '$config'"; exit 1
fi

if [ ! -d "$input_dir" ]; then
    echo "ERROR: input directory $input_dir does not exist. Did you not minimize, yet?"; exit 1
fi

mkdir -p $state_out_dir
$DIR/../tracing/gen_mmio_states.sh "$CONFIG" "$input_dir" "$state_out_dir"
