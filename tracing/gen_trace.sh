#!/bin/bash
DIR="$(dirname "$(readlink -f "$0")")"

if [ ! $# -ge 3 ]; then
    echo "Usage: $0 <config.yml> <input_file> <out_dir> [<out_state_file>]"
    exit -1
fi

yml_config=$1
input_file=$2
out_dir=$3

if [ ! -f "$yml_config" ]; then
    echo "config file does not exist"
    exit -1
fi

if [ ! -f "$input_file" ]; then
    echo "input_file does not exist"
    exit -1
fi

BINARY=$yml_config
echo "Using input file ${input_file}"
input_filename="$(basename $input_file)"
mmio_out_file="$out_dir/mmio_$input_filename.txt"
bbs_out_file="$out_dir/bbs_$input_filename.txt"
ram_out_file="$out_dir/ram_$input_filename.txt"

HARNESS="python3 -m hal_fuzz.harness -n --native-lib=$DIR/../hal_fuzz/native/native_hooks.so -m --mmio-trace-out=$mmio_out_file --ram-trace-out=$ram_out_file --bb-trace-out=$bbs_out_file -c $BINARY"

if [ ! $# -eq 3 ]; then
    state_out_file="$4"
    HARNESS="$HARNESS --state-out=$state_out_file"
fi

$HARNESS "$input_file"
echo "Wrote basic block trace to $bbs_out_file"
echo "Wrote mmio access trace to $mmio_out_file"
echo "Wrote ram access trace to $ram_out_file"

if [ $# -gt 3 ]; then
    echo "Wrote state to $state_out_file"
fi