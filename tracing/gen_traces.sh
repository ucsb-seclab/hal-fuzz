#!/bin/bash
DIR="$(dirname "$(readlink -f "$0")")"

if [ ! $# -ge 3 ]; then
    echo "Usage: $0 <config.yml> <input_dir> <out_dir> [<base_state> [<isr_num>]]"
    exit -1
fi

yml_config=$1
input_dir=$2
trace_dir=$3

if [ ! -f "$yml_config" ]; then
    echo "config file does not exist"
    exit -1
fi

if [ ! -d "$trace_dir" ]; then
    echo "trace_dir does not exist"
    exit -1
fi

if [ $# -ge 4 ] && [[ ! ( -z "$4" || -f "$4" ) ]]; then
    echo "state file $4 does not exist"
    exit -1
else
    state_file="$4"
fi

if [[ $# -ge 5 && -n "$5" ]]; then
    isr_num="$5"

    num_re='^[0-9]+$'
    if ! [[ $isr_num =~ $num_re ]] ; then
        echo "error: isr_num not a number" >&2; exit 1
    fi
fi

native_lib_path=$DIR/../hal_fuzz/native/native_hooks.so
if [ ! -f "$native_lib_path" ]; then
    echo "error: could not find native library at $native_lib_path" >&2; exit 1
fi

HARNESS="python3 -m hal_fuzz.harness -m -n --native-lib=$native_lib_path -c $yml_config"

if [ -n "$state_file" ]; then
    HARNESS="$HARNESS --restore-state=$state_file"
fi

if [ -n "$isr_num" ]; then
    HARNESS="$HARNESS -i $isr_num"
fi


if [ "$(ls -A $input_dir)" ]; then
    for input_file in $input_dir/*; do
        echo "Using input file $input_dir/${input_file##*/}"
        $HARNESS --mmio-trace-out=$trace_dir/mmio_${input_file##*/}.txt --bb-trace-out=$trace_dir/bbs_${input_file##*/}.txt --ram-trace-out=$trace_dir/ram_${input_file##*/}.txt "$input_file"
    done
fi

# Make sure we don't propagate a previous segfault signal in status code
exit 0