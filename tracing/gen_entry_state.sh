#!/bin/bash

DIR="$(dirname "$(readlink -f "$0")")"

if [ ! $# -eq 2 ]; then
    echo "Usage: $0 <myconf.yml> <out_file>"
    exit 1
fi

config=$1
out_file=$2

native_lib_path=$DIR/../hal_fuzz/native/native_hooks.so
if [ ! -f "$native_lib_path" ]; then
    echo "error: could not find native library at $native_lib_path"; exit 1
fi

if [ ! -f "$config" ]; then
    echo "error: could not find config at $config"; exit 1
fi

tmp_dir=$(mktemp -d)
bb_trace_file="$tmp_dir/bb_traces.txt"
EMPTY_FILE_NAME=0000_empty_input
tmp_input_file="$tmp_dir/$EMPTY_FILE_NAME"
touch "$tmp_input_file"

echo "Generating temp state files to: $tmp_dir"

python3 -m hal_fuzz.harness -l 5000000 -m --bb-trace-out="$bb_trace_file" -n --native-lib=$native_lib_path -c $config $tmp_input_file || exit -1

num_events=$(wc -l $bb_trace_file | cut -f1 -d' ')
# Events start at 0 and we need to start dump the state one bb earlier to not get into mmio-access-on-first-instruction problems
event_dump_num=$(( $num_events-2 ))
echo "Got number of events: $num_events. Dumping at: $event_dump_num"

python3 -m hal_fuzz.harness -l 5000000 -m --bb-trace-out="$bb_trace_file" --trace-event-limit="$event_dump_num" --state-out="$out_file" -n --native-lib=$native_lib_path -c $config $tmp_input_file || exit -1

rm -rf $tmp_dir
exit 0
