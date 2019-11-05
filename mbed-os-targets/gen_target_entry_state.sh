#!/bin/bash
DIR="$(dirname "$(readlink -f "$0")")"

if [ $# -ne 1 ]; then
    echo "Usage: $0 <target>"; exit 1
fi

TARGET_DIR=targets/$1
if [ ! -d "$TARGET_DIR" ]; then
    echo "ERROR: directory $TARGET_DIR does not exist"; exit 1
fi

# echo "Usage: $0 <myconf.yml> <afl_outdir> <out_dir> <num_remote_procs> [<state_file> [<isr_num>]]"
CONFIG="$TARGET_DIR/config.yml"

STATE_OUT_FILE="$TARGET_DIR/entry_state.state"

$DIR/../tracing/gen_entry_state.sh "$CONFIG" "$STATE_OUT_FILE"