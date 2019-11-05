#!/bin/bash
DIR="$(dirname "$(readlink -f "$0")")"

TARGET=targets/$1
if [ ! -d "$TARGET" ]; then
    echo "ERROR: directory $TARGET does not exist"
    exit 1
fi

# echo "Usage: $0 <myconf.yml> <afl_outdir> <out_dir> <num_remote_procs> [<state_file> [<isr_num>]]"
CONFIG="$TARGET/config.yml"

REMOTE_OUTDIR=ucsb-eric:/home/tobi/hal-fuzz/mbed-os-targets/$TARGET/output
LOCAL_OUTDIR=$TARGET/output
NUM_PROCS=2

$DIR/../tracing/collect_gen_visualize.sh "$CONFIG" $REMOTE_OUTDIR $LOCAL_OUTDIR $NUM_PROCS
