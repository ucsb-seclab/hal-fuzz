#!/bin/bash
DIR="$(dirname "$(readlink -f "$0")")"
TARGETS_DIR=$DIR/targets

# echo "Usage: $0 <myconf.yml> <afl_outdir> <out_dir> <num_remote_procs> [<state_file> [<isr_num>]]"
NUM_PROCS="2"

while read -r target; do
  AGGREGATED_OUTDIR="$TARGETS_DIR/$target/output_aggregated_minimized_traced"
  ORIG_OUTDIR="$TARGETS_DIR/$target/output"
  CONFIG="$TARGETS_DIR/$target/config.yml"
  
  tmux new-window -n "$target" "/bin/sh -c 'cd $TARGETS_DIR/$target && $DIR/../tracing/collect_gen_visualize.sh "$CONFIG" $ORIG_OUTDIR $AGGREGATED_OUTDIR $NUM_PROCS ; exec bash'"

done < <(ls "$TARGETS_DIR")