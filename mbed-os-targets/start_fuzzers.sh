#!/bin/bash
DIR="$(dirname "$(readlink -f "$0")")"

if [ $# -ne 1 ]; then
    echo "Usage: $0 <output_subdirname"
    exit 0
fi

TAR_DIR=$DIR/targets

output_dirname="$1"

while read -r target; do

  $DIR/gen_target_entry_state.sh $target
  tmux new-window -n "$target" "/bin/sh -c './run_fuzzer.sh $target $output_subdir --restore-state=$TAR_DIR/$target/entry_state.state; exec bash'"

done < <(ls "$TAR_DIR")