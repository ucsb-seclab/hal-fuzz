#!/bin/bash
DIR="$(dirname "$(readlink -f "$0")")"

if [ $# -lt 1 ]; then
    echo "Usage: <output_subdir> [<targets_base_dir>]"; exit 1
fi

output_subdir="$1"

if [ $# -lt 2 ]; then
    targets_dir="$DIR/targets"
else
    targets_dir="$2"
fi

if [ ! -d "$targets_dir" ]; then
    echo "Targets dir '$targets_dir' not found"; exit 1
fi

while read -r target; do

    target_dir="$targets_dir/$target"
    output_dir="$target_dir/$output_subdir"
    echo "annotating in $target_dir"

    if [ ! -d $output_dir ]; then
        echo "Could not find output dir: '$output_dir'"; exit 1
    fi

    $DIR/../tracing/annotate_traces.sh "$target_dir/basic_exercises.elf" "$output_dir/traces/queue_min"
    # $DIR/../tracing/annotate_traces.sh "$target_dir/basic_exercises.elf" "$output_dir/traces/queue"
    $DIR/../tracing/annotate_traces.sh "$target_dir/basic_exercises.elf" "$output_dir/traces/crashes"

    $DIR/summarize_annotations.sh "$output_dir/traces"

done < <(ls "$targets_dir")
#done < <(echo NUCLEO_L152RE)
