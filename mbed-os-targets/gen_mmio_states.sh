#!/bin/bash
DIR="$(dirname "$(readlink -f "$0")")"

if [ $# -lt 1 ]; then
    echo "Usage: $0 <output_subdir> [<targets_basedir>]"
fi

output_subdir="$1"

if [ $# -lt 2 ]; then
    targets_basedir="$DIR/targets"
else
    targets_basedir="$2"
fi

if [ ! -d "$targets_basedir" ]; then
    echo "Could not find targets base dir: $targts_basedir"; exit 1
fi

while read -r target; do
    $DIR/gen_target_mmio_states.sh "$target" "$output_subdir" "$targets_basedir"
done < <(ls "$targets_basedir")
