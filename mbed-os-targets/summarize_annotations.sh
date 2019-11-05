#!/bin/bash
DIR="$(dirname "$(readlink -f "$0")")"

if [ ! $# -eq 1 ]; then
    echo "Usage: $0 <trace_dir>"
    echo "Creates a summary of all annotated basic block traces in for a given target";
    exit 0
fi

#trace_dir="$DIR/targets/$1/output/traces"
trace_dir="$1"
if [ ! -d "$trace_dir" ]; then
    echo "ERROR: target directory does not exist: $trace_dir"; exit 1
fi

# extract the last n lines of all annotated_bbs* files and echo them out together with the filename
while read -r queue_dirname; do
    # Skip non-directory names
    if [ ! -d "$trace_dir/$queue_dirname" ]; then
        continue
    fi

    summary_file="$trace_dir/$queue_dirname/summary_bbs.txt"
    rm -f "$summary_file"
    for annotated_trace_file in $trace_dir/$queue_dirname/annotated_bbs_*; do
        if [ -f "$annotated_trace_file" ]; then
            echo "" >> $summary_file
            echo "======== $(basename $annotated_trace_file) ========" >> $summary_file
            tail -n 10 $annotated_trace_file >> $summary_file
        fi
    done
    if [ -f $summary_file ]; then
        echo "Wrote $summary_file"
    fi
done < <(ls "$trace_dir")
#done < <(echo ARCH_PRO)