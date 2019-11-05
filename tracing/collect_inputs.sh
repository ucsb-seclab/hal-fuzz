#!/bin/bash

if [ $# -ne 3 ]; then
    echo "Usage: $0 <afl_output_dir> <dest_dir> <num_remote_procs>"
    exit 1
fi

afl_outputs="$1"
dest_dir="$2"
proc_no="$3"

echo "collecting inputs from '$afl_outputs' to '$dest_dir'"

re='^[0-9]+$'
if ! [[ $proc_no =~ $re ]] ; then
    echo "error: number of remote procs not a number" >&2; exit 1
fi

mkdir -p $dest_dir

if [ $proc_no -eq 1 ]; then
    scp -r $afl_outputs/queue $afl_outputs/hangs $afl_outputs/crashes $dest_dir
else
    for i in `seq 1 $proc_no`; do
        scp -r $afl_outputs/master$i/queue $afl_outputs/master$i/hangs $afl_outputs/master$i/crashes $dest_dir
        # scp -r $afl_outputs/slave$i/queue $afl_outputs/slave$i/crashes $afl_outputs/slave$i/hangs $dest_dir
    done
fi

for subdir in queue hangs crashes; do
    rm -f $dest_dir/$subdir/README.txt
done