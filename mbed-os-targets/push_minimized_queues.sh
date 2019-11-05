#!/bin/bash

DIR="$(dirname "$(readlink -f "$0")")"

if [ ! $# -eq 2 ]; then
    echo "Usage: $0 <remote_host> <remote mbed-os-targets dir>"
    echo "Example: $0 ucsb-eric /home/tobi/hal-fuzz/mbed-os-targets"
    exit 0
fi

remote_host="$1"
remote_mbed_os_targets_dir="$2/targets"

targets_dir="$DIR/targets"

echo `l -1 "$targets_dir"`

while read -r target; do
    echo "Pushing to target: $target"
    #ssh $remote_host "/bin/bash -c 'mv $remote_mbed_os_targets_dir/$target/output/master1/queue $remote_mbed_os_targets_dir/$target/output/master1/queue_old && mkdir -p $remote_mbed_os_targets_dir/$target/output/queue'"
    ssh -n $remote_host "/bin/bash -c 'mkdir -p $remote_mbed_os_targets_dir/$target/min_inputs'"
    scp $targets_dir/$target/output/queue_min/* $remote_host:$remote_mbed_os_targets_dir/$target/min_inputs
done < <(ls "$targets_dir")