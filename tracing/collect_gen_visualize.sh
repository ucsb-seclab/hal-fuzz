#!/bin/bash

DIR="$(dirname "$(readlink -f "$0")")"
num_re='^[0-9]+$'

if [ ! $# -ge 3 ]; then
    echo "Usage: $0 <myconf.yml> <original_afl_outdir> <dest_aggregated_afl_outdir> [<num_remote_procs> [<state_file> [<isr_num>]]]"
    exit 1
fi

if [ $# -ge 5 ]; then
    state_file="$5"

    if [ ! -f "$state_file" ]; then
        echo "error: could not find state file at $state_file" >&2; exit 1    
    fi
fi

if [ $# -ge 6 ]; then
    isr_num="$6"
    
    if ! [[ $isr_num =~ $num_re ]] ; then
        echo "error: isr_num not a number" >&2; exit 1
    fi
fi

if [ $# -ge 4 ]; then
    proc_no="$4"
else
    proc_no=1
fi

config="$1"
source_afl_outdir="$2"
dest_afl_outdir="$3"


if [ ! -f "$config" ]; then
    echo "error: could not find config at $config" >&2; exit 1
fi

if ! [[ $proc_no =~ $num_re ]] ; then
    echo "error: number of remote procs not a number" >&2; exit 1
fi

native_lib_path=$DIR/../hal_fuzz/native/native_hooks.so
if [ ! -f "$native_lib_path" ]; then
    echo "error: could not find native library at $native_lib_path" >&2; exit 1
fi

if [ "$dest_afl_outdir" != "$source_afl_outdir" ]; then
    # 1. Collect files from remote or local directory
    $DIR/collect_inputs.sh "$source_afl_outdir" "$dest_afl_outdir" "$proc_no" || exit 1
elif [ $proc_no -ne 1 ]; then
    echo "got multi-process afl results, cannot generate in place"; exit -1
else
    echo "local and remote directory are equal, generating in place"
fi

INSTR_LIMIT=5000000
# 2. Minimize queue and hangs directories
HARNESS="python3 -m hal_fuzz.harness -l $INSTR_LIMIT -c $config -m -n --native-lib=$native_lib_path"

if [ -n "$state_file" ]; then
    HARNESS="$HARNESS --restore-state=$state_file"
    cp "$state_file" "$dest_afl_outdir"
fi

if [ -n "$isr_num" ]; then
    HARNESS="$HARNESS -i $isr_num"
fi

echo "using HARNESS: $HARNESS"

# TODO: differentiate basic block limits between hangs and queue
for subdir in queue hangs; do
    rm -f $dest_afl_outdir/$subdir/auto*
    $DIR/../afl-cmin -t 10000 -U -e -m none -i $dest_afl_outdir/${subdir} -o $dest_afl_outdir/${subdir}_cmin -- $HARNESS @@ || continue
    mkdir $dest_afl_outdir/${subdir}_min

    for file in $dest_afl_outdir/${subdir}_cmin/* $dest_afl_outdir/${subdir}_cmin/*; do
        if [[ ! ${file} == *.tmin ]] && [ ! -f "$file.tmin" ]; then
            filename="$(basename "$file")"
            $DIR/../afl-tmin -e -t 10000 -U -m none -i $file -o "$dest_afl_outdir/${subdir}_min/${filename}" -- $HARNESS @@ || exit -1
        fi
    done
done

# 3. Generate traces for all inputs
for subdir in queue_min queue hangs_min crashes; do
    mkdir -p "$dest_afl_outdir/traces/$subdir"
    $DIR/gen_traces.sh "$config" "$dest_afl_outdir/$subdir" "$dest_afl_outdir/traces/$subdir" "$state_file" "$isr_num"
done

# 4. Generate visualization for all inputs
for subdir in queue_min queue hangs_min crashes; do
    $DIR/visualization/draw_mmio_trace.py $dest_afl_outdir/traces/$subdir $dest_afl_outdir/$subdir.svg || exit -1
done

# 5. Generate mmio states?

echo 'done!'