#!/bin/bash
DIR="$(dirname "$(readlink -f "$0")")"

if [ $# -le 1 ]; then
    echo "Usage: $0 <target_name> <output_subdir> [<extra_aflfuzz_args> ...]"; exit 1
fi

TARGET="targets/$1"
output_dirname="$2"
if [ ! -d "$TARGET" ]; then
    echo "ERROR: directory $TARGET does not exist"
    exit 1
fi

shift
shift

BINARY="$TARGET/config.yml"

if [ -d "$TARGET/min_inputs" ]; then
    INPUTS="$TARGET/min_inputs"
else
    INPUTS="$DIR/base_inputs"
fi

MAX_INSTRS=1000000

OUTPUTS="$TARGET/$output_dirname"
# When looking for crashing out of bounds writes: --max-dynamic-mmio-pages=0
HARNESS="python3 -m hal_fuzz.harness -l $MAX_INSTRS -m -n --native-lib=$DIR/../hal_fuzz/native/native_hooks.so -c $BINARY $@"

nprocs=2

rm -rf "${OUTPUTS}_old"
mv "$OUTPUTS" "${OUTPUTS}_old"

# TODO: enable using minimized input base directory
child_pids=""
for i in `seq 2 $nprocs`; do
    $DIR/../afl-fuzz -t 2000 -S fuzzer$i -U -m none -i $INPUTS -o $OUTPUTS -- $HARNESS @@ >/dev/null 2>&1 &
	# Using multiple masters mode
    #$DIR/../afl-fuzz -t 2000 -M master$i:$i/$nprocs -U -m none -i $INPUTS -o $OUTPUTS -- $HARNESS @@ >/dev/null 2>&1 &
    # Using multiple masters mode (resuming)
    #$DIR/../afl-fuzz -t 2000 -M master$i:$i/$nprocs -U -m none -i- -o $OUTPUTS -- $HARNESS @@ >/dev/null 2>&1 &

    child_pids="$child_pids $!"
done

# Vanilla mode (1 core)
#$DIR/../afl-fuzz -t 2000+ -U -m none -i $INPUTS -o $OUTPUTS -- $HARNESS @@
# Vanilla mode (1 core, resuming)
#$DIR/../afl-fuzz -t 2000+ -U -m none -i- -o $OUTPUTS -- $HARNESS @@
# Master / slave mode
$DIR/../afl-fuzz -t 2000+ -M fuzzer1 -U -m none -i $INPUTS -o $OUTPUTS -- $HARNESS @@
# Multiple masters mode
#$DIR/../afl-fuzz -t 2000+ -M master1:1/$nprocs -U -m none -i $INPUTS -o $OUTPUTS -- $HARNESS @@
# Multiple Masters mode (resuming)
#$DIR/../afl-fuzz -t 2000+ -M master1:1/$nprocs -U -m none -i- -o $OUTPUTS -- $HARNESS @@

kill $child_pids
