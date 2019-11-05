#!/bin/bash
DIR="$(dirname "$(readlink -f "$0")")"

if [ ! $# -eq 2 ]; then
    echo "Usage: $0 <elf_file> <dir_name>"; exit 1
fi

elf_file="$1"
tar_dir="$2"

if [ ! -f "$elf_file" ]; then
    echo "not a file: '$elf_file'"; exit 1
fi

if [ ! -d "$tar_dir" ]; then
    echo "not a directory: '$tar_dir'"; exit 1
fi

files=$(echo -n " $tar_dir/mmio_* $tar_dir/bbs_*")
#for file in $files; do
#    if [ -f "$file" ]; then
#        $DIR/annotate_trace.py -o $tar_dir -e $elf_file $file
#    fi
#done
$DIR/annotate_trace.py -o $tar_dir -e $elf_file $files