#!/bin/bash
DIR="$(dirname "$(readlink -f "$0")")"
TAR_DIR=$DIR/targets

while read -r target; do
  
  echo "################# Generating at-main-state for $target #################"
  $DIR/gen_target_at_main_state.py "$target"

done < <(ls "$TAR_DIR")
#done < <(echo -e "ARCH_PRO\nLPC1549\nLPC1768\nMOTE_L152RC")
#done < <(echo -e "EFM32GG_STK3700")
