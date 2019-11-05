#!/bin/bash
DIR="$(dirname "$(readlink -f "$0")")"
TAR_DIR=$DIR/targets

while read -r target; do
  
  echo "################# Collecting $target #################"
  mv targets/$target/output_bak targets/$target/output_bak2
  mv targets/$target/output targets/$target/output_bak 
  $DIR/collect_result.sh "$target"

done < <(ls "$TAR_DIR")
#done < <(echo -e "ARCH_PRO\nLPC1549\nLPC1768\nMOTE_L152RC")
#done < <(echo -e "EFM32GG_STK3700")
