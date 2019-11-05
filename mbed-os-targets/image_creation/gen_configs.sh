#!/bin/bash
DIR="$(dirname "$(readlink -f "$0")")"

TARGETS="LPC1549 LPC1768 ARCH_PRO UBLOX_C027 NUCLEO_F103RB NUCLEO_F207ZG NUCLEO_L152RE MOTE_L152RC MAX32600MBED EFM32GG_STK3700 EFM32LG_STK3600"

for target in $TARGETS; do
    echo "Generating config for $target"
    path=$DIR/targets/$target
    $DIR/gen_config.py $path/basic_exercises.bin > $path/config.yml
done