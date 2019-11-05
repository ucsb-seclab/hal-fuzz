#NUCLEO_L152RE -> done STM32
#EV_COG_AD3029LZ -> done -> looks good
#XDOT_L151CC -> done STM32 -> looks good
#ARM_CM3DS_MPS2 -> done, no .bin file :-( -> looks good
#EFM32GG_STK3700 -> done -> looks good
#NCS36510 -> done, no .bin file -> looks good
#FVP_MPS2_M3 -> done, no .bin file -> looks good
#TMPM3HQ -> done -> looks good
#ARCH_PRO -> done -> looks good
#UBLOX_C027 -> done -> looks good

#REALTEK_RTL8195AM -> fail, mbed-os 5 not supported
#DISCO_F100RB -> fail, too small
#MAXWSNENV -> fail, mbed-os 5 not supported
#ARM_MPS2_M3 -> fail, toolchain not supported

# TARGETS="NUCLEO_L152RE EV_COG_AD3029LZ XDOT_L151CC ARM_CM3DS_MPS2 EFM32GG_STK3700 NCS36510 FVP_MPS2_M3 TMPM3HQ ARCH_PRO UBLOX_C027"
TARGETS="LPC1549 LPC1768 ARCH_PRO UBLOX_C027 NUCLEO_F103RB NUCLEO_F207ZG NUCLEO_L152RE MOTE_L152RC MAX32600MBED EFM32GG_STK3700 EFM32LG_STK3600"
BASE_PATH="ucsb-local:/home/tobi/research/mbed-os-projects/basic_exercises/BUILD"
for target in $TARGETS; do
    tar_dir="targets/$target"
    mkdir -p $tar_dir
    scp "$BASE_PATH/$target/GCC_ARM/basic_exercises.bin" "$tar_dir/basic_exercises.bin"
    scp "$BASE_PATH/$target/GCC_ARM/basic_exercises.elf" "$tar_dir/basic_exercises.elf"
done


