make clean
make PLATFORM=generic FW_FDT_PATH=/home/guokai/ELF/nemu_board/dts/build/xiangshan.dtb TYCHE_SM_PATH=/mnt/ssd4t/guokai/tyche FW_PAYLOAD=y FW_PAYLOAD_PATH=/home/guokai/ELF/linux-6.10.3/arch/riscv/boot/Image CROSS_COMPILE=riscv64-linux-gnu- -j $(nproc)
cd ..
