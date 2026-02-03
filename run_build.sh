cd opensbi-stage1
# Make clean doesn't erase everything in the build... so if you change FW_TEXT_ADDR or FW_PAYLOAD_OFFSET, then do rm -rf build/* or update the Makefile as needed.
export CROSS_COMPILE=riscv64-linux-gnu-
make clean
#make PLATFORM=generic TYCHE_SM_PATH=../target/riscv-unknown-kernel/release/tyche FW_PAYLOAD=y FW_PAYLOAD_PATH=../builds/linux-riscv/arch/riscv/boot/Image -j $(nproc)
make PLATFORM=generic TYCHE_SM_PATH=../target/riscv-unknown-kernel/release/tyche FW_PAYLOAD=y FW_PAYLOAD_PATH=/mnt/ssd4t/neelu/Image-XS -j $(nproc)
cd ..
