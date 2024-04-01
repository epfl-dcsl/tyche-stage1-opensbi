export ROT_FLAG=y
cd opensbi-stage1
make clean
make PLATFORM=generic CROSS_COMPILE=riscv64-unknown-linux-gnu- TYCHE_SM_PATH=../target/riscv-unknown-kernel/release/tyche FW_PAYLOAD=y FW_PAYLOAD_PATH=../builds/linux-riscv/arch/riscv/boot/Image -j $(nproc)
cd ..
