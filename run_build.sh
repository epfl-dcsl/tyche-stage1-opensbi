make clean
make PLATFORM=generic TYCHE_SM_PATH=../target/riscv-unknown-kernel/release/tyche FW_PAYLOAD=y FW_PAYLOAD_PATH=../builds/linux-riscv/arch/riscv/boot/Image -j $(nproc)

