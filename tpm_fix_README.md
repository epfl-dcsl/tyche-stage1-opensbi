Kconfig does not automatically enable the `CONFIG_TPM` variable

FIX: 
- Compile once for Kconfig to create its config file
- Go into the build/platform/generic/kconfig/ directory. Add `CONFIG_TPM=y` in the associated section at the bottom of the `.config` file.
