# QEMU Modified files
This branch contains the files that were modified to allow locality 4 DRTM operations. The base QEMU version used was QEMU stable release 8.1.

# Changes brought to QEMU

QEMU is well-equipped with capabilities to map a TPM into one if its processes. For TIS interfaces, we modified the following :

- QEMU was not supporting requesting changing localities to locality 4. This feature, or lack thereof, is documented as  "no system-level program should have to access locality 4". We decide against it for our purpose.

We also slightly modified the logic for the extended FIFO STS register : the regular FIFO has been untouched. We upgraded it to support locality 4 as well as to leverage the entire extended register. We also removed a check about locality locking.
