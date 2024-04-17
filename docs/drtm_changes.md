# Modifications brought to OSBI

## TL;DR
We implemented TPM support with relevant TPM commands that allow to : read PCRs, request attestations from the TPM for PCR `17` (DRTM-enabling PCR), and create RSA keys with signing capabilities. Signing keys also have other attributes that can be used to trace them back to a physical TPM.

## TPM driver
Low level TPM driver, centered around TIS interface implementations. Based on SeaBIOS's driver, and augmented for operations on locality 4 (detailed further below).

## TPM commands
Higher-level wrapper around the low-level driver, we added implementations for specific TPM commands, namely:
- `TPM2_CreatePrimary` (creates a primary key).
- `TPM2_CreateLoaded` (creates a key and loads it in the main TPM memory to be usable)
- `TPM2_PCRRead` (allows to read a user-defined set of PCRs).
- `TPM2_Quote` (allows to get a quotation for a given set of PCR's content).

## implementation details for each command

### TPM2\_CreatePrimary

As said, this command allows for creation of primary keys under one of the main authorities.
The implementation given has been hardcoded for our purposes, and the data structures have been chosen as well to reflect our choices of algorithms and other selectors in the variety the TPM offered.

We create a parent RSA key, bound to the platform hierarchy, parameters fully generated from the TPM, with restricted capabilities. (This is to ensure this key can not be used to load keys from external sources under this parent).


### TPM2\_CreateLoaded
This command allows for creation of a key and loading it into memory.
We use it to create a 3072-bits RSA key, with signing properties (as such, this is a child key). We chose upon the following attributes : fixed hierarchy, parameters fully chosen from the TPM (except for the public exponent, set to `65537`), with restricted capabilities. **This last attribute ensures that the key can only sign data emanating from within the TPM**. If proven by a third-party that this key belongs to the platform's TPM, this consists our trust anchor in the attestation mechanism.

### TPM2\_PCRRead

We limit the read capabilities to only one PCR selection, and explicitely for `SHA384` PCR digests. For simplicity reasons, our PCR\_read operation is also limited to statically read PCR 17 only.

### TPM2\_Quote

Our implementation for quotation only works for our DRTM purpose, i.e. attestation over the `SHA384`-content of PCR `17`.

## DRTM mechanism

DRTM operations can only happen on locality 4, and specifically on PCR `17`. Due to the peculiar nature of dynamically resetting PCR `17`, DRTM does not abide by the standard rule of chaining calls to `TPM2_PcrExtend`.
Instead, we send a control command to signal we are going to start sending a stream of data to be digested into this PCR (`TPM_HASH_START`). We then write into the STS register (FIFO register to pass data to the TPM) for locality 4, passing data to be measured until we are done and requesting closure and digesting with `TPM_HASH_END`.

Because we are interacting below the usual level of command codes with request headers and responses, we implemented DRTM-related mechanisms in the low-level driver.

Side note : we are writing data into the extended FIFO register (XFIFO) to make sure our implementation would not conflict with any other normal operations happening on the TPM.


## Full chain of operation

Nearing the end of platform configuration from OSBI, we request for the TPM to startup with `TPM2_Startup(ST_CLEAR)` to ensure a clean slate. If the TPM won't start or we are running on a platform that is not equipped with a TPM, we load Tyche in memory and directly transfer control to it. Otherwise we follow the procedure below.

After Tyche has been parsed and loaded into memory, we request hashing the entire Tyche binary (which does take a few minutes with the current throughput) and extend PCR `17`. We then read PCR 17 to ensure the bank is consistent (despite ignoring the value per se, or it can be checked for debugging purposes). We then move to quotation.

Quotation happens in three parts:
- Creating the Storage Root Key (`SRK`) (with `TPM2_CreatePrimary`).
- Create the Attestation Integrity Key (`AIK`) (with `TPM2_CreateLoaded` under the `SRK` authority).
- Request quotation over PCR `17` signed by the `AIK`.

Quotation returns whatever information needs to be passed to Tyche for attestation verification : the AIK modulus, the attestation itself, and the  attestation signature.

We then read the PCR bank one more time (mostly for debugging purposes), write the attestation verification information into the manifest, then transfer control to Tyche.

