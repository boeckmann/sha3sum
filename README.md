# SHA3SUM implementation using 32-bit little-endian integer arithmetic

This sha3sum implementation is restricted to 32-bit integer arithmetic, as some C compilers do not support 64-bit integer arithmetic, for example the ancient Borland Compilers (Turbo C++ 1.01 etc.).

Some optimizations were made, for example all expensive modulo 5 operations and array index calculations were pre-computed, and the (implicit) loops which are part of the keccak steps (not the keccak rounds) were unrolled.
