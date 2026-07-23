# SHA3SUM implementation using 32 or 64-bit little-endian integer arithmetic

This SHA3 and SHA3SUM implementation was made so that it can be compiled by C compilers not supporting 64-bit integer arithmetic, mainly ancient compilers like Borland Turbo C++.

It however defaults to 64-bit arithmetic. If 32-bit arithmetic is required, define the SHA3_32BIT preprocessor symbol, like for example under Unix-like operating systems:

```
cc -Os -DSHA3_32BIT sha3sum.c sha3.c -o sha3sum
```

The code is mildly optimized. For example, all expensive modulo 5 operations and array index calculations were pre-computed, and the (implicit) loops which are part of the keccak steps (not the keccak rounds) were unrolled. This makes the generated code somewhat large (~5kb Intel 8088 code), so it may not be suitable for use in embedded systems.
