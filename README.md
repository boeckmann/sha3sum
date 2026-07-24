# SHA3SUM implementation using 32 or 64-bit little-endian integer arithmetic

This SHA3 and SHA3SUM implementation was made so that it can be compiled by C compilers not supporting 64-bit integer arithmetic, mainly ancient compilers like Borland Turbo C++.

It however defaults to 64-bit arithmetic. If 32-bit arithmetic is required, define the SHA3_32BIT preprocessor symbol, like for example under Unix-like operating systems:

```
cc -Os -DSHA3_32BIT sha3sum.c sha3.c -o sha3sum
```

The code is mildly optimized. For example, all expensive modulo 5 operations and array index calculations were pre-computed, and the (implicit) loops which are part of the keccak steps (not the keccak rounds) were unrolled. This makes the generated code somewhat large (~5kb Intel 8088 code), so it may not be suitable for use in embedded systems.

## Benchmarks

### SHA3-256, 64-bit C arithmetic, AMD64 Linux
```
Linux Mint 22.3 / Intel(R) Core(TM) i5-8250U:

  This implementation    236 MB/s  100%   (32-bit arithmetic  88 MB/s 37%)
  fossil sha3sum         242 MB/s  103%
  libdigest-sha3-perl    169 MB/s   72%
```
This implementation was compiled by GCC 13.3.0 with optimization flag `-Os`. The fossil version is 2.28, binary fetched from the original site at https://fossil-scm.org. libdigest-sha3-perl is version 1.05, installed from the Linux Mint package repository.

### SHA3-256, 32-bit C arithmetic, IA16 FreeDOS Kernel 2043
```
Intel 8088 @ 4.7 MHz:

  IA16-GCC 6.3                  0.60 KB/s
  OpenWatcom C/C++ 2.0beta1     0.42 KB/s
  Borland Turbo C++ 1.01        0.39 KB/s

Intel 286 @ 6 MHz:

  IA16-GCC 6.3                  3.59 KB/s
  OpenWatcom C/C++ 2.0beta1     1.75 KB/s
  Borland Turbo C++ 1.01        1.98 KB/s

Intel 386DX @ 16 MHz:

  IA16-GCC 6.3                  9.35 KB/s
  OpenWatcom C/C++ 2.0beta1     4.33 KB/s
  Borland Turbo C++ 1.01        4.58 KB/s

Intel 486DX @ 25 MHz:

  IA16-GCC 6.3                 35.86 KB/s
  OpenWatcom C/C++ 2.0beta1    12.20 KB/s
  Borland Turbo C++ 1.01       21.03 KB/s

```
GCC binary was generated with `-Os` optimization flag, Watcom binary was generated with `-ox` optimization flag, Borland binary was generated with `-G` optimization flag.
