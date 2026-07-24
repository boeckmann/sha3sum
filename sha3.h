/* SHA3 implementation using 32 or 64-bit little endian integer arithmetic.
 * Licensed under the EUPL by Bernd Boeckmann, Aachen.
 */

#ifndef SHA3_H
#define SHA3_H

#if __STDC_VERSION__ >= 199901L
#include <inttypes.h>
typedef uint64_t u64;
typedef uint32_t u32;
typedef uint8_t u8;
#elif defined(__WATCOMC__)
typedef unsigned long long u64;
typedef unsigned long u32;
typedef unsigned char u8;
#elif defined(__TURBOC__)
#ifndef SHA3_32BIT
#error Turbo C++ does not support 64-bit arithmetic, define SHA3_32BIT to use 32-bit arithmetic
#endif
typedef unsigned long u32;
typedef unsigned char u8;
#else
#error unsupported compiler
#endif

#ifdef SHA3_32BIT
#define keccak keccak32
typedef u32 keccak_int;
#else
#define keccak keccak64
typedef u64 keccak_int;
#endif

typedef struct {
#ifdef SHA3_32BIT
    u32 state[50];
#else
    u64 state[25];
#endif
    u8 buf[200];
    int mode;
    int r;
    int nbuf;
    int finished;
} Sha3Ctx;

void sha3_init(Sha3Ctx *ctx, int mode);
void sha3_update(Sha3Ctx *ctx, const u8 *data, size_t len);
void sha3_finish(Sha3Ctx *ctx);
void sha3_hexdigest(Sha3Ctx *ctx, char *digest);

#endif
