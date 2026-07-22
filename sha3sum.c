/* SHA3[1] implementation using 32-bit little endian integer arithmetic.
 * Licensed under the EUPL by Bernd Boeckmann, Aachen.
 *
 * [1] https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define RELEASE "1"

#if __STDC_VERSION__ >= 199901L
#include <inttypes.h>
typedef uint32_t u32;
typedef uint8_t u8;
#else
#if __WATCOMC__ || __TURBOC__
typedef unsigned long u32;
typedef unsigned char u8;
#else
#error unsupported Compiler
#endif
#endif

#ifndef CHECKOUT
#define CHECKOUT "???"
#endif


int opt_algorithm = 256;
int opt_binary = 0;

typedef struct {
    u32 state[50];
    u8 buf[200];
    int mode;
    int r;
    int nbuf;
} Sha3Ctx;

void usage(void)
{
    puts("Usage: sha3sum [OPTION]... [FILE]...");
    puts("Print SHA3 checksums.");
    puts("With no FILE, or when FILE is -, read standard input.");
    puts("");
    puts("  -a, --algorithm  224, 256 (default), 386, 512");
    puts("  -b, --binary     compatibility, only affects checksum output");
    puts("  -t, --text       compatibility, only affects checksum output");
    puts("");
    puts("Despite -t or -b given, files are always read in binary.");
    puts("");
    puts("This is sha3sum release " RELEASE " built from checkout " CHECKOUT ".");
    puts("Licensed under the European Public License (EUPL) by Bernd Boeckmann, Aachen.");
}

/* a[] is the keccak state. One lane as defined in the specification is
 * represented by two 32-bit unsigned ints. This algorithm depends on
 * the integers being stored in little-endian representation.
 *
 * The mapping from our state a to A as defined in the spec is:
 *   a[1] * 0x100000000 + a[0] is A[0,0,z] is Lane(0,0)
 *   a[3] * 0x100000000 + a[2] is A[1,0,z] is Lane(1,0)
 *   a[11] * 0x100000000 + a[10] is A[0,1,z] is Lane(0,1)
 *   a[10*y+2*x+1] * 1x00000000 + a[10*y+2*x] is Lane(x,y)
 */

#define NR 24			/* number of permutation rounds */

static void keccak(u32 a[])
{
    static const u32 rc[] = {
	0x00000001, 0x00000000, 0x00008082, 0x00000000, 0x0000808a, 0x80000000,
	0x80008000, 0x80000000, 0x0000808b, 0x00000000, 0x80000001, 0x00000000,
	0x80008081, 0x80000000, 0x00008009, 0x80000000, 0x0000008a, 0x00000000,
	0x00000088, 0x00000000, 0x80008009, 0x00000000, 0x8000000a, 0x00000000,
	0x8000808b, 0x00000000, 0x0000008b, 0x80000000, 0x00008089, 0x80000000,
	0x00008003, 0x80000000, 0x00008002, 0x80000000, 0x00000080, 0x80000000,
	0x0000800a, 0x00000000, 0x8000000a, 0x80000000, 0x80008081, 0x80000000,
	0x00008080, 0x80000000, 0x80000001, 0x00000000, 0x80008008, 0x80000000
    };
    u32 b[50], e[50];
    u32 c[10], d[10];
    int ir;

    for (ir = 0; ir < NR; ir++) {
	/* theta */
	c[0] = a[0] ^ a[10] ^ a[20] ^ a[30] ^ a[40];
	c[1] = a[1] ^ a[11] ^ a[21] ^ a[31] ^ a[41];
	c[2] = a[2] ^ a[12] ^ a[22] ^ a[32] ^ a[42];
	c[3] = a[3] ^ a[13] ^ a[23] ^ a[33] ^ a[43];
	c[4] = a[4] ^ a[14] ^ a[24] ^ a[34] ^ a[44];
	c[5] = a[5] ^ a[15] ^ a[25] ^ a[35] ^ a[45];
	c[6] = a[6] ^ a[16] ^ a[26] ^ a[36] ^ a[46];
	c[7] = a[7] ^ a[17] ^ a[27] ^ a[37] ^ a[47];
	c[8] = a[8] ^ a[18] ^ a[28] ^ a[38] ^ a[48];
	c[9] = a[9] ^ a[19] ^ a[29] ^ a[39] ^ a[49];
	d[0] = ((c[2] << 1) | (c[3] >> 31)) ^ c[8];
	d[1] = ((c[3] << 1) | (c[2] >> 31)) ^ c[9];
	d[2] = ((c[4] << 1) | (c[5] >> 31)) ^ c[0];
	d[3] = ((c[5] << 1) | (c[4] >> 31)) ^ c[1];
	d[4] = ((c[6] << 1) | (c[7] >> 31)) ^ c[2];
	d[5] = ((c[7] << 1) | (c[6] >> 31)) ^ c[3];
	d[6] = ((c[8] << 1) | (c[9] >> 31)) ^ c[4];
	d[7] = ((c[9] << 1) | (c[8] >> 31)) ^ c[5];
	d[8] = ((c[0] << 1) | (c[1] >> 31)) ^ c[6];
	d[9] = ((c[1] << 1) | (c[0] >> 31)) ^ c[7];
	a[0] ^= d[0];
	a[1] ^= d[1];
	a[2] ^= d[2];
	a[3] ^= d[3];
	a[4] ^= d[4];
	a[5] ^= d[5];
	a[6] ^= d[6];
	a[7] ^= d[7];
	a[8] ^= d[8];
	a[9] ^= d[9];
	a[10] ^= d[0];
	a[11] ^= d[1];
	a[12] ^= d[2];
	a[13] ^= d[3];
	a[14] ^= d[4];
	a[15] ^= d[5];
	a[16] ^= d[6];
	a[17] ^= d[7];
	a[18] ^= d[8];
	a[19] ^= d[9];
	a[20] ^= d[0];
	a[21] ^= d[1];
	a[22] ^= d[2];
	a[23] ^= d[3];
	a[24] ^= d[4];
	a[25] ^= d[5];
	a[26] ^= d[6];
	a[27] ^= d[7];
	a[28] ^= d[8];
	a[29] ^= d[9];
	a[30] ^= d[0];
	a[31] ^= d[1];
	a[32] ^= d[2];
	a[33] ^= d[3];
	a[34] ^= d[4];
	a[35] ^= d[5];
	a[36] ^= d[6];
	a[37] ^= d[7];
	a[38] ^= d[8];
	a[39] ^= d[9];
	a[40] ^= d[0];
	a[41] ^= d[1];
	a[42] ^= d[2];
	a[43] ^= d[3];
	a[44] ^= d[4];
	a[45] ^= d[5];
	a[46] ^= d[6];
	a[47] ^= d[7];
	a[48] ^= d[8];
	a[49] ^= d[9];

	/* rho */
	b[0] = a[0];
	b[1] = a[1];
	b[2] = (a[2] << 1) | (a[3] >> 31);
	b[3] = (a[3] << 1) | (a[2] >> 31);
	b[20] = (a[20] << 3) | (a[21] >> 29);
	b[21] = (a[21] << 3) | (a[20] >> 29);
	b[14] = (a[14] << 6) | (a[15] >> 26);
	b[15] = (a[15] << 6) | (a[14] >> 26);
	b[22] = (a[22] << 10) | (a[23] >> 22);
	b[23] = (a[23] << 10) | (a[22] >> 22);
	b[34] = (a[34] << 15) | (a[35] >> 17);
	b[35] = (a[35] << 15) | (a[34] >> 17);
	b[36] = (a[36] << 21) | (a[37] >> 11);
	b[37] = (a[37] << 21) | (a[36] >> 11);
	b[6] = (a[6] << 28) | (a[7] >> 4);
	b[7] = (a[7] << 28) | (a[6] >> 4);
	b[10] = (a[11] << 4) | (a[10] >> 28);
	b[11] = (a[10] << 4) | (a[11] >> 28);
	b[32] = (a[33] << 13) | (a[32] >> 19);
	b[33] = (a[32] << 13) | (a[33] >> 19);
	b[16] = (a[17] << 23) | (a[16] >> 9);
	b[17] = (a[16] << 23) | (a[17] >> 9);
	b[42] = (a[42] << 2) | (a[43] >> 30);
	b[43] = (a[43] << 2) | (a[42] >> 30);
	b[48] = (a[48] << 14) | (a[49] >> 18);
	b[49] = (a[49] << 14) | (a[48] >> 18);
	b[8] = (a[8] << 27) | (a[9] >> 5);
	b[9] = (a[9] << 27) | (a[8] >> 5);
	b[30] = (a[31] << 9) | (a[30] >> 23);
	b[31] = (a[30] << 9) | (a[31] >> 23);
	b[46] = (a[47] << 24) | (a[46] >> 8);
	b[47] = (a[46] << 24) | (a[47] >> 8);
	b[38] = (a[38] << 8) | (a[39] >> 24);
	b[39] = (a[39] << 8) | (a[38] >> 24);
	b[26] = (a[26] << 25) | (a[27] >> 7);
	b[27] = (a[27] << 25) | (a[26] >> 7);
	b[24] = (a[25] << 11) | (a[24] >> 21);
	b[25] = (a[24] << 11) | (a[25] >> 21);
	b[4] = (a[5] << 30) | (a[4] >> 2);
	b[5] = (a[4] << 30) | (a[5] >> 2);
	b[40] = (a[40] << 18) | (a[41] >> 14);
	b[41] = (a[41] << 18) | (a[40] >> 14);
	b[28] = (a[29] << 7) | (a[28] >> 25);
	b[29] = (a[28] << 7) | (a[29] >> 25);
	b[44] = (a[45] << 29) | (a[44] >> 3);
	b[45] = (a[44] << 29) | (a[45] >> 3);
	b[18] = (a[18] << 20) | (a[19] >> 12);
	b[19] = (a[19] << 20) | (a[18] >> 12);
	b[12] = (a[13] << 12) | (a[12] >> 20);
	b[13] = (a[12] << 12) | (a[13] >> 20);

	/* pi */
	e[0] = b[0];
	e[1] = b[1];
	e[2] = b[12];
	e[3] = b[13];
	e[4] = b[24];
	e[5] = b[25];
	e[6] = b[36];
	e[7] = b[37];
	e[8] = b[48];
	e[9] = b[49];
	e[10] = b[6];
	e[11] = b[7];
	e[12] = b[18];
	e[13] = b[19];
	e[14] = b[20];
	e[15] = b[21];
	e[16] = b[32];
	e[17] = b[33];
	e[18] = b[44];
	e[19] = b[45];
	e[20] = b[2];
	e[21] = b[3];
	e[22] = b[14];
	e[23] = b[15];
	e[24] = b[26];
	e[25] = b[27];
	e[26] = b[38];
	e[27] = b[39];
	e[28] = b[40];
	e[29] = b[41];
	e[30] = b[8];
	e[31] = b[9];
	e[32] = b[10];
	e[33] = b[11];
	e[34] = b[22];
	e[35] = b[23];
	e[36] = b[34];
	e[37] = b[35];
	e[38] = b[46];
	e[39] = b[47];
	e[40] = b[4];
	e[41] = b[5];
	e[42] = b[16];
	e[43] = b[17];
	e[44] = b[28];
	e[45] = b[29];
	e[46] = b[30];
	e[47] = b[31];
	e[48] = b[42];
	e[49] = b[43];

	/* chi */
	a[0] = e[0] ^ (~e[2] & e[4]);
	a[1] = e[1] ^ (~e[3] & e[5]);
	a[2] = e[2] ^ (~e[4] & e[6]);
	a[3] = e[3] ^ (~e[5] & e[7]);
	a[4] = e[4] ^ (~e[6] & e[8]);
	a[5] = e[5] ^ (~e[7] & e[9]);
	a[6] = e[6] ^ (~e[8] & e[0]);
	a[7] = e[7] ^ (~e[9] & e[1]);
	a[8] = e[8] ^ (~e[0] & e[2]);
	a[9] = e[9] ^ (~e[1] & e[3]);
	a[10] = e[10] ^ (~e[12] & e[14]);
	a[11] = e[11] ^ (~e[13] & e[15]);
	a[12] = e[12] ^ (~e[14] & e[16]);
	a[13] = e[13] ^ (~e[15] & e[17]);
	a[14] = e[14] ^ (~e[16] & e[18]);
	a[15] = e[15] ^ (~e[17] & e[19]);
	a[16] = e[16] ^ (~e[18] & e[10]);
	a[17] = e[17] ^ (~e[19] & e[11]);
	a[18] = e[18] ^ (~e[10] & e[12]);
	a[19] = e[19] ^ (~e[11] & e[13]);
	a[20] = e[20] ^ (~e[22] & e[24]);
	a[21] = e[21] ^ (~e[23] & e[25]);
	a[22] = e[22] ^ (~e[24] & e[26]);
	a[23] = e[23] ^ (~e[25] & e[27]);
	a[24] = e[24] ^ (~e[26] & e[28]);
	a[25] = e[25] ^ (~e[27] & e[29]);
	a[26] = e[26] ^ (~e[28] & e[20]);
	a[27] = e[27] ^ (~e[29] & e[21]);
	a[28] = e[28] ^ (~e[20] & e[22]);
	a[29] = e[29] ^ (~e[21] & e[23]);
	a[30] = e[30] ^ (~e[32] & e[34]);
	a[31] = e[31] ^ (~e[33] & e[35]);
	a[32] = e[32] ^ (~e[34] & e[36]);
	a[33] = e[33] ^ (~e[35] & e[37]);
	a[34] = e[34] ^ (~e[36] & e[38]);
	a[35] = e[35] ^ (~e[37] & e[39]);
	a[36] = e[36] ^ (~e[38] & e[30]);
	a[37] = e[37] ^ (~e[39] & e[31]);
	a[38] = e[38] ^ (~e[30] & e[32]);
	a[39] = e[39] ^ (~e[31] & e[33]);
	a[40] = e[40] ^ (~e[42] & e[44]);
	a[41] = e[41] ^ (~e[43] & e[45]);
	a[42] = e[42] ^ (~e[44] & e[46]);
	a[43] = e[43] ^ (~e[45] & e[47]);
	a[44] = e[44] ^ (~e[46] & e[48]);
	a[45] = e[45] ^ (~e[47] & e[49]);
	a[46] = e[46] ^ (~e[48] & e[40]);
	a[47] = e[47] ^ (~e[49] & e[41]);
	a[48] = e[48] ^ (~e[40] & e[42]);
	a[49] = e[49] ^ (~e[41] & e[43]);

	/* iota */
	a[0] ^= rc[ir * 2];
	a[1] ^= rc[ir * 2 + 1];
    }
}

void sha3_init(Sha3Ctx *ctx, int mode)
{
    memset(ctx, 0, sizeof(Sha3Ctx));
    ctx->mode = mode;
    ctx->r = (1600 - 2 * mode) / 8;
}

static void sha3_xor_state(Sha3Ctx *ctx, const u8 *data)
{
    int i;
    for (i = 0; i < (ctx->r / 4); i++) {
	ctx->state[i] ^= ((u32 *) data)[i];
    }
}

void sha3_update(Sha3Ctx *ctx, const u8 *data, size_t len)
{
    int nbytes;

    /* bytes left from previous update? then use these with data to process first ctx->r bytes */
    if (ctx->nbuf) {
	nbytes = (ctx->nbuf + len >= ctx->r) ? ctx->r - ctx->nbuf : len;
	memcpy(ctx->buf + ctx->nbuf, data, nbytes);
	ctx->nbuf += nbytes;
	data += nbytes;
	len -= nbytes;
	if (ctx->nbuf == ctx->r) {
	    sha3_xor_state(ctx, ctx->buf);
	    keccak(ctx->state);
	    ctx->nbuf = 0;
	}
    }
    /* process multiple of ctx->r bytes */
    while (len >= ctx->r) {
	sha3_xor_state(ctx, data);
	keccak(ctx->state);
	data += ctx->r;
	len -= ctx->r;
    }
    /* save bytes we cannot process now to buffer for next update */
    ctx->nbuf = len;
    memcpy(ctx->buf, data, len);
}

void sha3_finish(Sha3Ctx *ctx)
{
    memset(ctx->buf + ctx->nbuf, 0, ctx->r - ctx->nbuf);
    ctx->buf[ctx->nbuf] |= 0x06;
    ctx->buf[ctx->r - 1] |= 0x80;

    sha3_xor_state(ctx, ctx->buf);
    keccak(ctx->state);
}

void sha3_print_hash(Sha3Ctx *ctx)
{
    int i;
    const u8 *b;
    b = (u8 *) ctx->state;
    for (i = 0; i < ctx->mode / 8; i++) {
	printf("%02x", b[i]);
    }
}

static void shift_argv(int *argc, char **argv)
{
    while (*argv) {
	*argv = *(argv + 1);
	argv++;
    }
    (*argc)--;
}

static void parse_args(int *argc, char **argv)
{
    argv++;			/* skip program name */
    while (*argv) {
	if (!strcmp(*argv, "-a") || !strcmp(*argv, "--algorithm")) {
	    shift_argv(argc, argv);
	    if (!strcmp(*argv, "224")) {
		opt_algorithm = 224;
	    } else if (!strcmp(*argv, "256")) {
		opt_algorithm = 256;
	    } else if (!strcmp(*argv, "384")) {
		opt_algorithm = 384;
	    } else if (!strcmp(*argv, "512")) {
		opt_algorithm = 512;
	    } else {
		usage();
		exit(1);
	    }
	    shift_argv(argc, argv);
	} else if (!strcmp(*argv, "-b") || !strcmp(*argv, "--binary")) {
	    /* MD5SUM binary compatibility flag */
	    shift_argv(argc, argv);
	    opt_binary = 1;
	} else if (!strcmp(*argv, "-t") || !strcmp(*argv, "--text")) {
	    /* MD5SUM text mode compatibility flag */
	    shift_argv(argc, argv);
	    opt_binary = 0;
	} else if ((*argv[0] == '-') && strcmp(*argv, "-")) {
	    usage();
	    exit(1);
	} else if (!strcmp(*argv, "-h") || !strcmp(*argv, "--help")) {
	    usage();
	    exit(0);
	} else {
	    argv++;
	}
    }
}

static int calculate_and_print_sha3_hash(FILE *f, u8 *buf, size_t bufsz)
{
    Sha3Ctx ctx;
    size_t avail;

    sha3_init(&ctx, opt_algorithm);
    while (1) {
	avail = fread(buf, 1, bufsz, f);
	if (ferror(f)) {
	    fprintf(stderr, "error: cannot read from file\n");
	    return 0;
	}
	if (!avail)
	    break;
	sha3_update(&ctx, buf, avail);
    };

    sha3_finish(&ctx);
    sha3_print_hash(&ctx);
    return 1;
}

#define BUF_SZ 16384

int main(int argc, char *argv[])
{
    const char *fn;
    FILE *f;
    u8 *buf;
    int errors;

    errors = 0;

    parse_args(&argc, argv);

    buf = malloc(BUF_SZ);
    if (buf == NULL) {
	fprintf(stderr, "error: not enough memory\n");
	return 1;
    }

    if (argc == 1) {
	*argv = "-";
    } else {
	argv++;
    }
    do {
	fn = *argv;
	if (!strcmp(fn, "-"))
	    f = stdin;
	else {
	    f = fopen(fn, "rb");
	    if (f == NULL) {
		fprintf(stderr, "error: cannot open %s\n", fn);
		errors++;
		argv++;
		continue;
	    }
	}
	if (!calculate_and_print_sha3_hash(f, buf, BUF_SZ)) {
	    fprintf(stderr, "error: cannot calculate hash for %s", fn);
	    errors++;
	}
	printf(" %c%s\n", ((opt_binary) ? '*' : ' '), *argv);
	if (f != stdin)
	    fclose(f);
	argv++;
    } while (*argv);

    free(buf);
    return (errors) ? 1 : 0;
}
