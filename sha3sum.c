/* SHA3SUM - print SHA3-[224,256,384,512] checksums.
 * Licensed under the EUPL by Bernd Boeckmann, Aachen.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sha3.h"

#ifndef RELEASE
#define RELEASE "?"
#endif
#ifndef CHECKOUT
#define CHECKOUT "???"
#endif

int opt_algorithm = 256;
int opt_binary = 0;

static void usage(void)
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

static int calculate_sha3_digest(FILE *f, u8 *buf, size_t bufsz, char *digest)
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

    sha3_digest(&ctx, digest);
    return 1;
}

#define BUF_SZ 16384

int main(int argc, char *argv[])
{
    const char *fn;
    FILE *f;
    u8 *buf;
    char digest[132];
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
	if (!calculate_sha3_digest(f, buf, BUF_SZ, digest)) {
	    fprintf(stderr, "error: cannot calculate hash for %s", fn);
	    errors++;
	    argv++;
	    continue;
	}

	printf("%s %c%s\n", digest, ((opt_binary) ? '*' : ' '), *argv);

	if (f != stdin)
	    fclose(f);
	argv++;
    } while (*argv);

    free(buf);
    return (errors) ? 1 : 0;
}
