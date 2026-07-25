#!/usr/bin/perl

use v5.24;
use strict;


my $x;
my $y;
my $i;
my $ident = "        ";

my @pi_perm =(
0,
6,
12,
18,
24,
3,
9,
10,
16,
22,
1,
7,
13,
19,
20,
4,
5,
11,
17,
23,
2,
8,
14,
15,
21
);

say "static void keccak64( u64 a[] )
{
    static u64 rc[] = {
	0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
	0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
	0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
	0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
	0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
	0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008
    };
    u64 b[25];
    u64 c[5], d[5];
    int round;

    for ( round=0; round<24; round++ ) {";

# theta
say "${ident}/* theta */";
for ($i = 0; $i < 5; $i++) {
	say "${ident}c[$i] = a[$i] ^ a[@{[$i+5]}] ^ a[@{[$i+10]}] ^ a[@{[$i+15]}] ^ a[@{[$i+20]}];";
}

for ($i = 0; $i < 5; $i++) {
	say "${ident}d[$i] = ((c[" . (($i + 1) % 5) ."] << 1) | (c[" . (($i+1) % 5) . "] >> 63)) ^ c[" . (($i + 4) % 5) . "];";
}

for ($y = 0; $y < 5; $y++) {
	for ($x = 0; $x < 5; $x++) {
		say "${ident}a[@{[$x+5*$y]}] ^= d[@{[$x]}]; ";
	}
}


# rho
say;
say "${ident}/* rho */";
say "${ident}b[0] = a[0];";
$x = 1;
$y = 0;
for ($i=0; $i<24; $i++) {
	my $sc = (($i+1)*($i+2)/2)%64;
	my $idx = $y*5+$x;
	if ($sc <= 32) {
		say "${ident}b[$idx] = (a[$idx] << $sc) | (a[$idx] >> @{[64-$sc]});";
	}
	else {
		say "${ident}b[$idx] = (a[$idx] << $sc) | (a[$idx] >> @{[64-$sc]});";		
	}
	($x, $y) = ($y, (2*$x+3*$y) % 5);
}

say;
say "${ident}/* pi implicitly implemented by b[] index transformation */";

#chi
say;
say "${ident}/* chi & iota */";
for ($y = 0; $y < 5; $y++) {
	for ($x = 0; $x < 5; $x++) {
		my $idx = $y*5+$x;
		my $bdx = $pi_perm[$y*5+$x];
		my $jdx = $pi_perm[$y*5+(($x+1)%5)];
		my $kdx = $pi_perm[$y*5+(($x+2)%5)];
		print "${ident}a[$idx] = b[$bdx] ^ (~b[$jdx] & b[$kdx])";
		if ($x == 0 && $y == 0) {
			say " ^ rc[round];";
		}
		else {
			say ";";
		}
	}
}

say "    }
}";
