#!/usr/bin/perl

use v5.24;
use strict;


my $x;
my $y;
my $i;
my $ident = "        ";

my @pi_perm = (
0,
1,
12,
13,
24,
25,
36,
37,
48,
49,
6,
7,
18,
19,
20,
21,
32,
33,
44,
45,
2,
3,
14,
15,
26,
27,
38,
39,
40,
41,
8,
9,
10,
11,
22,
23,
34,
35,
46,
47,
4,
5,
16,
17,
28,
29,
30,
31,
42,
43
);

say "static void keccak32( u32 a[] )
{
    static u32 rc[] = {
        0x00000001, 0x00000000, 0x00008082, 0x00000000, 0x0000808a, 0x80000000, 
        0x80008000, 0x80000000, 0x0000808b, 0x00000000, 0x80000001, 0x00000000, 
        0x80008081, 0x80000000, 0x00008009, 0x80000000, 0x0000008a, 0x00000000,
        0x00000088, 0x00000000, 0x80008009, 0x00000000, 0x8000000a, 0x00000000, 
        0x8000808b, 0x00000000, 0x0000008b, 0x80000000, 0x00008089, 0x80000000,
        0x00008003, 0x80000000, 0x00008002, 0x80000000, 0x00000080, 0x80000000,
        0x0000800a, 0x00000000, 0x8000000a, 0x80000000, 0x80008081, 0x80000000,
        0x00008080, 0x80000000, 0x80000001, 0x00000000, 0x80008008, 0x80000000
    };
    u32 b[50];
    u32 c[10], d[10];
    int round;

    for ( round=0; round<24; round++ ) {";

# theta
say "${ident}/* theta */";
for ($i = 0; $i < 10; $i++) {
	say "${ident}c[$i] = a[$i] ^ a[@{[$i+10]}] ^ a[@{[$i+20]}] ^ a[@{[$i+30]}] ^ a[@{[$i+40]}];";
}

for ($i = 0; $i < 10; $i+=2) {
	say "${ident}d[$i] = ((c[" . (($i + 2) % 10) ."] << 1) | (c[" . (($i+3) % 10) . "] >> 31)) ^ c[" . (($i + 8) % 10) . "];";
	say "${ident}d[" . ($i+1) . "] = ((c[" . (($i + 3) % 10) ."] << 1) | (c[" . (($i+2) % 10) . "] >> 31)) ^ c[" . (($i + 9) % 10) . "];";
}

for (my $d = 0; $d < 10; $d++) {
	for ($y = 0; $y < 5; $y++) {
		say "${ident}a[@{[10*$y+$d]}] ^= d[$d];";
	}
}


# rho
say;
say "${ident}/* rho */";
say "${ident}b[0] = a[0]; b[1] = a[1];";
$x = 1;
$y = 0;
for ($i=0; $i<24; $i++) {
	my $sc = (($i+1)*($i+2)/2)%64;
	my $idx = $y*10+$x*2;
	my $idx2 = $idx+1;
	if ($sc < 32) {
		say "${ident}b[$idx] = (a[$idx] << $sc) | (a[$idx2] >> @{[32-$sc]});";
		say "${ident}b[$idx2] = (a[$idx2] << $sc) | (a[$idx] >> @{[32-$sc]});";
	}
	else {
		$sc = $sc - 32;
		say "${ident}b[$idx] = (a[$idx2] << $sc) | (a[$idx] >> @{[32-$sc]});";		
		say "${ident}b[$idx2] = (a[$idx] << $sc) | (a[$idx2] >> @{[32-$sc]});";
	}
	($x, $y) = ($y, (2*$x+3*$y) % 5);
}


#iota
say;
say "${ident}/* pi, chi & iota */";
for ($y = 0; $y < 5; $y++) {
	for ($x = 0; $x < 5; $x++) {
		my $idx = $y*10+$x*2;
		my $idx2 = $idx+1;
		my $bdx = $pi_perm[$idx];
		my $bdx2 = $pi_perm[$idx2];
		my $jdx = $pi_perm[$y*10+(($x+1)%5)*2];
		my $jdx2 = $pi_perm[$y*10+(($x+1)%5)*2+1];
		my $kdx = $pi_perm[$y*10+(($x+2)%5)*2];
		my $kdx2 = $pi_perm[$y*10+(($x+2)%5)*2+1];
		if ($x == 0 && $y == 0) {
			say "${ident}a[$idx] = b[$bdx] ^ (~b[$jdx] & b[$kdx]) ^ rc[2*round];";
			say "${ident}a[$idx2] = b[$bdx2] ^ (~b[$jdx2] & b[$kdx2]) ^ rc[2*round+1];";
		}
		else {
			say "${ident}a[$idx] = b[$bdx] ^ (~b[$jdx] & b[$kdx]);";
			say "${ident}a[$idx2] = b[$bdx2] ^ (~b[$jdx2] & b[$kdx2]);";
		}
	}
}

say "    }
}";
