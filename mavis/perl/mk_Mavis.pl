#!/usr/bin/env perl
# A trivial script for generating Mavis.pm from ../mavis.h
#
# I currently only care about the #define's ... -MH
#

open H, "../mavis.h" or die;
while (<H>) {
	next if /^#define\s+AV_A_SPARE/;
	if (/^#define\s+((MAVIS_|AV_A|AV_V)[^\s]+)\s+([^\s]+)/) {
		$V{$1} = $3;
	}
}
close H;

$e = "";
$o = "";

foreach $v (sort keys %V) {
	$e .= "\t\t$v\n";
	$V{$v} = $V{$V{$v}} unless $V{$v} =~ /^("|-|\d)/;
	$o .= "use constant $v => $V{$v};\n";
}

print<<EOT;
# Mavis.pm
#
# MAVIS definitions for Perl, automatically generated from mavis.h
#
package Mavis;
use strict;
use warnings;

BEGIN {
	use Exporter ();
	our (\@ISA, \@EXPORT);
	\@ISA = qw(Exporter);
	\@EXPORT = qw(
$e
		quote_list
	);
};

$o

# The list format of TACMEMBER, MEMBEROF and SSHKEY*, as av_add_quoted() of libmavis writes it: each value in
# double quotes with a backslash before each double quote, joined by commas. A value with a CR, LF or NUL, or
# that ends with a backslash, cannot go in the list: it is skipped, with a message on stderr.
sub quote_list(\$\$@) {
	my (\$attribute, \$user, \@values) = \@_;
	my \@quoted;
	foreach my \$v (\@values) {
		if (\$v =~ /[\\r\\n\\0]|\\\\\$/) {
			print STDERR "user \$user: \$attribute value skipped: the list cannot carry it\\n";
			next;
		}
		(my \$q = \$v) =~ s/"/\\\\"/g;
		push \@quoted, '"' . \$q . '"';
	}
	return \@quoted ? join(',', \@quoted) : undef;
}

END { }

1;
EOT

