#!/usr/bin/env perl
# $Id$
#
# mavis_ldap_authonly.pl
# (C)2001-2010 Marc Huber <Marc.Huber@web.de>
# All rights reserved.
#
# Simple LDAP backend for libmavis_external.so
#

# Test input:
# 4 $USER
# 8 $PASS
# 49 AUTH
# =
#
# E.g.: printf "4 $USER\n8 $PASS\n49 AUTH\n=\n" | this_script.pl
#
# Environment variables: LDAP_HOSTS, LDAP_BASE, LDAP_SCOPE, LDAP_FILTER,
# LDAP_USER, LDAP_PASSWD, FLAG_CACHE_CONNECTION, LDAP_SKIP_STARTTLS and
# TLS_OPTIONS, as in mavis_tacplus-ng_ldap.pl. The server certificate is
# checked unless TLS_OPTIONS sets "verify", e.g. "verify => 'none'".
#

use lib '/usr/local/lib/mavis/';

use strict;
use Mavis;

my $LDAP_HOSTS	= ['ldap03', 'ldap04', 'ldap01', 'ldap02'];
my @LDAP_BIND = ();
my $LDAP_BASE	= 'ou=staff,dc=example,dc=com';
my $LDAP_SCOPE	= 'sub';
my $LDAP_FILTER	= '(uid=%s)';
my $skip_starttls = 0;
my $flag_cacheconn		= undef;
my %tls_options;

$flag_cacheconn			= $ENV{'FLAG_CACHE_CONNECTION'} if exists $ENV{'FLAG_CACHE_CONNECTION'};

if (exists $ENV{'LDAP_HOSTS'}) {
	$LDAP_HOSTS	= [];
	for my $h (split /\s+/, $ENV{'LDAP_HOSTS'}) {
		push @$LDAP_HOSTS, $h;
	}
}

$LDAP_SCOPE = $ENV{'LDAP_SCOPE'} if exists $ENV{'LDAP_SCOPE'};
$LDAP_BASE = $ENV{'LDAP_BASE'} if exists $ENV{'LDAP_BASE'};
$LDAP_FILTER = $ENV{'LDAP_FILTER'} if exists $ENV{'LDAP_FILTER'};
@LDAP_BIND = ($ENV{'LDAP_USER'}, password => $ENV{'LDAP_PASSWD'})
	if (exists $ENV{'LDAP_USER'} && exists $ENV{'LDAP_PASSWD'});
# check the certificate of the server unless TLS_OPTIONS says otherwise, e.g. "verify => 'none'"
if (exists $ENV{'TLS_OPTIONS'}) {
	# no values in the messages (e.g. a key password), also not in a Perl warning
	my @list = do { local $SIG{__WARN__} = sub {}; eval $ENV{'TLS_OPTIONS'} };
	die "invalid TLS_OPTIONS: not a list of Perl key-value pairs\n" if $@ || @list % 2;
	# Net::LDAP takes "-verify" for "verify"
	while (my ($k, $v) = splice @list, 0, 2) {
		$k =~ s/^-//;
		$tls_options{$k} = $v;
	}
}
$tls_options{'verify'} = 'require' unless exists $tls_options{'verify'};
# Net::LDAP takes an unknown verify value as 'none'
die "invalid TLS_OPTIONS: verify is not none, optional or require\n"
	unless defined $tls_options{'verify'} && $tls_options{'verify'} =~ /^(?:none|optional|require)\z/i;

# IO::Socket::SSL checks the name with the brackets of an IPv6 address in the URL: give it the address
sub tls_name($) {
	return $_[0] =~ m{^(?:\w+://)?\[([^\]]*)\]} ? (sslserver => $1) : ();
}

# Net::LDAP->new() for each URL until one answers; IO::Socket::SSL dies for a CA file it cannot read
sub ldap_connect {
	my ($hosts, @args) = @_;
	my $error = "no LDAP server";
	for my $url (ref $hosts ? @$hosts : ($hosts)) {
		my $ldap = eval { Net::LDAP->new($url, @args, tls_name($url), %tls_options) or do { $error = $@; undef } };
		return $ldap if $ldap;
		$error = $@ if $@;
	}
	chomp $error;
	print STDERR "no connection to the LDAP server: $error\n";
	return undef;
}

# StartTLS on $ldap: the error, or undef
sub start_tls_error($) {
	my ($ldap) = @_;
	my $mesg = eval { $ldap->start_tls(tls_name($ldap->host), %tls_options) };
	return $@ =~ s/\n\z//r unless $mesg;
	return $mesg->code ? $mesg->error : undef;
}
# StartTLS on ldap:// URLs unless LDAP_SKIP_STARTTLS=1
if (exists $ENV{'LDAP_SKIP_STARTTLS'}) {
	die "invalid LDAP_SKIP_STARTTLS: '$ENV{'LDAP_SKIP_STARTTLS'}' (0 or 1)\n" unless $ENV{'LDAP_SKIP_STARTTLS'} =~ /^[01]\z/;
	$skip_starttls = $ENV{'LDAP_SKIP_STARTTLS'};
}

use Net::LDAP;
use Net::LDAP qw(LDAP_SUCCESS LDAP_SERVER_DOWN LDAP_TYPE_OR_VALUE_EXISTS
	LDAP_NO_SUCH_ATTRIBUTE LDAP_INVALID_CREDENTIALS LDAP_CONSTRAINT_VIOLATION);

if ((!$skip_starttls || ($ENV{'LDAP_HOSTS'} =~ /ldaps:/))
    && !eval("require IO::Socket::SSL")){
		print STDERR "Warning: IO::Socket::SSL.pm not found. Neither StartTLS nor LDAPS connections will work.\n";
}

$| = 1;

my ($in);

$/ = "\n=\n";

my $ldap = undef;

while ($in = <>) {
	my ($a, @V, $result);

	@V = ();
	$result = MAVIS_DEFERRED;

	chomp $in;

	foreach $a (split (/\n/, $in)) {
		next unless $a =~ /^(\d+) (.*)$/;
		$V[$1] = $2;
	}

	if (!defined $V[AV_A_USER]){
		$V[AV_A_USER_RESPONSE] = "User not set.";
		goto fatal;
	}
	if ($V[AV_A_USER] =~ /\(|\)|,|\||&|\*/){
		$V[AV_A_USER_RESPONSE] = "Username not valid.";
		$V[AV_A_RESULT] = AV_V_RESULT_FAIL;
		$result = MAVIS_FINAL;
		goto bye;
	}
	if (!defined $V[AV_A_PASSWORD]){
		$result = MAVIS_DOWN;
		goto bye;
	}

	if ($ldap) {
		# Cached LDAP connection still available?
		my $sock = $ldap->socket();
		if ($sock) {
			my ($rin, $ein) = (0, 0);
			vec($rin, fileno($sock), 1) = 1;
			vec($ein, fileno($sock), 1) = 1;
			if (0 < select($rin, undef, $ein, 0)) {
				$ldap->unbind;
				$ldap->disconnect;
				$ldap = undef;
			}
		} else {
			$ldap->unbind;
			$ldap->disconnect;
			$ldap = undef;
		}
	}

	my $retry;
	$retry = $ldap ? 1 : undef;

  retry_once:

	unless ($ldap) {
		$ldap = ldap_connect($LDAP_HOSTS);
		unless ($ldap) {
			$V[AV_A_USER_RESPONSE] = "No answer from LDAP backend.";
			$V[AV_A_RESULT] = AV_V_RESULT_ERROR;
			$result = MAVIS_FINAL;
			goto bye;
		}
		if ($ldap->scheme eq 'ldap' && $skip_starttls) {
			print STDERR "the connection to the LDAP server has no TLS: the binds send the passwords in clear text\n";
		} elsif ($ldap->scheme eq 'ldap') {
			my $error = start_tls_error($ldap);
			if (defined $error) {
				print STDERR "StartTLS: $error\n";
				$V[AV_A_USER_RESPONSE] = "TLS negotiation failed.";
				goto fatal;
			}
		}
	}
	my $authdn = undef;
	my $mesg = $ldap->bind(@LDAP_BIND);
	if ($mesg->code && defined($retry)) {
		$retry = undef;
		$ldap->unbind;
		$ldap->disconnect;
		$ldap = undef;
		goto retry_once;
	}
	if ($mesg->code){
		$V[AV_A_USER_RESPONSE] = $mesg->error;
		goto fatal;
	}
	$mesg = $ldap->search(base=> $LDAP_BASE, filter => sprintf ($LDAP_FILTER, $V[AV_A_USER]),
						  scope => $LDAP_SCOPE, attrs => ['1.1']);
	if ($mesg->code){
		$V[AV_A_USER_RESPONSE] = $mesg->error;
		goto fatal;
	}
	foreach my $entry ($mesg->entries){
		$authdn = $entry->dn if (!defined $authdn) ||
			(length $entry->dn < length $authdn);
	}
	if ($authdn){
		my $mesg =  $ldap->bind($authdn, password =>
					$V[AV_A_PASSWORD]);
		if ($mesg->code) {
			$V[AV_A_USER_RESPONSE] = $mesg->error;
			$V[AV_A_RESULT] = AV_V_RESULT_ERROR;
			$V[AV_A_RESULT] = AV_V_RESULT_FAIL
				if ($mesg->code == LDAP_INVALID_CREDENTIALS || $mesg->code == LDAP_CONSTRAINT_VIOLATION);
			$result = MAVIS_FINAL;
			$ldap->unbind;
			$ldap->disconnect;
			$ldap = undef;
			goto bye;
		}

		$V[AV_A_DBPASSWORD] = $V[AV_A_PASSWORD];

		$V[AV_A_RESULT] = AV_V_RESULT_OK;
		$result = MAVIS_DOWN;
	} else {
		$V[AV_A_RESULT] = AV_V_RESULT_NOTFOUND;
		$result = MAVIS_DOWN;
	}

	goto bye;

fatal:
	$result = MAVIS_FINAL;
	$V[AV_A_RESULT] = AV_V_RESULT_ERROR;
	if (defined $ldap) {
		$ldap->unbind;
		$ldap->disconnect;
		$ldap = undef;
	}

bye:
	if (!defined($flag_cacheconn) && defined($ldap)) {
		$ldap->unbind;
		$ldap->disconnect;
		$ldap = undef;
	}
	my ($out) = "";
	for (my $i = 0; $i <= $#V; $i++) {
		$out .= sprintf ("%d %s\n", $i, $V[$i]) if defined $V[$i];
	}
	$out .= sprintf ("=%d\n", $result);
	print $out;
}

# vim: ts=4
