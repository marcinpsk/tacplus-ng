#!/usr/bin/env perl
# $Id$
#
# mavis_tacplus-ng_ldap2.pl
# (C)2001-2023 Marc Huber <Marc.Huber@web.de>
# All rights reserved.
#
# TACACS+ backend for libmavis_external.so
# Authenticates/authorizes against LDAP, optionally supports password changes.
# Suitable for tac_plus-ng only.
#

=pod

Test input for authentication:
0 TACPLUS
4 $USER
8 $PASS
49 AUTH
=

printf "0 TACPLUS\n4 $USER\n8 $PASS\n49 AUTH\n=\n" | this_script.pl

Test input for password change:
0 TACPLUS
4 $USER
8 $PASS
49 CHPW
50 $NEWPASS
=

printf "0 TACPLUS\n4 $USER\n8 $PASS\n49 CHPW\n50 $NEWPASS\n=\n" | this_script.pl

#######

Environment variables:

LDAP_HOSTS
	Space-separated list of LDAP URLs or IP addresses or hostnames
	Examples: "ldap01 ldap02", "ldaps://ads01:636 ldaps://ads02:636"

LDAP_SCOPE
	LDAP search scope (base, one, sub) for users
	Default: sub

LDAP_SCOPE_GROUP
	LDAP search scope (base, one, sub) for groups
	Default: sub

LDAP_SCOPE_POSIXGROUP
	LDAP search scope (base, one, sub) for POSIX groups
	Default: sub

LDAP_BASE
	Base user search DN of your LDAP server
	Example: "dc=example,dc=com"

LDAP_BASE_GROUP
	Base groupe search DN of your LDAP server, defaults to LDAP_BASE
	Example: "dc=example,dc=com"

LDAP_CONNECT_TIMEOUT
	Timeout for initital connect to remote LDAP server. Default: 1 (second)

LDAP_FILTER
	LDAP search filter
	Defaults depend on LDAP_SERVER_TYPE:
	- generic:	"(&(objectclass=posixaccount)(uid=%s))"
	- microsoft:	"(&(objectclass=user)(sAMAccountName=%s))"

LDAP_FILTER_GROUP
	LDAP group search filter
	Default: "(&(objectclass=groupOfNames)(member=%s))"

LDAP_USER
	User to use for LDAP bind if server doesn't permit anonymous searches.
	Default: unset

LDAP_PASSWD
	Password for LDAP_USER
	Default: unset

LDAP_MEMBEROF_REGEX
	Regular expression to derive group names from memberOf
	Default: "^cn=([^,]+),.*"

LDAP_MEMBEROF_FILTER
	Regular expression to limit memberOf lookups.
	Default: unset

LDAP_TACMEMBER
	LDAP attribute to use for group membership (fallback only).
	Default: "tacMember"

LDAP_TACMEMBER_MAP_OU
	Map organizational units from user DN to group membership.
	Default: unset

LDAP_SKIP_STARTTLS
	0: StartTLS on ldap:// URLs, before any bind. A server without
	   StartTLS or a failed StartTLS is a backend error.
	1: no StartTLS on ldap:// URLs; the binds send the passwords in
	   clear text, and a warning goes to stderr.
	ldaps:// URLs do not use StartTLS. USE_STARTTLS is no longer
	needed, because StartTLS is the default.
	ldapi:// URLs (a local Unix socket) use no TLS and give no
	warning, also with LDAP_SKIP_STARTTLS=0.
	Default: 0

FLAG_FALLTHROUGH
	If LDAP search fails, try next module (if any). Deprecated.
	Default: unset

FLAG_AUTHORIZE_ONLY
	Don't attempt to authenticate users.

TLS_OPTIONS
	Extra options for use with LDAPS or start_tls, in Perl hash syntax.
	See https://metacpan.org/pod/Net::LDAP for details.
	The server certificate is checked ("verify => 'require'") unless
	TLS_OPTIONS sets "verify": it must chain to a trusted CA and match
	the host name of the URL, or "sslserver => 'name'" if set.
	"cafile => '/path/to/ca.pem'" or
	"capath => '/path/to/dir'" names the CA instead of the CAs of the
	system; "verify => 'none'" turns the check off. An invalid value
	stops the back-end.
	Default: unset
	Example: "sslversion => 'tlsv1_2'"

LDAP_NESTED_GROUP_DEPTH
	Limit nested group lookups to the given value. Unlimited if unset.
	Example: 2

LDAP_SKIP_MEMBEROF
LDAP_SKIP_POSIXGROUP
LDAP_SKIP_GROUPOFNAMES
	0: never skip the corresponding LDAP group lookups
	1: always skip
	Default: unset

=cut

use lib '/usr/local/lib/mavis/';

use strict;
use Mavis;

my $LDAP_SERVER_TYPE;
my @LDAP_BIND;
my $LDAP_FILTER;
my $LDAP_FILTER_GROUP 		= "(&(objectclass=groupOfNames)(member=%s))";
my $LDAP_HOSTS			= ['ldaps://localhost'];
my $LDAP_BASE			= 'dc=example,dc=com';
my $LDAP_BASE_GROUP		= undef;
my $LDAP_BASE_POSIXGROUP	= undef;
my $LDAP_CONNECT_TIMEOUT 	= 1;
my $LDAP_SCOPE			= 'sub';
my $LDAP_SCOPE_GROUP		= 'sub';
my $LDAP_SCOPE_POSIXGROUP	= 'sub';
my $LDAP_MEMBEROF_REGEX 	= "^cn=([^,]+),.*";
my $LDAP_MEMBEROF_FILTER 	= undef;
my $LDAP_TACMEMBER		= "tacMember";
my $LDAP_TACMEMBER_MAP_OU	= undef;
my $LDAP_NESTED_GROUP_DEPTH	= undef;
my $LDAP_SKIP_MEMBEROF		= undef;
my $LDAP_SKIP_POSIXGROUP	= undef;
my $LDAP_SKIP_GROUPOFNAMES	= undef;
my $skip_starttls		= 0;
my %tls_options;
my $LDAP_DEBUG_TIME		= undef;

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

@$LDAP_HOSTS		= split /\s+/, $ENV{'LDAP_HOSTS'} if exists $ENV{'LDAP_HOSTS'};
$LDAP_SCOPE		= $ENV{'LDAP_SCOPE'} if exists $ENV{'LDAP_SCOPE'};
$LDAP_BASE		= $ENV{'LDAP_BASE'} if exists $ENV{'LDAP_BASE'};
$LDAP_SCOPE_GROUP	= $LDAP_SCOPE;
$LDAP_BASE_GROUP	= $LDAP_BASE;
$LDAP_BASE_POSIXGROUP	= $LDAP_BASE;
$LDAP_SCOPE_GROUP	= $ENV{'LDAP_SCOPE_GROUP'} if exists $ENV{'LDAP_SCOPE_GROUP'};
$LDAP_SCOPE_POSIXGROUP	= $ENV{'LDAP_SCOPE_POSIXGROUP'} if exists $ENV{'LDAP_SCOPE_POSIXGROUP'};
$LDAP_FILTER_GROUP	= $ENV{'LDAP_FILTER_GROUP'} if exists $ENV{'LDAP_FILTER_GROUP'};
$LDAP_BASE_GROUP	= $ENV{'LDAP_BASE_GROUP'} if exists $ENV{'LDAP_BASE_GROUP'};
$LDAP_BASE_POSIXGROUP	= $ENV{'LDAP_BASE_POSIXGROUP'} if exists $ENV{'LDAP_BASE_POSIXGROUP'};
$LDAP_FILTER		= $ENV{'LDAP_FILTER'} if exists $ENV{'LDAP_FILTER'};
$LDAP_CONNECT_TIMEOUT	= $ENV{'LDAP_CONNECT_TIMEOUT'} if exists $ENV{'LDAP_CONNECT_TIMEOUT'};
@LDAP_BIND		= ($ENV{'LDAP_USER'}, password => $ENV{'LDAP_PASSWD'}) if (exists $ENV{'LDAP_USER'} && exists $ENV{'LDAP_PASSWD'});
if (exists $ENV{'LDAP_SKIP_STARTTLS'}) {
	die "invalid LDAP_SKIP_STARTTLS: '$ENV{'LDAP_SKIP_STARTTLS'}' (0 or 1)\n" unless $ENV{'LDAP_SKIP_STARTTLS'} =~ /^[01]\z/;
	$skip_starttls = $ENV{'LDAP_SKIP_STARTTLS'};
}
$LDAP_MEMBEROF_REGEX	= $ENV{'LDAP_MEMBEROF_REGEX'} if exists $ENV{'LDAP_MEMBEROF_REGEX'};
$LDAP_MEMBEROF_FILTER	= $ENV{'LDAP_MEMBEROF_FILTER'} if exists $ENV{'LDAP_MEMBEROF_FILTER'};
$LDAP_TACMEMBER		= $ENV{'LDAP_TACMEMBER'} if exists $ENV{'LDAP_TACMEMBER'};
$LDAP_TACMEMBER_MAP_OU	= $ENV{'LDAP_TACMEMBER_MAP_OU'} if exists $ENV{'LDAP_TACMEMBER_MAP_OU'};
$LDAP_NESTED_GROUP_DEPTH	= $ENV{'LDAP_NESTED_GROUP_DEPTH'} if exists $ENV{'LDAP_NESTED_GROUP_DEPTH'};

$LDAP_SKIP_MEMBEROF	= $ENV{'LDAP_SKIP_MEMBEROF'} if exists $ENV{'LDAP_SKIP_MEMBEROF'};
$LDAP_SKIP_POSIXGROUP	= $ENV{'LDAP_SKIP_POSIXGROUP'} if exists $ENV{'LDAP_SKIP_POSIXGROUP'};

$LDAP_SKIP_GROUPOFNAMES	= $ENV{'LDAP_SKIP_GROUPOFNAMES'} if exists $ENV{'LDAP_SKIP_GROUPOFNAMES'};
$LDAP_DEBUG_TIME	= $ENV{'LDAP_DEBUG_TIME'} if exists $ENV{'LDAP_DEBUG_TIME'};

use Net::LDAP qw(LDAP_INVALID_CREDENTIALS LDAP_CONSTRAINT_VIOLATION);
use Net::LDAP::Constant qw(LDAP_EXTENSION_PASSWORD_MODIFY LDAP_CAP_ACTIVE_DIRECTORY);
use Net::LDAP::Extension::SetPassword;
use Net::LDAP::Extra qw(AD);
use Net::LDAP::Util qw(escape_filter_value);
use IO::Socket::SSL;
use Time::Local 'timegm';
use Time::HiRes qw(gettimeofday tv_interval);
use Socket qw(SOL_SOCKET SO_KEEPALIVE);

$| = 1;

my $in;
my $has_extension_password_modify;

$/ = "\n=\n";

my $ldap = undef;

my @V;

sub expand_groupOfNames($) {
	sub expand_groupOfNames_sub($$$) {
		my $depth = $_[2];
		return if defined($LDAP_NESTED_GROUP_DEPTH) && $LDAP_NESTED_GROUP_DEPTH <= $depth;

		sub get_groupOfNames($$) {
			my ($dn, $H) = @_;
			my @res = ( );
			my $mesg = $ldap->search(base => $LDAP_BASE_GROUP, scope=>$LDAP_SCOPE_GROUP, filter=>sprintf($LDAP_FILTER_GROUP, escape_filter_value($dn)), attrs=>['memberOf']);
			if ($mesg->code){
				$V[AV_A_USER_RESPONSE] = $mesg->error . " (" . __LINE__ . ")";
				goto fatal;
			}
			foreach my $entry ($mesg->entries) {
				push @res, $entry->dn unless exists $H->{$entry->dn};
			}
			return @res;
		}
		sub expand_groupOfNames_sub($$$);

		my $H = $_[1];
		foreach my $g (get_groupOfNames($_[0], $H)) {
			unless (exists $H->{$g}) {
				$H->{$g} = 1;
				expand_groupOfNames_sub($g, $H, $depth + 1);
			}
		}
	}
	my %H;
	expand_groupOfNames_sub($_[0], \%H, 0);
	my @res = sort keys %H;
	return \@res;
}

sub expand_memberof($) {
	sub expand_memberof_sub($$$) {
		my $depth = $_[2];
		sub get_memberof($) {
			my $mesg = $ldap->search(base => $_[0], scope=>'base', filter=>'(objectclass=*)', attrs=>['memberOf']);
			if ($mesg->code){
				$V[AV_A_USER_RESPONSE] = $mesg->error . " (" . __LINE__ . ")";
				goto fatal;
			}
			my $entry = $mesg->entry(0);
			return $entry->get_value('memberOf', asref => 1) if $entry;
			return [ ];
		}
		sub expand_memberof_sub($$$);

		return if defined($LDAP_NESTED_GROUP_DEPTH) && $LDAP_NESTED_GROUP_DEPTH <= $depth;
		my ($a, $H) = @_;
		foreach my $m (@$a) {
			next if defined $LDAP_MEMBEROF_FILTER && $m !~ /$LDAP_MEMBEROF_FILTER/i;
			unless (exists $H->{$m}) {
				$H->{$m} = 1;
				my $g = get_memberof($m);
				expand_memberof_sub($g, $H, $depth + 1);
			}
		}
	}

	my %H;
	expand_memberof_sub($_[0], \%H, 0);
	my @res = sort keys %H;
	return \@res;
}

my $debug_timer;
my $debug_title = "";

sub debug_timer_start($)
{
	return unless $LDAP_DEBUG_TIME;
	$debug_title = $_[0];
	$debug_timer = [gettimeofday];
}

sub debug_timer_stop()
{
	return unless $LDAP_DEBUG_TIME;
	my $line;
	(undef, undef, $line) = caller;
	print STDERR $debug_title , " ($line): " , tv_interval($debug_timer, [gettimeofday]), "\n";
}

use Time::Local;
my @now = localtime(time);

my %gidHash; # cache gidNumber-to-cn mapping

while ($in = <>) {
	my ($a, $result);

	@V = ();
	$result = MAVIS_DEFERRED;

	chomp $in;

	foreach $a (split (/\n/, $in)) {
		next unless $a =~ /^(\d+) (.*)$/;
		$V[$1] = $2;
	}

	if (defined $V[AV_A_TYPE] && $V[AV_A_TYPE] ne AV_V_TYPE_TACPLUS) {
		$result = MAVIS_DOWN;
		goto bye;
	}
	if (!defined $V[AV_A_USER]){
		$V[AV_A_USER_RESPONSE] = "User not set.";
		goto fatal;
	}
	if ($V[AV_A_USER] =~ /\(|\)|,|\||&|=|\*/){
		$V[AV_A_USER_RESPONSE] = "Username not valid.";
		goto fail;
	}
	if ($V[AV_A_TACTYPE] eq AV_V_TACTYPE_AUTH && !defined $V[AV_A_PASSWORD]){
		$V[AV_A_USER_RESPONSE] = "Password not set.";
		goto fatal;
	}
	if ($V[AV_A_TACTYPE] eq AV_V_TACTYPE_CHPW && (!defined $V[AV_A_PASSWORD]||!defined $V[AV_A_PASSWORD_NEW])){
		$V[AV_A_USER_RESPONSE] = "Old or new password not set";
		goto fatal;
	}

	if ($ldap) {
# Cached LDAP connection still available?
		my $sock = $ldap->socket();
		if ($sock) {
			my ($rin, $ein) = (0, 0);
			vec($rin, fileno($sock), 1) = 1;
			vec($ein, fileno($sock), 1) = 1;
			if (0 < select($rin, undef, $ein, 0)) {
				printf STDERR "ldap connection detected dead (" . __LINE__ . ")\n";
				$ldap->unbind;
				$ldap->disconnect;
				$ldap = undef;
			}
		} else {
			printf STDERR "ldap connection dead (" . __LINE__ . ")\n";
			$ldap->unbind;
			$ldap->disconnect;
			$ldap = undef;
		}
	}

	my $retry;
	$retry = $ldap ? 1 : undef;

retry_once:

	unless ($ldap) {
		debug_timer_start("ldap init");
		$ldap = ldap_connect($LDAP_HOSTS, timeout=>$LDAP_CONNECT_TIMEOUT);
		unless ($ldap) {
			$V[AV_A_USER_RESPONSE] = "No answer from LDAP backend.";
			goto fatal;
		}
		my $sock = $ldap->socket();
		setsockopt($sock, SOL_SOCKET, SO_KEEPALIVE, 1);
		if ($ldap->scheme eq 'ldap' && $skip_starttls) {
			print STDERR "the connection to the LDAP server has no TLS: the binds send the passwords in clear text\n";
		} elsif ($ldap->scheme eq 'ldap') {
			my $error = start_tls_error($ldap);
			if (defined $error) {
				print STDERR "StartTLS: $error\n";
				$V[AV_A_USER_RESPONSE] = "TLS negotiation failed.";
				debug_timer_stop;
				# the socket is plain TCP again: do not use it for the next request
				$ldap->disconnect;
				$ldap = undef;
				goto fatal;
			}
		}
		my $mesg = $ldap->bind(@LDAP_BIND);
		if ($mesg->code){
			$V[AV_A_USER_RESPONSE] = $mesg->error . " (" . __LINE__ . ")";
			debug_timer_stop;
			goto fatal;
		}
		unless (defined $LDAP_SERVER_TYPE) {
			# before root_dse(): is_AD() reuses its cached root DSE, which has no supportedCapabilities
			if ($ldap->is_AD() || $ldap->is_ADAM()) {
				$LDAP_SERVER_TYPE = "microsoft";
				$LDAP_FILTER = '(&(objectclass=user)(sAMAccountName=%s))' unless defined $LDAP_FILTER;
				$LDAP_SKIP_POSIXGROUP = "1" unless defined $LDAP_SKIP_POSIXGROUP;
				$LDAP_SKIP_GROUPOFNAMES = "1" unless defined $LDAP_SKIP_GROUPOFNAMES;
			} else {
				$LDAP_SERVER_TYPE = "generic";
				$LDAP_FILTER = '(&(objectclass=posixAccount)(uid=%s))' unless defined $LDAP_FILTER;
			}
		}
		my $root_dse = $ldap->root_dse;
		# the server can refuse the root DSE to LDAP_USER: the generic type, as in ldapmavis-mt
		printf STDERR "no root DSE: the LDAP server type is generic\n" unless $root_dse;
		my $vendor = $root_dse ? $root_dse->get_value('vendorname') : undef;
		if (defined($vendor) && $vendor =~ /389 Project/ && $#LDAP_BIND < 0) {
			printf STDERR "The 389 directory server will not return the memberOf attribute for anonymous binds. " .
				      "Please set the LDAP_USER and LDAP_PASSWD environment variables.\n";
		}
		debug_timer_stop;
	}

	my $authdn = undef;
	debug_timer_start("ldap bind");
	my $mesg = $ldap->bind(@LDAP_BIND);
	if ($mesg->code && defined($retry)) {
		$retry = undef;
		$ldap->unbind;
		$ldap->disconnect;
		$ldap = undef;
		printf STDERR "ldap retry, due to bind failure (" . __LINE__ . ")\n";
		goto retry_once;
	}
	debug_timer_stop;
	if ($mesg->code){
		$V[AV_A_USER_RESPONSE] = $mesg->error . " (" . __LINE__ . ")";
		goto fatal;
	}
	unless (defined $has_extension_password_modify) {
		my $root_dse = $ldap->root_dse;
		$has_extension_password_modify = $root_dse ? $root_dse->supported_extension(LDAP_EXTENSION_PASSWORD_MODIFY) : 0;
	}
	debug_timer_start("ldap search");
	$mesg = $ldap->search(base => $LDAP_BASE, filter => sprintf($LDAP_FILTER, escape_filter_value($V[AV_A_USER])), scope => $LDAP_SCOPE,
		attrs => ['shadowExpire','memberOf','dn', 'uidNumber', 'gidNumber', 'loginShell', 'homeDirectory', 'sshPublicKey',
			  'krbPasswordExpiration', $LDAP_TACMEMBER]);
	debug_timer_stop;
	if ($mesg->count() == 1) {
		my $entry = $mesg->entry(0);

		my $val = [ ];
		$val = $entry->get_value('memberOf', asref => 1) unless defined $LDAP_SKIP_MEMBEROF && $LDAP_SKIP_MEMBEROF eq "1";
		$authdn = $entry->dn;
		my (@M, @MO);
		if ($#{$val} > -1) {
			$LDAP_SKIP_GROUPOFNAMES = "1" unless defined $LDAP_SKIP_GROUPOFNAMES;
			debug_timer_start("ldap expand memberOf");
			$val = expand_memberof($val) unless defined $LDAP_SKIP_MEMBEROF && $LDAP_SKIP_MEMBEROF eq "1";
			debug_timer_stop;
		} else {
			debug_timer_start("ldap expand groupOfNames");
			$val = expand_groupOfNames($entry->dn) unless defined $LDAP_SKIP_GROUPOFNAMES && $LDAP_SKIP_GROUPOFNAMES eq "1";
			debug_timer_stop;
		}
		foreach my $m (sort @$val) {
			if ($m =~ /$LDAP_MEMBEROF_REGEX/i) {
				push @M, $1;
				push @MO, $m;
			}
		}
		$V[AV_A_DN] = $authdn;
		$V[AV_A_UID] = $val if $val = $entry->get_value('uidNumber');
		$V[AV_A_SHELL] = $val if $val = $entry->get_value('loginShell');
		$V[AV_A_HOME] = $val if $val = $entry->get_value('homeDirectory');
		$val = $entry->get_value('sshPublicKey', asref => 1);
		$V[AV_A_SSHKEY] = '"' . join('","', @$val) . '"' if $val;

		my $authdn = $mesg->entry(0)->dn;

		$val = $entry->get_value($LDAP_TACMEMBER, asref => 1);
		push @M, @$val if $val;

		if (defined $LDAP_TACMEMBER_MAP_OU) {
			for my $ou (split(/,/, $authdn)) {
				push @M, $1 if $ou =~ /^ou=(.+)$/i;
			}
		}

		my $gidNumber = $entry->get_value('gidNumber');
		$V[AV_A_GID] = $gidNumber if defined $gidNumber;
		if (defined $gidNumber && (!defined $LDAP_SKIP_POSIXGROUP || $LDAP_SKIP_POSIXGROUP ne "1")) {
			my @G = ($gidNumber);
			unless (exists $gidHash{$gidNumber}) {
				debug_timer_start("ldap gidNumber");
				$mesg = $ldap->search(base => $LDAP_BASE_POSIXGROUP, scope => $LDAP_SCOPE_POSIXGROUP, attrs => ['cn'],
					filter => sprintf('(&(objectclass=posixGroup)(gidNumber=%s))', escape_filter_value($gidNumber)));
				$gidHash{$gidNumber} = $mesg->entry(0)->get_value('cn') if $mesg->count() == 1;
				debug_timer_stop;
			}
			push @M, $gidHash{$gidNumber} if exists $gidHash{$gidNumber};

			debug_timer_start("ldap gidNumber");
			$mesg = $ldap->search(base => $LDAP_BASE_POSIXGROUP, scope => $LDAP_SCOPE_POSIXGROUP, attrs => ['cn', 'gidNumber'],
				filter => sprintf('(&(objectclass=posixGroup)(memberUid=%s))', escape_filter_value($V[AV_A_USER])));
			debug_timer_stop;
			for (my $i = 0; $i < $mesg->count(); $i++) {
				push @M, $mesg->entry($i)->get_value('cn');
				push @G, $mesg->entry($i)->get_value('gidNumber');
			}
			$V[AV_A_GIDS] = join(',', @G);
		}

		$V[AV_A_TACMEMBER] = '"' . join('","', @M) . '"' if $#M > -1;
		$V[AV_A_MEMBEROF] = '"' . join('","', @MO) . '"' if $#MO > -1;

		if ($V[AV_A_TACTYPE] eq AV_V_TACTYPE_AUTH) {
			my $caller_cap_chpw = exists($V[AV_A_CALLER_CAP]) && $V[AV_A_CALLER_CAP] =~ /:chpw:/;
			my $expiry = undef;
			$val = $entry->get_value('shadowExpire');
			if (defined $val) {
				$expiry = 86400 * $val if $val > -1;
			} else {
				$val = $entry->get_value('krbPasswordExpiration');
				if (defined $val) {
					if ($val =~ /^(\d\d\d\d)(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)Z$/) {
						my $gmt_offset = timelocal(@now) - timegm(@now);
						$expiry = timegm($6, $5, $4, $3, $2 - 1, $1 - 1900);
					}
				}
			}
			if (defined $expiry) {
				if ($expiry < time) {
					$V[AV_A_USER_RESPONSE] = "Password has expired.";
					if ($caller_cap_chpw && $has_extension_password_modify) {
						$V[AV_A_PASSWORD_MUSTCHANGE] = 1;
					} else {
						goto fail;
					}
				} else {
					$V[AV_A_PASSWORD_EXPIRY] = $expiry;
				}
			}
			debug_timer_start("ldap user bind");
			$mesg =  $ldap->bind($authdn, password => $V[AV_A_PASSWORD]);
			debug_timer_stop;
			my $code = $mesg->code;
			my $userresponse = undef;
			if ($code == LDAP_INVALID_CREDENTIALS && $LDAP_SERVER_TYPE eq 'microsoft') {
				my %ad_error_codes = (
					"525" => "Invalid credentials.", # "User not found.", actually
					"52e" => "Invalid credentials.",
					"530" => "Not permitted to logon at this time.",
					"531" => "Not permitted to logon at this workstation.",
					"532" => "Password expired.",
					"533" => "Account disabled.",
					"701" => "Account expired.",
					"773" => "User must reset password.",
					"775" => "User account locked.",
				);
				my $m = $mesg->error;
				$m =~ s/.*DSID-.*, data ([0-9A-Fa-f]+),.*/$1/;
				if($caller_cap_chpw && ($m eq "532" || $m eq "773")) {
					$code = 0;
					$V[AV_A_PASSWORD_MUSTCHANGE] = 1;
				} elsif (exists $ad_error_codes{$m}) {
					$userresponse = $ad_error_codes{$m};
				}
			}
			if ($code) {
				$userresponse = $mesg->error unless defined $userresponse;
				$V[AV_A_USER_RESPONSE] = $userresponse;
				goto fail if $mesg->code == LDAP_INVALID_CREDENTIALS || $mesg->code == LDAP_CONSTRAINT_VIOLATION;
				goto fatal;
			}
			$V[AV_A_RESULT] = AV_V_RESULT_OK;
			$V[AV_A_PASSWORD_ONESHOT] = "1";
		} elsif ($V[AV_A_TACTYPE] eq AV_V_TACTYPE_CHPW){
			if ($LDAP_SERVER_TYPE eq 'microsoft') {
				$mesg = $ldap->change_ADpassword($authdn, $V[AV_A_PASSWORD], $V[AV_A_PASSWORD_NEW]);
			} else {
				unless ($has_extension_password_modify) {
					$V[AV_A_USER_RESPONSE] = "Password change is unsupported.";
					goto fail;
				}
				debug_timer_start("bind chpw");
				$mesg =  $ldap->bind($authdn, password => $V[AV_A_PASSWORD]);
				debug_timer_stop;
				if ($mesg->code) {
					$V[AV_A_USER_RESPONSE] = $mesg->error . " (" . __LINE__ . ")";
					goto fail if ($mesg->code == LDAP_INVALID_CREDENTIALS || $mesg->code == LDAP_CONSTRAINT_VIOLATION);
					goto fatal;
				}

				$mesg = $ldap->set_password(oldpasswd => $V[AV_A_PASSWORD], newpasswd => $V[AV_A_PASSWORD_NEW]);
			}

			if ($mesg->code){
				if ($mesg->error =~ /CONSTRAINT_ATT_TYPE/s) {
					$V[AV_A_USER_RESPONSE] = "Password change rejected by policy.";
				} else {
					$V[AV_A_USER_RESPONSE] = $mesg->error;
				}
				print STDERR "chpw for ", $authdn, ": ", $mesg->error, " (" , __LINE__ , ")", "\n";
				goto fail;
			}
			delete $V[AV_A_PASSWORD_MUSTCHANGE];
			$V[AV_A_USER_RESPONSE] = "Password change was successful.";
			$V[AV_A_PASSWORD_ONESHOT] = "1";
			$V[AV_A_RESULT] = AV_V_RESULT_OK;
		} elsif ($V[AV_A_TACTYPE] eq AV_V_TACTYPE_INFO){
			$V[AV_A_RESULT] = AV_V_RESULT_OK;
		}
		$result = MAVIS_FINAL;
		goto bye;
	} else {
		goto down;
	}

fail:
	$V[AV_A_RESULT] = AV_V_RESULT_FAIL;
	$result = MAVIS_FINAL;
	goto bye;

down:
	$V[AV_A_RESULT] = AV_V_RESULT_NOTFOUND;
	$result = MAVIS_DOWN;
	goto bye;

fatal:
	$result = MAVIS_FINAL;
	$V[AV_A_RESULT] = AV_V_RESULT_ERROR;

bye:
	my ($out) = "";
	for (my $i = 0; $i <= $#V; $i++) {
		if (defined $V[$i]) {
			$V[$i] =~ tr/\n/\r/;
			$V[$i] =~ s/\0//g;
			$out .= sprintf ("%d %s\n", $i, $V[$i]);
		}
	}
	$out .= sprintf ("=%d\n", $result);
	print $out;
}

# vim: ts=4
