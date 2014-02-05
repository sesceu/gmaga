#!/usr/bin/perl -w
#
#   This code is based on smtpprox, by Bennett Todd, as found at
#                http://bent.latency.net/smtpprox/
#   as well as the content filter of Jonathan Hitchcock, as found at
#                Jonathan Hitchcock.
#
#   It is distributed according to the terms of the GNU Public License as
#   found at <URL:http://www.fsf.org/copyleft/gpl.html>.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
# Written by Sebastian Schneider <mail@doc-network.de>
#
# Settings can be edited below.  The configuration file specified
# can be used instead of (or in addition to) passing options on the
# command line.  It simply consists of lines like:
#   children = 4
# where the keyword is the command-line option.
#
# When run, the script creates a .pid file in /var/run, which can
# be used by a shutdown script - the script will respond to a
# SIGTERM by killing all its children and shutting down.
#
# In other words, a startup/shutdown script could be as simple as
# the following, if a config file has been made:
#
#PROGNAME=proxfilter
#case "$1" in
#	start)
#		/var/spool/filter/$PROGNAME
#	;;
#	stop)
#		if [ ! -e /var/run/$PROGNAME.pid ] ; then
#			echo "$PROGNAME not running"
#		else
#			kill `cat /var/run/$PROGNAME.pid`
#		fi
#		echo
#	;;
#	restart)
#		$0 stop
#		$0 start
#	;;
#esac

use strict;

################################################################################
package GMaGa::Server;

#   Originally known as MSDW::SMTP::Server
#
#   This code is Copyright (C) 2001 Morgan Stanley Dean Witter, and
#   is distributed according to the terms of the GNU Public License
#   as found at <URL:http://www.fsf.org/copyleft/gpl.html>.
#
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
# Written by Bennett Todd <bet@rahul.net>

use IO::Socket;
use IO::File;

=head1 NAME

  MSDW::SMTP::Server --- SMTP server for content-scanning proxy

=head1 SYNOPSIS

  use MSDW::SMTP::Server;

  my $server = MSDW::SMTP::Server->new(interface => $interface,
				       port => $port);
  while (1) {
    # prefork here
    $server->accept([options]);
    # per-connect fork here
    $server->ok("220 howdy");
    while (my $what = $server->chat) {
      if ($what =~ /^mail/i) {
	if (isgood($server->{from})) {
	  $server->ok([ ack msg ]);
	} else {
	  $server->fail([ fail msg ]);
	}
      } elsif ($what =~ /^rcpt/i) {
	if (isgood(@{$server}{qw(from to)})) {
	  $sever->ok([ ack msg ]);
	} else {
	  $server->fail([ fail msg ]);
	}
      } elsif ($what =~ /^data/i) {
	if (isgood(@{$server}{qw(from to)})) {
	  # NB to is now an array of all recipients
	  $self->ok("354 natter on.");
	} else {
	  $self->fail;
	}
      } elsif ($what eq '.') {
        if (isgood(@server->{from,to,data})) {
	  $server->ok;
	} else {
	  $server->fail;
	}
      } else {
        # deal with other msg types as you will
	die "can't happen";
      }
      # process $server->{from,to,data} here
      $server->ok; # or $server->fail;
    }
  }

=head1 DESCRIPTION

MSDW::SMTP::Server fills a gap in the available range of Perl SMTP
servers. The existing candidates are not suitable for a
high-performance, content-scanning robust SMTP proxy. They insist on
heavy-weight structuring and parsing of the body, and they
acknowledge receipt of the data before returning control to the
caller.

This server simply gathers the SMTP acquired information (envelope
sender and recipient, and data) into unparsed memory buffers (or a
file for the data), and returns control to the caller to explicitly
acknowlege each command or request. Since acknowlegement or failure
are driven explicitly from the caller, this module can be used to
create a robust SMTP content scanning proxy, transparent or not as
desired.

=head1 METHODS

=over 8

=item new(interface => $interface, port => $port);

The interface and port to listen on must be specified. The interface
must be a valid numeric IP address (0.0.0.0 to listen on all
interfaces, as usual); the port must be numeric. If this call
succeeds, it returns a server structure with an open
IO::Socket::INET in it, ready to listen on. If it fails it dies, so
if you want anything other than an exit with an explanatory error
message, wrap the constructor call in an eval block and pull the
error out of $@ as usual. This is also the case for all other
methods; they succeed or they die.

=item accept([debug => FD]);

accept takes optional args and returns nothing. If an error occurs
it dies, otherwise it returns when a client connects to this server.
This is factored out as a separate entry point to allow preforking
(e.g. Apache-style) or fork-per-client strategies to be implemented
on the common protocol core. If a filehandle is passed for debugging
it will receive a complete trace of the entire SMTP dialogue, data
and all. Note that nothing in this module sends anything to the
client, including the initial login banner; all such backtalk must
come from the calling program.

=item chat;

The chat method carries the SMTP dialogue up to the point where any
acknowlegement must be made. If chat returns true, then its return
value is the previous SMTP command. If the return value begins with
'mail' (case insensitive), then the attribute 'from' has been filled
in, and may be checked; if the return value begins with 'rcpt' then
both from and to have been been filled in with scalars, and should
be checked, then either 'ok' or 'fail' should be called to accept
or reject the given sender/recipient pair. If the return value is
'data', then the attributes from and to are populated; in this case,
the 'to' attribute is a reference to an anonymous array containing
all the recipients for this data. If the return value is '.', then
the 'data' attribute (which may be pre-populated in the "new" or
"accept" methods if desired) is a reference to a filehandle; if it's
created automatically by this module it will point to an unlinked
tmp file in /tmp. If chat returns false, the SMTP dialogue has been
completed and the socket closed; this server is ready to exit or to
accept again, as appropriate for the server style.

The return value from chat is also remembered inside the server
structure in the "state" attribute.

=item ok([message]);

Approves of the data given to date, either the recipient or the
data, in the context of the sender [and, for data, recipients]
already given and available as attributes. If a message is given, it
will be sent instead of the internal default.

=item fail([message]);

Rejects the current info; if processing from, rejects the sender; if
processing 'to', rejects the current recipient; if processing data,
rejects the entire message. If a message is specified it means the
exact same thing as "ok" --- simply send that message to the sender.

=back

=cut

sub new {
    my ( $this, @opts ) = @_;
    my $class = ref($this) || $this;
    my $self = bless {@opts}, $class;
    $self->{sock} = IO::Socket::INET->new(
        LocalAddr => $self->{interface},
        LocalPort => $self->{port},
        Proto     => 'tcp',
        Type      => SOCK_STREAM,
        Listen    => 65536,
        Reuse     => 1,
    );
    die "$0: socket bind failure: $!\n" unless defined $self->{sock};
    $self->{state} = 'just bound', return $self;
}

sub accept {
    my ( $self, @opts ) = @_;
    %$self = ( %$self, @opts );
    ( $self->{"s"}, $self->{peeraddr} ) = $self->{sock}->accept
      or die "$0: accept failure: $!\n";
    $self->{state} = ' accepted';
}

sub chat {
    my ($self) = @_;
    local (*_);
    if ( $self->{state} !~ /^data/i ) {
        return 0 unless defined( $_ = $self->getline );
        s/[\r\n]*$//;
        $self->{state} = $_;
        if (s/^helo\s+//i) {
            s/\s*$//;
            s/\s+/ /g;
            $self->{helo} = $_;
        }
        elsif (s/^rset\s*//i) {
            delete $self->{to};
            delete $self->{data};
            delete $self->{recipients};
        }
        elsif (s/^mail\s+from:\s*//i) {
            delete $self->{to};
            delete $self->{data};
            delete $self->{recipients};
            s/\s*$//;
            $self->{from} = $_;
        }
        elsif (s/^rcpt\s+to:\s*//i) {
            s/\s*$//;
            s/\s+/ /g;
            $self->{to} = $_;
            push @{ $self->{recipients} }, $_;
        }
        elsif (/^data/i) {
            $self->{to} = $self->{recipients};
        }
    }
    else {
        if ( defined( $self->{data} ) ) {
            $self->{data}->seek( 0, 0 );
            $self->{data}->truncate(0);
        }
        else {
            $self->{data} = IO::File->new_tmpfile;
        }
        while ( defined( $_ = $self->getline ) ) {
            if ( $_ eq ".\r\n" ) {
                $self->{data}->seek( 0, 0 );
                return $self->{state} = '.';
            }
            s/^\.\./\./;
            $self->{data}->print($_) or die "$0: write error saving data\n";
        }
        return (0);
    }
    return $self->{state};
}

sub getline {
    my ($self) = @_;
    local ($/) = "\r\n";
    return $self->{"s"}->getline unless defined $self->{debug};
    my $tmp = $self->{"s"}->getline;
    $self->{debug}->print($tmp) if ($tmp);
    return $tmp;
}

sub print {
    my ( $self, @msg ) = @_;
    $self->{debug}->print(@msg) if defined $self->{debug};
    $self->{"s"}->print(@msg);
}

sub ok {
    my ( $self, @msg ) = @_;
    @msg = ("250 ok.") unless @msg;
    $self->print("@msg\r\n")
      or die "$0: write error acknowledging $self->{state}: $!\n";
}

sub fail {
    my ( $self, @msg ) = @_;
    @msg = ("550 no.") unless @msg;
    $self->print("@msg\r\n")
      or die "$0: write error acknowledging $self->{state}: $!\n";
}

1;

################################################################################
package GMaGa::Client;

#   Originally known as MSDW::SMTP::Client
#
#   This code is Copyright (C) 2001 Morgan Stanley Dean Witter, and
#   is distributed according to the terms of the GNU Public License
#   as found at <URL:http://www.fsf.org/copyleft/gpl.html>.
#
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
# Written by Bennett Todd <bet@rahul.net>

use IO::Socket;

=head1 NAME

  MSDW::SMTP::Client --- SMTP client for content-scanning proxy

=head1 SYNOPSIS

  use MSDW::SMTP::Client;

  my $client = MSDW::SMTP::Client->new(interface => $interface,
				       port => $port);
  my %response;
  $response{banner} = $client->hear;
  $client->say("helo bunky");
  $response{helo} = $client->hear;
  $client->say("mail from: me");
  $response{from} = $client->hear;
  $client->say("rcpt to: you");
  $response{to} = $client->hear;
  $client->say("data");
  $response{data} = $client->hear;
  $client->yammer(FILEHANDLE);
  $response{dot} = $client->hear;
  $client->say("quit");
  $response{quit} = $client->hear;
  undef $client;

=head1 DESCRIPTION

MSDW::SMTP::Client provides a very lean SMTP client implementation;
the only protocol-specific knowlege it has is the structure of SMTP
multiline responses. All specifics lie in the hands of the calling
program; this makes it appropriate for a semi-transparent SMTP
proxy, passing commands between a talker and a listener.

=head1 METHODS

=over 8

=item new(interface => $interface, port => $port[, timeout = 300]);

The interface and port to talk to must be specified. The interface
must be a valid numeric IP address; the port must be numeric. If
this call succeeds, it returns a client structure with an open
IO::Socket::INET in it, ready to talk to. If it fails it dies,
so if you want anything other than an exit with an explanatory
error message, wrap the constructor call in an eval block and pull
the error out of $@ as usual. This is also the case for all other
methods; they succeed or they die. The timeout parameter is passed
on into the IO::Socket::INET constructor.

=item hear

hear collects a complete SMTP response and returns it with trailing
CRLF removed; for multi-line responses, intermediate CRLFs are left
intact. Returns undef if EOF is seen before a complete reply is
collected.

=item say("command text")

say sends an SMTP command, appending CRLF.

=item yammer(FILEHANDLE)

yammer takes a filehandle (which should be positioned at the
beginning of the file, remember to $fh->seek(0,0) if you've just
written it) and sends its contents as the contents of DATA. This
should only be invoked after a $client->say("data") and a
$client->hear to collect the reply to the data command. It will send
the trailing "." as well. It will perform leading-dot-doubling in
accordance with the SMTP protocol spec, where "leading dot" is
defined in terms of CR-LF terminated lines --- i.e. the data should
contain CR-LF data without the leading-dot-quoting. The filehandle
will be left at EOF.

=back

=cut

sub new {
    my ( $this, @opts ) = @_;
    my $class = ref($this) || $this;
    my $self = bless { timeout => 300, @opts }, $class;
    $self->{sock} = IO::Socket::INET->new(
        PeerAddr => $self->{interface},
        PeerPort => $self->{port},
        Timeout  => $self->{timeout},
        Proto    => 'tcp',
        Type     => SOCK_STREAM,
    );
    die "$0: socket connect failure: $!\n" unless defined $self->{sock};
    return $self;
}

sub hear {
    my ($self) = @_;
    my ( $tmp, $reply );
    return undef unless $tmp = $self->{sock}->getline;
    while ( $tmp =~ /^\d{3}-/ ) {
        $reply .= $tmp;
        return undef unless $tmp = $self->{sock}->getline;
    }
    $reply .= $tmp;
    $reply =~ s/\r\n$//;
    return $reply;
}

sub say {
    my ( $self, @msg ) = @_;
    return unless @msg;
    $self->{sock}->print( "@msg", "\r\n" ) or die "$0: write error: $!";
}

sub yammer {
    my ( $self, $fh ) = (@_);
    local (*_);
    local ($/) = "\r\n";
    while (<$fh>) {
        s/^\./../;
        $self->{sock}->print($_) or die "$0: write error: $!\n";
    }
    $self->{sock}->print(".\r\n") or die "$0: write error: $!\n";
}

1;

################################################################################
package GMaGa::Client;

use Getopt::Long;
use IO::File;
use lib '.';
use POSIX;
use Mail::GnuPG;
use MIME::Parser;

use File::Basename qw/dirname/;

use lib dirname($0);

BEGIN {
    import GMaGa::Server;
    import GMaGa::Client;
}

############################
# Settings
############################

my $children    = 4;
my $minperchild = 100;
my $maxperchild = 200;
my $debugtrace  = undef;
my $listen      = undef;
my $talk        = undef;
my $progname    = "gmaga";
my $debugdir    = "/tmp";
my $pidfile     = "/var/run/$progname.pid";

my $configfile = "/etc/$progname.conf";

my $gmagaheaderpassed       = "X-GMaGa: Message passed GMaGa (testing)";
my $gmagaheaderdecrypted    = "X-GMaGa: Message decrypted";
my $gmagaheadernotencrypted = "X-GMaGa: Message wasn't encrypted";
my $gmagaheadermissingkey   = "X-GMaGa: Missing key for decryption";

############################
# Arguments
############################

my $syntax =
    "syntax: $0 [--children=$children] [--minperchild=$minperchild] "
  . "[--maxperchild=$maxperchild] [--debugtrace=undef] "
  . "--listen=listen.addr:port --talk=talk.addr:port\n";

if ( -e $configfile ) {
    open CFG, $configfile;
    while (<CFG>) {
        if (m/^\s*(\S+)\s*=\s*(\S+)\s*$/) {
            my ( $key, $val ) = ( lc($1), $2 );
            if ( $key eq "children" )    { $children    = $val; }
            if ( $key eq "minperchild" ) { $minperchild = $val; }
            if ( $key eq "maxperchild" ) { $maxperchild = $val; }
            if ( $key eq "debugtrace" )  { $debugtrace  = $val; }
            if ( $key eq "listen" )      { $listen      = $val; }
            if ( $key eq "talk" )        { $talk        = $val; }
            if ( $key eq "pidfile" )     { $pidfile     = $val; }
        }
    }
}
GetOptions(
    "children=n"    => \$children,
    "minperchild=n" => \$minperchild,
    "maxperchild=n" => \$maxperchild,
    "debugtrace=s"  => \$debugtrace,
    "listen=s"      => \$listen,
    "talk=s"        => \$talk,
    "pidfile=s"     => \$pidfile
) or die $syntax;

die $syntax unless ( $listen and $talk );
my ( $srcaddr, $srcport ) = split /:/, $listen;
my ( $dstaddr, $dstport ) = split /:/, $talk;
die $syntax unless defined($srcport) and defined($dstport);

############################
# Daemonize
############################

my $i = fork();
if ( !defined $i ) { die "Fork"; }
if ( $i > 0 )      { exit(0); }
setsid();

############################
# Server
############################

my $server = GMaGa::Server->new( interface => $srcaddr, port => $srcport );

# This should allow a kill on the parent to also blow away the
# children, I hope
my %children;
my $isparent = 1;
use vars qw($please_die);
$please_die = 0;
$SIG{TERM} = sub { $please_die = 1; kill 15, keys %children if ($isparent); };

open PID, "> $pidfile";
print PID $$;
close PID;

# close our streams
close STDIN;
close STDOUT;
close STDERR;
open STDIN, "/dev/null";
if ( defined $debugtrace ) {
    open STDOUT, ">$debugdir/$progname.parent.out.$$";
    open STDERR, ">$debugdir/$progname.parent.err.$$";
}
else {
    open STDOUT, ">/dev/null";
    open STDERR, ">/dev/null";
}

# This block is the parent daemon, never does an accept, just herds
# a pool of children who accept and service connections, and
# occasionally kill themselves off
PARENT: while (1) {
    while ( scalar( keys %children ) >= $children ) {
        my $child = wait;
        delete $children{$child} if exists $children{$child};
        if ($please_die) { kill 15, keys %children; exit 0; }
    }
    my $pid = fork;
    die "$0: fork failed: $!\n" unless defined $pid;
    last PARENT if $pid == 0;
    $children{$pid} = 1;
    select( undef, undef, undef, 0.1 );
    if ($please_die) { kill 15, keys %children; exit 0; }
}

$isparent = 0;

# If we daemonize, we must close our streams
close STDIN;
close STDOUT;
close STDERR;
open STDIN, "/dev/null";
if ( defined $debugtrace ) {
    open STDOUT, ">$debugdir/$progname.child.out.$$";
    open STDERR, ">$debugdir/$progname.child.err.$$";
}
else {
    open STDOUT, ">/dev/null";
    open STDERR, ">/dev/null";
}

# This block is a child service daemon. It inherited the bound
# socket created by SMTP::Server->new, it will service a random
# number of connection requests in [minperchild..maxperchild] then
# exit

my $lives = $minperchild + ( rand( $maxperchild - $minperchild ) );
my %opts;
if ( defined $debugtrace ) {
    $opts{debug} = IO::File->new(">$debugtrace.$$");
    $opts{debug}->autoflush(1);
}
else {
    $opts{debug} = IO::File->new(">/dev/null");
}

while (1) {
    $server->accept(%opts);
    my $client = GMaGa::Client->new( interface => $dstaddr, port => $dstport );
    my $banner = $client->hear;
    $banner = "220 $debugtrace.$$" if defined $debugtrace;
    $server->ok($banner);
    my $datawhat;
    while ( my $what = $server->chat ) {
        if ( $what =~ m/^data/i ) {

       # Beginning of DATA segment.  "DATA" command is not passed on to client,
       # because content filters might reject it, in which case we don't want to
       # send it on to the client.  SMTP is such that if we QUIT before we DATA,
       # no mail will be sent. But once we DATA, there's no clean way to get
       # out of it.
            $server->{debug}
              ->print("Received DATA command, beginning filtering.\n");

            # Store the DATA command to send later if the filters pass
            $datawhat = $what;

            # Ask the server to send us the data
            $server->ok("354 End data with <CR><LF>.<CR><LF>");
        }
        elsif ( $what eq '.' ) {

            # For now just add the gmaga passed header and forward the mail
            $client->say($datawhat);

            # get its reply
            $client->hear();

            my @addheaders;
            $server->{data}->seek( 0, 0 );

            # Add our own little header
            push @addheaders, $gmagaheaderpassed;

            yammer_add_headers( $server, $client, @addheaders );
            $server->{debug}->print("PASSED\n");
            $server->ok( $client->hear );

##            # Now we have received the entire data segment, we need to scan it.
##            # scan() can get hold of the data from $server
##            my $ref = 1;#scan( $server, $client );
##
##            # if scan() returned non-undef, the data passed:
##            if ($ref) {
##
##                # send the original DATA command to the client
##                $client->say($datawhat);
##
##                # get its reply
##                $client->hear();
##
##               # and then yammer it.  An additional parameter is the array that
##               # was returned by scan() - this contains headers to add in to the
##               # data segment that can specify what the content filter found
##                yammer_add_headers( $server, $client, @{$ref} );
##                $server->{debug}->print("PASSED\n");
##                $server->ok( $client->hear );
##            }
##            else {
##                # content rejected
##                $server->{debug}->print("FAILED\n");
##
##                # tell the server that we like it, anyway.  We don't want viruses
##                # and suchlike bouncing to the senders, since the sending address
##                # was probably faked anyway.  We want to fail silently.
##                $server->ok();
##
##                # So far, the client has merely had "MAIL FROM:" and "RCPT TO:"
##                # commands from us.  If we "QUIT" here, it won't think twice about
##                # it, and nothing will be sent on.  Which is what we want.
##                $client->say("QUIT");
##            }

            # Delete the temporary file here.
            # unlink( $server->{datafilename} );
        }
        else {
            # Normal conversation.
            $client->say($what);
            $server->ok( $client->hear );
        }
    }
    $client = undef;
    delete $server->{"s"};
    exit 0 if $lives-- <= 0;
}

sub yammer_add_headers {
    my ( $server, $client, @addheaders ) = (@_);
    my $fh = $server->{data};
    local (*_);
    local ($/) = "\r\n";

# This is set until we find a blank line, which means the headers are about to end.
    my $inheaders = 1;
    while (<$fh>) {
        if ( defined($inheaders) and m/^\r\n$/ ) {

            # End of headers
            undef $inheaders;

            # Quickly add in all our own headers
            foreach my $h (@addheaders) {
                $client->{sock}->print("$h\r\n");
            }
        }
        s/^\./../;
        $client->{sock}->print($_) or die "$0: write error: $!\n";
    }
    $client->{sock}->print(".\r\n") or die "$0: write error: $!\n";
}

############################
# Scanning
############################

sub scan {
    my ( $server, $client ) = (@_);
    my @addheaders;
    my $ret;

# While we're scanning, we don't want the client to time-out. That would
# suck, because then what do we do with this email?  The sender has already been
# given the okay, so they think the mail has gone.
# Send a NOOP every ten seconds, while we're scanning.
    local $SIG{ALRM} = sub { $client->say("NOOP"); $client->hear(); alarm 10; };

  # WARNING:
  # You can't combine 'alarm' with 'sleep', since some systems implement 'sleep'
  # using 'alarm', and you can only have one alarm at a time.  So, don't use
  # sleep during scan() or anything called by scan()
    alarm 10;

    ## # Basically, any scanner can be called here.  They can access the data by
    ## # using $server->{data} (a filehandle) or $server->{datafilename}
    ## # if they return undef, they failed
    ## # if they return anything else, it's taken to be a header to add to the
    ## # message when it gets passed on
    ## $ret = clamscan($server);
    ## if ( !$ret ) { return undef; }
    ## push @addheaders, $ret;

    ## $ret = spamscan($server);
    ## push @addheaders, $ret;

    $server->{data}->seek( 0, 0 );

    # Add our own little header
    push @addheaders, $gmagaheaderpassed;

    # Disable the alarm now:
    alarm 0;
    return \@addheaders;
}

## ############################
## # ClamAV
## ############################
##
## use Net::Telnet ();
## use Fcntl qw/F_SETFD F_GETFD/;
##
## sub clamscan {
##     my ($server) = (@_);
##
##     # Connect to clamd and ask it to scan our file.
##     # This is why we need to use "new IO::File" in GMaGa::Server,
##     # instead of new_tmpfile
##     my $t =
##       new Net::Telnet( Host => $clamhost, Port => $clamport, Timeout => 300 );
##     my $fn = $server->{datafilename};
##     $t->put( "SCAN " . $fn . "\n" );
##     my $clamoutput = $t->getline();
##     chomp($clamoutput);
##     $server->{debug}->print("CLAM: '$clamoutput'\n");
##     $t->close();
##
##     if ( $clamoutput =~ m/:\s+(.+)\s+FOUND$/ ) {
##         return undef;
##     }
##     return $clamavheader;
## }
##
## ############################
## # Spamassassin
## ############################
##
## use IPC::Open2;
##
## sub spamscan {
##     my ($server) = (@_);
##
##     my ( $outsa, $insa );
##     no warnings;
##     open F, $server->{datafilename};
##
##     # connect to spamc and pipe the mail through it
##     my $sapid = open2( $outsa, "<&F", $spamc );
##
##     waitpid $sapid, 0;
##     my @spamcout = <$outsa>;
##     foreach my $s (@spamcout) {
##         $server->{debug}->print("SPAM: $s");
##     }
##     $spamcout[0] =~ m!^(.*)/(.*)$!;
##     my $score = $1;
##
##     return $spamcheader . $score;
## }
##
