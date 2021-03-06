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
package GMaGa::Exception;

sub new {
    my $class = shift;
    my $text = shift;
    my $self = {
        text_ => " ",
    };
    bless $self, $class;
    return $self;
}

sub what {
    my $self = shift;
    return $self->{text_};
}

1;

################################################################################
package GMaGa::InvalidRecipientException;
use base qw(GMaGa::Exception);

1;

################################################################################
package GMaGa::MissingPrivateKeyException;
use base qw(GMaGa::Exception);

1;

################################################################################
package GMaGa::NotEncryptedException;
use base qw(GMaGa::Exception);

1;

################################################################################
package GMaGa::GPGException;
use base qw(GMaGa::Exception);

1;

################################################################################
package GMaGa::GnuPG;

# originally known as Mail::GnuPG
# modified get_decrypt_key to return the list of all email addresses

=head1 NAME

Mail::GnuPG - Process email with GPG.

=head1 SYNOPSIS

  use Mail::GnuPG;
  my $mg = new Mail::GnuPG( key => 'ABCDEFGH' );
  $ret = $mg->mime_sign( $MIMEObj, 'you@my.dom' );

=head1 DESCRIPTION

Use GnuPG::Interface to process or create PGP signed or encrypted
email.

=cut

use 5.006;
use strict;
use warnings;

our $VERSION = '0.15';
my $DEBUG = 0;

use GnuPG::Interface;
use File::Spec;
use File::Temp;
use IO::Handle;
use MIME::Entity;
use MIME::Parser;
use Mail::Address;
use IO::Select;
use Errno qw(EPIPE);

=head2 new

  Create a new Mail::GnuPG instance.

 Arguments:
   Paramhash...

   key    => gpg key id
   keydir => gpg configuration/key directory
   passphrase => primary key password

   # FIXME: we need more things here, maybe primary key id.


=cut

sub new {
  my $proto = shift;
  my $class = ref($proto) || $proto;
  my $self  = {
	       key	    => undef,
	       keydir	    => undef,
	       passphrase   => "",
	       gpg_path	    => "gpg",
	       @_
	      };
  $self->{last_message} = [];
  $self->{plaintext} = [];
  bless ($self, $class);
  return $self;
}

sub _set_options {
  my ($self,$gnupg) = @_;
  $gnupg->options->meta_interactive( 0 );
  $gnupg->options->hash_init( armor   => 1,
			      ( defined $self->{keydir} ?
				(homedir => $self->{keydir}) : () ),
			      ( defined $self->{key} ?
				( default_key => $self->{key} ) : () ),
#			      ( defined $self->{passphrase} ?
#				( passphrase => $self->{passphrase} ) : () ),
			    );
  $gnupg->call( $self->{gpg_path} ) if defined $self->{gpg_path};
}


=head2 decrypt

 Decrypt an encrypted message

 Input:
   MIME::Entity containing email message to decrypt.

  The message can either be in RFC compliant-ish multipart/encrypted
  format, or just a single part ascii armored message.

 Output:
  On Failure:
    Exit code of gpg.  (0 on success)

  On Success: (just encrypted)
    (0, undef, undef)

  On success: (signed and encrypted)
    ( 0,
      keyid,           # ABCDDCBA
      emailaddress     # Foo Bar <foo@bar.com>
    )

   where the keyid is the key that signed it, and emailaddress is full
   name and email address of the primary uid


  $self->{last_message} => any errors from gpg
  $self->{plaintext}    => plaintext output from gpg
  $self->{decrypted}    => parsed output as MIME::Entity

=cut

sub decrypt {
  my ($self, $message) = @_;
  my $ciphertext = "";

  $self->{last_message} = [];

  unless (ref $message && $message->isa("MIME::Entity")) {
    die "decrypt only knows about MIME::Entitys right now";
    return 255;
  }

  my $armor_message = 0;
  if ($message->effective_type =~ m!multipart/encrypted!) {
    die "multipart/encrypted with more than two parts"
      if ($message->parts != 2);
    die "Content-Type not pgp-encrypted"
      unless $message->parts(0)->effective_type =~
	m!application/pgp-encrypted!;
    $ciphertext = $message->parts(1)->stringify_body;
  }
  elsif ($message->body_as_string
	 =~ m!^-----BEGIN PGP MESSAGE-----!m ) {
    $ciphertext = $message->body_as_string;
    $armor_message = 1;
  }
  else {
    die "Unknown Content-Type or no PGP message in body"
  }

  my $gnupg = GnuPG::Interface->new();
  $self->_set_options($gnupg);
  # how we create some handles to interact with GnuPG
  # This time we'll catch the standard error for our perusing
  # as well as passing in the passphrase manually
  # as well as the status information given by GnuPG
  my ( $input, $output, $error, $passphrase_fh, $status_fh )
    = ( new IO::Handle, new IO::Handle,new IO::Handle,
	new IO::Handle,new IO::Handle,);

  my $handles = GnuPG::Handles->new( stdin      => $input,
				     stdout     => $output,
				     stderr     => $error,
				     passphrase => $passphrase_fh,
				     status     => $status_fh,
				   );

  # this sets up the communication
  my $pid = $gnupg->decrypt( handles => $handles );

  die "NO PASSPHRASE" unless defined $passphrase_fh;
  my $read = _communicate([$output, $error, $status_fh],
                        [$input, $passphrase_fh],
                        { $input => $ciphertext,
                          $passphrase_fh => $self->{passphrase}}
             );

  my @plaintext    = split(/^/m, $read->{$output});
  my @error_output = split(/^/m, $read->{$error});
  my @status_info  = split(/^/m, $read->{$status_fh});

  waitpid $pid, 0;
  my $return = $?;
   $return = 0 if $return == -1;

  my $exit_value  = $return >> 8;
  


  $self->{last_message} = \@error_output;
  $self->{plaintext}    = \@plaintext;

  my $parser = new MIME::Parser;
  $parser->output_to_core(1);

  # for armor message (which usually contain no MIME entity)
  # and if the first line seems to be no header, add an empty
  # line at the top, otherwise the first line of a text message
  # will be removed by the parser.
  if ( $armor_message and $plaintext[0] and $plaintext[0] !~ /^[\w-]+:/ ) {
    unshift @plaintext, "\n";
  }

  my $entity = $parser->parse_data(\@plaintext);
  $self->{decrypted} = $entity;

  return $exit_value if $exit_value; # failure

  # if the message was signed and encrypted, extract the signature
  # information and return it.  In some theory or another, you can't
  # trust an unsigned encrypted message is from who it says signed it.
  # (Although I think it would have to go hand in hand at some point.)

  # FIXME: these regex are likely to break under non english locales.
  my $result = join "", @error_output;
  my ($keyid)  = $result =~ /using \S+ key ID (.+)$/m;
  my ($pemail) = $result =~ /Good signature from "(.+)"$/m;

  return ($exit_value,$keyid,$pemail);

}

=head2 get_decrypt_key

 determines the decryption key (and corresponding mail) of a message

 Input:
   MIME::Entity containing email message to analyze.

  The message can either be in RFC compliant-ish multipart/signed
  format, or just a single part ascii armored message.

 Output:
  $key    -- decryption key
  @emails -- corresponding mail addresses

=cut

sub get_decrypt_key {
  my ($self, $message) = @_;

  unless (ref $message && $message->isa("MIME::Entity")) {
    die "decrypt only knows about MIME::Entitys right now";
  }

  my $ciphertext;

  if ($message->effective_type =~ m!multipart/encrypted!) {
    die "multipart/encrypted with more than two parts"
      if ($message->parts != 2);
    die "Content-Type not pgp-encrypted"
      unless $message->parts(0)->effective_type =~
	m!application/pgp-encrypted!;
    $ciphertext = $message->parts(1)->stringify_body;
  }
  elsif ($message->body_as_string
	 =~ m!^-----BEGIN PGP MESSAGE-----!m ) {
    $ciphertext = $message->body_as_string;
  }
  else {
    die "Unknown Content-Type or no PGP message in body"
  }

  my $gnupg = GnuPG::Interface->new();

  # how we create some handles to interact with GnuPG
  # This time we'll catch the standard error for our perusing
  # as well as passing in the passphrase manually
  # as well as the status information given by GnuPG
  my ( $input, $output, $stderr )
    = ( new IO::Handle, new IO::Handle, new IO::Handle );

  my $handles = GnuPG::Handles->new( stdin      => $input,
				     stdout     => $output,
				     stderr     => $stderr,
				   );

  # this sets up the communication
  my $pid = $gnupg->wrap_call(
  	handles      => $handles,
  	commands     => [ "--decrypt" ],
	command_args => [ "--batch", "--list-only", "--status-fd", "1" ],
  );

  my $read = _communicate([$output], [$input], { $input => $ciphertext });

  # reading the output
  my @result = split(/^/m, $read->{$output});

  # clean up the finished GnuPG process
  waitpid $pid, 0;
  my $return = $?;
   $return = 0 if $return == -1;

  my $exit_value  = $return >> 8;
  


  # set last_message
  $self->{last_message} = \@result;

  # grep ENC_TO and NO_SECKEY items
  my (@enc_to_keys, %no_sec_keys);
  for ( @result ) {
  	push @enc_to_keys, $1 if /ENC_TO\s+([^\s]+)/;
	$no_sec_keys{$1} = 1  if /NO_SECKEY\s+([^\s]+)/;
  }

  # find first key we have the secret portion of
  my $key;
  foreach my $k ( @enc_to_keys ) {
  	if ( not exists $no_sec_keys{$k} ) {
	  	$key = $k;
		last;
	}
  }

  return if not $key;

  # get mail addresses of this key
  die "Invalid Key Format: $key" unless $key =~ /^[0-9A-F]+$/i;
  my $cmd = $self->{gpg_path} . " --with-colons --list-keys $key 2>&1";
  my $gpg_out = qx[ $cmd ];
  ## FIXME: this should probably use open| instead.
  die "Couldn't find key $key in keyring" if $gpg_out !~ /\S/ or $?;

  my @emails;
  my @lines = split /\r?\n/, $gpg_out;
  foreach my $line (@lines) {
    if ( $line =~ m/^(pub|uid):-:/i ) {
      push @emails, (split(":", $line))[9];
    }
  }
  
  return ($key, @emails);
}

=head2 verify

 verify a signed message

 Input:
   MIME::Entity containing email message to verify.

  The message can either be in RFC compliant-ish multipart/signed
  format, or just a single part ascii armored message.

  Note that MIME-encoded data should be supplied unmodified inside
  the MIME::Entity input message, otherwise the signature will be 
  broken. Since MIME-tools version 5.419, this can be achieved with
  the C<decode_bodies> method of MIME::Parser. See the MIME::Parser
  documentation for more information.

 Output:
  On error:
    Exit code of gpg.  (0 on success)
  On success
    ( 0,
      keyid,           # ABCDDCBA
      emailaddress     # Foo Bar <foo@bar.com>
    )

   where the keyid is the key that signed it, and emailaddress is full
   name and email address of the primary uid

  $self->{last_message} => any errors from gpg

=cut

# Verify RFC2015/RFC3156 email
sub verify {
  my ($self, $message) = @_;

  my $ciphertext = "";
  my $sigtext    = "";

  $self->{last_message} = [];

  unless (ref $message && $message->isa("MIME::Entity")) {
    die "VerifyMessage only knows about MIME::Entitys right now";
    return 255;
  }

  if ($message->effective_type =~ m!multipart/signed!) {
    die "multipart/signed with more than two parts"
      if ($message->parts != 2);
    die "Content-Type not pgp-signed"
      unless $message->parts(1)->effective_type =~
	m!application/pgp-signature!;
    $ciphertext = $message->parts(0)->as_string;
    $sigtext    = $message->parts(1)->stringify_body;
  }
  elsif ( $message->bodyhandle and $message->bodyhandle->as_string
	 =~ m!^-----BEGIN PGP SIGNED MESSAGE-----!m ) {
    # don't use not $message->body_as_string here, because
    # the body isn't decoded in this case!!!
    # (which is evil for quoted-printable transfer encoding)
    # also the headers and stuff are not needed here
    $ciphertext = undef;
    $sigtext    = $message->bodyhandle->as_string; # well, actually both
  }
  else {
    die "Unknown Content-Type or no PGP message in body"
  }

  my $gnupg = GnuPG::Interface->new();
  $self->_set_options($gnupg);
  # how we create some handles to interact with GnuPG
  my $input   = IO::Handle->new();
  my $error   = IO::Handle->new();
  my $handles = GnuPG::Handles->new( stderr => $error, stdin  => $input );

  my ($sigfh, $sigfile)
    = File::Temp::tempfile('mgsXXXXXXXX',
			   DIR => File::Spec->tmpdir,
			   UNLINK => 1,
			  );
  print $sigfh $sigtext;
  close($sigfh);

  my ($datafh, $datafile) =
    File::Temp::tempfile('mgdXXXXXX',
			 DIR => File::Spec->tmpdir,
			 UNLINK => 1,
			);

  # according to RFC3156 all line endings MUST be CR/LF
  if ( defined $ciphertext ) {
    $ciphertext =~ s/\x0A/\x0D\x0A/g;
    $ciphertext =~ s/\x0D+/\x0D/g;
  }

  # Read the (unencoded) body data:
  # as_string includes the header portion
  print $datafh $ciphertext if $ciphertext;
  close($datafh);

  my $pid = $gnupg->verify( handles => $handles,
			    command_args => ( $ciphertext ?
					      ["$sigfile", "$datafile"] :
					      "$sigfile" ),
			  );

  my $read = _communicate([$error], [$input], {$input => ''});

  my @result = split(/^/m, $read->{$error});

  unlink $sigfile, $datafile;

  waitpid $pid, 0;
  my $return = $?;
   $return = 0 if $return == -1;

  my $exit_value  = $return >> 8;

  $self->{last_message} = [@result];

  return $exit_value if $exit_value; # failure

  # FIXME: these regex are likely to break under non english locales.
  my $result = join "", @result;
  my ($keyid)  = $result =~ /using \S+ key ID (.+)$/m;
  my ($pemail) = $result =~ /Good signature from "(.+)"$/m;


  return ($exit_value,$keyid,$pemail);

}

# Should this go elsewhere?  The Key handling stuff doesn't seem to
# make sense in a Mail:: module.  
my %key_cache;
my $key_cache_age = 0;
my $key_cache_expire = 60*60*30; # 30 minutes

sub _rebuild_key_cache {
  my $self = shift;
  local $_;
  %key_cache = ();
  # sometimes the best tool for the job... is not perl
  open(my $fh, "$self->{gpg_path} --list-public-keys --with-colons | cut -d: -f10|")
    or die $!;
  while(<$fh>) {
    next unless $_;
    # M::A may not parse the gpg stuff properly.  Cross fingers
    my ($a) = Mail::Address->parse($_); # list context, please
    $key_cache{$a->address}=1 if ref $a;
  }
}

=head2 has_public_key

Does the keyring have a public key for the specified email address? 

 FIXME: document better.  talk about caching.  maybe put a better
 interface in.

=cut


sub has_public_key {
  my ($self,$address) = @_;

  # cache aging is disabled until someone has enough time to test this
  if (0) {
    $self->_rebuild_key_cache() unless ($key_cache_age);

    if ( $key_cache_age && ( time() - $key_cache_expire > $key_cache_age )) {
      $self->_rebuild_key_cache();
    }
  }

  $self->_rebuild_key_cache();

  return 1 if exists $key_cache{$address};
  return 0;

}

=head2 mime_sign

  sign an email message

 Input:
   MIME::Entity containing email message to sign

 Output:
  Exit code of gpg.  (0 on success)

  $self->{last_message} => any errors from gpg

  The provided $entity will be signed.  (i.e. it _will_ be modified.)

=cut


sub mime_sign {
  my ($self,$entity) = @_;

  die "Not a mime entity"
    unless $entity->isa("MIME::Entity");

  $entity->make_multipart;
  my $workingentity = $entity;
  if ($entity->parts > 1) {
    $workingentity = MIME::Entity->build(Type => $entity->head->mime_attr("Content-Type"));
    $workingentity->add_part($_) for ($entity->parts);
    $entity->parts([]);
    $entity->add_part($workingentity);
  }

  my $gnupg = GnuPG::Interface->new();
  $self->_set_options( $gnupg );
  my ( $input, $output, $error, $passphrase_fh, $status_fh )
    = ( new IO::Handle, new IO::Handle,new IO::Handle,
	new IO::Handle,new IO::Handle,);
  my $handles = GnuPG::Handles->new( stdin      => $input,
				     stdout     => $output,
				     stderr     => $error,
				     passphrase => $passphrase_fh,
				     status     => $status_fh,
				   );
  my $pid = $gnupg->detach_sign( handles => $handles );
  die "NO PASSPHRASE" unless defined $passphrase_fh;

  # this passes in the plaintext
  my $plaintext;
  if ($workingentity eq $entity) {
    $plaintext = $entity->parts(0)->as_string;
  } else {
    $plaintext = $workingentity->as_string;
  }

  # according to RFC3156 all line endings MUST be CR/LF
  $plaintext =~ s/\x0A/\x0D\x0A/g;
  $plaintext =~ s/\x0D+/\x0D/g;

  # DEBUG:
#  print "SIGNING THIS STRING ----->\n";
#  $plaintext =~ s/\n/-\n/gs;
#  warn("SIGNING:\n$plaintext<<<");
#  warn($entity->as_string);
#  print STDERR $plaintext;
#  print "<----\n";
  my $read = _communicate([$output, $error, $status_fh],
                        [$input, $passphrase_fh],
                        { $input => $plaintext,
                          $passphrase_fh => $self->{passphrase}}
             );

  my @signature  = split(/^/m, $read->{$output});
  my @error_output = split(/^/m, $read->{$error});
  my @status_info  = split(/^/m, $read->{$status_fh});

  waitpid $pid, 0;
  my $return = $?;
   $return = 0 if $return == -1;

  my $exit_value  = $return >> 8;


  $self->{last_message} = \@error_output;

  $entity->attach( Type => "application/pgp-signature",
		   Disposition => "inline",
		   Data => [@signature],
		   Encoding => "7bit");

  $entity->head->mime_attr("Content-Type","multipart/signed");
  $entity->head->mime_attr("Content-Type.protocol","application/pgp-signature");
#  $entity->head->mime_attr("Content-Type.micalg","pgp-md5");
# Richard Hirner notes that Thunderbird/Enigmail really wants a micalg
# of pgp-sha1 (which will be GPG version dependent.. older versions
# used md5.  For now, until we can detect which type was used, the end
# user should read the source code, notice this comment, and insert
# the appropriate value themselves.

  return $exit_value;
}

=head2 clear_sign

  clearsign the body of an email message

 Input:
   MIME::Entity containing email message to sign.
   This entity MUST have a body.

 Output:
  Exit code of gpg.  (0 on success)

  $self->{last_message} => any errors from gpg

  The provided $entity will be signed.  (i.e. it _will_ be modified.)

=cut

sub clear_sign {
  my ($self, $entity) = @_;
  
  die "Not a mime entity"
    unless $entity->isa("MIME::Entity");

  my $body = $entity->bodyhandle;
  
  die "Message has no body"
    unless defined $body;

  my $gnupg = GnuPG::Interface->new();
  $self->_set_options( $gnupg );
  $gnupg->passphrase ( $self->{passphrase} );

  my ( $input, $output, $error )
    = ( new IO::Handle, new IO::Handle, new IO::Handle);

  my $handles = GnuPG::Handles->new(
  	stdin	=> $input,
	stdout	=> $output,
	stderr	=> $error,
  );

  my $pid = $gnupg->clearsign ( handles => $handles );

  my $plaintext = $body->as_string;

  $plaintext =~ s/\x0A/\x0D\x0A/g;
  $plaintext =~ s/\x0D+/\x0D/g;

  my $read = _communicate([$output, $error], [$input], { $input => $plaintext });
  
  my @ciphertext = split(/^/m, $read->{$output});
  my @error_output = split(/^/m, $read->{$error});
  
  waitpid $pid, 0;
  my $return = $?;
   $return = 0 if $return == -1;

  my $exit_value  = $return >> 8;
  
  $self->{last_message} = [@error_output];

  my $io = $body->open ("w") or die "can't open entity body";
  $io->print (join('',@ciphertext));
  $io->close;

  return $exit_value;
}


=head2 ascii_encrypt

  encrypt an email message body using ascii armor

 Input:
   MIME::Entity containing email message to encrypt.
   This entity MUST have a body.

   list of recipients

 Output:
  Exit code of gpg.  (0 on success)

  $self->{last_message} => any errors from gpg

  The provided $entity will be encrypted.  (i.e. it _will_ be modified.)

=head2 ascii_signencrypt

  encrypt and sign an email message body using ascii armor

 Input:
   MIME::Entity containing email message to encrypt.
   This entity MUST have a body.

   list of recipients

 Output:
  Exit code of gpg.  (0 on success)

  $self->{last_message} => any errors from gpg

  The provided $entity will be encrypted.  (i.e. it _will_ be modified.)

=cut

sub ascii_encrypt {
  my ($self, $entity, @recipients) = @_;
  $self->_ascii_encrypt($entity, 0, @recipients);
}

sub ascii_signencrypt {
  my ($self, $entity, @recipients) = @_;
  $self->_ascii_encrypt($entity, 1, @recipients);
}

sub _ascii_encrypt {
  my ($self, $entity, $sign, @recipients) = @_;
  
  die "Not a mime entity"
    unless $entity->isa("MIME::Entity");

  my $body = $entity->bodyhandle;
  
  die "Message has no body"
    unless defined $body;

  my $plaintext = $body->as_string;

  my $gnupg = GnuPG::Interface->new();
  $self->_set_options( $gnupg );
  $gnupg->passphrase ( $self->{passphrase} );
  $gnupg->options->push_recipients( $_ ) for @recipients;

  my ( $input, $output, $error )
    = ( new IO::Handle, new IO::Handle, new IO::Handle);

  my $handles = GnuPG::Handles->new(
  	stdin	=> $input,
	stdout	=> $output,
	stderr	=> $error,
  );

  my $pid = do {
  	if ( $sign ) {
		$gnupg->sign_and_encrypt ( handles => $handles );
	} else {
		$gnupg->encrypt ( handles => $handles );
	}
  };

  my $read = _communicate([$output, $error], [$input], { $input => $plaintext });
  
  my @ciphertext = split(/^/m, $read->{$output});
  my @error_output = split(/^/m, $read->{$error});
  
  waitpid $pid, 0;
  my $return = $?;
   $return = 0 if $return == -1;

  my $exit_value  = $return >> 8;
  

  $self->{last_message} = [@error_output];

  my $io = $body->open ("w") or die "can't open entity body";
  $io->print (join('',@ciphertext));
  $io->close;

  return $exit_value;
}

=head2 mime_encrypt

  encrypt an email message

 Input:
   MIME::Entity containing email message to encrypt
   list of email addresses to sign to

 Output:
  Exit code of gpg.  (0 on success)

  $self->{last_message} => any errors from gpg

  The provided $entity will be encrypted.  (i.e. it _will_ be modified.)

=head2 mime_signencrypt

  sign and encrypt an email message

 Input:
   MIME::Entity containing email message to sign encrypt
   list of email addresses to sign to

 Output:
  Exit code of gpg.  (0 on success)

  $self->{last_message} => any errors from gpg

  The provided $entity will be encrypted.  (i.e. it _will_ be modified.)

=cut

sub mime_encrypt {
  my $self = shift;
  $self->_mime_encrypt(0,@_);
}

sub mime_signencrypt {
  my $self = shift;
  $self->_mime_encrypt(1,@_);
}

sub _mime_encrypt {
  my ($self,$sign,$entity,@recipients) = @_;

  die "Not a mime entity"
    unless $entity->isa("MIME::Entity");

  my $workingentity = $entity;
  $entity->make_multipart;
  if ($entity->parts > 1) {
    $workingentity = MIME::Entity->build(Type => $entity->head->mime_attr("Content-Type"));
    $workingentity->add_part($_) for ($entity->parts);
    $entity->parts([]);
    $entity->add_part($workingentity);
  }

  my $gnupg = GnuPG::Interface->new();

  $gnupg->options->push_recipients( $_ ) for @recipients;
  $self->_set_options($gnupg);
  my ( $input, $output, $error, $passphrase_fh, $status_fh )
    = ( new IO::Handle, new IO::Handle,new IO::Handle,
	new IO::Handle,new IO::Handle,);
  my $handles = GnuPG::Handles->new( stdin      => $input,
				     stdout     => $output,
				     stderr     => $error,
				     passphrase => $passphrase_fh,
				     status     => $status_fh,
				   );

  my $pid = do {
    if ($sign) {
      $gnupg->sign_and_encrypt( handles => $handles );
    } else {
      $gnupg->encrypt( handles => $handles );
    }
  };

 # this passes in the plaintext
  my $plaintext;
  if ($workingentity eq $entity) {
    $plaintext= $entity->parts(0)->as_string;
  } else {
    $plaintext=$workingentity->as_string;
  }

  # no need to mangle line endings for encryption (RFC3156)
  # $plaintext =~ s/\n/\x0D\x0A/sg;
  # should we store this back into the body?

  # DEBUG:
  #print "ENCRYPTING THIS STRING ----->\n";
#  print $plaintext;
#  print "<----\n";

  die "NO PASSPHRASE" unless defined $passphrase_fh;
  my $read = _communicate([$output, $error, $status_fh],
                        [$input, $passphrase_fh],
                        { $input => $plaintext,
                          $passphrase_fh => $self->{passphrase}}
             );

  my @plaintext    = split(/^/m, $read->{$output});
  my @ciphertext = split(/^/m, $read->{$output});
  my @error_output = split(/^/m, $read->{$error});
  my @status_info  = split(/^/m, $read->{$status_fh});

  waitpid $pid, 0;
  my $return = $?;
   $return = 0 if $return == -1;

  my $exit_value  = $return >> 8;
  

  
  
  $self->{last_message} = [@error_output];


  $entity->parts([]); # eliminate all parts

  $entity->attach(Type => "application/pgp-encrypted",
		  Disposition => "inline",
		  Filename => "msg.asc",
		  Data => ["Version: 1",""],
		  Encoding => "7bit");
  $entity->attach(Type => "application/octet-stream",
		  Disposition => "inline",
		  Data => [@ciphertext],
		  Encoding => "7bit");

  $entity->head->mime_attr("Content-Type","multipart/encrypted");
  $entity->head->mime_attr("Content-Type.protocol","application/pgp-encrypted");

  $exit_value;
}

=head2 is_signed

  best guess as to whether a message is signed or not (by looking at
  the mime type and message content)

 Input:
   MIME::Entity containing email message to test

 Output:
  True or False value

=head2 is_encrypted

  best guess as to whether a message is signed or not (by looking at
  the mime type and message content)

 Input:
   MIME::Entity containing email message to test

 Output:
  True or False value

=cut

sub is_signed {
  my ($self,$entity) = @_;
  return 1
    if (($entity->effective_type =~ m!multipart/signed!)
	||
	($entity->as_string =~ m!^-----BEGIN PGP SIGNED MESSAGE-----!m));
  return 0;
}

sub is_encrypted {
  my ($self,$entity) = @_;
  return 1
    if (($entity->effective_type =~ m!multipart/encrypted!)
	||
	($entity->as_string =~ m!^-----BEGIN PGP MESSAGE-----!m));
  return 0;
}

# interleave reads and writes
# input parameters: 
#  $rhandles - array ref with a list of file handles for reading
#  $whandles - array ref with a list of file handles for writing
#  $wbuf_of  - hash ref indexed by the stringified handles
#              containing the data to write
# return value:
#  $rbuf_of  - hash ref indexed by the stringified handles
#              containing the data that has been read
#
# read and write errors due to EPIPE (gpg exit) are skipped silently on the
# assumption that gpg will explain the problem on the error handle
#
# other errors cause a non-fatal warning, processing continues on the rest
# of the file handles
#
# NOTE: all the handles get closed inside this function

sub _communicate {
    my $blocksize = 2048;
    my ($rhandles, $whandles, $wbuf_of) = @_;
    my $rbuf_of = {};

    # the current write offsets, again indexed by the stringified handle
    my $woffset_of;

    my $reader = IO::Select->new;
    for (@$rhandles) {
        $reader->add($_);
        $rbuf_of->{$_} = '';
    }

    my $writer = IO::Select->new;
    for (@$whandles) {
        die("no data supplied for handle " . fileno($_)) if !exists $wbuf_of->{$_};
        if ($wbuf_of->{$_}) {
            $writer->add($_);
        } else { # nothing to write
            close $_;
        }
    }

    # we'll handle EPIPE explicitly below
    local $SIG{PIPE} = 'IGNORE';

    while ($reader->handles || $writer->handles) {
        my @ready = IO::Select->select($reader, $writer, undef, undef);
        if (!@ready) {
            die("error doing select: $!");
        }
        my ($rready, $wready, $eready) = @ready;
        if (@$eready) {
            die("select returned an unexpected exception handle, this shouldn't happen");
        }
        for my $rhandle (@$rready) {
            my $n = fileno($rhandle);
            my $count = sysread($rhandle, $rbuf_of->{$rhandle},
                                $blocksize, length($rbuf_of->{$rhandle}));
            warn("read $count bytes from handle $n") if $DEBUG;
            if (!defined $count) { # read error
                if ($!{EPIPE}) {
                    warn("read failure (gpg exited?) from handle $n: $!")
                        if $DEBUG;
                } else {
                    warn("read failure from handle $n: $!");
                }
                $reader->remove($rhandle);
                close $rhandle;
                next;
            }
            if ($count == 0) { # EOF
                warn("read done from handle $n") if $DEBUG;
                $reader->remove($rhandle);
                close $rhandle;
                next;
            }
        }
        for my $whandle (@$wready) {
            my $n = fileno($whandle);
            $woffset_of->{$whandle} = 0 if !exists $woffset_of->{$whandle};
            my $count = syswrite($whandle, $wbuf_of->{$whandle},
                                 $blocksize, $woffset_of->{$whandle});
            if (!defined $count) {
                if ($!{EPIPE}) { # write error
                    warn("write failure (gpg exited?) from handle $n: $!")
                        if $DEBUG;
                } else {
                    warn("write failure from handle $n: $!");
                }
                $writer->remove($whandle);
                close $whandle;
                next;
            }
            warn("wrote $count bytes to handle $n") if $DEBUG;
            $woffset_of->{$whandle} += $count;
            if ($woffset_of->{$whandle} >= length($wbuf_of->{$whandle})) {
                warn("write done to handle $n") if $DEBUG;
                $writer->remove($whandle);
                close $whandle;
                next;
            }
        }
    }
    return $rbuf_of;
}

# FIXME: there's no reason why is_signed and is_encrypted couldn't be
# static (class) methods, so maybe we should support that.

# FIXME: will we properly deal with signed+encrypted stuff?  probably not.

# Autoload methods go after =cut, and are processed by the autosplit program.

1;

=head1 LICENSE

Copyright 2003 Best Practical Solutions, LLC

This program is free software; you can redistribute it and/or modify
it under the terms of either:

    a) the GNU General Public License as published by the Free
    Software Foundation; version 2
    http://www.opensource.org/licenses/gpl-license.php

    b) the "Artistic License"
    http://www.opensource.org/licenses/artistic-license.php

This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See either the
GNU General Public License or the Artistic License for more details.

=head1 AUTHOR

Robert Spier

=head1 BUGS/ISSUES/PATCHES

Please send all bugs/issues/patches to
    bug-Mail-GnuPG@rt.cpan.org

=head1 SEE ALSO

L<perl>.

GnuPG::Interface,

MIME::Entity

=cut

################################################################################
package GMaGa;

use Getopt::Long;
use IO::File;
use lib '.';
use POSIX;
use Mail::GnuPG;
use MIME::Parser;
use Email::Valid;
use File::Basename qw/dirname/;
use Error qw(:try);

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
my $tmpdir    = "/tmp";
my $debugdir    = $tmpdir;
my $pidfile     = "/var/run/$progname.pid";

my $configfile = "/etc/$progname.conf";

my $gmagaheaderpassed       = "Message passed GMaGa (testing)";
my $gmagaheaderdecrypted    = "Message decrypted";
my $gmagaheadernotencrypted = "Message wasn't encrypted";
my $gmagaheadermissingkey   = "Missing key for decryption";

my $decrypt_status_success = 0;

my $header_key = "X-GMaGa";
my $header_status_success = "Message decrypted";
my $header_status_invalid_recipient = "Invalid recipient: ";
my $header_status_missing_private_key = "Missing private key for decryption";
my $header_status_not_encrypted = "Plain message, no encryption necessary";
my $header_status_gpg_error = "GPG error: ";
my $header_status_unknown_failure = "Unknown failure. ";

############################
# Arguments
############################

my $syntax =
    "syntax: $0 [--children=$children] [--minperchild=$minperchild] "
  . "[--maxperchild=$maxperchild] [--debugtrace=undef] "
  . "--listen=listen.addr:port --talk=talk.addr:port --pidfile=$pidfile --tmpdir=/tmp\n";

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
            if ( $key eq "tmpdir" )      { $tmpdir      = $val; }
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
    "pidfile=s"     => \$pidfile,
    "tmpdir=s"      => \$tmpdir
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
    $opts{debug} = IO::File->new(">$debugdir/$debugtrace.$$");
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
    my $recipient = undef;

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

            # create the MIME parser
            my $parser = MIME::Parser->new;

            # configure MIME Parser
            $parser->decode_bodies(0);
            $parser->output_under($tmpdir);
            $parser->output_to_core(1);

            # parse the data
            $server->{data}->seek( 0, 0 );
            my $entity = $parser->parse($server->{data});
            my $entity_clone = $entity->dup;

            # decrypt message if possible
            eval {
                decrypt( $entity, $recipient );
                $entity->head()->add( $header_key, $header_status_success );
                return;
            };
            if ($@) {
                if ( $@->isa( 'GMaGa::InvalidRecipientException' ) ) {
                    $entity = $entity_clone;
                    $entity->head()->add( $header_key, $header_status_invalid_recipient.$@->what() );
                }
                elsif ( $@->isa( 'GMaGa::MissingPrivateKeyException' ) ) {
                    $entity = $entity_clone;
                    $entity->head()->add( $header_key, $header_status_missing_private_key );
                }
                elsif ( $@->isa( 'GMaGa::NotEncryptedException' ) ) {
                    $entity = $entity_clone;
                    $entity->head()->add( $header_key, $header_status_not_encrypted );
                }
                elsif ( $@->isa( 'GMaGa::GPGException' ) ) {
                    $entity = $entity_clone;
                    $entity->head()->add( $header_key, $header_status_gpg_error.$@->what() );
                }
                elsif ( $@->isa( 'GMaGa::Exception' ) ) {
                    $entity = $entity_clone;
                    $entity->head()->add( $header_key, $header_status_unknown_failure.$@->what() );
                }
                else {
                    $entity = $entity_clone;
                    $entity->head()->add( $header_key, $header_status_unknown_failure );
                }
            }
            
            # tell client that the data is coming
            $client->say($datawhat);
            $client->hear();

            # prepare the data
            my $new_data = $entity->stringify;
           
            # send the data 
            send_data( $client, $new_data );
            $server->ok( $client->hear );

            $parser = undef;
        }
        elsif ( $what =~ m/^rcpt\s+to:\s*(.*)/i )
        {
            $recipient = email_from_string( $1 );
            $client->say($what);
            $server->ok( $client->hear );
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

sub send_data {
    my ( $client, $data ) = (@_);
    local (*_);
    local ($/) = "\r\n";

    my @lines = split /\r?\n/, $data;
    foreach my $line (@lines) {
        $line =~ s/^\./../;
        $client->{sock}->print($line."\r\n") or die "$0: write error: $!\n";
    }
    $client->{sock}->print(".\r\n") or die "$0: write error: $!\n";
}

sub email_from_string {
    my $mail_string = shift;
    if ( !defined( $mail_string ) ) {
        return undef;
    }
    my $result = undef;

    # check the whole string
    my $addr = eval {
        $result = Email::Valid->address( -address => $mail_string,
                                       -mxcheck => 0 );
        return $result;
    };
    if ( defined $addr ) {
        return $addr;
    }

    # check, if we have ORCPT=rfc822;...
    if ( $mail_string =~ m/ORCPT=rfc822;\s*(.*?)$/i )
    {
        my $rfc822 = $1;
        $addr = eval {
            $result = Email::Valid->address( -address => $rfc822,
                                       -mxcheck => 0 );
            return $result;
        };
        if ( defined $addr ) {
            return $addr;
        }
    }

    # check, if we have <....>
    if ( $mail_string =~ m/<(.*?)>/i )
    {
        my $braced = $1;
        $addr = eval {
            $result = Email::Valid->address( -address => $braced,
                                       -mxcheck => 0 );
            return $result;
        };
        if ( defined $addr ) {
            return $addr;
        }
    }

    return undef;
}

sub decrypt {
    my ( $entity, $recipient ) = (@_);
    my $email;
    my @addresses;
    my $keyid;
    my $code;

    if ( !defined( $recipient ) ) {
         #print( "decrypt: recipient undefined\n" );
         die GMaGa::InvalidRecipientException->new( "undefined" );
    }

    # open the interface to GPG
    my $gpg = new GMaGa::GnuPG;

    # check if the mail is encrypted
    if ( !$gpg->is_encrypted( $entity ) ) {
         #print( "decrypt: message not encrypted\n" );
         die GMaGa::NotEncryptedException->new( "" );
    }

    # get the keyid and email for this message
    ( $keyid, @addresses ) = $gpg->get_decrypt_key( $entity );

    if ( !defined( $keyid ) ) {
         #print( "decrypt: missing key\n" );
         die GMaGa::MissingPrivateKeyException->new( "" );
    }

    # check the list of addresses if it contains $recipient
    my $is_allowed = 0;
    foreach ( @addresses ) {
         if ( email_from_string( $_ ) eq $recipient ) {
              $is_allowed = 1;
         }
    }

    # if the recipient is not among the addresses for the key, we don't allow decryption,
    # because we don't want you to be able to read mails addressed to you, but encrypted
    # with your colleagues public key
    if ( $is_allowed == 0 ) {
         #print( "decrypt: recipients mismatch\n" );
         die GMaGa::InvalidRecipientException->new( "Recipient '$recipient' doesn't match any of the allowed uids for the key: ".join( ', ', @addresses ) );
    }

    # decrypt
    ( $code, $keyid, $email ) = $gpg->decrypt( $entity );
    my $decrypted = $gpg->{decrypted};

    # if decryption failed, at least tell why
    if ( !$code == 0 ) {
         #print( "decrypt: gpg failed: ".join( ', ', $gpg->{last_message} )."\n" );
         die GMaGa::GPGException->new( join( ', ', $gpg->{last_message} ) );
    }

    eval {
        $entity->parts([]);
        $entity->head->mime_attr("Content-Type", $decrypted->head->mime_attr("Content-Type"));
        $entity->head->mime_attr("Content-Type.boundary", $decrypted->head->mime_attr("Content-Type.boundary"));
        for ( my $part = 0; $part < $decrypted->parts; $part++ ) {
             $entity->add_part($decrypted->parts( $part ) );
        }
    };
    die GMaGa::Exception->new( $@ ) if $@;

    return $decrypt_status_success;
}
