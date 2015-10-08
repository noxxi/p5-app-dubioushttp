use strict;
use warnings;
package App::DubiousHTTP::TestServer;
use Scalar::Util 'weaken';
use Digest::MD5 'md5_base64';
use App::DubiousHTTP::Tests::Common qw($TRACKHDR ungarble_url);

use IO::Socket::INET;
my $IOCLASS;
BEGIN {
    $IOCLASS = 'IO::Socket::'. ( eval { require IO::Socket::IP } ? 'IP':'INET' );
}

my $MAX_CLIENTS = 100;
my $SELECT = App::DubiousHTTP::TestServer::Select->new;
my %clients;
my $DEBUG = 0;
my %trackhdr;

sub _debug {
    $DEBUG or return;
    my $msg = shift;
    $msg = sprintf($msg,@_) if @_;
    my $time = localtime();
    $msg =~s{^}{DEBUG: $time }mg;
    print STDERR $msg."\n";
}

# close down properly socket etc if user closes program
$SIG{TERM} = $SIG{INT} = sub { exit(0) };

sub run {
    shift;
    my ($addr,$sslargs,$response) = @_;
    if ($sslargs) {
	# XXX do we need a specific minimal version?
	eval { require IO::Socket::SSL } or
	    die "need IO::Socket::SSL for SSL support";
	$sslargs = eval { IO::Socket::SSL::SSL_Context->new( SSL_server => 1, %$sslargs) }
	    or die "creating SSL context: $@";
    }
    my $srv = $IOCLASS->new( LocalAddr => $addr, Listen => 10, Reuse => 1 )
	or die "listen failed: $!";
    $srv->blocking(0);
    $SELECT->handler($srv,0,sub {
	my $cl = $srv->accept or return;
	if (keys(%clients)>$MAX_CLIENTS) {
	    my @cl = sort { $clients{$a}{time} <=> $clients{$b}{time} } keys %clients;
	    while (@cl>$MAX_CLIENTS) {
		my $old = $clients{ shift(@cl) };
		delete_client($old->{fd});
	    }
	}
	$cl->blocking(0);
	add_client($cl,$response,$sslargs);
    });
    $SELECT->mask($srv,0,1);
    $SELECT->loop;
}

sub delete_client {
    my $cl = shift;
    delete $clients{fileno($cl)};
    $SELECT->delete($cl);
}

sub add_client {
    my ($cl,$response,$sslctx) = @_;
    my $addr = $cl->sockhost.':'.$cl->sockport;
    $DEBUG && _debug("new client from $addr");

    $clients{fileno($cl)}{time} = time();
    weaken($clients{fileno($cl)}{fd} = $cl);

    return _install_check_https($cl,$response,$sslctx) if $sslctx;
    return _install_http($cl,$response);
}

sub _install_check_https {
    my ($cl,$response,$sslctx) = @_;
    $DEBUG && _debug("add handler for checking https");
    $SELECT->handler($cl,0,sub {
	my $cl = shift;
	my $buf;
	$DEBUG && _debug("socket readable - peek");
	if (!defined recv($cl,$buf,2,MSG_PEEK)) {
	    $DEBUG && _debug("peek failed: $!");
	    delete_client($cl);
	    return;
	}
	# assume GET|POST if only uppercase word characters
	return _install_http($cl,$response) if $buf =~m{^[A-Z]+$};

	# initiate TLS handshake
	if (!IO::Socket::SSL->start_SSL($cl,
	    SSL_startHandshake => 0,
	    SSL_server => 1,
	    SSL_reuse_ctx => $sslctx
	)) {
	    warn "sslify failed: $IO::Socket::SSL::SSL_ERROR";
	    delete_client($cl);
	    return;
	}
	return _install_https($cl,$response);
    });
    $SELECT->mask($cl,0,1);

}

sub _install_https {
    my ($cl,$response) = @_;
    my $handler = sub {
	my $cl = shift;
	if ($cl->accept_SSL) {
	    # handshake finally done
	    return _install_http($cl,$response,'https');
	}
	if ($IO::Socket::SSL::SSL_ERROR == IO::Socket::SSL::SSL_WANT_READ()) {
	    $SELECT->mask($cl, 0 => 1, 1 => 0);
	} elsif ($IO::Socket::SSL::SSL_ERROR == IO::Socket::SSL::SSL_WANT_WRITE()) {
	    $SELECT->mask($cl, 0 => 0, 1 => 1);
	} else {
	    warn "sslify failed: $IO::Socket::SSL::SSL_ERROR";
	    delete_client($cl);
	    return;
	}
    };
    $SELECT->handler($cl, 0 => $handler, 1 => $handler);
    $SELECT->mask($cl, 0 => 1);
}

sub _install_http {
    my ($cl,$response,$ssl) = @_;
    
    my ($clen,$hdr,$page,$payload,$close);

    my $write;
    my $rbuf = my $wbuf = '';
    my $read = sub {
	my $cl = shift;
	my $n = sysread($cl,$rbuf,8192,length($rbuf));
	$DEBUG && _debug("read on ".fileno($cl)." -> ".(defined $n ? $n : $!));
	if ( !$n ) {
	    # close on eof or error
	    delete_client($cl) if defined($n) || ! $!{EAGAIN}; 
	    return;
	}

	$clients{fileno($cl)}{time} = time();

	handle_data:
	if (defined $clen) {
	    # has header, extract payload
	    if (length($rbuf) > $clen) {
		$payload .= substr($rbuf,0,$clen,'');
		$clen = 0;
	    } else {
		$payload .= $rbuf;
		$clen -= length($rbuf);
		$rbuf = '';
	    }
	    return if $clen>0; # need more

	    my $addr = $cl->sockhost.':'.$cl->sockport;
	    if ( ! eval { $wbuf .= $response->($page,$addr,$hdr,$payload,$ssl) } ) {
		warn "[$page] creating response failed: $@";
		delete_client($cl);
		return;
	    }

	    $clen = $hdr = undef;
	    if (!$close) {
		if ($wbuf =~m{(\r?\n)\1}g) {
		    $close = _mustclose( substr($wbuf,0,pos($wbuf)) );
		} else {
		    $DEBUG && _debug("set close=1 because of no header end in wbuf=$wbuf");
		    $close = 1;
		}
	    }

	    $write->($cl);
	    return;

	} elsif ( $rbuf =~m{(\r?\n)\1}g ) {
	    # read header
	    $hdr = substr($rbuf,0,pos($rbuf),'');
	    my ($line) = $hdr =~m{^([^\r\n]*)};
	    $line = ungarble_url($line);
	    $line =~s{\?rand=0\.\d+ }{ };  # remove random for anti-caching

	    my $digest = '';
	    if ($TRACKHDR) {
		my $xhdr = $hdr;
		$xhdr =~s{\r?\n}{\n}g;
		$xhdr =~s{\A.*\n}{}; # remove request line
		my %KEEPHDR = map { lc($_) => 1 } qw(Accept-Encoding Accept User-Agent Accept-Language);
		( my $dhdr = $xhdr ) =~s{^([^\s:]+)(:\s*)(.*(\n[ \t].*)*\n)}{
		    $KEEPHDR{lc($1)} ? "$1$2$3" : "$1$2XXX\r\n"
		}emg;
		my $digest = substr(md5_base64($dhdr),0,8);
		$digest =~ tr{+/}{\$%};
		if (!$trackhdr{$digest}) {
		    $trackhdr{$digest} = 1;
		    my $accept = $xhdr =~m{^Accept:\s*([^\r\n]+)}mi && $1 || '-';
		    my $ua = $xhdr =~m{^User-Agent:\s*([^\r\n]+)}mi && $1 || 'Unknown-UA';
		    my @via = $xhdr =~m{^Via:\s*([^\r\n]*)}mig;
		    $xhdr =~s{^}{ |$digest|- }mg;
		    warn " |$digest|-BEGIN $accept | $ua\n |$digest|- $line\n$xhdr";
		}
		warn localtime()." |$digest| ". $cl->peerhost." | $line".($ssl ? " | $ssl":"")."\n";
	    } else {
		my $ua = $hdr =~m{^User-Agent:\s*([^\r\n]+)}mi && $1 || 'Unknown-UA';
		my @via = $hdr =~m{^Via:\s*([^\r\n]*)}mig;
		warn localtime()." | $ua  | ". $cl->peerhost." | $line | @via\n";
	    }

	    (my $method,$page) = $line =~m{ \A 
		(GET|POST) [\040]+ 
		(/\S*) [\040]+ 
		HTTP/1\.[01] \z
	    }x or do {
		$wbuf .= "HTTP/1.0 204 ok\r\n\r\n";
		$close = 1;
		$write->($cl);
		return;
	    };
	    $clen = $method eq 'POST' && $hdr =~m{^Content-length:[ \t]*(\d+)}mi && $1 || 0;
	    if ($clen > 2**22) {
		warn "request body too large ($clen)";
		delete_client($cl);
		return;
	    }
	    $close = _mustclose($hdr);
	    $page =~s{%([\da-fA-F]{2})}{ chr(hex($1)) }esg; # urldecode
	    goto handle_data;

	} elsif ( length($rbuf)>4096 ) {
	    warn "request header too large";
	    delete_client($cl);
	    return;
	}
    };

    $write = sub {
	my $cl = shift;

	handle_data:
	if ( $wbuf eq '' ) {
	    # nothing to write
	    if ($rbuf eq '' && $close) {
		# done
		$DEBUG && _debug("close client because all done and close flag set");
		delete_client($cl);
	    } else {
		$SELECT->mask($cl,1,0);
	    }
	    return;
	} 
	my $n = syswrite($cl,$wbuf);
	$DEBUG && _debug("write on ".fileno($cl)." -> ".(defined $n ? $n : $!));
	if ( ! $n ) {
	    if ( defined($n) || ! $!{EAGAIN} ) {
		# connection broke
		delete_client($cl);
	    } else {
		# try later
		$SELECT->mask($cl,1,1);
	    }
	    return;
	}

	$clients{fileno($cl)}{time} = time();
	substr($wbuf,0,$n,'');
	goto handle_data;
    };

    $SELECT->handler($cl,0,$read,1,$write);
    $SELECT->mask($cl,0,1);
}


sub _mustclose {
    my $hdr = shift;
    my $close;
    my $type = $hdr =~m{^[A-Z]+ /} ? 'request':'response';
    while ($hdr =~m{^Connection:[ \t]*(?:(close)|keep-alive)}mig) {
	$close = $1 ? 1: ($close||-1);
    }
    if ($close) {
	$close = 0 if $close<0;
	$DEBUG && _debug("set close=$close because of connection header in $type");
    } elsif ($hdr =~m{\A(?:.* )?HTTP/1\.(?:0|(1))}) {
	$close = $1 ? 0:1;
	$DEBUG && _debug("set close=$close because of HTTP version in $type");
    } else {
	$close = 1;
	$DEBUG && _debug("set close=$close because no other information are known in $type");
    }
    return $close;
}

package App::DubiousHTTP::TestServer::Select;
use Scalar::Util 'weaken';

my $maxfn = 0;
my @handler;
my @mask = ('','');
my @tmpmask;
*_debug = \&App::DubiousHTTP::TestServer::_debug;

sub new { bless {},shift }
sub delete {
    my ($self,$cl) = @_;
    defined( my $fn = fileno($cl) ) or die "invalid fd";
    $DEBUG && _debug("remove fd $fn");
    vec($mask[0],$fn,1) = vec($mask[1],$fn,1) = 0;
    vec($tmpmask[0],$fn,1) = vec($tmpmask[1],$fn,1) = 0 if @tmpmask;
    $handler[$fn] = undef;
    if ($maxfn == $fn) {
	$maxfn-- while ($maxfn>=0 && !$handler[$maxfn]);
    }
}

sub handler {
    my ($self,$cl,%sub) = @_;
    defined( my $fn = fileno($cl) ) or die "invalid fd";
    $maxfn = $fn if $fn>$maxfn;
    weaken(my $wcl = $cl);
    while (my ($rw,$sub) = each %sub) {
	$sub = [ $sub ] if ref($sub) eq 'CODE';
	splice(@$sub,1,0,$wcl);
	$handler[$fn][$rw] = $sub;
	$DEBUG && _debug("add handler($fn,$rw)");
    }
}

sub mask {
    my ($self,$cl,%val) = @_;
    defined( my $fn = fileno($cl) ) or die "invalid fd";
    while (my ($rw,$val) = each %val) {
	$DEBUG && _debug("set mask($fn,$rw) to $val");
	vec($mask[$rw],$fn,1) = $val;
    }
}

sub loop {
    loop:
    @tmpmask = @mask;
    my $rv = select($tmpmask[0],$tmpmask[1],undef,undef);
    $DEBUG && _debug("select -> $rv");
    die "loop failed: $!" if $rv <= 0;
    for my $rw (0,1) {
	for( my $fn=0; $fn<=$maxfn; $fn++) {
	    vec($tmpmask[$rw],$fn,1) or next;
	    $DEBUG && _debug("selected($fn,$rw)");
	    my $sub = $handler[$fn][$rw] or die "no handler";
	    $sub->[0](@{$sub}[1..$#$sub]);
	}
    }
    goto loop;
}

1;
