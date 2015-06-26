use strict;
use warnings;
package App::DubiousHTTP::TestServer;
use IO::Socket::INET;
use Scalar::Util 'weaken';

my $MAX_CLIENTS = 10;
my $SELECT = App::DubiousHTTP::TestServer::Select->new;
my %clients;
my $DEBUG = 0;

sub run {
    shift;
    my ($addr,$response) = @_;
    my $srv = IO::Socket::INET->new( LocalAddr => $addr, Listen => 10, Reuse => 1 )
	or die "listen failed: $!";
    $SELECT->handler($srv,0,sub {
	my $cl = $srv->accept or return;
	if (keys(%clients)>$MAX_CLIENTS) {
	    my @cl = sort { $a->{time} <=> $b->{time} } keys %clients;
	    while (@cl>$MAX_CLIENTS) {
		my $old = $clients{ shift(@cl) };
		delete_client($old->{fd});
	    }
	}
	add_client($cl,$response);
    });
    $SELECT->mask($srv,0,1);
    $SELECT->loop;
}

sub delete_client {
    my $cl = shift;
    delete $clients{$cl};
    $SELECT->delete($cl);
}

sub add_client {
    my ($cl,$response) = @_;
    my $addr = $cl->sockhost.':'.$cl->sockport;
    $DEBUG && warn "new client from $addr\n";

    my ($clen,$hdr,$page,$payload,$close);

    $clients{$cl}{time} = time();
    weaken($clients{$cl}{fd} = $cl);
    
    my $write;
    my $rbuf = my $wbuf = '';
    my $read = sub {
	my $cl = shift;
	my $n = sysread($cl,$rbuf,8192,length($rbuf));
	$DEBUG && warn "read on ".fileno($cl)." -> ".(defined $n ? $n : $!)."\n";
	if ( !$n ) {
	    # close on eof or error
	    delete_client($cl) if defined($n) || ! $!{EAGAIN}; 
	    return;
	}

	$clients{$cl}{time} = time();

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

	    if ( ! eval { $wbuf .= $response->($page,$addr,$hdr,$payload) } ) {
		warn "[$page] creating response failed: $@";
		delete_client($cl);
		return;
	    }
		
	    if (!$close && $wbuf =~m{(\r?\n)\1}g) {
		$close = _mustclose( substr($wbuf,0,pos($wbuf)) );
	    }

	    $write->($cl);
	    return;

	} elsif ( $rbuf =~m{(\r?\n)\1}g ) {
	    # read header
	    $hdr = substr($rbuf,0,pos($rbuf),'');
	    my ($line) = $hdr =~m{^([^\r\n]*)};
	    my ($ua) = $hdr =~m{^User-Agent:\s*([^\r\n]*)}mi;
	    $ua ||= 'Unknown-UA';
	    my @via = $hdr =~m{^Via:\s*([^\r\n]*)}mig;
	    $line =~s{\?rand=0\.\d+ }{ };  # remove random for anti-caching
	    warn localtime()." | $ua  | ". $cl->peerhost." | $line | @via\n";
	    (my $method,$page) = $hdr =~m{ \A 
		(GET|POST) [\040]+ 
		(/\S*) [\040]+ 
		HTTP/1\.[01] \r?\n
	    }x or do {
		$wbuf .= "HTTP/1.0 204 ok\r\n\r\n";
		$close = 1;
		$write->($cl);
		return;
	    };
	    $clen = $method eq 'POST' && $hdr =~m{^Content-length:[ \t]*(\d+)}mi && $1 || 0;
	    if ($clen > 2**16) {
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
		delete_client($cl);
	    } else {
		$SELECT->mask($cl,1,0);
	    }
	    return;
	} 
	my $n = syswrite($cl,$wbuf);
	$DEBUG && warn "write on ".fileno($cl)." -> ".(defined $n ? $n : $!)."\n";
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

	$clients{$cl}{time} = time();
	substr($wbuf,0,$n,'');
	goto handle_data;
    };

    $SELECT->handler($cl,0,$read,1,$write);
    $SELECT->mask($cl,0,1);
}


sub _mustclose {
    my $hdr = shift;
    # keep-alive by header
    while ($hdr =~m{^Connection:[ \t]*(?:(close)|keep-alive)}mig) {
	return $1 ? 0:1;
    }
    # keep-alive by response
    return $hdr =~m{\A.* HTTP/1\.(?:0|(1))} ? $1 ? 0:1:1;
}

package App::DubiousHTTP::TestServer::Select;
use Scalar::Util 'weaken';

my $maxfn = 0;
my @handler;
my @mask = ('','');
my @tmpmask;

sub new { bless {},shift }
sub delete {
    my ($self,$cl) = @_;
    defined( my $fn = fileno($cl) ) or die "invalid fd";
    $DEBUG && warn "remove fd $fn\n";
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
	$DEBUG && warn "add handler($fn,$rw)\n";
    }
}

sub mask {
    my ($self,$cl,%val) = @_;
    defined( my $fn = fileno($cl) ) or die "invalid fd";
    while (my ($rw,$val) = each %val) {
	$DEBUG && warn "set mask($fn,$rw) to $val\n";
	vec($mask[$rw],$fn,1) = $val;
    }
}

sub loop {
    loop:
    @tmpmask = @mask;
    my $rv = select($tmpmask[0],$tmpmask[1],undef,undef);
    $DEBUG && warn "select -> $rv\n";
    die "loop failed: $!" if $rv <= 0;
    for my $rw (0,1) {
	for( my $fn=0; $fn<=$maxfn; $fn++) {
	    vec($tmpmask[$rw],$fn,1) or next;
	    $DEBUG && warn "selected($fn,$rw)\n";
	    my $sub = $handler[$fn][$rw] or die "no handler";
	    $sub->[0](@{$sub}[1..$#$sub]);
	}
    }
    goto loop;
}

1;
