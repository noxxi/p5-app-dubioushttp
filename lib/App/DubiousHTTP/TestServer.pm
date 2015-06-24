use strict;
use warnings;
package App::DubiousHTTP::TestServer;
use AnyEvent;
use IO::Socket;

my $MAX_CLIENTS = 10;

sub run {
    shift;
    my ($addr,$response) = @_;
    my $srv = IO::Socket::INET->new( LocalAddr => $addr, Listen => 10, Reuse => 1 );
    my @clients;
    my $listen = AnyEvent->io(
	fh => $srv,
	poll => 'r',
	cb => sub {
	    my $cl = $srv->accept or return;
	    @clients = grep { %$_ } @clients; # remove done clients
	    while (@clients> $MAX_CLIENTS) {
		my $fo = shift(@clients);
		#warn "destroy client from ".( time() - $fo->{time} )." ago\n";
		%$fo = ();
	    }
	    push @clients, new_client($cl,$response);
	}
    );
    AnyEvent->condvar->recv;
}

sub new_client {
    my ($cl,$response) = @_;
    my $addr = $cl->sockhost.':'.$cl->sockport;
    my %fo = ( 
	read  => { buf => '' }, 
	write => { buf => '' },
	time  => time(),
    );

    my ($clen,$hdr,$page,$payload);
    $fo{read}{sub} = sub {
	my $rbuf = \$fo{read}{buf};
	my $n = sysread($cl,$$rbuf,8192,length($$rbuf));
	if ( ! $n ) {
	    %fo = () if defined($n) || ! $!{EAGAIN}; # eof or connection broke
	    return;
	}

	handle_data:
	if (defined $clen) {
	    # has header, extract payload
	    if (length($$rbuf) > $clen) {
		$payload .= substr($$rbuf,0,$clen,'');
		$clen = 0;
	    } else {
		$payload .= $$rbuf;
		$clen -= length($$rbuf);
		$$rbuf = '';
	    }
	    return if $clen>0; # need more

	    if ( ! eval { $fo{write}{buf} .= $response->($page,$addr,$hdr,$payload) } ) {
		warn "creating response failed: $@\n";
		%fo = ();
		return;
	    }
		
	    $fo{write}{sub}->();
	    return;

	} elsif ( $$rbuf =~m{(\r?\n)\1}g ) {
	    # read header
	    $hdr = substr($$rbuf,0,pos($$rbuf),'');
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
		print $cl "HTTP/1.0 204 ok\r\n\r\n";
		%fo = ();
		return;
	    };
	    $clen = $method eq 'POST' && $hdr =~m{^Content-length:[ \t]*(\d+)}mi && $1 || 0;
	    if ($clen > 2**16) {
		warn "request body too large ($clen)";
		%fo = ();
		return;
	    }
	    $page =~s{%([\da-fA-F]{2})}{ chr(hex($1)) }esg; # urldecode
	    goto handle_data;

	} elsif ( length($$rbuf)>4096 ) {
	    warn "request header too large";
	    %fo = ();
	    return;
	}
    };

    $fo{write}{sub} = sub {
	my $wbuf = \$fo{write}{buf};
	if ( $$wbuf eq '' ) {
	    # nothing to write
	    $fo{write}{watch} = undef;
	    return;
	}
	my $n = syswrite($cl,$$wbuf);
	if ( ! $n ) {
	    if ( defined($n) || ! $!{EAGAIN} ) {
		# connection broke
		%fo = ();
		return;
	    }
	} else {
	    substr($$wbuf,0,$n,'');
	}
	if ( $$wbuf eq '' ) {
	    $fo{write}{watch} = undef;
	    %fo = (); # done with request
	} else {
	    $fo{write}{watch} ||= AnyEvent->io(
		fh => $cl,
		poll => 'w',
		cb => sub { $fo{write}{sub}->() }
	    );
	}
    };

    $fo{read}{watch} = AnyEvent->io(
	fh => $cl,
	poll => 'r',
	cb => sub { $fo{read}{sub}->() }
    );

    return \%fo;
}

1;
