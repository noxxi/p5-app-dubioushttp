#!/usr/bin/perl
use strict;
use warnings;
use Getopt::Long qw(:config posix_default bundling);

sub usage { 
    print STDERR <<USAGE;

Checks the sanity of the servers response, i.e. if it is uses invalid HTTP or
uncommon features of HTTP, which might be interpreted differently by browsers or
firewalls. 
The intended use is to use it as a client against the HTTP Evader test server
and to put a proxy in between to detect, how good the proxy is able to sanitize
the traffic.

Usage: $0 [-h|--help] [-P|--proxy P] [-M|--manifest url] [url...]
Options:
 -h|--help          this help
 -M|--manifest URL  uses URL as manifest file for available tests (see below)
 -B|--body F        use expected response body from file F. Will not use body
                    based on manifest then.
 -P|--proxy URL     uses URL as HTTP proxy. If not given will use http_proxy
                    environment variable. Set to '' to definitely use no proxy.

Features:
- detection of invalid HTTP headers and invalid chunking
- detection of corrupted but usable gzip data
- detection if uses compression algorithms match the content-encoding of the
  HTTP header
- detection of other invalid or uncommon HTTP responses as offered by 
  HTTP Evader, see also http://noxxi.de/research/http-evader.html
Limitations:
- will not accept any body size larger than 2^17

The results will be of the form:
  what|id info
where 'what' is either BAD, WARN or NOTE, 'id' is the id from manifest (see
below) or the URL and info is an id for the problem. If the resulting HTTP
response does not match the expected response no matter how robust the client
behaves then only the result of 'BAD|id match:mismatch' is given for this test
since all other problems are irrelevant anyway.

Format of manifest:
The manifest is a text/plain document consististing of lines as follows:
  id | path | validity | description
'id' is a short name for the test and 'path' the absolute path (host from
manifest-URL is used). 'validity' is >0 if a fully valid response is sent by the
server, ==0 if an invalid response is sent and for the edge cases -1 (valid, but
unusual) or -2 (invalid, but common) is given. If the validity is 3 this URL
will be considered absolutely sane and will be used to retrieve the body which
then will be expected in the following tests.

USAGE
    exit(2);
    
}

my ($proxy,@todo,$payload);
GetOptions(
    'h|help' => sub { usage() },
    'P|proxy=s' => \$proxy,
    'M|manifest=s' => sub {
	my $url = $_[1];
	$url .= "manifest/all/novirus.txt" if $url =~m{^(\w+://[^/]+)/\z};
	push @todo, {
	    url => $url,
	    manifest => 1,
	}
    },
    'B|body=s' => sub {
	open( my $fh,'<',$_[1]) or die "cannot read file $_[1]: $!";
	local $/;
	$payload = <$fh>;
    },
);

$|=1;

push @todo, @ARGV;
@todo or usage("no manifest or other URL's given");

my (%bad,%warn,%note);
my (%lbad,%lwarn,%lnote);
my $ua = UA->new( 
    defined($proxy) ? ( proxy => $proxy ) : (env_proxy => 1), 
    bad => \%lbad, warn => \%lwarn, note => \%lnote
);

while (my $todo = shift(@todo)) {
    if (!ref($todo)) {
	unshift @todo,{ 
	    url => $todo,
	    body => $payload,
	};
	next;
    }
    if ($todo->{manifest}) {
	my @t;
	my ($base) = $todo->{url} =~m{^(\w+://[^/]+)/} or die;
	my $resp = $ua->request($todo->{url});
	for( split(m{\r?\n},$resp) ) {
	    m{\S} or next;
	    my ($num,$id,$path,$expect,$desc) = split(m{ \| },$_,5);
	    $desc or next;
	    if ($expect == 3) {
		$payload = $ua->request($base.$path)
		    or die "failed to retrieve $base$path";
	    } else {
		push @t, {
		    num => $num,
		    id => $id,
		    url => $base.$path,
		    expect => $expect,
		    desc => $desc,
		    body => $payload,
		};
	    }
	}
	unshift @todo,@t;
	next;
    }

    if (my $sub = $todo->{sub}) {
	$sub->($todo);
    }
    my $url = $todo->{url} or next;
    %lbad = %lwarn = %lnote = ();
    my $body = $ua->request($url);
    if ($todo->{body}) {
	my ($mismatch,$match);
	if ( $todo->{body} eq $body) {
	    $match = 'same';
	} elsif ($body eq '') {
	    $mismatch = 'empty';
	} elsif (( my $pos = index($body,$todo->{body}))>=0) {
	    $mismatch = $match = "substr($pos)"
	} elsif (( $pos = index($todo->{body},$body))>=0) {
	    $mismatch= $match = "part($pos,".length($body).")"
	} else {
	    $mismatch = 'mismatch'
	}
	if (defined(my $e = $todo->{expect})) {
	    %lbad = %lwarn = %lnote = () if $mismatch && !$match;
	    if ($mismatch) {
		if ($e>0) {
		    $lbad{"match:$mismatch"} =1;
		} elsif ($e<0) {
		    $lnote{"match:$mismatch"} =1;
		}
	    } elsif ($match) {
		if ($e == 0) {
		    $lbad{"match:$match"} =1;
		} elsif ($e<0) {
		    $lnote{"match:$match"} =1;
		}
	    }

	}
    }

    my $num = $todo->{num} || '-';
    my $id = $todo->{id} || $todo->{url};
    for(sort keys %lnote) {
	push @{ $note{$_} },$id;
	print "NOTE|$num|$id $_\n";
    }
    for(sort keys %lwarn) {
	push @{ $warn{$_} },$id;
	print "WARN|$num|$id $_\n";
    }
    for(sort keys %lbad) {
	push @{ $bad{$_} },$id;
	print "BAD|$num|$id $_\n";
    }
}

sub show_result {
    print "NOTE $_: @{$note{$_}}\n" for sort keys %note;
    print "WARN $_: @{$warn{$_}}\n" for sort keys %warn;
    print "BAD $_: @{$bad{$_}}\n" for sort keys %bad;
}


package UA;
use IO::Socket::INET;
use Compress::Raw::Zlib;
use Compress::Raw::Lzma;

my $IOCLASS;
my $host46port;
BEGIN {
    $IOCLASS = 
	eval { require IO::Socket::IP; 'IO::Socket::IP' } ||
	eval { require IO::Socket::INET6; 'IO::Socket::INET6' } ||
	'IO::Socket::INET';
    $host46port = qr{(?:([\w\-\.]+)|\[([^\]]+)\])(?::(\w+))?};
}

sub new {
    my ($class,%args) = @_;
    my $proxy = delete $args{proxy};
    $proxy ||= $args{env_proxy} && $ENV{http_proxy};
    my ($proxy_ip,$proxy_port) = 
	! $proxy ? () :
	$proxy =~m{^(?:http://)?$host46port/*\z}o ? ($1||$2,$3) :
	die "invalid proxy specification";

    return bless {
	%args,
	$proxy_ip ? ( proxy => [ $proxy_ip, $proxy_port ] ):(),
    }, $class;
}

sub request {
    my ($self,$url) = @_;
    $url =~m{^http(s?)://($host46port)(/.*)}o or die "invalid url $url";
    my ($secure,$host,$dst,$port,$path) = ($1,$2,$3||$4,$5,$6);
    $secure and die "https:// not supported yet";
    my $fd = _connect($self, $self->{proxy} || [ $dst,$port ]);
    my $rq = "GET ".($self->{proxy} ? $url : $path)." HTTP/1.1\r\n".
	"Host: $host\r\n".
	"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n".
	"Accept-Encoding: gzip, deflate\r\n".
	"Accept-Language: en-US;q=0.8,en;q=0.6\r\n".
	"User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2490.86 Safari/537.36\r\n".
	"Connection: close\r\n".
	"\r\n";
    print $fd $rq;

    my $buf = '';
    my ($hdr,$body);
    vec( my $vec = '',fileno($fd),1) = 1;
    $fd->blocking(0);
    while (!defined $body 
	and length($buf) < 2**17
	and select(my $r = $vec,undef,undef,5)) {
	sysread($fd,$buf,16384,length($buf)) or last;
	$hdr ||= _read_hdr($self,\$buf);
	$body = _read_body($self,\$buf,$hdr) if $hdr;
    }

    if (!$hdr && $buf ne '') {
	# assume HTTP/0.9
	$self->{bad}{'http09'} = 1;
	$hdr = {};
    }

    if ($hdr) {
	$body //= _read_body($self,\$buf,$hdr,1);
	_decode_body($self,\$body,$hdr) if defined $body;
	$self->{bad}{'data-behind-body'} =1 if $buf ne '';
    } else {
	$self->{warn}{'empty-response'} = 1;
    }



    close($fd);
    return $body // '';
}

sub _connect {
    my ($self,$dst) = @_;
    return $IOCLASS->new(
	PeerAddr => $dst->[0],
	PeerPort => $dst->[1] || 80,
    ) || die "failed to connect to @$dst: $@";
}

sub _read_hdr {
    my ($self,$buf) = @_;
    $$buf =~m{HTTP.*?(\r?\n\r?\n)}si 
	|| $$buf =~m{HTTP.*?(\r?\n[ \t\r\v\f\240]+\n)}si # no so empty (white-space)
	|| return;
    my $hdr = substr($$buf,0,$-[1]);
    substr($$buf,0,$+[1],'');
    my $end = $1;

    # analyze header for abnormal stuff =============
    my $warn = $self->{warn}||={};
    my $bad  = $self->{bad} ||={};

    # End of header ---------------------------------
    if ($end eq "\r\n\r\n") { # good
    } elsif ($end eq "\n\n") {
	$warn->{'end:nlnl'} = 1;
    } else {
	$bad->{'end:white-space'} = 1;
    }

    # Strange characters inside ---------------------
    # remove all control WS CR LF
    $bad->{'char:ctrl'} = 1 if $hdr =~s{[^\r\n\t\x20-\x7e\x80-\xff]}{}g;
    # neutralize all 8bit
    $bad->{'char:8bit'} = 1 if $hdr =~s{[\x80-\xff]}{.}g;

    # Normalize line-ends --------------------------
    # change all standalone CR to CRLF
    $bad->{'lineend:cr'} = 1 if $hdr =~s{\r(?!\n)}{\r\n}g;
    # change all standalone LF to CRLF
    $warn->{'lineend:nl'} = 1 if $hdr =~s{(?<!\r)\n}{\r\n}g;

    # extract important header lines ---------------
    my (@hdr,%hdr,$status,$pre);
    for(split(m{\r\n},$hdr)) {
	if (!defined $status) {
	    if (m{\A([^\w]*)(HTTP.*\z)}mi) {
		$status = $2;
		$bad->{'junk-before-status'} = 1 if $1 ne '';
	    } elsif (m{\S}) {
		$bad->{'junk-before-status'} = 1;
	    } else {
		$bad->{'ws-before-status'} = 1;
	    }
	} else {
	    if (my ($k,$space,$v) = m{^([^:\s]+)([ \t\v\f\240\000]*):\s*(.*?)\s*\z}) {
		$bad->{'ws-before-colon'} =1 if $space ne '';
		$bad->{'invalid-hdrkey'} =1 if $k !~ m{^([\x21-\x39\x3b-\x7e]+)\z};
		$v =~ s{\s+\z}{};
		$k = lc($k);
		push @hdr,[ $k, $v ];
		push @{ $hdr{$k} }, $v;
	    } elsif (@hdr && m{^[ \t]}) {
		$hdr[-1][1].= $_;
		$bad->{folding} = 1;
		$hdr{ $hdr[-1][0] }[-1].= $_;
	    } else {
		# lines with invalid data
		$bad->{'invalid-hdrline'} = 1;
	    }
	}
    }

    my ($version,$code);
    if ($status =~s{^HTTP/(1\.[01])}{}) {
	$version = $1
    } elsif ($status =~s{^\w+/\d+(?:\.\d+)?}{}i) {
	$bad->{'protocol:malformed'} = 1;
    }
    if ($status =~s{^[ ](?=\S)|^([ \t]+)(?=\S)}{}) {
	$bad->{'invalid-ws-status'} = 1 if defined $1;
	if ($status =~s{(\d\d\d)($| +)}{}) {
	    $code = $1
	} else {
	    $bad->{'code:malformed'} = 1;
	}
    } else {
	$bad->{'code:none'} = 1;
    }

    my ($need_location,$need_auth,$no_body);
    if ($code) {
	if ($code<100 || $code>599) {
	    $bad->{'code:out-of-range'} = 1;
	} elsif ($code<200) {
	    $bad->{'code:1xx'} = 1;
	} elsif ($code<300) {
	    if ($code == 200) {
	    } elsif ($code == 204 || $code == 205) {
		$no_body = 1;
	    } else {
		$bad->{'code:unknown-2xx'} = 1;
	    }
	} elsif ($code<400) {
	    $need_location = ($code != 304);
	} elsif ($code<500) {
	    $need_auth = $code if $code == 401 || $code == 407;
	}
    }

    my $chunked;
    if (my $te = $hdr{'transfer-encoding'}) {
	if (!$version || $version ne '1.1') {
	    $bad->{'chunked:wrong-version'} = 1;
	}
	if ($no_body) {
	    $warn->{'chunked-hdr:but-code-nobody'} = 1;
	}
	$chunked = my $badte = 0;
	for(@$te) {
	    if ($_ eq 'chunked') { # fine
		$chunked++;
	    } elsif (lc($_) eq 'chunked') {
		$chunked++;
		$warn->{'chunked-hdr:mixed-case'} = 1;
	    } elsif (m{\b(chunked)\b}i) {
		$chunked++;
		$bad->{'chunked-hdr:subword'} = 1;
		$warn->{'chunked-hdr:mixed-case'} = 1 if lc($1) ne $1;
	    } elsif (m{(chunked)}i) {
		$chunked++;
		$bad->{'chunked-hdr:substring'} = 1;
		$warn->{'chunked-hdr:mixed-case'} = 1 if lc($1) ne $1;
	    } else {
		$badte++;
		$bad->{'te:invalid'} = 1;
	    }
	}
	if ($badte && $chunked) {
	    $bad->{'chunked-hdr:multiple-different'} = 1;
	} elsif ($chunked>1) {
	    $warn->{'chunked-hdr:multiple-same'} = 1;
	}
    }

    my $content_length;
    if (my $clen = $hdr{'content-length'}) {

	if ($chunked) {
	    $warn->{'clen:superset-by-chunked'} = 1;
	}

	for(@$clen) {
	    my $l;
	    if (m{\A(\d+)\z}) {
		$l = $1;
	    } elsif (m{\b(\d+)\b}) {
		$bad->{'clen:subword'} = 1;
		$l = $1;
	    } elsif (m{(\d+)}) {
		$bad->{'clen:substring'} = 1;
		$l = $1;
	    } else {
		$bad->{'clen:invalid'} = 1;
	    }
	    if (defined $l) {
		if (defined $content_length) {
		    if ($content_length == $l) {
			$warn->{'clen:multiple-same'} = 1;
		    } else {
			$bad->{'clen:multiple-different'} = 1;
			$content_length = -1;
		    }
		} else {
		    $content_length = $l;
		}
	    }
	}

	$content_length = undef if $content_length && $content_length<0;
	if ($content_length && $no_body) {
	    $warn->{'clen:but-code-nobody'} = 1;
	    $content_length = 0;
	}
    }

    my @ce;
    if (my $ce = $hdr{'content-encoding'}) {
	for (@$ce) {
	    for (split(m{\s*,\s*})) {
		if (m{^(gzip|deflate|lzma|identity)\z}) {
		} elsif (m{^(gzip|deflate|lzma|identity)\z}i) {
		    $warn->{'ce:mixed-case'} = 1;
		} elsif (m{\b(gzip|deflate|lzma|identity)\b}i) {
		    $warn->{'ce:mixed-case'} = 1 if lc($1) ne $1;
		    $bad->{'ce:subword'} = 1;
		} elsif (m{(gzip|deflate|lzma|identity)}i) {
		    $warn->{'ce:mixed-case'} = 1 if lc($1) ne $1;
		    $bad->{'ce:substring'} = 1;
		} else {
		    $bad->{'ce:invalid'} = 1;
		    next;
		}
		my $e = lc($1);
		if ($e eq 'identity') {
		    $bad->{'ce:identity'} = 1;
		} else {
		    push @ce,$e
		}
	    }
	}
	$bad->{'ce:multiple'} = 1 if @ce>1;
    }

    return {
	kv => \@hdr,
	@ce ? (content_encoding => \@ce):(),
	$chunked ? (chunked => 1):(),
	defined($content_length) ? (content_length => $content_length):(),
    };
}

sub _read_body {
    my ($self,$buf,$hdr,$eof) = @_;

    my $clen = $hdr->{content_length};
    if (defined $clen) {
	# length defined by Content-length header
	return if length($$buf)<$clen;
	return substr($$buf,0,$clen,'');
    }
    if (!$hdr->{chunked}) {
	# End with EOF
	return if ! $eof;
	my $data = $$buf;
	$$buf = '';
	return $data;
    }

    # chunked
    my $size = undef;
    my @chunks;
    while (1) {
	if (!defined $size) {
	    # size not known yet -> read size
	    if ($$buf =~m{\G([^\da-f]*)([\da-f]+)(.*?)\n}gci) {
		$size = hex($2);
		$self->{warn}{'chunked:mixed-case-size'} = 1 if lc($2) ne $2;
		$self->{bad}{'chunked:junk-before-size'} = 1 if length($1);
		if ($3 eq "") {
		    $self->{warn}{'chunked:nl-not-crlf'} = 1;
		} elsif ($3 ne "\r") {
		    $self->{bad}{'chunked:junk-after-size'} = 1;
		}
	    } elsif ($eof) {
		last;
	    } else {
		return;
	    }
	} elsif ($size) {
	    # read chunk of given size>0
	    if ($$buf =~m{\G(.{$size})(\r?\n)}gcs) {
		push @chunks,$1;
		$self->{warn}{'chunked:nl-not-crlf'} = 1 if $2 eq "\n";
		$size = undef;
	    } elsif ($eof) {
		last;
	    } else {
		return;
	    }
	} elsif ($$buf =~m{\G([^\n]*)\n}gc) {
	    # last chunk with size==0
	    if ($1 eq "") {
		$self->{warn}{'chunked:nl-not-crlf'} = 1;
	    } elsif ($1 ne "\r") {
		$self->{warn}{'chunked:junk-inside-final'} = 1;
	    }
	    last;
	} elsif ($eof) {
	    last;
	} else {
	    # wait for more
	    return;
	}
    }
    if (pos($$buf)) {
	substr($$buf,0,pos($$buf),'');
	return join('',@chunks);
    } elsif ($eof) {
	# not chunked?
	$self->{bad}{'chunked:not-chunked'} = 1;
	my $data = $$buf;
	$$buf = '';
	return $data;
    }
}

sub _decode_body {
    my ($self,$body,$hdr) = @_;
    my @real_ce;
    while ($$body ne '') {
	push @real_ce, _try_decode($self,$body) || last;
    }
    my $hdr_ce = $hdr->{content_encoding} || [];

    if ("@real_ce" eq "@$hdr_ce") {
    } elsif (@real_ce == @$hdr_ce) {
	$self->{warn}{'ce:body-wrong-order'} = 1;
    } elsif (@real_ce>@$hdr_ce) {
	$self->{warn}{'ce:body-more-ce'} = 1;
    } else {
	$self->{warn}{'ce:body-less-ce'} = 1;
    }
}

sub _try_decode {
    my ($self,$body) = @_;
    my ($out,$ce,$data);
    if ( defined( $out = _gzip(\( $data = $$body),$self))) {
	$ce = 'gzip';
    } elsif ( defined( $out = _deflate(-MAX_WBITS(),\( $data = $$body),$self))) {
	$ce = 'deflate';
    } elsif ( defined( $out = _deflate(+MAX_WBITS(),\( $data = $$body),$self))) {
	$ce = 'deflate';
	$self->{bad}{'ce:deflate-raw'} = 1;
    } elsif ( defined( $out = _lzma(\($data = $$body),$self))) {
	$ce = 'lzma';
	$self->{bad}{'ce:lzma'} = 1;
    } else {
	return
    }

    $self->{bad}{'ce:junk-after-body'} = 1 if $data ne '';
    $$body = $out;
    return $ce;
}

sub _deflate {
    my ($wb,$in,$self) = @_;
    my $zlib = Compress::Raw::Zlib::Inflate->new(
	-WindowBits => $wb,
	-ConsumeInput => 1,
	-AppendOutput => 1,
    );
    my $out = '';
    my $status = $zlib->inflate($in,$out);
    if ($status == Z_STREAM_END) {
	return $out
    } elsif ($status == Z_OK) {
	$self->{'ce:incomplete-body'} = 1;
	return $out;
    } else {
	return;
    }
}

sub _gzip {
    my ($in,$self) = @_;
    return if substr($$in,0,2) ne "\x1f\x8b";
    my $data = $$in;
    my (%bad,%warn);
    my ($cm,$flg) = unpack("x2CCx4x2",substr($data,0,10,''));
    $bad{'bad-compression-method'} = 1 if $cm != 8;
    $warn{'ftext'} = 1 if $flg & 0b1;  # FTEXT
    if ($flg & 0b100) { # FEXTRA
	$bad{'extra'} = 1;
	my $len = unpack("v",$data);
	substr($data,0,$len+2,'');
    }
    if ($flg & 0b1000) { # FNAME
	$warn{'fname'} = 1;
	return if $data !~s{^[^\000]*\000}{};
    }
    if ($flg & 0b1_0000) { # FCOMMENT
	$bad{'fcomment'} = 1;
	return if $data !~s{^[^\000]*\000}{};
    }
    if ($flg & 0b10) { # FHCRC
	$bad{'fhcrc'} = 1;
	my $crc = substr($data,0,2,'');
	$bad{'badhcrc'} = 1 if $crc eq "\000\000";
    }
    my $out = _deflate(-MAX_WBITS(),\$data,$self) // return;
    my ($crc,$isize);
    if (length($data) <8 ) {
	$bad{'missing-isize'} = 1;
	if (length($data) <4 ) {
	    $bad{'missing-crc'} = 1;
	} else {
	    $crc = unpack("V",substr($data,0,4,''));
	}
    } else {
	($crc,$isize) = unpack("VV",substr($data,0,8,''));
	$bad{'invalid-isize'} =1 if $isize != length($out);
    }

    if (defined $crc and $crc != Compress::Raw::Zlib::crc32($out)) {
	$bad{'invalid-crc'} =1;
    }

    $$in = $data;
    $self->{bad}{'ce:gzip-'.$_} = 1 for keys %bad;
    $self->{warn}{'ce:gzip-'.$_} = 1 for keys %warn;
    return $out;
}


sub _lzma {
    my ($in,$self) = @_;
    my ($lzma,$status) = Compress::Raw::Lzma::AloneDecoder->new(
	AppendOutput => 1,
	ConsumeInput => 1,
    );
    $status == LZMA_OK or die $status;
    my $out = '';
    $status = $lzma->code($in,$out);
    if ($status == LZMA_STREAM_END) {
	return $out
    } elsif ($status == LZMA_OK) {
	$self->{'ce:incomplete-body'} = 1;
	return $out;
    } else {
	return;
    }
    return $out;
}
