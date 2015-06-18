use strict;
use warnings;
package App::DubiousHTTP::Tests::Chunked;
use App::DubiousHTTP::Tests::Common;

SETUP(
    'chunked',
    "Variations of server side chunked encoding",
    <<'DESC',
Various tests with invalid or uncommon forms of setting or not setting the
Transfer-Encoding: chunked header:
- chunked is not defined for HTTP/1.0, but some systems still interprete the
  header for HTTP/1.0 responses
- some systems do not support breaking HTTP header over multiple lines
- some systems are happy if 'chunked' is matched somewhere in the header,
- some even interprete the existence of a Transfer-Encoding header as enough
  to expect chunked data
Details see http://noxxi.de/research/dubious-http.html
DESC

    # ------------------------ Tests -----------------------------------
    [ 1,'simple chunked encoding', 
	[ 'chunked' => 'valid chunking'],
	[ 'chUnked' => 'valid chunking mixed case'],
	# according to RFC2616 TE chunked has preference to clen
	[ 'chunked,clen' => 'chunking and content-length'],
	# continuations lines are ok
	[ 'nl-chunked' => "chunked header with continuation line"],
	#[ 'chunked-semicolon' => "Transfer-Encoding: chunked;" ],
	[ 'chunked-ext-junk' => "some junk chunk extension" ],
	[ 'chunked-ext-chunk' => "some junk chunk extension looking like a chunk" ],
	[ 'chunked-lf' => "chunk with LF as delimited instead of CRLF" ],
    ],
    [ 1,'chunked encoding gets prefered over content-length',
	[ 'clen' => 'valid content-length'],
    ],
    [ 0, 'chunking is only allowed with HTTP/1.1', 
	[ 'chunked,http10' => 'chunking with HTTP/1.0'],
	[ 'chunked,clen,http10' => 'chunking and content-length with HTTP/1.0'],
    ],
    [ 0, 'invalid variations on "chunked" value',
	[ 'chu' => '"chu" not "chunked"'],
	[ 'xchunked' => '"xchunked" not "chunked"'],
	[ 'chunkedx' => '"chunkedx" not "chunked"'],
	[ 'chunked-x' => '"chunked x" not "chunked"'],
	[ 'x-chunked' => '"x chunked" not "chunked"'],
	[ 'x-nl-chunked' => '"x-folding-chunked" not "chunked"'],
	[ 'rfc2047,do_chunked' => "rfc2047 encoded with base64, serve chunked" ],
	[ 'rfc2047,do_clen' => "rfc2047 encoded with base64, not served chunked" ],
	[ 'rfc2047,clen,do_clen' => "rfc2047 encoded with base64, serve with content-length" ],
	[ 'xte,chunked,do_chunked' => "double Transfer-Encoding: first junk, last chunked. Served chunked." ],
	[ 'chunked,xte,do_chunked' => "double Transfer-Encoding: first chunked, last junk. Served chunked." ],
	[ 'chunked,xte,clen,do_chunked' => "double Transfer-Encoding: first chunked, last junk. Served chunked but include content-length header." ],
	[ 'xte,chunked,clen,do_chunked' => "double Transfer-Encoding: first junk, last chunked. Served chunked but include content-length header." ],
    ],
);


sub make_response {
    my ($self,$page,$spec) = @_;
    return make_index_page() if $page eq '';
    my ($hdr,$data) = content($page,$spec) or die "unknown page $page";
    my $version = '1.1';
    my $te;
    for (split(',',$spec)) {
	if ( ! $_ || $_ eq 'chunked' ) {
	    $hdr .= "Transfer-Encoding: chunked\r\n"
	} elsif ( $_ eq '1chunk' ) {
	    $hdr .= "Transfer-Encoding: chunked\r\n";
	    $te = $_
	} elsif ( $_ eq 'chUnked' ) {
	    $hdr .= "Transfer-Encoding: chUnked\r\n"
	} elsif ( m{^(.*-)?nl-chunked$} ) {
	    my $prefix = $1 //'';
	    $hdr .= "Transfer-Encoding: $prefix\r\n chunked\r\n"
	} elsif ( $_ eq 'chu' ) {
	    $hdr .= "Transfer-Encoding: chu\r\n"
	} elsif ( $_ eq 'xchunked' ) {
	    $hdr .= "Transfer-Encoding: xchunked\r\n"
	} elsif ( $_ eq 'chunkedx' ) {
	    $hdr .= "Transfer-Encoding: chunkedx\r\n"
	} elsif ( $_ eq 'x-chunked' ) {
	    $hdr .= "Transfer-Encoding: x chunked\r\n"
	} elsif ( $_ eq 'chunked-x' ) {
	    $hdr .= "Transfer-Encoding: chunked x\r\n"
	} elsif ( $_ eq 'clen' ) {
	    $hdr .= "Content-length: ".length($data)."\r\n"
	} elsif ( $_ eq 'http10' ) {
	    $version = "1.0";
	} elsif ( $_ eq 'do_clen' ) {
	    $te = 'clen'
	} elsif ( $_ eq 'do_chunked' ) {
	    $te = 'chunked'
	} elsif ( $_ eq 'chunked-semicolon' ) {
	    $hdr .= "Transfer-Encoding: chunked;\r\n"
	} elsif ( m{^chunked-ext|^chunked-lf}) {
	    $hdr .= "Transfer-Encoding: chunked\r\n";
	    $te = $_
	} elsif ( $_ eq 'rfc2047' ) {
	    $hdr .= "Transfer-Encoding: =?UTF-8?B?Y2h1bmtlZAo=?=\r\n";
	} elsif ( $_ eq 'xte' ) {
	    $hdr .= "Transfer-Encoding: lalala\r\n";
	} else {
	    die $_
	}
    }
    $hdr = "HTTP/$version 200 ok\r\n$hdr";
    $te ||= $hdr =~m{^Transfer-Encoding:}im ? 'chunked':'clen';
    if ( $te eq 'chunked' ) {
	$data = join("", 
	    map { sprintf("%x\r\n%s\r\n",length($_),$_) } 
	    ( $data =~m{(..)}smg,'')
	)
    } elsif ( $te eq '1chunk' ) {
	$data = sprintf("%0x\r\n%s\r\n0\r\n\r\n",length($data),$data);
    } elsif ($te eq 'chunked-ext-junk') {
	$data = join("", 
	    map { sprintf("%x; foobar\r\n%s\r\n",length($_),$_) } 
	    ( $data =~m{(..)}smg,'')
	)
    } elsif ($te eq 'chunked-ext-chunk') {
	$data = join("", 
	    map { sprintf(
		"%x; %s  %x\r\n%s\r\n",
		length($_),                    # chunk length
		"x" x length($_), length($_),  # chunk extensions looking like chunk if any two bytes are skipped instead of \r\n
		$_                             # chunk
	    )} 
	    ( $data =~m{(..)}smg,'')
	)
    } elsif ($te eq 'chunked-lf') {
	$data = join("", 
	    map { sprintf("%x\n%s\n",length($_),$_) } 
	    ( $data =~m{(..)}smg,'')
	)
    }

    return "$hdr\r\n$data";
}


1;
