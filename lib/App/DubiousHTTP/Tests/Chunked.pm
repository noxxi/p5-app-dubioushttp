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
    ]
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
	} elsif ( $_ eq 'chUnked' ) {
	    $hdr .= "Transfer-Encoding: chUnked\r\n"
	} elsif ( $_ eq 'nl-chunked' ) {
	    $hdr .= "Transfer-Encoding:\r\n chunked\r\n"
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
	} else {
	    die $_
	}
    }
    $hdr = "HTTP/$version 200 ok\r\n$hdr";
    $te ||= $hdr =~m{^Transfer-Encoding:}im ? 'chunked':'clen';
    if ( $te eq 'chunked' ) {
	$data = join("", map { sprintf("%x\r\n%s\r\n",length($_),$_) } ( $data =~m{(..)}smg,''))
    }
    return "$hdr\r\n$data";
}


1;
