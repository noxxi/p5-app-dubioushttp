use strict;
use warnings;
package App::DubiousHTTP::Tests::Clen;
use App::DubiousHTTP::Tests::Common;

SETUP(
    'clen',
    "playing with content-length",
    <<'DESC',
These tests look at the behavior if the content-length mismatches the content,
e.g. content is short or longer then specified length or contradicting 
content-lenth headers are given.
DESC

    # ------------------------ Tests -----------------------------------
    [ 1,'single or no content-length', 
	[ 'close,clen,content' => 'single content-length with connection close'],
	#[ 'keep-alive,clen,content' => 'single content-length with keep-alive'],
	[ 'close,content' => 'no content-length with connection close'],
	[ 'close,clen,content,junk' => 'single content-length with connection close, content followed by junk'],
	[ 'close,clen,clen,content,junk' => 'correct content-length twice, content followed by junk' ],
    ],
    [ 0, 'content-length does not match content', 
	[ 'close,clen200,content' => 'content-length double real content, eof after real content' ],
	[ 'close,clen50,content' => 'content-length half real content, eof after real content' ],
    ],
    [ 0, 'double content-length', 
	[ 'close,clen50,clen,content' => 'content-length half and full' ],
	[ 'close,clen,clen50,content' => 'content-length full and half' ],
	[ 'close,clen200,clen,content,junk' => 'content-length double and full' ],
	[ 'close,clen,clen200,content,junk' => 'content-length full and double' ],
	[ 'close,clen-folding100,clen200,content,junk' => 'content-length full (folded) and double' ],
    ],
    [ 0, 'content-length header containing two numbers',
	[ 'close,clen50-folding100,content' => 'content-length half but full after line folding, eof after real content' ],
	[ 'close,clen50-100,content' => 'content-length half and full on same line, eof after real content' ],
	[ 'close,clen100-folding50,content' => 'content-length full but half after line folding, eof after real content' ],
	[ 'close,clen100-50,content' => 'content-length full and half on same line, eof after real content' ],
	[ 'close,clen100-folding200,content,junk' => 'content-length full but double after line folding, eof after real content+junk' ],
	[ 'close,clen200-folding100,content,junk' => 'content-length double but full after line folding, eof after real content+junk' ],
    ],

);


sub make_response {
    my ($self,$page,$spec) = @_;
    return make_index_page() if $page eq '';
    my ($hdr,$data) = content($page,$spec) or die "unknown page $page";
    my $version = '1.1';
    my $body;
    my $te;
    for (split(',',$spec)) {
	if ( ! $_ || $_ eq 'close' ) {
	    $hdr .= "Connection: close\r\n";
	} elsif ( s{^clen(\d+)?}{} ) {
	    $hdr .= "Content-length: ";
	    $hdr .= int((($1||100)/100)*length($data)) if $1 || $_ eq '';
	    while (s{^-(folding)?(\d+)}{}) {
		$hdr .= "\r\n" if $1;
		$hdr .= " ".int(($2/100)*length($data));
	    }
	    $hdr .= "\r\n";
	} elsif ( $_ eq 'content' ) {
	    $body = $data;
	} elsif ( $_ eq 'junk' ) {
	    $body .= 'X' x length($data);
	} else {
	    die $_
	}
    }
    $hdr = "HTTP/$version 200 ok\r\n$hdr";
    return "$hdr\r\n$body";
}


1;
