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
<ul>
<li> chunked is not defined for HTTP/1.0, but some systems still interpret the header for HTTP/1.0 responses</li>
<li> some systems do not support breaking HTTP header over multiple lines</li>
<li> some systems are happy if 'chunked' is matched somewhere in the header</li>
<li>some even interprete the existence of a Transfer-Encoding header as enough to expect chunked data</li>
</ul>
DESC

    # ------------------------ Tests -----------------------------------
    [ 'VALID: basic tests' ],
    [ VALID, 'chunked' => 'simple and valid chunking'],
    [ VALID, 'clen' => 'content-length header, not chunked'],

    [ 'VALID: use of extensions in chunked header' ],
    [ VALID, 'chunked-ext-junk' => "chunked with some junk chunk extension" ],
    [ VALID, 'chunked-ext-chunk' => "chunked with some junk chunk extension looking like a chunk" ],

    [ 'VALID: combined with content-length' ],
    # according to RFC2616 TE chunked has preference to clen
    [ VALID, 'chunked,clen' => 'chunked first then content-length, served chunked'],
    [ VALID, 'clen,chunked' => 'content-length first then chunked, served chunked'],
    # but some still expect clen bytes
    [ VALID, 'chunked,clen200' => 'chunking and content-length header with double length, served chunked'],
    [ VALID, 'chunked,clen50'  => 'chunking and content-length header with half length, served chunked'],

    [ 'INVALID: chunking is only allowed with HTTP/1.1' ],
    [ INVALID, 'chunked,http10' => 'Chunked Header and HTTP/1.0. Served chunked.'],
    [ INVALID, 'chunked,clen,http10' => 'Chunked Header and Content-length and HTTP/1.0. Served chunked.'],
    [ INVALID, 'clen,chunked,http10' => 'Content-length Header and Chunked and HTTP/1.0. Served chunked.'],

    [ 'VALID: chunked header should be ignored with HTTP/1.0' ],
    [ UNCOMMON_VALID, 'chunked,http10,do_clen' => 'Chunked Header and HTTP/1.0. Not served chunked.'],
    [ UNCOMMON_VALID, 'chunked,clen,http10,do_clen' => 'Chunked Header and Content-length and HTTP/1.0. Not served chunked.'],
    [ UNCOMMON_VALID, 'clen,chunked,http10,do_clen' => 'Content-length Header and Chunked and HTTP/1.0. Not served chunked.'],

    [ 'INVALID: chunking with invalid HTTP versions' ],
    [ INVALID, 'chunked,HTTP/1.2' => 'Chunked Header and HTTP/1.2. Served chunked.'],
    [ INVALID, 'chunked,clen,HTTP/1.2,do_clen' => 'Chunked Header and HTTP/1.2. Not served chunked.'],
    [ INVALID, 'chunked,HTTP/2.0' => 'Chunked Header and HTTP/2.0. Served chunked.'],
    [ INVALID, 'chunked,clen,HTTP/2.0,do_clen' => 'Chunked Header and HTTP/2.0. erved chunked.'],
    [ INVALID, 'chunked,HTTP/2.1' => 'Chunked Header and HTTP/2.1. Served chunked.'],
    [ INVALID, 'chunked,clen,HTTP/2.1,do_clen' => 'Chunked Header and HTTP/2.1. erved chunked.'],
    [ INVALID, 'chunked,HTTP/0.9' => 'Chunked Header and HTTP/0.9. Served chunked.'],
    [ INVALID, 'chunked,clen,HTTP/0.9,do_clen' => 'Chunked Header and HTTP/0.9. Not served chunked.'],
    [ INVALID, 'chunked,HTTP/1.01' => 'Chunked Header and HTTP/1.01. Served chunked.'],
    [ INVALID, 'chunked,clen,HTTP/1.01,do_clen' => 'Chunked Header and HTTP/1.01. Not served chunked.'],
    [ INVALID, 'chunked,HTTP/1.10' => 'Chunked Header and HTTP/1.10. Served chunked.'],
    [ INVALID, 'chunked,clen,HTTP/1.10,do_clen' => 'Chunked Header and HTTP/1.10. Not served chunked.'],
    [ INVALID, 'chunked,http/1.1' => 'Chunked Header and http/1.1. Served chunked.'],
    [ INVALID, 'chunked,clen,http/1.1,do_clen' => 'Chunked Header and http/1.1. Not served chunked.'],
    [ INVALID, 'chunked,http/1.0' => 'Chunked Header and http/1.0. Served chunked.'],
    [ INVALID, 'chunked,clen,http/1.0,do_clen' => 'Chunked Header and http/1.0. Not served chunked.'],

    [ 'VALID: valid variations on "chunked" value' ],
    [ VALID, 'chUnked' => 'mixed case "chUnked", served chunked'],
    [ UNCOMMON_VALID,'nl-chunked' => "chunked header with continuation line, served chunked"],
    [ UNCOMMON_VALID,'nl-nl-chunked' => "chunked header with double continuation line, served chunked"],
    [ UNCOMMON_VALID,'nl-nl-chunked-nl-' => "chunked header with double continuation line and continuation afterwareds, served chunked"],

    [ 'INVALID: invalid variations on "chunked" value' ],
    [ INVALID, 'chu' => '"chu" not "chunked"'],
    [ INVALID, 'chunked-semicolon' => '"Transfer-Encoding: chunked;"' ],
    [ INVALID, 'xchunked' => '"xchunked" not "chunked"'],
    [ INVALID, 'chunkedx' => '"chunkedx" not "chunked"'],
    [ INVALID, 'chunked-x' => '"chunked x" not "chunked"'],
    [ INVALID, 'x-chunked' => '"x chunked" not "chunked"'],
    [ UNCOMMON_INVALID, 'chunked-x,do_clen' => '"chunked x" not "chunked", not served chunked'],
    [ UNCOMMON_INVALID, 'x-chunked,do_clen' => '"x chunked" not "chunked", not served chunked'],
    [ INVALID, 'x-nl-chunked' => '"x-folding-chunked" not "chunked"'],
    [ INVALID, 'rfc2047,do_chunked' => 'rfc2047/base64 encoded "chunked", served chunked' ],
    [ UNCOMMON_VALID, 'rfc2047,do_clen' => 'rfc2047/base64 encoded "chunked", not served chunked' ],
    [ UNCOMMON_VALID, 'rfc2047,clen,do_clen' => 'rfc2047/base64 encoded "chunked" and content-length, not served chunked' ],
    [ INVALID,'nl-chunked,do_clen' => "chunked header with continuation line. Not served chunked."],
    [ INVALID,'nl-nl-chunked,do_clen' => "chunked header with double continuation line, not served chunked"],
    [ INVALID,'ce-chunked,do_chunked' => "Content-encoding chunked instead of Transfer-encoding. Served chunked."],

    [ 'INVALID: hiding with another Transfer-Encoding' ],
    [ INVALID, 'xte,chunked,do_chunked' => "double Transfer-Encoding: first junk, last chunked. Served chunked." ],
    [ INVALID, 'chunked,xte,do_chunked' => "double Transfer-Encoding: first chunked, last junk. Served chunked." ],
    [ INVALID, 'xte,chunked,xte,do_chunked' => "triple Transfer-Encoding: first junk, then chunked, then junk again. Served chunked." ],
    [ INVALID, 'xte,chunked,do_clen' => "double Transfer-Encoding: first junk, last chunked. Not served chunked." ],
    [ INVALID, 'chunked,xte,do_clen' => "double Transfer-Encoding: first chunked, last junk. Not served chunked." ],
    [ INVALID, 'chunked,xte,clen,do_chunked' => "double Transfer-Encoding: first chunked, last junk. Also Content-length header. Served chunked." ],
    [ INVALID, 'xte,chunked,clen,do_chunked' => "double Transfer-Encoding: first junk, last chunked. Also Content-length header. Served chunked." ],
    [ INVALID, 'xte,chunked,xte,clen,do_chunked' => "triple Transfer-Encoding: first junk, then chunked, then junk again. Also Content-length header. Served chunked." ],
    [ INVALID, 'chunked,xte,clen,do_clen' => "double Transfer-Encoding: first chunked, last junk. Also Content-length header. Not served chunked." ],
    [ INVALID, 'xte,chunked,clen,do_clen' => "double Transfer-Encoding: first junk, last chunked. Also Content-length header. Not served chunked." ],
    [ INVALID, 'chunked,clen,do_clen' => 'chunking and content-length, not served chunked'],

    [ 'INVALID: hiding the Transfer-Encoding header' ],
    [ INVALID, 'space-colon-chunked,do_chunked' => '"Transfer-Encoding<space>:", served chunked' ],
    [ UNCOMMON_INVALID, 'space-colon-chunked,do_clen' => '"Transfer-Encoding<space>:", not served chunked' ],
    [ INVALID, 'colon-colon-chunked,do_chunked' => '"Transfer-Encoding::", served chunked' ],
    [ UNCOMMON_INVALID, 'colon-colon-chunked,do_clen' => '"Transfer-Encoding::", not served chunked' ],
    [ INVALID, 'cronly-chunked,do_chunked' => 'Transfer-Encoding with only <CR> as line delimiter before, served chunked' ],
    [ UNCOMMON_INVALID, 'cronly-chunked,do_clen' => 'Transfer-Encoding with only <CR> as line delimiter before, not served chunked' ],
    [ UNCOMMON_INVALID, 'lfonly-chunked,do_chunked' => 'Transfer-Encoding with only <LF> as line delimiter before, served chunked' ],
    [ INVALID, 'lfonly-chunked,do_clen' => 'Transfer-Encoding with only <LF> as line delimiter before, not served chunked' ],

    [ 'INVALID: invalid chunks' ],
    [ INVALID, 'chunked-lf' => "chunk with LF as delimiter instead of CRLF" ],
);


sub make_response {
    my ($self,$page,$spec) = @_;
    return make_index_page() if $page eq '';
    my ($hdr,$data) = content($page,$spec) or die "unknown page $page";
    my $version = 'HTTP/1.1';
    my $te;
    for (split(',',$spec)) {
	if ( m{^(x|-|nl)*chunked(x|-|nl)*$}i ) {
	    s{-}{ }g;
	    s{nl}{\r\n}g;
	    $hdr .= "Transfer-Encoding: $_\r\nConnection: close\r\n";
	} elsif ( $_ eq 'space-colon-chunked' ) {
	    $te = 'chunked';
	    $hdr .= "Connection: close\r\nTransfer-Encoding : chunked\r\n"
	} elsif ( $_ eq 'colon-colon-chunked' ) {
	    $te = 'chunked';
	    $hdr .= "Connection: close\r\nTransfer-Encoding:: chunked\r\n"
	} elsif ( my ($crlf) = m {^(lf|cr)only-chunked$} ) {
	    $te = 'chunked';
	    $hdr = "X-Foo: bar" if $hdr !~s{\r\n\z}{};
	    $hdr .= ($crlf eq 'lf') ? "\n":"\r";
	    $hdr .= "Transfer-Encoding: chunked\r\nConnection: close\r\n";
	} elsif ( $_ eq '1chunk' ) {
	    $hdr .= "Transfer-Encoding: chunked\r\n";
	    $te = $_
	} elsif ( $_ eq 'chu' ) {
	    $hdr .= "Transfer-Encoding: chu\r\nConnection: close\r\n"
	} elsif ( $_ eq 'ce-chunked' ) {
	    $hdr .= "Content-Encoding: chunked\r\nConnection: close\r\n"
	} elsif ( $_ =~ m{^clen(\d+)?$} ) {
	    $hdr .= "Content-length: ". int(($1||100)/100*length($data)) ."\r\n"
	} elsif ( $_ eq 'http10' ) {
	    $version = "HTTP/1.0";
	} elsif ( $_ =~m{^HTTP/\S+}i ) {
	    $version = $_;
	} elsif ( $_ eq 'do_clen' ) {
	    $te = 'clen'
	} elsif ( $_ eq 'do_chunked' ) {
	    $te = 'chunked'
	} elsif ( $_ eq 'chunked-semicolon' ) {
	    $hdr .= "Transfer-Encoding: chunked;\r\nConnection: close\r\n"
	} elsif ( m{^chunked-ext|^chunked-lf}) {
	    $hdr .= "Transfer-Encoding: chunked\r\n";
	    $te = $_
	} elsif ( $_ eq 'rfc2047' ) {
	    $hdr .= "Transfer-Encoding: =?UTF-8?B?Y2h1bmtlZAo=?=\r\nConnection: close\r\n";
	} elsif ( $_ eq 'xte' ) {
	    $hdr .= "Transfer-Encoding: lalala\r\nConnection: close\r\n";
	} else {
	    die $_
	}
    }
    $hdr = "$version 200 ok\r\n$hdr";
    $te ||= $hdr =~m{^Transfer-Encoding:}im ? 'chunked':'clen';
    if ( $te eq 'chunked' ) {
	$data = join("", 
	    map { sprintf("%x\r\n%s\r\n",length($_),$_) } 
	    ( $data =~m{(..?)}smg,'')
	)
    } elsif ( $te eq '1chunk' ) {
	$data = sprintf("%x\r\n%s\r\n0\r\n\r\n",length($data),$data);
    } elsif ($te eq 'chunked-ext-junk') {
	$data = join("", 
	    map { sprintf("%x; foobar\r\n%s\r\n",length($_),$_) } 
	    ( $data =~m{(..?)}smg,'')
	)
    } elsif ($te eq 'chunked-ext-chunk') {
	$data = join("", 
	    map { sprintf(
		"%x; %s  %x\r\n%s\r\n",
		length($_),                    # chunk length
		"x" x length($_), length($_),  # chunk extensions looking like chunk if any two bytes are skipped instead of \r\n
		$_                             # chunk
	    )} 
	    ( $data =~m{(..?)}smg,'')
	)
    } elsif ($te eq 'chunked-lf') {
	$data = join("", 
	    map { sprintf("%x\n%s\n",length($_),$_) } 
	    ( $data =~m{(..?)}smg,'')
	)
    }

    return "$hdr\r\n$data";
}


1;
