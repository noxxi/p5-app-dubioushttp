use strict;
use warnings;
package App::DubiousHTTP::Tests::Chunked;
use App::DubiousHTTP::Tests::Common;
use Compress::Raw::Zlib;

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
    [ SHOULDBE_VALID, 'chunked' => 'simple and valid chunking'],
    [ MUSTBE_VALID, 'clen' => 'content-length header, not chunked'],

    [ 'VALID: modification of chunk size' ],
    [ UNCOMMON_VALID, '0size' => "chunks size prefixed with 0" ],
    [ UNCOMMON_VALID, '00size' => "chunks size prefixed with 00" ],
    [ UNCOMMON_VALID, 'ucsize' => "upper case size" ],
    [ UNCOMMON_VALID, '0ucsize' => "upper case size prefix with 0" ],
    [ INVALID, '32-size' => "negative size for 32bit uint" ],
    [ INVALID, '64-size' => "negative size for 64bit uint" ],
    [ INVALID, 'size-space' => "size followed by space" ],
    [ INVALID, 'size-tab' => "size followed by tab" ],
    [ INVALID, 'size-cr' => "size followed by <CR>" ],
    [ INVALID, 'size-lf' => "size followed by <LF>" ],
    [ INVALID, 'size-x' => "size followed by char 'x'" ],
    [ INVALID, 'size-\054' => "size followed by char ','" ],
    [ INVALID, 'size-\000' => "size followed by char \\000" ],
    [ INVALID, 'size-\013' => "size followed by char \\v" ],
    [ INVALID, 'size-\014' => "size followed by char \\f" ],
    [ INVALID, 'size-spacex' => "size followed by space and char 'x'" ],
    [ INVALID, 'space-size' => "size prefixed by space" ],
    [ INVALID, 'tab-size' => "size prefixed by tab" ],
    [ INVALID, 'cr-size' => "size prefixed by cr" ],
    [ INVALID, 'lf-size' => "size prefixed by lf" ],
    [ INVALID, 'crlf-size' => 'size prefixed by "\r\n"' ],
    [ INVALID, 'crlf-crlf-size' => 'size prefixed by "\r\n\r\n"' ],
    [ INVALID, 'crlf-x-crlf-size' => 'size prefixed by "\r\nx\r\n"' ],
    [ INVALID, 'x-size' => "size prefixed by char 'x'" ],
    [ INVALID, '\054-size' => "size prefixed by char ','" ],
    [ INVALID, '\073-size' => "size prefixed by char ';'" ],
    [ INVALID, '\000-size' => "size prefixed by char \\000" ],
    [ INVALID, '\013-size' => "size prefixed by char \\v" ],
    [ INVALID, '\014-size' => "size prefixed by char \\f" ],
    [ INVALID, 'xspace-size' => "size prefixed by char 'x' and space" ],
    [ INVALID, '\053-size' => "size prefixed by char '+'" ],
    [ INVALID, '\060\170-size' => "size prefixed by '0x'" ],
    [ UNCOMMON_VALID, 'final=00' => 'final chunk size "00"' ],
    [ UNCOMMON_VALID, 'final=00000000000000000000' => 'final chunk size "00000000000000000000"' ],
    [ INVALID, 'final=0x' => 'final chunk size "0x"' ],
    [ INVALID, 'final=Foo' => 'final chunk size "Foo"' ],
    [ INVALID, 'finalchunk=0\012' => 'final chunk just "0\n"' ],
    [ INVALID, 'finalchunk=0\015' => 'final chunk just "0\r"' ],
    [ INVALID, 'finalchunk=0' => 'final chunk just "0"' ],
    [ INVALID, 'finalchunk=0\012\012' => 'final chunk "0\n\n"' ],
    [ INVALID, 'finalchunk=0\012\040\012' => 'final chunk "0\n<space>\n"' ],
    [ INVALID, 'finalchunk=0\012\015\012' => 'final chunk "0\n\r\n"' ],
    [ INVALID, 'finalchunk=0\012\015\015\012' => 'final chunk "0\n\r\r\n"' ],
    [ INVALID, 'finalchunk=0\015\012foobar\015\012' => 'final chunk "0\r\nfoobar\r\n"' ],

    [ 'VALID: (but uncommon) use of extensions in chunked header' ],
    [ UNCOMMON_VALID, 'chunk-ext-junk' => "chunked with some junk chunk extension" ],
    [ UNCOMMON_VALID, 'chunk-ext-chunk' => "chunked with some junk chunk extension looking like a chunk" ],

    [ 'VALID: combined with content-length' ],
    # according to RFC2616 TE chunked has preference to clen
    [ VALID, 'chunked,clen' => 'chunked first then content-length, served chunked'],
    [ VALID, 'clen,chunked' => 'content-length first then chunked, served chunked'],
    # but some still expect clen bytes
    # safari does not like it, so mark it as uncommon
    [ UNCOMMON_VALID, 'chunked,clen200' => 'chunking and content-length header with double length, served chunked'],
    [ UNCOMMON_VALID, 'chunked,clen50'  => 'chunking and content-length header with half length, served chunked'],
    [ UNCOMMON_VALID, 'chunked,clen-big'  => 'chunking and content-length header with huge length, served chunked'],
    [ INVALID, 'addjunk,chunked,clen50'  => 'content+junk, chunked, content-length header includes content only' ],

    [ 'INVALID: chunking is only allowed with HTTP/1.1' ],
    [ INVALID, 'chunked,http10' => 'Chunked Header and HTTP/1.0. Served chunked.'],
    [ INVALID, 'chunked,clen,http10' => 'Chunked Header and Content-length and HTTP/1.0. Served chunked.'],
    [ INVALID, 'clen,chunked,http10' => 'Content-length Header and Chunked and HTTP/1.0. Served chunked.'],
    [ INVALID, 'chunked,http10,gzip' => 'Chunked Header and HTTP/1.0. Served chunked with gzip.'],
    [ INVALID, 'chunked,clen,http10,gzip' => 'Chunked Header and Content-length and HTTP/1.0. Served chunked with gzip.'],
    [ INVALID, 'clen,chunked,http10,gzip' => 'Content-length Header and Chunked and HTTP/1.0. Served chunked with gzip.'],

    [ 'VALID: chunked header should be ignored with HTTP/1.0' ],
    [ UNCOMMON_VALID, 'chunked,http10,do_clen' => 'Chunked Header and HTTP/1.0. Not served chunked.'],
    [ UNCOMMON_VALID, 'chunked,clen,http10,do_clen' => 'Chunked Header and Content-length and HTTP/1.0. Not served chunked.'],
    [ UNCOMMON_VALID, 'clen,chunked,http10,do_clen' => 'Content-length Header and Chunked and HTTP/1.0. Not served chunked.'],
    [ UNCOMMON_VALID, 'chunked,http10,do_clen,gzip' => 'Chunked Header and HTTP/1.0. Not served chunked. Compressed with gzip.'],
    [ UNCOMMON_VALID, 'chunked,clen,http10,do_clen,gzip' => 'Chunked Header and Content-length and HTTP/1.0. Not served chunked. Compressed with gzip.'],
    [ UNCOMMON_VALID, 'clen,chunked,http10,do_clen,gzip' => 'Content-length Header and Chunked and HTTP/1.0. Not served chunked. Compressed with gzip.'],

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

    [ INVALID, 'chunked,HTTP/0.1,gzip' => 'Chunked Header and HTTP/0.1. Served chunked and with gzip.'],
    [ INVALID, 'chunked,clen,HTTP/0.1,gzip,do_clen' => 'Chunked Header and HTTP/0.1. Not served chunked but with gzip.'],
    [ INVALID, 'chunked,HTTP/01.1,gzip' => 'Chunked Header and HTTP/01.1. Served chunked and with gzip.'],
    [ INVALID, 'chunked,clen,HTTP/01.1,gzip,do_clen' => 'Chunked Header and HTTP/01.1. Not served chunked but with gzip.'],
    [ INVALID, 'chunked,HTTP/11.01,gzip' => 'Chunked Header and HTTP/11.01. Served chunked and with gzip.'],
    [ INVALID, 'chunked,clen,HTTP/11.01,gzip,do_clen' => 'Chunked Header and HTTP/11.01. Not served chunked but with gzip.'],
    [ INVALID, 'chunked,HTTP/11.10,gzip' => 'Chunked Header and HTTP/11.10. Served chunked and with gzip.'],
    [ INVALID, 'chunked,clen,HTTP/11.10,gzip,do_clen' => 'Chunked Header and HTTP/11.10. Not served chunked but with gzip.'],
    [ INVALID, 'chunked,HTTP/9.9,gzip' => 'Chunked Header and HTTP/9.9. Served chunked and with gzip.'],
    [ INVALID, 'chunked,clen,HTTP/9.9,gzip,do_clen' => 'Chunked Header and HTTP/9.9. Not served chunked but with gzip.'],

    [ 'VALID: valid variations on "chunked" value' ],
    [ VALID, 'chUnked' => 'mixed case "chUnked", served chunked'],
    [ UNCOMMON_VALID,'nl-chunked' => "chunked header with continuation line, served chunked"],
    [ UNCOMMON_VALID,'chunkednl-' => "chunked header followed by empty with continuation line, served chunked"],
    [ UNCOMMON_VALID,'nl-nl-chunked' => "chunked header with double continuation line, served chunked"],
    [ UNCOMMON_VALID,'nl-nl-chunked-nl-' => "chunked header with double continuation line and continuation afterwareds, served chunked"],
    [ UNCOMMON_VALID,'huge-white-space-chunked' => "'Transfer-Encoding:<lots of space>chunked'"],

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
    [ INVALID, 'chunked-nl-x' => '"chunked-folding-x" not "chunked"'],
    [ INVALID, 'rfc2047,do_chunked' => 'rfc2047/base64 encoded "chunked", served chunked' ],
    [ UNCOMMON_VALID, 'rfc2047,do_clen' => 'rfc2047/base64 encoded "chunked", not served chunked' ],
    [ UNCOMMON_VALID, 'rfc2047,clen,do_clen' => 'rfc2047/base64 encoded "chunked" and content-length, not served chunked' ],
    [ INVALID,'nl-chunked,do_clen' => "chunked header with continuation line. Not served chunked."],
    [ INVALID,'chunkednl-,do_clen' => "chunked header followed by empty continuation line. Not served chunked."],
    [ INVALID,'nl-nl-chunked,do_clen' => "chunked header with double continuation line, not served chunked"],
    [ INVALID,'crchunked,do_chunked' => "Transfer-Encoding:<CR>chunked. Served chunked."],
    [ INVALID,'crchunked,do_clen' => "Transfer-Encoding:<CR>chunked. Not served chunked."],
    [ INVALID,'cr-chunked,do_chunked' => "Transfer-Encoding:<CR><space>chunked. Served chunked."],
    [ INVALID,'cr-chunked,do_clen' => "Transfer-Encoding:<CR><space>chunked. Not served chunked."],
    [ INVALID,'chunkedcr-,do_chunked' => "Transfer-Encoding:chunked<CR><space>. Served chunked."],
    [ INVALID,'chunkedcr-,do_clen' => "Transfer-Encoding:chunked<CR><space>. Not served chunked."],
    [ INVALID,'ce-chunked,do_chunked' => "Content-encoding chunked instead of Transfer-encoding. Served chunked."],

    [ 'INVALID: hiding with another Transfer-Encoding header' ],
    [ INVALID, 'xte,chunked,do_chunked' => "double Transfer-Encoding: first junk, last chunked. Served chunked." ],
    [ INVALID, 'xte,chunked,do_chunked,gzip' => "double Transfer-Encoding: first junk, last chunked. Served chunked and gzipped." ],
    [ INVALID, 'chunked,xte,do_chunked' => "double Transfer-Encoding: first chunked, last junk. Served chunked." ],
    [ INVALID, 'chunked,xte,do_chunked,gzip' => "double Transfer-Encoding: first chunked, last junk. Served chunked and gzipped." ],
    [ INVALID, 'xte,chunked,xte,do_chunked' => "triple Transfer-Encoding: first junk, then chunked, then junk again. Served chunked." ],
    [ INVALID, 'xte,chunked,xte,do_clen' => "triple Transfer-Encoding: first junk, then chunked, then junk again. Not served chunked." ],
    [ INVALID, 'xte,chunked,do_clen' => "double Transfer-Encoding: first junk, last chunked. Not served chunked." ],
    [ INVALID, 'chunked,xte,do_clen' => "double Transfer-Encoding: first chunked, last junk. Not served chunked." ],
    [ INVALID, 'chunked,xte,clen,do_chunked' => "double Transfer-Encoding: first chunked, last junk. Also Content-length header. Served chunked." ],
    [ INVALID, 'xte,chunked,clen,do_chunked' => "double Transfer-Encoding: first junk, last chunked. Also Content-length header. Served chunked." ],
    [ INVALID, 'xte,chunked,xte,clen,do_chunked' => "triple Transfer-Encoding: first junk, then chunked, then junk again. Also Content-length header. Served chunked." ],
    [ INVALID, 'xte,chunked,xte,clen,do_clen' => "triple Transfer-Encoding: first junk, then chunked, then junk again. Also Content-length header. Not served chunked." ],
    [ INVALID, 'chunked,xte,clen,do_clen' => "double Transfer-Encoding: first chunked, last junk. Also Content-length header. Not served chunked." ],
    [ INVALID, 'chunked,xte,clen,do_clen,gzip' => "double Transfer-Encoding: first chunked, last junk. Also Content-length header. Not served chunked. Compressed with gzip." ],
    [ INVALID, 'xte,chunked,clen,do_clen' => "double Transfer-Encoding: first junk, last chunked. Also Content-length header. Not served chunked." ],
    [ INVALID, 'xte,chunked,clen,do_clen,gzip' => "double Transfer-Encoding: first junk, last chunked. Also Content-length header. Not served chunked. Compressed with gzip." ],
    [ INVALID, 'chunked,clen,do_clen' => 'chunking and content-length, not served chunked'],
    [ INVALID, 'chunked,clen,do_clen,gzip' => 'chunking and content-length, not served chunked. Compressed with gzip.'],
    [ INVALID, 'emptyte,chunked,do_chunked,gzip' => "double Transfer-Encoding: first empty, last chunked. Served chunked and gzipped." ],
    [ INVALID, 'emptyte,chunked,do_clen,gzip' => "double Transfer-Encoding: first empty, last chunked. Served with content-length and gzipped." ],
    [ INVALID, 'chunked,emptyte,do_chunked,gzip' => "double Transfer-Encoding: first chunked, last empty. Served chunked and gzipped." ],
    [ INVALID, 'chunked,emptyte,do_clen,gzip' => "double Transfer-Encoding: first chunked, last empty. Served with content-length and gzipped." ],

    [ 'INVALID: hiding the Transfer-Encoding header' ],
    [ INVALID, 'space-colon-chunked,do_chunked' => '"Transfer-Encoding<space>:", served chunked' ],
    [ INVALID, 'tab-colon-chunked,do_chunked' => '"Transfer-Encoding<tab>:", served chunked' ],
    [ INVALID, 'cr-colon-chunked,do_chunked' => '"Transfer-Encoding<CR>:", served chunked' ],
    [ UNCOMMON_INVALID, 'space-colon-chunked,do_clen' => '"Transfer-Encoding<space>:", not served chunked' ],
    [ UNCOMMON_INVALID, 'tab-colon-chunked,do_clen' => '"Transfer-Encoding<tab>:", not served chunked' ],
    [ UNCOMMON_INVALID, 'cr-colon-chunked,do_clen' => '"Transfer-Encoding<CR>:", not served chunked' ],
    [ INVALID, 'colon-colon-chunked,do_chunked' => '"Transfer-Encoding::", served chunked' ],
    [ UNCOMMON_INVALID, 'colon-colon-chunked,do_clen' => '"Transfer-Encoding::", not served chunked' ],
    [ INVALID, 'cronly-chunked,do_chunked' => 'Transfer-Encoding with only <CR> as line delimiter before, served chunked' ],
    [ INVALID, 'crxonly-chunked,do_chunked' => 'Only <CR> as line delimiter followed by "xTransfer-Encoding", served chunked' ],
    [ UNCOMMON_INVALID, 'cronly-chunked,do_clen' => 'Transfer-Encoding with only <CR> as line delimiter before, not served chunked' ],
    [ UNCOMMON_INVALID, 'lfonly-chunked,do_chunked' => 'Transfer-Encoding with only <LF> as line delimiter before, served chunked' ],
    [ INVALID, 'lfonly-chunked,do_clen' => 'Transfer-Encoding with only <LF> as line delimiter before, not served chunked' ],

    [ 'INVALID: invalid chunks' ],
    [ INVALID, 'chunk-lf' => "chunk with LF as delimiter instead of CRLF" ],
    [ INVALID, 'chunk-cr' => "chunk with CR as delimiter instead of CRLF" ],
    [ INVALID, 'chunk-crcr' => "chunk with CRCR as delimiter instead of CRLF" ],
    [ INVALID, 'chunk-lflf' => "chunk with LFLF as delimiter instead of CRLF" ],
    [ INVALID, 'chunk-lfcr' => "chunk with LFCR as delimiter instead of CRLF" ],
    [ INVALID, 'nofinal' => 'missing final chunk' ],
    [ INVALID, 'eof-inchunk' => 'eof inside some chunk' ],
    [ INVALID, 'space-before-chunks' => 'space before chunks start' ],
    [ INVALID, 'lf-before-chunks' => '<LF> before chunks start' ],
    [ INVALID, 'cr-before-chunks' => '<CR> before chunks start' ],
    [ INVALID, 'crlf-before-chunks' => '<CR><LF> before chunks start' ],
    [ INVALID, 'junk\000-after-chunkdata' => 'junk \000 after each chunk payload' ],
    [ INVALID, 'junk\012-after-chunkdata' => 'junk \n after each chunk payload' ],
    [ INVALID, 'junk\015-after-chunkdata' => 'junk \r after each chunk payload' ],
    [ INVALID, 'junk\040-after-chunkdata' => 'junk space after each chunk payload' ],
    [ INVALID, 'junk\011-after-chunkdata' => 'junk tab after each chunk payload' ],
    [ INVALID, 'size-1' => 'size given for chunk is one to small' ],
    [ INVALID, 'size+1' => 'size given for chunk is one to large' ],
);


sub make_response {
    my ($self,$page,$spec) = @_;
    return make_index_page() if $page eq '';
    my ($hdr,$data) = content($page,$self->ID."-".$spec) or die "unknown page $page";
    my $version = 'HTTP/1.1';
    my ($te,@chunks,%chunkmod,$clen);
    my $sizefmt = '%x';
    my $before_chunks = '';
    my $final = '0';
    my $finalchunk;
    for (split(',',$spec)) {
	if ( m{^(x|-|nl|lf|cr)*chunked(x|-|nl|lf|cr)*$}i ) {
	    s{-}{ }g;
	    s{nl}{\r\n}g;
	    s{lf}{\n}g;
	    s{cr}{\r}g;
	    $hdr .= "Transfer-Encoding: $_\r\nConnection: close\r\n";
	} elsif ( $_ eq 'huge-white-space-chunked') {
	    $hdr .= "Transfer-Encoding: ". ( ' ' x 10000 )."chunked\r\nConnection: close\r\n";
	} elsif ( m{^(space|tab|cr|colon)-colon-chunked$} ) {
	    my $c = $1;
	    $c =~s{space}{ }g;
	    $c =~s{colon}{:}g;
	    $c =~s{tab}{\t}g;
	    $c =~s{cr}{\r}g;
	    $te = 'chunked';
	    $hdr .= "Connection: close\r\nTransfer-Encoding$c: chunked\r\n"
	} elsif ( my ($crlf) = m {^((?:lf|cr|x)+)only-chunked$} ) {
	    $te = 'chunked';
	    $hdr = "X-Foo: bar" if $hdr !~s{\r\n\z}{};
	    $crlf =~s{lf}{\n}g;
	    $crlf =~s{cr}{\r}g;
	    $hdr .= $crlf . "Transfer-Encoding: chunked\r\nConnection: close\r\n";
	} elsif ( $_ eq '1chunk' ) {
	    $hdr .= "Transfer-Encoding: chunked\r\n";
	    @chunks = $data;
	} elsif ( $_ eq 'chu' ) {
	    $hdr .= "Transfer-Encoding: chu\r\nConnection: close\r\n"
	} elsif ( $_ eq 'ce-chunked' ) {
	    $hdr .= "Content-Encoding: chunked\r\nConnection: close\r\n"
	} elsif ( $_ eq 'clen-big') {
	    $clen = 1_000_000_000;
	} elsif ( $_ =~ m{^clen(\d+)?$} ) {
	    $clen = $1 || 100;
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
	} elsif ( $_ eq 'rfc2047' ) {
	    $hdr .= "Transfer-Encoding: =?UTF-8?B?Y2h1bmtlZAo=?=\r\nConnection: close\r\n";
	} elsif ( $_ eq 'emptyte' ) {
	    $hdr .= "Transfer-Encoding: \r\nConnection: close\r\n";
	} elsif ( $_ eq 'xte' ) {
	    $hdr .= "Transfer-Encoding: lalala\r\nConnection: close\r\n";
	} elsif ( m{^junk(\S*)-after-chunkdata$}) {
	    my $junk = $1 // 'x';
	    $junk =~ s{\\([0-7]{3})}{ chr(oct($1)) }eg;
	    $hdr .= "Transfer-Encoding: chunked\r\nConnection: close\r\n";
	    $chunkmod{'junk-after-chunk'} = $junk;
	} elsif ( m{^size([+-])(\d+)$}) {
	    $hdr .= "Transfer-Encoding: chunked\r\nConnection: close\r\n";
	    $chunkmod{'size-adjust'} = int("$1$2");
	} elsif ( m{^(chunk-ext-|nofinal$|eof-inchunk$)} ) {
	    $hdr .= "Transfer-Encoding: chunked\r\nConnection: close\r\n";
	    $chunkmod{$_} = 1;
	} elsif ( my ($eol) = m{^chunk-((?:lf|cr)+)$} ) {
	    $hdr .= "Transfer-Encoding: chunked\r\nConnection: close\r\n";
	    $eol =~s{cr}{\r}g;
	    $eol =~s{lf}{\n}g;
	    $chunkmod{lineend} = $eol;
	} elsif (m{^(32|64)-size\z}) {
	    my $o = ($1 == 64) ? 'ffffffff':'';
	    $sizefmt = sub { sprintf("-$o%08x", 1+(0xffffffff & ~shift())) };
	    $hdr .= "Transfer-Encoding: chunked\r\nConnection: close\r\n";
	} elsif ( m{^(-|space|cr|lf|tab|x|\\[0-7]{3})*(0*)(uc)?size(-|space|cr|lf|tab|x|\\[0-7]{3})*$}) {
	    $hdr .= "Transfer-Encoding: chunked\r\nConnection: close\r\n";
	    @chunks = ( $data =~m{(.{1,15})}smg,'') if ! @chunks;
	    s{ucsize}{%X};
	    s{size}{%x};
	    s{\\r}{\r}g;
	    s{\\n}{\n}g;
	    s{-}{}g;
	    s{space}{ }g;
	    s{tab}{\t}g;
	    s{cr}{\r}g;
	    s{lf}{\n}g;
	    s{\\([0-7]{3})}{ chr(oct($1)) }eg;
	    $sizefmt = $_;
	} elsif (m{((?:space|tab|cr|lf)*)-before-chunks}) {
	    $hdr .= "Transfer-Encoding: chunked\r\nConnection: close\r\n";
	    $before_chunks = $1;
	    $before_chunks =~ s{space}{ }g;
	    $before_chunks =~ s{tab}{\t}g;
	    $before_chunks =~ s{cr}{\r}g;
	    $before_chunks =~ s{lf}{\n}g;
	} elsif (m{^final=(.*)$}) {
	    $hdr .= "Transfer-Encoding: chunked\r\nConnection: close\r\n";
	    $final = $1;
	} elsif (m{^finalchunk=(.*)$}) {
	    $hdr .= "Transfer-Encoding: chunked\r\nConnection: close\r\n";
	    (my $d = $1 ) =~ s{\\([0-7]{3})}{ chr(oct($1)) }eg;
	    $finalchunk = $d;
	} elsif ( $_ eq 'addjunk' ) {
	    # fake PKZIP magic for confusion
	    my $junk = "PK\003\004" x int(length($data)/4+1);
	    $data .= substr($junk,0,length($data));
	} elsif ( $_ eq 'gzip' ) {
	    $data = _compress($data,'gzip');
	    $hdr .= "Content-Encoding: gzip\r\n";
	} else {
	    die $_
	}
    }
    $hdr .= "Content-length: ". int($clen/100*length($data)) ."\r\n" 
	if defined $clen;
    $hdr = "$version 200 ok\r\n$hdr";
    $te ||= $hdr =~m{^Transfer-Encoding:}im ? 'chunked':'clen';
    @chunks = ( $data =~m{(.{1,5})}smg,'') if $te eq 'chunked' && ! @chunks;
    if (@chunks) {
	@chunks = map { [ length($_), $_ ] } @chunks;
	my $nl = $chunkmod{lineend} || "\r\n";
	if ($chunkmod{'chunk-ext-chunk'}) {
	    $_->[2] = sprintf("; %s  %x","x" x $_->[0],$_->[0]) for @chunks;
	} elsif ($chunkmod{'chunk-ext-junk'}) {
	    $_->[2] = "; foobar" for @chunks;
	}
	pop @chunks if $chunkmod{nofinal} && ! $chunks[-1][0];

	my $end = '';
	if ($chunkmod{'eof-inchunk'}) {
	    pop @chunks if ! $chunks[-1][0]; # remove final chunk
	    my $last = pop(@chunks);
	    $end = sprintf("%x%s%s%s",$last->[0]+10,$last->[2]||'',$nl,$last->[1]);
	}
	if (defined(my $junk = $chunkmod{'junk-after-chunk'})) {
	    $_->[1] .= $junk for @chunks;
	}
	if (my $diff = $chunkmod{'size-adjust'}) {
	    $_->[0] += $diff for @chunks;
	    $chunks[-1][0] = 0; # keep at 0 last chunk
	}

	$finalchunk = "$final$nl$nl" if ! defined $finalchunk;
	$data = join("",map { 
	    $_->[0] ? sprintf("%s%s%s%s%s",
		ref($sizefmt) ? $sizefmt->($_->[0]): sprintf($sizefmt,$_->[0]), # size
		$_->[2] || '',    # ext
		$nl,
		$_->[1],
		$nl
	    ) : $finalchunk
	} @chunks).$end;
    }
    return "$hdr\r\n$before_chunks$data";
}

sub _compress {
    my ($data,$w) = @_;
    my $zlib = Compress::Raw::Zlib::Deflate->new(
	-WindowBits => $w eq 'gzip' ? WANT_GZIP : -MAX_WBITS(),
	-AppendOutput => 1,
    );
    my $newdata = '';
    $zlib->deflate( $data, $newdata);
    $zlib->flush($newdata,Z_FINISH);
    return $newdata;
}

1;
