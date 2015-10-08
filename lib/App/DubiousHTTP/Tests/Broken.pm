use strict;
use warnings;
package App::DubiousHTTP::Tests::Broken;
use App::DubiousHTTP::Tests::Common;

SETUP( 
    'broken',
    "Various broken responses",
    <<'DESC',
This test tries various kinds of broken HTTP responses like
<ul>
<li>invalid characters inside the response header</li>
<li>invalid HTTP versions</li>
<li>invalid status codes or missing information for these status codes (like location with redirects)</li>
</ul>
DESC

    # ------------------------- Tests ----------------------------------------

    [ VALID,  'ok' => 'VALID: simple request with content-length'],
    [ UNCOMMON_VALID, 'http09' => 'HTTP 0.9 response (no header)'],

    [ 'INVALID: junk data around transfer-encoding' ],
    [ INVALID, 'chunked;177' => 'Transfer-Encoding: chunked\r\n\177\r\n, served chunked' ],
    [ INVALID, 'hdrfirst;space;chunked' => '<space>Transfer-Encoding: chunked as first header line, served chunked' ],
    [ INVALID, 'hdrfirst;tab;chunked' => '<tab>Transfer-Encoding: chunked as first header line, served chunked' ],
    [ INVALID, 'hdrfirst;space;chunked;do_clen' => '<space>Transfer-Encoding: chunked as first header line, not served chunked' ],
    [ INVALID, 'hdrfirst;tab;chunked;do_clen' => '<tab>Transfer-Encoding: chunked as first header line, not served chunked' ],
    [ INVALID, 'hdrfirst;space;chunked;do_close' => '<space>Transfer-Encoding: chunked as first header line, not served chunked and no content-length' ],
    [ INVALID, 'hdrfirst;tab;chunked;do_close' => '<tab>Transfer-Encoding: chunked as first header line, not served chunked and no content-length' ],
    [ INVALID, 'somehdr;space;chunked' => '<space>Transfer-Encoding: chunked as continuation of some header line, served chunked' ],
    [ INVALID, 'somehdr;tab;chunked' => '<tab>Transfer-Encoding: chunked as continuation of some header line, served chunked' ],
    [ VALID, 'somehdr;space;chunked;do_clen' => '<space>Transfer-Encoding: chunked as continuation of some header line, not served chunked' ],
    [ VALID, 'somehdr;tab;chunked;do_clen' => '<tab>Transfer-Encoding: chunked as continuation of some header line, not served chunked' ],
    [ INVALID, '8bitkey;chunked' => 'line using 8bit field name, followed by TE chunked'],
    [ INVALID, 'colon;chunked' => 'line with empty field name (single colon on line), followed by TE chunked'],
    [ INVALID, '177;chunked' => 'line \177\r\n, followed by TE chunked' ],
    [ INVALID, 'junkline;chunked' => 'ASCII junk line w/o colon, followed by TE chunked'],
    [ INVALID, 'cr;chunked' => 'line just containing <CR>: \r\r\n, followed by TE chunked'],
    [ INVALID, 'lf;chunked' => 'line just containing <LF>: \n\r\n, followed by TE chunked'],
    [ INVALID, 'crcr;chunked' => 'line just containing <CR><CR>: \r\r\r\n, followed by TE chunked'],
    [ INVALID, 'lfcr;chunked' => 'line just containing <LF><CR>: \n\r\r\n, followed by TE chunked'],

    [ 'INVALID: various broken responses' ],
    [ INVALID, 'emptycont' => 'empty continuation line'],
    [ INVALID, '8bitkey' => 'line using 8bit field name'],
    [ INVALID, 'colon' => 'line with empty field name (single colon on line)'],
    [ INVALID, '177' => 'line \177\r\n' ],
    [ INVALID, '177;only' => 'line \177\r\n and then the body, no other header after status line' ],
    [ INVALID, 'junkline' => 'ASCII junk line w/o colon'],
    [ INVALID, 'cr' => 'line just containing <CR>: \r\r\n'],
    [ INVALID, 'lf' => 'line just containing <LF>: \n\r\n'],
    [ INVALID, 'crcr' => 'line just containing <CR><CR>: \r\r\r\n'],
    [ INVALID, 'lfcr' => 'line just containing <LF><CR>: \n\r\r\n'],
    [ INVALID, 'code-only' => 'status line stops after code, no phrase'],
    [ INVALID, 'http-lower' => 'version given as http/1.1 instead of HTTP/1.1'],
    [ INVALID, 'proto:HTTP/0.9' => 'version given as HTTP/0.9 instead of HTTP/1.1'],
    [ INVALID, 'proto:HTTP/1.10' => 'version given as HTTP/1.10 instead of HTTP/1.1'],
    [ INVALID, 'proto:HTTP/1.00' => 'version given as HTTP/1.00 instead of HTTP/1.0'],
    [ INVALID, 'proto:HTTP/1.01' => 'version given as HTTP/1.01 instead of HTTP/1.0'],
    [ INVALID, 'proto:HTTP/1.2' => 'version given as HTTP/1.2 instead of HTTP/1.1'],
    [ INVALID, 'proto:HTTP/2.0' => 'version given as HTTP/2.0 instead of HTTP/1.1'],
    [ INVALID, 'proto:HTTP/1.1 ' => 'HTTP/1.1+SPACE: space after version in status line'],
    [ INVALID, 'proto:HTTP/1.1\t' => 'HTTP/1.1+TAB: tab after version in status line'],
    [ INVALID, 'proto:HTTP/1.1\r' => 'HTTP/1.1+CR: \r after version in status line'],
    [ INVALID, "proto: HTTP/1.1" => 'version prefixed with space: SPACE+HTTP/1.1'],
    [ INVALID, 'proto:FTP/1.1' => 'version FTP/1.1 instead of HTTP/1.1'],
    [ INVALID, 'cr-no-crlf' => 'single \r instead of \r\n' ],
    [ INVALID, 'lf-no-crlf' => 'single \n instead of \r\n' ],
    [ INVALID, 'crcr-no-crlf' => '\r\r instead of \r\n' ],
    [ INVALID, 'lfcr-no-crlf' => '\n\r instead of \r\n' ],

    [ 'INVALID: redirect without location' ],
    [ INVALID, '300' => 'code 300 without location header'],
    [ INVALID, '301' => 'code 301 without location header'],
    [ INVALID, '302' => 'code 302 without location header'],
    [ INVALID, '303' => 'code 303 without location header'],
    [ INVALID, '305' => 'code 305 without location header'],
    [ INVALID, '307' => 'code 307 without location header'],
    [ INVALID, '308' => 'code 308 without location header'],

    [ 'INVALID: other status codes with invalid behavior' ],
    [ INVALID, '100' => 'code 100 with body'],
    [ INVALID, '101' => 'code 101 with body'],
    [ INVALID, '102' => 'code 102 with body'],
    [ INVALID, '204' => 'code 204 with body'],
    [ INVALID, '205' => 'code 205 with body'],
    [ INVALID, '206' => 'code 206 with body'],
    [ INVALID, '304' => 'code 304 with body'],
    [ INVALID, '401' => 'code 401 with body and no authorization requested'],
    [ INVALID, '407' => 'code 407 with body and no authorization requested'],

    [ 'VALID: other status codes with valid behavior' ],
    [ UNCOMMON_VALID, '400' => 'code 400 with body'],
    [ UNCOMMON_VALID, '403' => 'code 403 with body'],
    [ UNCOMMON_VALID, '404' => 'code 404 with body'],
    [ UNCOMMON_VALID, '406' => 'code 406 with body'],
    [ UNCOMMON_VALID, '500' => 'code 500 with body'],
    [ UNCOMMON_VALID, '502' => 'code 502 with body'],

    [ 'INVALID: malformed status codes' ],
    [ INVALID, '2xx' => 'invalid status code with non-digits (2xx)'],
    [ INVALID, '20x' => 'invalid status code with non-digits (20x)'],
    [ INVALID, '2'   => 'invalid status code, only single digit (2)'],
    [ INVALID, '20'  => 'invalid status code, two digits (20)'],
    [ INVALID, '2000' => 'invalid status code, too much digits (2000)'],
    [ INVALID, '0200' => 'invalid status code, numeric (0200)'],
    [ INVALID, ' 200' => 'invalid status code, SPACE+200)'],
);

sub make_response {
    my ($self,$page,$spec) = @_;
    return make_index_page() if $page eq '';
    my ($cthdr,$data) = content($page,$spec) or die "unknown page $page";
    my $version = '1.1';
    my $te = 'clen';
    my $only = 0;
    my $code = 200;
    my $statusline;
    my @transform;
    my $hdr = '';
    my $hdrfirst;
    for (split(';',$spec)) {
	if ( $_ eq 'emptycont' ) {
	    $hdr .= "Foo: bar\r\n \r\n"
	} elsif ( $_ eq '8bitkey' ) {
	    $hdr .= "Löchriger-Häddar: foobar\r\n"
	} elsif ( $_ eq 'spacekey' ) {
	    $hdr .= "Foo Bar: foobar\r\n"
	} elsif ( $_ eq 'colon' ) {
	    $hdr .= ": foo\r\n"
	} elsif ( $_ eq 'space' ) {
	    $hdr .= " "
	} elsif ( $_ eq 'tab' ) {
	    $hdr .= "\t"
	} elsif ( $_ eq 'somehdr') {
	    $hdr .= "X-Foo: bar\r\n";
	} elsif ( $_ eq 'hdrfirst') {
	    $hdrfirst = 1;
	} elsif ( $_ eq 'junkline' ) {
	    $hdr .= "qutqzdafsdshadsdfdshsdd sddfd\r\n"
	} elsif ( m{^(?:(cr|lf)+)$} ) {
	    s{cr}{\r}g;
	    s{lf}{\n}g;
	    $hdr .= "$_\r\n"
	} elsif ( $_ eq 'chunked' ) {
	    $te = 'chunked';
	    $hdr .= "Transfer-Encoding: chunked\r\n";
	} elsif ( $_ eq 'do_clen') {
	    $te = 'clen';
	} elsif ( $_ eq 'do_close') {
	    $te = 'close';
	} elsif ( $_ eq '177' ) {
	    $hdr .= "\177\r\n";
	} elsif ( $_ eq 'only' ) {
	    $only = 1;
	} elsif ( $_ eq 'http09' ) {
	    return $data;
	} elsif ( m{^(\s*\d.*)$} ) {
	    $code = $1;
	    $hdr .= "Connection: close\r\n";
	} elsif ( $_ eq 'code-only' ) {
	    $statusline = "HTTP/$version $code\r\n";
	} elsif ( $_ eq 'http-lower' ) {
	    $statusline = "http/$version $code ok\r\n";
	} elsif ( $_ =~ m{^((?:cr|lf)+)-no-crlf$} ) {
	    my $w = $1;
	    $w =~s{cr}{\r}g;
	    $w =~s{lf}{\n}g;
	    push @transform, sub { $_[0] =~ s{\r?\n}{$w}g }
	} elsif ( m{^proto:(.*)} ) {
	    my $proto = $1;
	    $proto =~s{\\r}{\r};
	    $proto =~s{\\t}{\t};
	    $proto =~s{\\n}{\n};
	    $statusline = "$proto $code ok\r\n";
	} elsif ( $_ eq 'ok' ) {
	} else {
	    die $_
	}
    }
    $data = join('', map { sprintf("%x\r\n%s\r\n", length($_),$_) } ($data =~m{(.{1,4})}sg,''))
	if $te eq 'chunked';
    if (!$only) {
	$hdr .= "Yet-another-header: foo\r\n";
	$hdr .= "Content-length: ".length($data)."\r\n" if $te eq 'clen';
    }
    $statusline ||= "HTTP/$version $code ok\r\n";
    if ($hdrfirst) {
	$hdr .= $cthdr
    } else {
	$hdr = $cthdr . $hdr
    }
    $hdr = "$statusline$hdr\r\n";
    for(@transform) {
	$_->($hdr,$data);
    }
    return $hdr . $data;
}

1;
