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

    [ VALID,  '' => 'simple and valid request'],
    [ UNCOMMON_VALID, 'http09' => 'HTTP 0.9 response (no header)'],

    [ 'invalid data before content-length and content' ],
    [ INVALID, 'emptycont' => 'empty continuation line'],
    [ INVALID, '8bitkey' => 'line using 8bit field name'],
    [ INVALID, 'colon' => 'line with empty field name (single colon on line)'],
    [ INVALID, '177' => 'line \177\r\n' ],
    [ INVALID, 'chunked;177' => 'chunked, after that line \177\r\n' ],
    [ INVALID, '177;only' => 'line \177\r\n and then the body, no other header' ],
    [ INVALID, 'junkline' => 'ASCII junk line w/o colon'],
    [ INVALID, 'cr' => 'line just containing CR: \r\r\n'],

    [ 'various broken responses' ],
    [ INVALID, 'code-only' => 'status line stops after code, no phrase'],
    [ INVALID, 'http-lower' => 'http/1.1 instead of HTTP/1.1'],
    [ INVALID, 'proto:HTTP/0.9' => 'HTTP/0.9 instead of HTTP/1.1'],
    [ INVALID, 'proto:HTTP/1.10' => 'HTTP/1.10 instead of HTTP/1.1'],
    [ INVALID, 'proto:HTTP/1.00' => 'HTTP/1.00 instead of HTTP/1.0'],
    [ INVALID, 'proto:HTTP/1.01' => 'HTTP/1.01 instead of HTTP/1.0'],
    [ INVALID, 'proto:HTTP/1.2' => 'HTTP/1.2 instead of HTTP/1.1'],
    [ INVALID, 'proto:HTTP/1.1 ' => 'HTTP/1.1+SPACE instead of HTTP/1.1'],
    [ INVALID, "proto:HTTP/1.1\t" => 'HTTP/1.1+TAB instead of HTTP/1.1'],
    #[ INVALID, "proto:HTTP/1.1\r" => 'HTTP/1.1+CR instead of HTTP/1.1'],
    [ INVALID, "proto: HTTP/1.1" => 'SPACE+HTTP/1.1 instead of HTTP/1.1'],
    [ INVALID, 'proto:FTP/1.1' => 'FTP/1.1 instead of HTTP/1.1'],
    [ INVALID, 'cr-no-lf' => 'use \r instead of \r\n' ],
    [ INVALID, 'no-cr-lf' => 'use \n instead of \r\n' ],

    [ 'redirect without location' ],
    [ INVALID, '300' => 'code 300 without location header'],
    [ INVALID, '301' => 'code 301 without location header'],
    [ INVALID, '302' => 'code 302 without location header'],
    [ INVALID, '303' => 'code 303 without location header'],
    [ INVALID, '305' => 'code 305 without location header'],
    [ INVALID, '307' => 'code 307 without location header'],
    [ INVALID, '308' => 'code 308 without location header'],

    [ 'other status codes' ],
    [ INVALID, '100' => 'code 100 with body'],
    [ INVALID, '101' => 'code 101 with body'],
    [ INVALID, '102' => 'code 102 with body'],
    [ INVALID, '204' => 'code 204 with body'],
    [ INVALID, '205' => 'code 205 with body'],
    [ INVALID, '206' => 'code 206 with body'],
    [ INVALID, '304' => 'code 304 with body'],
    [ UNCOMMON_VALID, '400' => 'code 400 with body'],
    [ INVALID, '401' => 'code 401 with body and no authorization requested'],
    [ UNCOMMON_VALID, '403' => 'code 403 with body'],
    [ UNCOMMON_VALID, '404' => 'code 404 with body'],
    [ UNCOMMON_VALID, '406' => 'code 406 with body'],
    [ INVALID, '407' => 'code 407 with body and no authorization requested'],
    [ UNCOMMON_VALID, '500' => 'code 500 with body'],
    [ UNCOMMON_VALID, '502' => 'code 502 with body'],
    [ INVALID, '2xx' => 'invalid status code with non-digits (2xx)'],
    [ INVALID, '2'   => 'invalid status code, only single digit (2)'],
    [ INVALID, '2000' => 'invalid status code, too much digits (2000)'],
    [ INVALID, '0200' => 'invalid status code, numeric (0200)'],
);

sub make_response {
    my ($self,$page,$spec) = @_;
    return make_index_page() if $page eq '';
    my ($hdr,$data) = content($page,$spec) or die "unknown page $page";
    my $version = '1.1';
    my $te = 'clen';
    my $only = 0;
    my $code = 200;
    my $statusline;
    my @transform;
    for (split(';',$spec)) {
	if ( $_ eq 'emptycont' ) {
	    $hdr .= "Foo: bar\r\n \r\n"
	} elsif ( $_ eq '8bitkey' ) {
	    $hdr .= "Löchriger-Häddar: foobar\r\n"
	} elsif ( $_ eq 'spacekey' ) {
	    $hdr .= "Foo Bar: foobar\r\n"
	} elsif ( $_ eq 'colon' ) {
	    $hdr .= ": foo\r\n"
	} elsif ( $_ eq 'junkline' ) {
	    $hdr .= "qutqzdafsdshadsdfdshsdd sddfd\r\n"
	} elsif ( $_ eq 'cr' ) {
	    $hdr .= "\r\r\n"
	} elsif ( $_ eq 'space' ) {
	    $hdr .= " ";
	} elsif ( $_ eq 'chunked' ) {
	    $te = 'chunked';
	    $data = sprintf("%x\r\n%s\r\n0\r\n\r\n",length($data),$data);
	    $hdr .= "Transfer-Encoding: chunked\r\n";
	} elsif ( $_ eq '177' ) {
	    $hdr .= "\177\r\n";
	} elsif ( $_ eq 'only' ) {
	    $only = 1;
	} elsif ( $_ eq 'http09' ) {
	    return $data;
	} elsif ( m{^(\d.*)$} ) {
	    $code = $1;
	    $hdr .= "Connection: close\r\n";
	} elsif ( $_ eq 'code-only' ) {
	    $statusline = "HTTP/$version $code\r\n";
	} elsif ( $_ eq 'http-lower' ) {
	    $statusline = "http/$version $code\r\n";
	} elsif ( $_ eq 'cr-no-lf' ) {
	    push @transform, sub { $_[0] =~ s{\r?\n}{\r}g }
	} elsif ( $_ eq 'no-cr-lf' ) {
	    push @transform, sub { $_[0] =~ s{\r?\n}{\n}g }
	} elsif ( m{^proto:(.*)} ) {
	    $statusline = "$1 $code ok\r\n";
	} else {
	    die $_
	}
    }
    if (!$only) {
	$hdr .= "Yet-another-header: foo\r\n";
	$hdr .= "Content-length: ".length($data)."\r\n" if $te eq 'clen';
    }
    $statusline ||= "HTTP/$version $code ok\r\n";
    $hdr = "$statusline$hdr\r\n";
    for(@transform) {
	$_->($hdr,$data);
    }
    return $hdr . $data;
}

1;
