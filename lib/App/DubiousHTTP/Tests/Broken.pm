use strict;
use warnings;
package App::DubiousHTTP::Tests::Broken;
use App::DubiousHTTP::Tests::Common;

SETUP( 
    'broken',
    "Various broken requests",
    <<'DESC',
This tries various kinds of broken HTTP responses.
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

    [ 'redirect without location' ],
    [ INVALID, '301' => 'code 301 without location header'],
    [ INVALID, '302' => 'code 301 without location header'],
    [ INVALID, '303' => 'code 301 without location header'],
    [ INVALID, '307' => 'code 301 without location header'],
    [ INVALID, '308' => 'code 301 without location header'],

    [ 'other status codes' ],
    [ INVALID, '300' => 'code 300 with body'],
    [ INVALID, '100' => 'code 100 with body'],
    [ INVALID, '101' => 'code 101 with body'],
    [ INVALID, '102' => 'code 102 with body'],
    [ INVALID, '204' => 'code 204 with body'],
    [ INVALID, '304' => 'code 304 with body'],
    [ INVALID, '305' => 'code 305 with body'],
);

sub make_response {
    my ($self,$page,$spec) = @_;
    return make_index_page() if $page eq '';
    my ($hdr,$data) = content($page,$spec) or die "unknown page $page";
    my $version = '1.1';
    my $te = 'clen';
    my $only = 0;
    my $code = 200;
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
	} elsif ( m{^(\d+)$} ) {
	    $code = $1;
	    $hdr .= "Connection: close\r\n";
	} else {
	    die $_
	}
    }
    if (!$only) {
	$hdr .= "Yet-another-header: foo\r\n";
	$hdr .= "Content-length :".length($data)."\r\n" if $hdr eq 'clen';
    }
    return "HTTP/$version $code ok\r\n$hdr\r\n$data";
}

1;
