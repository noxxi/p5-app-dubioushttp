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

    # these should be fine
    [ 1,'correct request, should succeed',
	[ '' => 'nothing special'],
    ],

    [ 0, 'http 0.9',
	[ 'http09' => 'HTTP 0.9 response (no header)'],
    ],
    [ 0, 'invalid data before content-length and content',
	[ 'emptycont' => 'empty continuation line'],
	[ '8bitkey' => 'line using 8bit field name'],
	[ 'colon' => 'line with empty field name'],
	[ '177' => 'line \177\r\n' ],
	[ 'chunked;177' => 'chunked, after that line \177\r\n' ],
	[ '177;only' => 'line \177\r\n and then the body, no other header' ],
	[ 'junkline' => 'ASCII junk line w/o colon'],
	[ 'cr' => 'line just containing CR: \r\r\n'],
    ],
);

sub make_response {
    my ($self,$page,$spec) = @_;
    return make_index_page() if $page eq '';
    my ($hdr,$data) = content($page,$spec) or die "unknown page $page";
    my $version = '1.1';
    my $te = 'clen';
    my $only = 0;
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
	} else {
	    die $_
	}
    }
    if (!$only) {
	$hdr .= "Yet-another-header: foo\r\n";
	$hdr .= "Content-length :".length($data)."\r\n" if $hdr eq 'clen';
    }
    return "HTTP/$version 200 ok\r\n$hdr\r\n$data";
}

1;
