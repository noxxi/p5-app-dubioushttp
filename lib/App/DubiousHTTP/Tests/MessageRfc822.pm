use strict;
use warnings;
package App::DubiousHTTP::Tests::MessageRfc822;
use App::DubiousHTTP::Tests::Common;
use Compress::Raw::Zlib;
use Compress::Zlib;
use MIME::Base64;

SETUP( 
    'messagerfc822',
    "...",
    <<'DESC',
...
DESC

    # ------------------------- Tests ----------------------------------------

    # these should be fine
    [ 1,'plain data',
	[ '' => 'plain data'],
	[ 'ce:gzip' => 'data with global content-encoding gzip'],
    ],

    # packed inside message/rfc822
    [ 0 => 'packed inside message/rfc822', 
	[ 'rfc822' => 'simply packed in message/rfc822' ],
	[ 'cte:base64;rfc822' => 'packed in message/rfc822 with content-transfer-encoding base64' ],
	[ 'ce:gzip;rfc822' => 'packed in message/rfc822 with content-encoding gzip' ],
    ],
);

sub make_response {
    my ($self,$page,$spec) = @_;
    return make_index_page() if $page eq '';
    my ($hdr,$data) = content($page,$spec) or die "unknown page $page";
    my $version = '1.0';
    for (split(';',$spec)) {
	if ( $_ eq 'ce:gzip' ) {
	    $hdr .= "Content-Encoding: gzip\r\n";
	    $data = Compress::Zlib::memGzip($data);
	} elsif ( $_ eq 'cte:base64' ) {
	    $hdr .= "Content-Transfer-Encoding: base64\r\n";
	    $data = encode_base64($data)."\r\n";
	} elsif ( $_ eq 'rfc822' ) {
	    $hdr .= "Content-length: ".length($data)."\r\n";
	    $data = "$hdr\r\n$data\r\n";
	    $hdr = "Content-type: message/rfc822\r\n";
	} else {
	    die $_
	}
    }
    $hdr .= "Content-length: ".length($data)."\r\n";
    return "HTTP/$version 200 ok\r\n$hdr\r\n$data";
}

1;
