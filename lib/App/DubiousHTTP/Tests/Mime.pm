use strict;
use warnings;
package App::DubiousHTTP::Tests::Mime;
use App::DubiousHTTP::Tests::Common;
use MIME::Base64 'encode_base64';

SETUP(
    'mime',
    "no all MIME makes sense for HTTP",
    <<'DESC',
Various tests with multipart contents. 
Most systems do not handle multipart in a special way but Firefox often just
uses the last part and ignores the rest while Opera additionally interprets
Content-Transfer-Encoding header.
DESC
    
    # ---------------------- Tests ------------------------------------
    [ 'VALID: single parts' ],
    [ MUSTBE_VALID, 'single' => 'single part'],
    [ VALID, 'single,ct64',"single part with Content-Transfer-Encoding base64 header but unencoded data" ],

    [ 'INVALID: single part with base64 content' ],
    [ INVALID, 'single,ct64,base64',"single part with Content-Transfer-Encoding base64 and encoded data" ],

    [ 'INVALID: content packed into multipart messages' ],
    [ INVALID, 'mixed',"multipart/mixed" ],
    [ INVALID, 'mixed,ct64,base64',"multipart/mixed with Content-Transfer-Encoding base64" ],
    [ INVALID, 'related',"multipart/related" ],
    [ INVALID, 'related,ct64,base64',"multipart/related with Content-Transfer-Encoding base64" ],

    # only supported in older IE
    [ 'INVALID: MHTML' ],
    [ INVALID, 'related,mhtml',"multipart/related with mhtml schema" ],
    [ INVALID, 'mixed,mhtml',"multipart/mixed with mhtml schema" ],
    [ INVALID, 'multi-plain,mhtml',"text/plain with mhtml schema" ],
    [ INVALID, 'related,mhtml,base64',"multipart/related with mhtml schema base64" ],
    [ INVALID, 'mixed,mhtml,base64',"multipart/mixed with mhtml schema base64" ],
    [ INVALID, 'multi-plain,mhtml,base64',"text/plain with mhtml schema base64" ],
);


sub make_response {
    my ($self,$page,$spec) = @_;
    return make_index_page() if $page eq '';
    my ($hdr,$data) = content($page,$spec) or die "unknown page $page";
    my $version = '1.1';
    my %spec = map { $_ => 1 } split(',',$spec);
    my $resp = "HTTP/$version 200 ok\r\n";
    my $multi = 
	delete $spec{mixed} ? 'multipart/mixed' :
	delete $spec{related} ? 'multipart/related' :
	delete $spec{'multi-plain'} ? 'text/plain' :
	'';
    if ( $multi ) {
	$resp .= "Content-type: $multi; boundary=foobar\r\n";
	my $part = $hdr;
	$part .= "Content-transfer-Encoding: base64\r\n" if delete $spec{ct64};
	$data = encode_base64($data) if delete $spec{base64};
	$part .= "Content-length: ".length($data)."\r\n\r\n$data\r\n";
	my $body = "\r\n".
	    "--foobar\r\nContent-Location: p1\r\n$part".
	    "--foobar\r\nContent-Location: p2\r\n$part".
	    "--foobar--\r\n";
	$resp .= "Content-length: ".length($body)."\r\n\r\n$body";
    } else {
	$resp .= "Content-transfer-Encoding: base64\r\n" if delete $spec{ct64};
	$data = encode_base64($data) if delete $spec{base64};
	$resp .= "Content-length: ".length($data)."\r\n\r\n$data";
    }
    return $resp;
}

1;
