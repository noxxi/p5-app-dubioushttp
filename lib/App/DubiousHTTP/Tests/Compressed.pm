use strict;
use warnings;
package App::DubiousHTTP::Tests::Compressed;
use App::DubiousHTTP::Tests::Common;
use Compress::Raw::Zlib;

SETUP( 
    'compressed',
    "Variations on content compression",
    <<'DESC',
Compression of Content is usueally done with a Content-Encoding header and a
value of 'gzip' (RFC1952) or 'deflate' (RFC1951). Most browsers additionally 
accept RFC1950 compressed data for 'deflate'.
Some browsers also support compression with the Transfer-Encoding header, 
which is actually specified in the HTTP RFC, but most browsers don't.
Some browsers just guess the encoding, e.g. accept gzip even if deflate is
specified.
And some browsers accept x-gzip and x-deflate specifications, and some even
specifications like "x gzip" or "gzip x".
Most browsers accept multiple content-encoding headers, even if it does not
make much sense to compress content twice with the same encoding.
DESC

    # ------------------------- Tests ----------------------------------------

    # these should be fine
    [ 'VALID: correct compressed requests' ],
    [ VALID, 'ce:gzip;gzip' => 'content-encoding gzip'],
    [ VALID, 'ce:x-gzip;gzip' => 'content-encoding x-gzip == gzip'],
    [ VALID, 'ce:deflate;deflate' => 'content-encoding deflate'],
    [ VALID, 'ce:identity', '"content-encoding:identity" and no encoding' ],

    # these might be strange/unsupported
    [ 'VALID: less common but valid requests' ],
    [ UNCOMMON_INVALID, 'ce:deflate;deflate-raw' => 'content-encoding deflate with RFC1950 style deflate'],
    [ UNCOMMON_VALID, 'ce:nl-gzip;gzip' => 'content-encoding header with continuation line'],

    # These should be fine according to RFC, but are not supported in the browsers
    # Thus treat is as problem if they get supported.
    [ 'INVALID: transfer-encoding with compression should not be supported' ],
    [ INVALID, 'te:gzip;gzip' => 'transfer-encoding gzip'],
    [ INVALID, 'te:deflate;deflate' => 'transfer-encoding deflate'],
    [ INVALID, 'te:gzip;ce:gzip;gzip;gzip' => 'transfer-encoding and content-encoding gzip'],

    # double encodings
    [ 'VALID: double encodings' ],
    [ UNCOMMON_VALID, 'ce:gzip;ce:gzip;gzip;gzip' => 'double gzip, double content-encoding header'],
    [ UNCOMMON_VALID, 'ce:gzip,gzip;gzip;gzip' => 'double gzip, single content-encoding header gzip,gzip'],
    [ UNCOMMON_VALID, 'ce:deflate;ce:deflate;deflate;deflate' => 'double deflate, double content-encoding header'],
    [ UNCOMMON_VALID, 'ce:deflate,deflate;deflate;deflate' => 'double deflate, single content-encoding header deflate,deflate'],
    [ UNCOMMON_VALID, 'ce:gzip;ce:deflate;gzip;deflate' => 'gzip+deflate, content-encoding header for gzip and deflate'],
    [ UNCOMMON_VALID, 'ce:gzip,deflate;gzip;deflate' => 'gzip+deflate, single content-encoding header gzip,deflate'],
    [ UNCOMMON_VALID, 'ce:deflate;ce:gzip;deflate;gzip' => 'deflate+gzip, content-encoding header for deflate and gzip'],
    [ UNCOMMON_VALID, 'ce:deflate,gzip;deflate;gzip' => 'deflate+gzip, single content-encoding header deflate,gzip'],

    [ 'INVALID: specified double encodings, but content not or only once encoded' ],
    [  INVALID, 'ce:gzip;ce:gzip;gzip' => 'single gzip, double content-encoding header'],
    [  INVALID, 'ce:gzip;ce:gzip' => 'no gzip, double content-encoding gzip header'],
    [  INVALID, 'ce:deflate;ce:deflate;deflate' => 'single deflate, double content-encoding header'],
    [  INVALID, 'ce:deflate;ce:deflate' => 'no deflate, double content-encoding deflate header'],
    [  INVALID, 'ce:gzip;ce:deflate;deflate;gzip' => 'deflate+gzip, content-encoding header for gzip and deflate'],
    [  INVALID, 'ce:gzip;ce:deflate;deflate' => 'only deflate, but content-encoding header for gzip and deflate'],
    [  INVALID, 'ce:gzip;ce:deflate;gzip' => 'only gzip, but content-encoding header for gzip and deflate'],
    [  INVALID, 'ce:gzip;ce:deflate' => 'no encoding, but content-encoding header for gzip and deflate'],
    [  INVALID, 'ce:gzip,deflate;deflate;gzip' => 'deflate+gzip, single content-encoding header gzip,deflate'],
    [  INVALID, 'ce:gzip,deflate;deflate' => 'only deflate, single content-encoding header gzip,deflate'],
    [  INVALID, 'ce:gzip,deflate;gzip' => 'only gzip, single content-encoding header gzip,deflate'],
    [  INVALID, 'ce:gzip,deflate' => 'no encoding, single content-encoding header gzip,deflate'],
    [  INVALID, 'ce:deflate;ce:gzip;gzip;deflate' => 'gzip+deflate, content-encoding header for deflate and gzip'],
    [  INVALID, 'ce:deflate;ce:gzip;deflate' => 'only deflate, but content-encoding header for deflate and gzip'],
    [  INVALID, 'ce:deflate;ce:gzip;gzip' => 'only gzip, but content-encoding header for deflate and gzip'],
    [  INVALID, 'ce:deflate;ce:gzip' => 'no encoding, but content-encoding header for deflate and gzip'],
    [  INVALID, 'ce:deflate,gzip;gzip;deflate' => 'gzip+deflate, single content-encoding header deflate,gzip'],
    [  INVALID, 'ce:deflate,gzip;deflate' => 'only deflate, single content-encoding header deflate,gzip'],
    [  INVALID, 'ce:deflate,gzip;gzip' => 'only gzip, single content-encoding header deflate,gzip'],
    [  INVALID, 'ce:deflate,gzip' => 'no encoding, single content-encoding header deflate,gzip'],

    # triple encodings
    [ 'VALID: triple encodings' ],
    [ UNCOMMON_VALID, 'ce:gzip;ce:deflate;ce:gzip;gzip;deflate;gzip' => 'gzip + deflate + gzip, separate content-encoding header'],
    [ UNCOMMON_VALID, 'ce:gzip,deflate,gzip;gzip;deflate;gzip' => 'gzip + deflate + gzip, single content-encoding header'],
    [ UNCOMMON_VALID, 'ce:gzip,deflate;ce:gzip;gzip;deflate;gzip' => 'gzip + deflate + gzip, two content-encoding headers'],
    [ UNCOMMON_VALID, 'ce:deflate;ce:gzip;ce:deflate;deflate;gzip;deflate' => 'deflate + gzip + gzip, separate content-encoding header'],
    [ UNCOMMON_VALID, 'ce:deflate,gzip,deflate;deflate;gzip;deflate' => 'deflate + gzip + deflate, single content-encoding header'],
    [ UNCOMMON_VALID, 'ce:deflate,gzip;ce:deflate;deflate;gzip;deflate' => 'deflate + gzip + deflate, two content-encoding headers'],

    # and the bad ones
    [ 'INVALID: incorrect compressed response, should not succeed' ],
    [ INVALID, 'ce:x-deflate;deflate' => 'content-encoding x-deflate'],
    [ INVALID, 'ce:x-deflate;deflate-raw' => 'content-encoding x-deflate with RFC1950 style deflate'],
    [ INVALID, 'ce:gzipx;gzip' => 'content-encoding gzipx != gzip' ],
    [ INVALID, 'ce:xgzip;gzip' => 'content-encoding xgzip != gzip' ],
    [ INVALID, 'ce:gzip_x;gzip' => 'content-encoding "gzip x" != gzip' ],
    [ INVALID, 'ce:x_gzip;gzip' => 'content-encoding "x gzip" != gzip' ],
    [ INVALID, 'ce:deflate;gzip' => 'content-encoding deflate with gzipped encoding'],
    [ INVALID, 'ce:gzip;deflate' => 'content-encoding gzip with deflate encoding'],
    [ INVALID, 'ce:gzip;gzip-split' => 'content-encoding gzip, content split into 2 gzip parts concatenated'],

    [ 'INVALID: invalid content-encodings should not be ignored' ],
    [ INVALID, 'ce:gzip_x' => 'content-encoding "gzip x", but not encoded' ],
    [ INVALID, 'ce:deflate;ce:gzip_x;deflate' => 'content-encoding deflate + "gzip x", but only deflated' ],
    [ INVALID, 'ce:gzip_x;ce:deflate;deflate' => 'content-encoding  "gzip x" + deflate, but only deflated' ],
    [ INVALID, 'ce:foo', '"content-encoding:foo" and no encoding' ],

    [ 'VALID: transfer-encoding should be ignored for compression' ],
    [ UNCOMMON_VALID,'te:gzip' => 'transfer-encoding gzip but not compressed'],
);

sub make_response {
    my ($self,$page,$spec) = @_;
    return make_index_page() if $page eq '';
    my ($hdr,$data) = content($page,$spec) or die "unknown page $page";
    my $version = '1.1';
    for (split(';',$spec)) {
	if ( m{^(ce|te):(nl-)?(x_)?(x-gzip|x-deflate|gzip|deflate|xgzip|gzipx|foo|identity)(_x)?((?:,(?:deflate|gzip))*)$} ) {
	    $hdr .= $1 eq 'ce' ? 'Content-Encoding:':'Transfer-Encoding:';
	    $hdr .= "\r\n " if $2;
	    $hdr .= "x " if $3;
	    $hdr .= $4;
	    $hdr .= $6 if $6;
	    $hdr .= " x" if $5;
	    $hdr .= "\r\n";
	} elsif ( m{^(?:(gzip)|deflate(-raw)?)$} ) {
	    my $zlib = Compress::Raw::Zlib::Deflate->new(
		-WindowBits => $1 ? WANT_GZIP : $2 ? +MAX_WBITS() : -MAX_WBITS(),
		-AppendOutput => 1,
	    );
	    my $newdata = '';
	    $zlib->deflate($data, $newdata);
	    $zlib->flush($newdata,Z_FINISH);
	    $data = $newdata;
	} elsif ( $_ =~m{^gzip-split(\d+)?$} ) {
	    my $count = $1 || 2;
	    my @parts;
	    my $size = int(length($data)/$count);
	    my $newdata = '';
	    for( my $i=0;$i<$count-1;$i++) {
		my $zlib = Compress::Raw::Zlib::Deflate->new(
		    -WindowBits => WANT_GZIP,
		    -AppendOutput => 1,
		);
		my $out = '';
		$zlib->deflate(substr($data,0,$size,''), $out);
		$zlib->flush($out,Z_FINISH);
		$newdata .= $out;
	    }
	    $data = $newdata;
	} else {
	    die $_
	}
    }
    $hdr .= "Content-length: ".length($data)."\r\n";
    return "HTTP/$version 200 ok\r\n$hdr\r\n$data";
}

1;
