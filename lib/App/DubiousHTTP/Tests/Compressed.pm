use strict;
use warnings;
package App::DubiousHTTP::Tests::Compressed;
use App::DubiousHTTP::Tests::Common;
use Compress::Raw::Zlib;
use Compress::Zlib;

sub ID { 'compressed' }
sub SHORT_DESC { "Variations on content compression" }
sub LONG_DESC { return <<'DESC'; }
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

Details see http://noxxi.de/research/unusual-http-content-encoding.html
DESC
my @tests; # set below
sub TESTS { @tests }

# these should be fine
my @good = (
    [ 'ce:gzip,gzip' => 'content-encoding gzip'],
    [ 'ce:x-gzip,gzip' => 'content-encoding x-gzip == gzip'],
    [ 'ce:deflate,deflate' => 'content-encoding deflate'],
    [ 'ce:deflate,deflate-raw' => 'content-encoding deflate with RFC1950 style deflate'],
    [ 'ce:nl-gzip,gzip' => 'content-encoding header with continuation line'],
    [ 'ce:gzip,ce:gzip,gzip,gzip' => 'double gzip, double content-encoding header'],
    [ 'ce:deflate,ce:deflate,deflate,deflate' => 'double deflate, double content-encoding header'],
    [ 'ce:gzip,ce:deflate,gzip,deflate' => 'gzip+deflate, both content-encoding header'],
    [ 'ce:deflate,ce:gzip,deflate,gzip' => 'deflate+gzip, both content-encoding header'],

);

# these should be fine according to RTC, but it is not supported in all browsers
my @bad_goodies = (
    [ 'te:gzip,gzip' => 'transfer-encoding gzip'],
    [ 'te:deflate,deflate' => 'transfer-encoding deflate'],
    [ 'te:gzip,ce:gzip,gzip,gzip' => 'transfer-encoding and content-encoding gzip'],
);
# and the bad ones
my @bad = (
    [ 'ce:x-deflate,deflate' => 'content-encoding x-deflate'],
    [ 'ce:x-deflate,deflate-raw' => 'content-encoding x-deflate with RFC1950 style deflate'],
    [ 'ce:gzipx,gzip' => 'content-encoding gzipx != gzip' ],
    [ 'ce:xgzip,gzip' => 'content-encoding xgzip != gzip' ],
    [ 'ce:gzip_x,gzip' => 'content-encoding "gzip x" != gzip' ],
    [ 'ce:x_gzip,gzip' => 'content-encoding "x gzip" != gzip' ],
    [ 'ce:deflate,gzip' => 'content-encoding deflate with gzipped encoding'],
    [ 'ce:gzip,deflate' => 'content-encoding gzip with deflate encoding'],
    [ 'ce:deflate,ce:gzip,gzip,deflate' => 'gzip+deflate, both content-encoding header but wrong order'],
    [ 'ce:gzip,ce:deflate,deflate' => 'gzip+deflate content-encoding header but only deflated'],
    [ 'ce:deflate,ce:gzip,deflate' => 'deflate+gzip content-encoding header but only deflated'],
    [ 'ce:deflate,ce:gzip' => 'deflate+gzip content-encoding header but no encoding'],
    [ 'ce:foo', '"content-encoding:foo" and no encoding' ],
    [ 'ce:identity', '"content-encoding:identity" and no encoding' ],
);


for (@good,@bad) {
    my $tst = bless [ @$_ ],'App::DubiousHTTP::Tests::Compressed::Test';
    push @tests, $tst;
}


sub make_response {
    my ($self,$page,$spec) = @_;
    return make_index_page() if $page eq '';
    my ($hdr,$data) = content($page) or die "unknown page $page";
    my $version = '1.1';
    for (split(',',$spec)) {
	if ( m{^(ce|te):(nl-)?(x_)?(x-gzip|x-deflate|gzip|deflate|xgzip|gzipx|foo|identity)(_x)?$} ) {
	    $hdr .= $1 eq 'ce' ? 'Content-Encoding:':'Transfer-Encoding:';
	    $hdr .= "\r\n " if $2;
	    $hdr .= "x " if $3;
	    $hdr .= $4;
	    $hdr .= " x" if $5;
	    $hdr .= "\r\n";
	} elsif ( $_ eq 'gzip' ) {
	    $data = Compress::Zlib::memGzip($data);
	} elsif ( m{^deflate(-raw)?$} ) {
	    my $zlib = Compress::Raw::Zlib::Deflate->new(
		-WindowBits => $1 ? +MAX_WBITS() : -MAX_WBITS(),
		-AppendOutput => 1,
	    );
	    my $newdata = '';
	    $zlib->deflate($data, $newdata);
	    $zlib->flush($newdata,Z_FINISH);
	    $data = $newdata;
	} else {
	    die $_
	}
    }
    return "HTTP/$version 200 ok\r\n$hdr\r\n$data";
}

sub make_index_page {
    my $body = "<!doctype html><html lang=en><body>";
    $body .= "<pre>".html_escape(LONG_DESC())."</pre>";
    $body .= "<table>";
    my $line = sub {
	my ($test,$gif) = @_;
	bless $test, 'App::DubiousHTTP::Tests::Compressed::Test';
	$body .= "<tr>";
	$body .= "<td>". $test->ID ."</td>";
	$body .= "<td><img src=". $_->url($gif). " /></td>";
	$body .= "<td>". $test->DESCRIPTION ."</td>";
	$body .= "<td><a href=". $test->url('eicar.txt').">load EICAR</a></td>";
	$body .= "</tr>";
    };

    $body .= "<tr><td colspan=4><hr>correct compressed requests, should all succeed<hr></td></tr>";
    $line->($_,'ok.gif') for(@good);
    $body .= "<tr><td colspan=4><hr>correct compressed requests, but not supported everywhere<hr></td></tr>";
    $line->($_,'ok.gif') for(@bad_goodies);
    $body .= "<tr><td colspan=4><hr>incorrect compressed response, should not succeed (broken image is fine)<hr></td></tr>";
    $line->($_,'bad.gif') for(@bad);

    $body .= "</table>";
    $body .= "</body></html>";
    return "HTTP/1.0 200 Ok\r\n".
	"Content-type: text/html\r\n".
	"Content-length: ".length($body)."\r\n\r\n".
	$body;

}


{
    package App::DubiousHTTP::Tests::Compressed::Test;
    sub ID { shift->[0] }
    sub DESCRIPTION { shift->[1] }
    sub url { 
	my ($self,$page) = @_;
	return "/compressed/$page/$self->[0]"
    }
    sub make_response {
	my ($self,$page) = @_;
	App::DubiousHTTP::Tests::Compressed->make_response( $page,$self->[0] );
    }
}


1;
