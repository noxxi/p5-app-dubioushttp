use strict;
use warnings;
package App::DubiousHTTP::Tests::Mime;
use App::DubiousHTTP::Tests::Common;
use MIME::Base64 'encode_base64';

sub ID { 'mime' }
sub SHORT_DESC { "no all MIME makes sense for HTTP" }
sub LONG_DESC { return <<'DESC'; }
Various tests with multipart contents.
- most systems do not handle multipart in a special way
- but Firefox often just uses the last part and ignores the rest
- while Opera additionally interprets Content-Transfer-Encoding header
Details see http://noxxi.de/research/dubious-http.html
DESC
my @tests;
sub TESTS { @tests }

# these should be fine
my @good = (
    [ 'single' => 'single part'],
);

# and the bad ones
my @bad = (
    [ 'mixed',"multipart/mixed" ],
    [ 'mixed,base64',"multipart/mixed with Content-Transfer-Encoding base64" ],
    [ 'related',"multipart/related" ],
    [ 'related,base64',"multipart/related with Content-Transfer-Encoding base64" ],
);

my @mhtml = (
    [ 'related,mhtml',"multipart/related with mhtml schema" ],
    [ 'mixed,mhtml',"multipart/mixed with mhtml schema" ],
    [ 'multi-plain,mhtml',"text/plain with mhtml schema" ],
    [ 'related,mhtml,base64',"multipart/related with mhtml schema base64" ],
    [ 'mixed,mhtml,base64',"multipart/mixed with mhtml schema base64" ],
    [ 'multi-plain,mhtml,base64',"text/plain with mhtml schema base64" ],
);

for (@good,@bad) {
    my $tst = bless [ @$_ ],'App::DubiousHTTP::Tests::Mime::Test';
    push @tests, $tst;
}


sub make_response {
    my ($self,$page,$spec) = @_;
    return make_index_page() if $page eq '';
    my ($hdr,$data) = content($page) or die "unknown page $page";
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
	if ( delete $spec{base64} ) {
	    $part .= "Content-transfer-Encoding: base64\r\n\r\n".
		encode_base64($data)."\r\n"
	} else {
	    $part .= "Content-length: ".length($data)."\r\n\r\n".
		"$data\r\n";
	}
	my $body = "\r\n".
	    "--foobar\r\nContent-Location: p1\r\n$part".
	    "--foobar\r\nContent-Location: p2\r\n$part".
	    "--foobar--\r\n";
	$resp .= "Content-length: ".length($body)."\r\n\r\n$body";
    } else {
	$resp .= "Content-length: ".length($data)."\r\n\r\n$data";
    }
    return $resp;
}

sub make_index_page {
    my $body = "<!doctype html><html lang=en><body>";
    $body .= "<pre>".html_escape(LONG_DESC())."</pre>";
    $body .= "<table>";
    my $line = sub {
	my ($test,$base,$prefix,$postfix) = @_;
	$prefix //= '';
	$postfix //= '';
	bless $test, 'App::DubiousHTTP::Tests::Mime::Test';
	$body .= "<tr>";
	$body .= "<td>". $test->ID ."</td>";
	$body .= "<td style='border-style:solid; border-width:1px'><img src=$prefix". $test->url("$base.gif"). "$postfix /></td>";
	$body .= "<td style='border-style:solid; border-width:1px'><iframe style='width: 10em; height: 3em;' src=$prefix". $test->url("$base.html"). "$postfix></iframe></td>";
	#$body .= "<td><script src=$prefix".$test->url("$base.js")."$postfix></script></td>";
	$body .= "<td>". $test->DESCRIPTION ."</td>";
	$body .= "<td><a href=$prefix". $test->url('eicar.txt')."$postfix>load EICAR</a></td>";
	$body .= "</tr>";
    };

    $body .= "<tr><td colspan=5><hr>single part response, should succeed<hr></td></tr>";
    $line->($_,'ok') for(@good);
    $body .= "<tr><td colspan=5><hr>multipart response, should better fail (broken image is fine)<hr></td></tr>";
    $line->($_,'bad') for(@bad);

    # requires MSIE <= 7
    if(0) {
	$body .= "<tr><td colspan=5><hr>multipart with MHTML schema<hr></td></tr>";
	$line->($_,'bad','mhtml:','!p1') for(@mhtml);
    }

    $body .= "</table>";
    $body .= "</body></html>";
    return "HTTP/1.0 200 Ok\r\n".
	"Content-type: text/html\r\n".
	"Content-length: ".length($body)."\r\n\r\n".
	$body;

}


{
    package App::DubiousHTTP::Tests::Mime::Test;
    sub ID { shift->[0] }
    sub DESCRIPTION { shift->[1] }
    sub url { 
	my ($self,$page) = @_;
	return "$::BASE_URL/mime/$page/$self->[0]"
    }
    sub make_response {
	my ($self,$page) = @_;
	App::DubiousHTTP::Tests::Mime->make_response( $page,$self->[0] );
    }
}


1;
