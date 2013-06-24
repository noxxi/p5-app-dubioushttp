use strict;
use warnings;
package App::DubiousHTTP::Tests::Range;
use App::DubiousHTTP::Tests::Common;

sub ID { 'range' }
sub SHORT_DESC { "unexpected range header" }
sub LONG_DESC { return <<'DESC'; }
Try to trick browsers into accepting partial data (and requesting rest)
by using Range headers in response, even if no range was requested.
It seems, that this does not work - but at least wget tries to automatically
resume a broken request with a partial request.
DESC
my @tests;
sub TESTS { @tests }

# these should be fine
my @good = (
    [ 'full' => 'all data at once' ],
);

# and the bad ones
my @bad = (
    [ 'range',"send partial response even if full was requested" ],
    [ 'range,incomplete',"use incomplete response to trigger partial request for rest of data" ],
);


for (@good,@bad) {
    my $tst = bless [ @$_ ],'App::DubiousHTTP::Tests::Range::Test';
    push @tests, $tst;
}


sub make_response {
    my ($self,$page,$spec,$rqhdr) = @_;
    return make_index_page() if $page eq '';
    my ($hdr,$data) = content($page) or die "unknown page $page";
    my $version = '1.1';
    my %spec = map { $_ => 1 } split(',',$spec);
    my $resp = "";
    if ( $spec{range} ) {
	my $total = length($data);
	if ($rqhdr =~m{^Range:\s*bytes=(\d+)-(\d*)}mi ) {
	    # send requested range
	    my ($start,$end) = ($1,$2);
	    $end = length($data) if $end eq '';
	    $data = substr($data,$start,$end);
	    $resp = sprintf "HTTP/$version 206 partial content\r\n".
		"Content-length: %d\r\n".
		"Accept-Ranges: bytes\r\n".
		"Content-Range: bytes %d-%d/%d\r\n",
		length($data),$start,$end-1,$total;
	} elsif ( $spec{incomplete} ) {
	    $resp = "HTTP/$version 200 ok\r\n".
		"Content-length: ".length($data)."\r\n";
	    $data = substr($data,0,1);
	} else {
	    # only send first byte
	    $data = substr($data,0,1);
	    $resp = sprintf "HTTP/$version 206 partial content\r\n".
		"Content-length: %d\r\n".
		"Accept-Ranges: bytes\r\n".
		"Content-Range: bytes 0-0/%d\r\n",
		length($data),$total;
	}
	$resp .= $hdr;
    } else {
	$resp = sprintf "HTTP/$version 200 ok\r\n".
	    "Content-length: %d\r\n%s",
	    length($data),$hdr;
    }
    return $resp."\r\n".$data;
}

sub make_index_page {
    my $body = "<!doctype html><html lang=en><body>";
    $body .= "<pre>".html_escape(LONG_DESC())."</pre>";
    $body .= "<table>";
    my $line = sub {
	my ($test,$base,$prefix,$postfix) = @_;
	$prefix //= '';
	$postfix //= '';
	bless $test, 'App::DubiousHTTP::Tests::Range::Test';
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

    $body .= "</table>";
    $body .= "</body></html>";
    return "HTTP/1.0 200 Ok\r\n".
	"Content-type: text/html\r\n".
	"Content-length: ".length($body)."\r\n\r\n".
	$body;

}


{
    package App::DubiousHTTP::Tests::Range::Test;
    sub ID { shift->[0] }
    sub DESCRIPTION { shift->[1] }
    sub url { 
	my ($self,$page) = @_;
	return "$::BASE_URL/range/$page/$self->[0]"
    }
    sub make_response {
	my ($self,$page,undef,$hdr) = @_;
	App::DubiousHTTP::Tests::Range->make_response( $page,$self->[0],$hdr );
    }
}


1;
