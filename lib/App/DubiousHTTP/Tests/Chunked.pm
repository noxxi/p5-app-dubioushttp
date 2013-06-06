use strict;
use warnings;
package App::DubiousHTTP::Tests::Chunked;
use App::DubiousHTTP::Tests::Common;

sub ID { 'chunked' }
sub DESCRIPTION { "Variations of server side chunked encoding" }
my @tests; # set below
sub TESTS { @tests }

# these should be fine
my @good_chunked = (
    [ 'chunked' => 'valid chunking'],
    [ 'chUnked' => 'valid chunking mixed case'],
    # according to RFC2616 TE chunked has preference to clen
    [ 'chunked,clen' => 'chunking and content-length'],
    # continuations lines are ok
    [ 'nl-chunked' => "chunked header with continuation line"],
    #[ 'chunked-semicolon' => "Transfer-Encoding: chunked;" ],
);

my @good_clen = (
    [ 'clen' => 'valid content-length'],
);

# and the bad ones
my @bad = (
    # chunking is only allowed with HTTP/1.1
    [ 'chunked,http10' => 'chunking with HTTP/1.0'],
    [ 'chunked,clen,http10' => 'chunking and content-length with HTTP/1.0'],
    [ 'chu' => '"chu" not "chunked"'],
    [ 'xchunked' => '"xchunked" not "chunked"'],
    [ 'chunkedx' => '"chunkedx" not "chunked"'],
    [ 'chunked-x' => '"chunked x" not "chunked"'],
    [ 'x-chunked' => '"x chunked" not "chunked"'],
);

for (@good_chunked,@good_clen,@bad) {
    my $tst = bless [ @$_ ],'App::DubiousHTTP::Tests::Chunked::Test';
    push @tests, $tst;
}


sub make_response {
    my ($self,$page,$spec) = @_;
    return make_index_page() if $page eq '';
    my ($hdr,$data) = content($page) or die "unknown page $page";
    my $version = '1.1';
    my $te;
    for (split(',',$spec)) {
	if ( ! $_ || $_ eq 'chunked' ) {
	    $hdr .= "Transfer-Encoding: chunked\r\n"
	} elsif ( $_ eq 'chUnked' ) {
	    $hdr .= "Transfer-Encoding: chUnked\r\n"
	} elsif ( $_ eq 'nl-chunked' ) {
	    $hdr .= "Transfer-Encoding:\r\n chunked\r\n"
	} elsif ( $_ eq 'chu' ) {
	    $hdr .= "Transfer-Encoding: chu\r\n"
	} elsif ( $_ eq 'xchunked' ) {
	    $hdr .= "Transfer-Encoding: xchunked\r\n"
	} elsif ( $_ eq 'chunkedx' ) {
	    $hdr .= "Transfer-Encoding: chunkedx\r\n"
	} elsif ( $_ eq 'x-chunked' ) {
	    $hdr .= "Transfer-Encoding: x chunked\r\n"
	} elsif ( $_ eq 'chunked-x' ) {
	    $hdr .= "Transfer-Encoding: chunked x\r\n"
	} elsif ( $_ eq 'clen' ) {
	    $hdr .= "Content-length: ".length($data)."\r\n"
	} elsif ( $_ eq 'http10' ) {
	    $version = "1.0";
	} elsif ( $_ eq 'do_clen' ) {
	    $te = 'clen'
	} elsif ( $_ eq 'do_chunked' ) {
	    $te = 'chunked'
	} elsif ( $_ eq 'chunked-semicolon' ) {
	    $hdr .= "Transfer-Encoding: chunked;\r\n"
	} else {
	    die $_
	}
    }
    $hdr = "HTTP/$version 200 ok\r\n$hdr";
    $te ||= $hdr =~m{^Transfer-Encoding:}im ? 'chunked':'clen';
    $data = sprintf("%x\r\n%s\r\n0\r\n\r\n",length($data),$data) 
	if $te eq 'chunked';
    return "$hdr\r\n$data";
}

sub make_index_page {
    my $body = "<!doctype html><html lang=en><body>";
    $body .= "<table>";
    my $line = sub {
	my ($test,$gif) = @_;
	bless $test, 'App::DubiousHTTP::Tests::Chunked::Test';
	$body .= "<tr>";
	$body .= "<td>". $test->ID ."</td>";
	$body .= "<td><img src=". $_->url($gif). " /></td>";
	$body .= "<td>". $test->DESCRIPTION ."</td>";
	$body .= "<td><a href=". $test->url('eicar.txt').">load EICAR</a></td>";
	$body .= "</tr>";
    };

    $body .= "<tr><td colspan=4><hr>correct unchunked requests, should all succeed<hr></td></tr>";
    $line->($_,'ok.gif') for(@good_clen);
    $body .= "<tr><td colspan=4><hr>correct chunked requests, should all succeed<hr></td></tr>";
    $line->($_,'ok.gif') for(@good_chunked);
    $body .= "<tr><td colspan=4><hr>incorrect chunked response, should not succeed (broken image is fine)<hr></td></tr>";
    $line->($_,'bad.gif') for(@bad);

    $body .= "</table>";
    $body .= "</body></html>";
    return "HTTP/1.0 200 Ok\r\n".
	"Content-type: text/html\r\n".
	"Content-length: ".length($body)."\r\n\r\n".
	$body;

}


{
    package App::DubiousHTTP::Tests::Chunked::Test;
    sub ID { shift->[0] }
    sub DESCRIPTION { shift->[1] }
    sub url { 
	my ($self,$page) = @_;
	return "/chunked/$page/$self->[0]"
    }
    sub make_response {
	my ($self,$page) = @_;
	App::DubiousHTTP::Tests::Chunked->make_response( $page,$self->[0] );
    }
}


1;
