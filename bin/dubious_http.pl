#!/usr/bin/perl
use strict;
use warnings;
use Getopt::Long qw(:config posix_default bundling);
use App::DubiousHTTP::Tests;
use App::DubiousHTTP::Tests::Common;
use App::DubiousHTTP::TestServer;

sub usage {
    print STDERR "ERROR: @_\n" if @_;
    print STDERR <<USAGE;

Test various behaviors of browsers, IDS... by working as a
web server or alternativly creating pcaps with dubios HTTP.
See --mode doc for details about the tests.

Help:               $0 -h|--help
Test descriptions:  $0 -M|--mode doc
Export Pcaps:       $0 -M|--mode pcap [options]
Use as HTTP server: $0 -M|--mode server [options] ip:port

Options for server mode:

 --cert cert.pem    SSL certificate if SSL should be used. It will listen for
		    SSL and plain requests on the same address.
 --key  key.pem     Key for SSL certificate
 --no-garble-url    Use clear names for URL's instead of the default garbled
		    names which were introduced to defer simple URL filters.
		    Logging will be done always with the clear names.
 --no-track-header  Disable logging of header information for requests, which
		    are used to analyze the origin and path of the request in
		    more detail.
 --fast-feedback    Don't collect all results and send them at once at the end
                    but send parts of the output earlier so that the recipient
		    needs to collect them. This saves memory in the client too.

Options for pcap mode:

 --file F          write all TCP streams to single pcap file F
 --prefix P        one stream per pcap file, files prefixed with P
 --manifest M      write mapping between source port and URL to M
 --filter-any      filter based on existing reports from server mode.
		   All remaining args are considered reports and a stream will
		   be included if at least one report shows a match.
		   This is the default if arguments are given.
 --filter-all      Like --filter-any, but include stream only if all reports
		   show a match.

USAGE
    exit(1);
}

our $BASE_URL="http://foo";
$TRACKHDR=1;
GetOptions(
    'h|help' => sub { usage() },
    'M|mode' => sub { 1 },
) or usage();
my $mode = shift(@ARGV) || 'doc';

if ( $mode eq 'server' ) {
    my ($cert,$key);
    GetOptions(
	'no-garble-url' => \$NOGARBLE,
	'track-header!' => \$TRACKHDR,
	'fast-feedback' => \$FAST_FEEDBACK,
	'cert=s'   => \$cert,
	'key=s'    => \$key,
    ) or usage();

    my $addr = shift(@ARGV) or usage('no listen address given');
    serve($addr, $cert
	? { SSL_cert_file => $cert, SSL_key_file => $key||$cert }
	: ()
    );

} elsif ( $mode eq 'doc' ) {
    print make_doc();
} elsif ( $mode eq 'pcap' ) {
    make_pcaps();
} else {
    usage('unknown mode '.$mode);
}

############################ make documentation
sub make_doc {
    my $dok = '';
    for my $cat ( App::DubiousHTTP::Tests->categories ) {
	$cat->TESTS or next;
	$dok .= "[".$cat->ID."] ".$cat->SHORT_DESC."\n";
	for my $tst ( $cat->TESTS ) {
	    $dok .= " - [".$tst->ID."] ".$tst->DESCRIPTION."\n"
	}
    }
    return $dok;
}

############################ create pcap files
sub make_pcaps {
    eval { require Net::PcapWriter }
	or die "cannot load Net::PcapWriter\n";

    my $filter_any = 1;
    my ($pcap_prefix,$pcap_file,$manifest);
    GetOptions(
	'prefix=s' => \$pcap_prefix,
	'file=s'   => \$pcap_file,
	'manifest=s' => \$manifest,
	'filter-any' => sub { $filter_any = 1; },
	'filter-all' => sub { $filter_any = 0; },
    ) or usage();

    my %include;
    for (@ARGV) {
	open( my $fh,'<',$_ ) or die "open $_: $!";
	while (<$fh>) {
	    my ($code,$string,$page) = m{^ ([INW]) \| (\S+) \| (/\S+) } or next;
	    $page =~s{^(/\w+)/[^/]+/(.*)}{$1/eicar.txt/$2} or next;
	    my $v = $string =~m{match|success} ? 1:0;
	    if (!exists $include{$page}) {
		$include{$page} = $v;
	    } elsif ($filter_any) {
		$include{$page} = 1 if $v;
	    } else {
		$include{$page} = 0 if !$v;
	    }
	}
    }

    my $pcap;
    if ($pcap_file) {
	$pcap = Net::PcapWriter->new($pcap_file)
	    or die "failed to create $pcap_file: $!";
    } elsif ($pcap_prefix) {
    } else {
	usage('no target file/prefix for pcap');
    }

    if ($manifest) {
	open(my $fh,'>',$manifest) or die "create $manifest: $!";
	$manifest = $fh;
    }

    $NOGARBLE = 1;
    my $base = 0;
    for my $cat ( App::DubiousHTTP::Tests->categories ) {
	$cat->TESTS or next;
	$base += 5000;
	my $pc = $pcap;
	my $port = $base;
	for my $tst ( $cat->TESTS ) {
	    my $valid = $tst->VALID;
	    $port = 10*int($port/10+1);
	    $port += $valid>0 ? $valid : $valid<0 ? 4-$valid : 9;

	    my $xurl = $tst->url('eicar.txt');
	    my $url = url_encode($xurl);
	    if (!%include) {
	    } elsif (!exists $include{$url}) {
		warn "$url not in existing reports - including anyway\n";
	    } elsif (!$include{$url}) {
		warn "skip $url\n";
		next;
	    }

	    if (!$pc) {
		( my $id = $cat->ID ) =~s{[^\w\-.,;+=]+}{_}g;
		my $file = "$pcap_prefix$id.pcap";
		$pc = Net::PcapWriter->new($file)
		    or die "failed to create $file: $!";
	    }

	    my $conn = $pc->tcp_conn('1.1.1.1',$port,'8.8.8.8',80);
	    $conn->write(0, "GET $url HTTP/1.1\r\nHost: evader.example.com\r\n\r\n" );
	    for( $tst->make_response('eicar.txt') ) {
		$conn->write(1, $_ );
	    }

	    print $manifest "$port | $xurl | ".$tst->DESCRIPTION."\n" if $manifest;
	    undef $pc if !$pcap;
	}
    }
}

############################ work as server
sub serve {
    my ($addr,$sslargs) = @_;
    my %iscat = map { $_->ID => 1 } App::DubiousHTTP::Tests->categories;

    App::DubiousHTTP::TestServer->run($addr, $sslargs, sub {
	my ($path,$listen,$rqhdr,$payload,$ssl) = @_;

	if ($path =~m{\A/submit_(details|results|part)/([^/]+)(?:/(\d+))?} 
	    && defined $payload) {
	    my ($what,$id,$part) = ($1,$2,$3);
	    $rqhdr .= $payload;
	    $rqhdr =~s{( /[=-][A-Za-z0-9_\-]+={0,2} )}{ ungarble_url($1) }eg;
	    $rqhdr =~s{^}{ }mg;
	    my $body = '';
	    print STDERR $rqhdr;
	    if ($what ne 'part') {
		$body = "<!doctype html>"
		    ."<h1>Thanks for providing us with the feedback.</h1>";
	    }
	    return "HTTP/1.1 200 ok\r\nContent-type: text/html\r\n".
		"X-ID: $path\r\n".
		"Content-length: ".length($body)."\r\n"
	}

	local $BASE_URL = "http://$listen";
	my ($auto,$src,$manifest,$cat,$page,$spec,$qstring) = $path =~m{\A / 
	    (?:auto(js|img|html|xhr|)/|((?:raw)?src)/|(manifest)/)?
	    ([^/]+)
	    (?: / ([^/\?]*))?
	    (?: / ([^\?]*))?
	    (?: \? (.*))?
	}x;
	for ($cat,$page,$spec,$qstring) {
	    $_ = '' if ! defined $_;
	}

	if ($manifest) {
	    return App::DubiousHTTP::Tests->manifest(
		$cat,$page,$spec,$qstring,$rqhdr);
	}


	if (defined $auto && ($iscat{$cat} || $cat eq 'all')) {
	    return App::DubiousHTTP::Tests->auto(
		$auto || 'xhr',$cat,$page,$spec,$qstring,$rqhdr)
	}

	if ( $page eq 'ALL' && $cat ) {
	    for ( App::DubiousHTTP::Tests->categories ) {
		return $_->make_index_page(undef,,$spec,$rqhdr)
		    if $_->ID eq $cat;
	    }
	}


	if ( $page && $cat ) {
	    for ( App::DubiousHTTP::Tests->categories ) {
		$_->ID eq $cat or next;
		my @content;
		for ( $_->TESTS ) {
		    $_->ID eq $spec or next;
		    @content = $_->make_response($page,undef,$rqhdr);
		    last;
		}
		@content = $_->make_response($page,$spec,$rqhdr) if ! @content;
		if (!$src) {
		    return @content;
		} elsif ($src eq 'rawsrc') {
		    my $content = join('',@content);
		    return "HTTP/1.0 200 ok\r\n".
			"Content-type: application/octet-stream\r\n".
			"Content-Disposition: attachment; filename=\"$cat+$page+$spec\"\r\n".
			"Content-length: ".length($content)."\r\n\r\n".$content;
		} else {
		    for (@content) {
			s{([\x00-\x1f\\<>\x7f-\xff])}{
			    $1 eq "\\" ? "\\\\" :
			    $1 eq "\r" ? "\\r" :
			    $1 eq "\t" ? "\\t" :
			    $1 eq "\n" ? "\\n\n" :
			    $1 eq "<" ? "&lt;" :
			    $1 eq ">" ? "&gt;" :
			    sprintf("\\x%02x",ord($1))
			}esg;
		    }

		    (my $raw = $path) =~s{/src/}{/rawsrc/};
		    my $content = "<pre>".join("<----PACKET-BOUNDARY---->",@content)."</pre><hr>".
			"<a class=srclink href=".garble_url($raw).">raw source</a>";

		    return "HTTP/1.0 200 ok\r\n".
			"Content-type: text/html\r\n".
			"Content-length: ".length($content)."\r\n\r\n".$content;
		    
		}

	    }
	}

	if ( my ($hdr,$data) = content($path)) {
	    return "HTTP/1.0 200 ok\r\n$hdr\r\n$data";
	} elsif ( $path =~m{^([^?]+)(?:\?(.*))?} and ($hdr,$data) = content($1,$2) ) {
	    return "HTTP/1.0 200 ok\r\n$hdr\r\n$data";
	}

	if ( $cat ) {
	    for ( App::DubiousHTTP::Tests->categories ) {
		return $_->make_index_page($page,$spec,$rqhdr)
		    if $_->ID eq $cat;
	    }
	}

	return App::DubiousHTTP::Tests->make_response($cat,$page,$spec,$rqhdr);
    });
}

