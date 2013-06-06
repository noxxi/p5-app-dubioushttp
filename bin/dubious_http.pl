use strict;
use warnings;
use Getopt::Long qw(:config posix_default bundling);
use App::DubiousHTTP::Tests;
use App::DubiousHTTP::Tests::Common;
use App::DubiousHTTP::TestServer;
use Net::PcapWriter;

sub usage {
    print STDERR "ERROR: @_\n" if @_;
    print STDERR <<USAGE;

Test various behaviors of browsers, IDS... by working as a
web server or alternativly creating pcaps with dubios HTTP.
See --mode doc for details about the tests.

Help:               $0 -h|--help
Test descriptions:  $0 -M|--mode doc
Use as HTTP server: $0 -M|--mode server ip:port
Export Pcaps:       $0 -M|--mode pcap target-dir

USAGE
    exit(1);
}

our $BASE_URL="http://foo";
my $mode = 'doc';
GetOptions(
    'h|help'   => sub { usage() },
    'M|mode=s' => \$mode,
);

if ( $mode eq 'server' ) {
    my $addr = shift(@ARGV) or usage('no listen address given');
    serve($addr);
} elsif ( $mode eq 'doc' ) {
    print make_doc();
} elsif ( $mode eq 'pcap' ) {
    my $dir = shift(@ARGV) or usage('no target dir for pcap');
    make_pcaps($dir);
} else {
    usage('unknown mode '.$mode);
}

############################ make documentation
sub make_doc {
    my $dok = '';
    for my $cat ( App::DubiousHTTP::Tests->categories ) {
	$cat->TESTS or next;
	$dok .= "[".$cat->ID."] ".$cat->DESCRIPTION."\n";
	for my $tst ( $cat->TESTS ) {
	    $dok .= " - [".$tst->ID."] ".$tst->DESCRIPTION."\n"
	}
    }
    return $dok;
}

############################ create pcap files
sub make_pcaps {
    my $base = shift;
    -d $base or die "$base does not exist";
    for my $cat ( App::DubiousHTTP::Tests->categories ) {
	$cat->TESTS or next;
	my $dir = "$base/".$cat->ID;
	-d $dir or mkdir($dir) or die "cannot create $dir: $!";
	for my $tst ( $cat->TESTS ) {
	    my $pc = Net::PcapWriter->new( "$dir/".$tst->ID.".pcap" );
	    my $conn = $pc->tcp_conn('1.1.1.1',1111,'8.8.8.8',80);
	    $conn->write(0, "GET ".$tst->url('eicar.txt')." HTTP/1.1\r\nHost: foo.bar\r\n\r\n" );
	    $conn->write(1, $tst->make_response('eicar.txt') );
	}
    }
}

############################ work as server
sub serve {
    my $addr = shift;
    App::DubiousHTTP::TestServer->run($addr, sub {
	my ($path,$listen) = @_;
	local $BASE_URL = "http://$listen";
	my ($cat,$page,$spec) = $path =~m{\A / 
	    ([^/]+)
	    (?: / ([^/]*))?
	    (?: / (.*))?
	}x;
	$_ //= '' for ($cat,$page,$spec);
	if ( $page && $cat ) {
	    for ( App::DubiousHTTP::Tests->categories ) {
		$_->ID eq $cat or next;
		for ( $_->TESTS ) {
		    return $_->make_response($page)
			if $_->ID eq $spec;
		}
	    }
	}

	if ( my ($hdr,$data) = content($path)) {
	    # static pages
	    return "HTTP/1.0 200 ok\r\n$hdr\r\n$data";
	}

	if ( $cat ) {
	    for ( App::DubiousHTTP::Tests->categories ) {
		return $_->make_response($page,$spec)
		    if $_->ID eq $cat;
	    }
	}

	return App::DubiousHTTP::Tests->make_response($cat,$page,$spec);
    });
}

