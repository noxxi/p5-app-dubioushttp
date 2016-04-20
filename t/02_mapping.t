use strict;
use warnings;
use App::DubiousHTTP::Tests;
use App::DubiousHTTP::Tests::Common;

use Test::More tests => 2;

my $map = App::DubiousHTTP::Tests::Common->load_nummap(9999);
my $num = keys %$map;
ok($num>1,"map has $num entries");
ok(!$map->{10000},"all entries are in TestID map");
if ($map->{10000}) {
    for( my $i = 10000;1;$i++ ) {
	my $path = $map->{$i} or last;
	diag("missing - $path ($i)");
    }
}
