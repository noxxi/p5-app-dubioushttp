use strict;
use warnings;
use Test::More tests => 1;
ok( system( $^X,'-Mblib','-cw','bin/dubious_http.pl') == 0, 'syntax check dubious_http.pl');
