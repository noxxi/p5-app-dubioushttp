#!/usr/bin/perl
use strict;
use warnings;
use App::DubiousHTTP::Tests;
use App::DubiousHTTP::Tests::Common;


my $oldmap = eval( 
    "require App::DubiousHTTP::Tests::TestID; ".
    "App::DubiousHTTP::Tests::TestID->num2path"
) || {};
my $newmap = App::DubiousHTTP::Tests::Common->load_nummap(0);
exit(0) if keys %$oldmap == keys %$newmap; # no changes

# need to update map
my $mapping = '';
for(sort { $a <=> $b } keys %$newmap) {
    $mapping .= "    $_\t=> \"\Q$newmap->{$_}\E\",\n";
}

my $code = <<CODE;
use strict;
use warnings;
package App::DubiousHTTP::Tests::TestID;

sub num2path {{
$mapping
}};

1;
CODE


# update existing file or create new one
my $path = $INC{'App/DubiousHTTP/Tests/TestID.pm'};
if (!$path) {
    $path = $INC{'App/DubiousHTTP/Tests/Common.pm'} or die;
    $path =~s{/[^/]+\z}{/TestID.pm};
}
open( my $fh,'>',$path) or die "failed to create $path: $!";
print $fh $code;
close($fh);
exit(0);
