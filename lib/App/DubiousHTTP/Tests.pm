use strict;
use warnings;
package App::DubiousHTTP::Tests;

my @cat;
for my $cat ( qw( Chunked Mime ) ) {
    my $mod = 'App::DubiousHTTP::Tests::'.$cat;
    eval "require $mod" or die "cannot load $mod: $@";
    push @cat, $mod;
}

sub categories { @cat }
sub make_response {
    my $page = join("\n",
	"<!doctype html><html><body>",
	( map { "<a href=/".$_->ID.">".$_->DESCRIPTION."</a><br />" } grep { $_->TESTS } @cat ),
	"</body></html>");
    return "HTTP/1.0 200 ok\r\n".
	"Content-type: text/html\r\n".
	"Content-length: ".length($page)."\r\n".
	"\r\n".
	$page;
}
1;
