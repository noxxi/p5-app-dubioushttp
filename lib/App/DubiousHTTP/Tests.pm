use strict;
use warnings;
package App::DubiousHTTP::Tests;
use App::DubiousHTTP::Tests::Common;

my @cat;
for my $cat ( qw( Chunked Mime Range Compressed ) ) {
    my $mod = 'App::DubiousHTTP::Tests::'.$cat;
    eval "require $mod" or die "cannot load $mod: $@";
    push @cat, $mod;
}

sub categories { @cat }
sub make_response {
    my $page = "<!doctype html><html><body>";
    for( grep { $_->TESTS } @cat ) {
	$page .= "<a href=/".$_->ID.">".html_escape($_->SHORT_DESC)."</a>\n";
	$page .= "<pre>".html_escape( $_->LONG_DESC )."</pre>";
    }
    $page .= "</body></html>";
    return "HTTP/1.0 200 ok\r\n".
	"Content-type: text/html\r\n".
	"Content-length: ".length($page)."\r\n".
	"\r\n".
	$page;
}

1;
