use strict;
use warnings;
package App::DubiousHTTP;
our $VERSION = '0.036';

1;
__END__

=head1 NAME

App::DubiousHTTP - test security systems with dubious HTTP

=head1 DESCRIPTION

While HTTP is defined in RFC2616 (HTTP/1.1) the specification does not address
every tiny detail. This makes browsers behave similar for the usual HTTP
traffic, but they differ in behavior regarding unusual or invalid traffic.

The same interpretation problems can be seen in security systems, e.g.
Intrusion Detection Systems (IDS), proxies or firewalls. Thus differences in the
interpretation of HTTP leave enough room for circumventing these security
systems.

This module contains predefined tests to generate dubious HTTP responses.
The distribution contains also a script C<dubious_http.pl> which can be used
as an HTTP server to serve these dubious HTTP responses. It can alternatively be
used to generate pcap-Files containing the dubious HTTP traffic, which instead
of life traffic can be fed for analysis into IDS systems.

If used as a webserver several bulk-tests are available which feature automatic
firewall evasion tests and HTTP conformance tests using XMLHttpRequest, script
and img tags.

Right now the following major tests groups are defined:

=over 4

=item Tests with Transfer-Encoding chunked

These tests have shown a variety of differences among browsers and IDS regarding
the use of chunked encoding. For example they differ, if Transfer-Encoding
chunked is specified within an HTTP/1.0 response (chunked is defined for
HTTP/1.1 only) or if not specified as "chunked", but as "chunked xx" or similar.

=item Tests with Compression Using Content-Encoding and Transfer-Encoding

Various compression schemas, invalid schemas, combining schemas etc get tested.
These tests show a wide variety of behavior among browsers, firewalls and IDS.

=item Variations on Content-Length

This includes duplicate headers, contradicting headers, headers featuring MIME
comments, line folding and much more.

=item Various Broken HTTP-Headers

These are tests featuring invalid status codes or use of status code outside of
its normal context, fancy variations of white-space, HTTP version numbers,
invalid characters and much more.

=item Tests with MIME

The interpretation of multipart MIME-Messages differs a lot between browsers.
While some don't interprete multipart messages at all, others simply take the
last part and some even interprete Content-Transfer-Encoding information.

=item Tests with Range Header

These tests check the behavior, if the server sends only partial responses
back, even if the client did not ask for partial response.
With luck the client tries to resume starting with the given position.

=back

=head1 SEE ALSO

http://noxxi.de/research/http-evader.html
http://noxxi.de/research/semantic-gap.html

=head1 AUTHOR

Steffen Ullrich, 2013..2015

