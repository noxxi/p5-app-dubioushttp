# HTTP Evader: Automate Firewall and IDS Evasion Tests, Analyse Browser Behavior

While HTTP is defined in RFC2616 (HTTP/1.1) the specification does not address
every tiny detail. This makes browsers behave similar for the usual HTTP
traffic, but they differ in behavior regarding unusual or invalid traffic.

The same interpretation problems can be seen in security systems, e.g.
Intrusion Detection Systems (IDS), proxies or firewalls. Thus differences in the
interpretation of HTTP leave enough room for bypassing these security
systems.

This module contains predefined tests to generate dubious HTTP responses.
The distribution contains also a script `dubious_http.pl` which can be used
as an HTTP server to serve these dubious HTTP responses. This can also be used
to automatically test a firewall for possible evasion.
Alternativly it can be used to generate pcap-Files containing the dubious HTTP
traffic, which instead of life traffic can be fed for analysis into IDS
systems.

See http://noxxi.de/research/http-evader.html for on overview of the automatic
evasion tests and http://noxxi.de/research/semantic-gap.html for more details on
using interpretation differences between different browsers and security systems 
to bypass the latter.

## Dependencies

+ [ExtUtils::MakeMaker](http://deps.cpantesters.org/?module=ExtUtils::MakeMaker;perl=latest;os=any%20OS;pureperl=0)
+ [Compress::Raw::Lzma](http://deps.cpantesters.org/?module=Compress::Raw::Lzma;perl=latest;os=Linux;pureperl=0) (may require manual steps, see [iss-4](https://github.com/noxxi/p5-app-dubioushttp/issues/4))
+ [Time::HiRes](http://deps.cpantesters.org/?module=Time::HiRes;perl=latest;os=Linux;pureperl=0)
+ [Compress::Raw::Zlib](http://deps.cpantesters.org/?module=Compress::Raw::Zlib;perl=latest;os=Linux;pureperl=0)

Also see [dependencies](http://deps.cpantesters.org/?module=App%3A%3ADubiousHTTP;perl=latest) on CPAN.

## Installation

### Automatic installation

To install the latest perl module automatically with [CPAN](https://www.cpan.org/), just run:

```
$ cpan App::DubiousHTTP
```

Also see [App::DubiousHTTP](http://search.cpan.org/search?query=App%3ADubioushttp&mode=all) on CPAN.

### Manual installation

To manually buid the perl module from the git:

```
$ git clone https://github.com/noxxi/p5-app-dubioushttp.git dubioushttp
$ cd dubioushttp
$ perl Makefile.PL
$ make install
$ make test
# make install
```

## Quickstart Test Server

To start a test server at localhost port 8001 simply use:

```
// for global install
$ dubious_http.pl -M server --no-garble-url 127.0.0.1:8001

// locally
$ perl dubious_http.pl -M server --no-garble-url 127.0.0.1:8001
```

Additional options are available, i.e. for https support and others.
Start the script with `--help` to get more information.
