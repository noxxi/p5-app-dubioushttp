use strict;
use warnings;
package App::DubiousHTTP::Tests::Common;
use MIME::Base64 'decode_base64';
use Exporter 'import';
our @EXPORT = qw(SETUP content html_escape SANITY_VALID VALID INVALID UNCOMMON_VALID UNCOMMON_INVALID garble_url ungarble_url $NOGARBLE $TRACKHDR);
use Scalar::Util 'blessed';

our $NOGARBLE = 0;
use constant {
    SANITY_VALID => 2, # no browser should fail on this
    VALID => 1,
    INVALID => 0,
    UNCOMMON_VALID => -1,
    UNCOMMON_INVALID => -2,
};

my $basedir = 'static/';
sub basedir { $basedir = pop }

my %builtin = (
    'novirus.txt' => [ 
	"Content-type: application/octet-stream\r\n".
	"Content-disposition: attachment; filename=\"novirus.txt\"\r\n",
	"Don't be afraid to look at this message. It is completely harmless. Really!",
    ],
    'eicar.txt' => [ 
	"Content-type: application/octet-stream\r\n".
	"Content-disposition: attachment; filename=\"eicar.txt\"\r\n",
	'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*',
	'EICAR test virus',
    ],
    # zipped eicar, zip prefixed with dummy gzip
    'eicar-gz-zip.zip' => [ 
	"Content-type: application/octet-stream\r\n".
	"Content-disposition: attachment; filename=\"eicar.zip\"\r\n",
	pack("H*",'1f8b08006d718255000373492c56c82c2e5148cdcc5308492d2e01008b9f3a4b10000000504b03040a0000000000a84ad2463ccf5168440000004400000009001c0065696361722e636f6d55540900036b7182556b71825575780b000104e903000004e903000058354f2150254041505b345c505a58353428505e2937434329377d2445494341522d5354414e444152442d414e544956495255532d544553542d46494c452124482b482a504b01021e030a0000000000a84ad2463ccf51684400000044000000090018000000000001000000b4810000000065696361722e636f6d55540500036b71825575780b000104e903000004e9030000504b050600000000010001004f000000870000000000'),
	'EICAR test virus in zip file, prefixed with gzip junk',
    ],
    'warn.png' => [ "Content-type: image/png\r\n", decode_base64( <<'IMAGE' ) ],
iVBORw0KGgoAAAANSUhEUgAAABkAAAAZCAIAAABLixI0AAAAI0lEQVQ4y2N8fkObgUqAiYF6YNSs
UbNGzRo1a9SsUbOGi1kA82oCHFP7+koAAAAASUVORK5CYII=
IMAGE
    'ok.png' => [ "Content-type: image/png\r\n", decode_base64( <<'IMAGE' ) ],
iVBORw0KGgoAAAANSUhEUgAAABkAAAAZCAIAAABLixI0AAAAIklEQVQ4y2Nk+MZALcDEwDBq1qhZ
o2aNmjVq1qhZo2ahAQDhPQEogMYUlwAAAABJRU5ErkJggg==
IMAGE
    'bad.png' => [ "Content-type: image/png\r\n", decode_base64( <<'IMAGE' ) ],
iVBORw0KGgoAAAANSUhEUgAAABkAAAAZCAIAAABLixI0AAAAI0lEQVQ4y2N8zKfDQCXAxEA9MGrW
qFmjZo2aNWrWqFnDxSwAAzgBT9lsF30AAAAASUVORK5CYII=
IMAGE
    'chunked.gif' => [ "Content-type: image/gif\r\n", decode_base64( <<'IMAGE' ) ],
R0lGODlhFAAUAKUrAAAAAAQEBAUFBQsLCxMTExYWFhcXFxwcHB0dHSAgICEhISwsLDExMTMzMzY2
Njo6OkFBQUJCQkZGRkhISGhoaGlpaZiYmJmZmZqamp6enqCgoKKiosfHx9bW1tfX19/f3+Dg4OTk
5Obm5ujo6Onp6erq6vX19fb29vn5+fr6+vv7+///////////////////////////////////////
/////////////////////////////////////////////yH5BAEKAD8ALAAAAAAUABQAAAZgwJVw
SCwaj8ikcslEqjQTg2CwoHCUIgdgy90mUw3AwfJJmTqYRxIDSJCawwhgAx8SAKO6MABQ6Vd3eXoQ
c38XAAoleigMAAgXICknHmlKIWFdXEspGRIFAVQVV3+kpUpBADs=
IMAGE
    'clen.gif' => [ "Content-type: image/gif\r\n", decode_base64( <<'IMAGE' ) ],
R0lGODlhFAAUAKEBAAAAAP///////////yH5BAEKAAIALAAAAAAUABQAAAIhjI+py+0PFwAxzYou
Nnp3/FVhNELlczppM7Wt6b7bTGMFADs=
IMAGE
    'ok.html' =>  sub {
	my $spec = shift;
	return [ "Content-type: text/html\r\n", 
	    "<script src=/ping.js></script><script>ping_back('/ping?OK:$spec')</script><body style='background: #00e800;'><div style='text-align:center'>HTML</div></body>" ]
    },
    'bad.html' =>  sub {
	my $spec = shift;
	return [ "Content-type: text/html\r\n", 
	    "<script src=/ping.js></script><script>ping_back('/ping?BAD:$spec')</script><body style='background: #e30e2c;'><div style='text-align:center'>HTML</div></body>" ]
    },
    'warn.html' =>  sub {
	my $spec = shift;
	return [ "Content-type: text/html\r\n", 
	    "<script src=/ping.js></script><script>ping_back('/ping?WARN:$spec')</script><body style='background: #e7d82b'><div style='text-align:center'>HTML</div></body>" ]
    },

    # we hide javascript behind GIF87a to work around content filters :)
    'ok.js' => sub {
	my $spec = shift;
	return [ "Content-type: application/javascript\n",
	    "GIF87a=1;try { document.getElementById('$spec').style.backgroundColor = '#00e800'; } catch(e) {} ping_back('/ping?OK:$spec');" ]
    },
    'bad.js' => sub {
	my $spec = shift;
	return [ "Content-type: application/javascript\r\n",
	    "GIF87a=1;try { document.getElementById('$spec').style.backgroundColor = '#e30e2c'; } catch(e) {} ping_back('/ping?BAD:$spec');" ]
    },
    'warn.js' => sub {
	my $spec = shift;
	return [ "Content-type: application/javascript\r\n",
	    "GIF87a=1;try { document.getElementById('$spec').style.backgroundColor = '#e7d82b'; } catch(e) {} ping_back('/ping?WARN:$spec');" ]
    },
    'ping' =>  [ "Content-type: text/plain\r\n", "pong" ],
    'ping.js' => [ 
	"Content-type: application/javascript\r\n".
	"Expires: Tue, 30 Jul 2033 20:04:02 GMT\r\n",
	<<'PING_JS' ],
GIF87a=1;
function ping_back(url) {
    var xmlHttp = null;
    try { xmlHttp = new XMLHttpRequest(); } 
    catch(e) {
	try { xmlHttp  = new ActiveXObject("Microsoft.XMLHTTP"); } 
	catch(e) {
	    try { xmlHttp  = new ActiveXObject("Msxml2.XMLHTTP"); } 
	    catch(e) { xmlHttp  = null; }
	}
    }
    if (xmlHttp) {
	xmlHttp.open('GET', url, true);
	xmlHttp.send(null);
    }
}
PING_JS
    'stylesheet.css' => [
	"Content-type: text/css\r\n".
	"Expires: Tue, 30 Jul 2033 20:04:02 GMT\r\n",
	<<'STYLESHEET' ],
body { max-width: 55em; line-height: 140%; margin-left: 2em; }
ul { list-style-type: square; padding-left: 2em; }
h1 { font-variant: small-caps; font-size: x-large; }
h2,h3 { font-size: large; }
.runtest { text-align: right; margin-right: 20%; }
.runtest a {
  text-decoration: none;
  background-color: #a3a9d4;
  color: #333333;
  padding: 4px 6px 4px 6px;
  white-space: nowrap;
}

h1,h2,h3 { border: 1px; border-style: solid; padding: 5px 10px 5px 10px; }
h1 { color: #000; background: #eee; padding-top: 10px; padding-bottom: 10px; }
h2 { color: #444; background: #eee; }
h3 { color: #444; background: #fff; }
h2,h3 { margin-top: 2em; }

* { font-size: medium; font-family: Verdana,sans-serif; }

pre { font-family: Monospace,monospace; }

.button {
  text-decoration: none;
  background-color: #EEEEEE;
  color: #333333;
  padding: 2px 6px 2px 6px;
  border-top: 1px solid #CCCCCC;
  border-right: 1px solid #333333;
  border-bottom: 1px solid #333333;
  border-left: 1px solid #CCCCCC;
  white-space: nowrap;
}
STYLESHEET
);


sub content {
    my ($page,$spec) = @_;
    $page =~s{^/+}{};
    my ($hdr,$data);
    if ( my $builtin = $builtin{$page} ) {
	$builtin = $builtin->($spec) if ref($builtin) eq 'CODE';
	return @$builtin;
    } 
    if ( $basedir && open( my $fh,'<',"$basedir/$page" )) {
	$hdr = 
	    $page =~m{\.js$} ? "Content-type: application/javascript\r\n" :
	    $page =~m{\.css$} ? "Content-type: text/css\r\n" :
	    $page =~m{\.html?$} ? "Content-type: text/html\r\n" :
	    $page =~m{\.(gif|png|jpeg)$} ? "Content-type: image/$1\r\n" :
	    "";
	$data = do { local $/; <$fh> };
	return ($hdr,$data);
    }
    return;
}

sub html_escape {
    local $_ = shift;
    s{\&}{&amp;}g;
    s{<}{&lt;}g;
    s{>}{&gt;}g;
    return $_
}

sub SETUP {
    my ($id,$desc,$ldesc,@tests) = @_;
    my $pkg = caller();
    my @tests_only;
    for my $t (@tests) {
	# title | valid,spec,desc
	if (@$t>1) {
	    $t = bless [ @{$t}[1,2,0] ], $pkg.'::Test';
	    push @tests_only, $t;
	}
    }

    no strict 'refs';
    *{$pkg.'::ID'} = sub { $id };
    *{$pkg.'::SHORT_DESC'} = sub { $desc };
    *{$pkg.'::LONG_DESC_HTML'} = sub { $ldesc };
    *{$pkg.'::TESTS'} = sub { @tests_only };
    *{$pkg.'::make_index_page'} = sub { 
	my ($self,$page,$spec,$rqhdr) = @_;
	return make_index_page($pkg,@tests) if ! $spec;
	return make_index_page($pkg,undef,grep { $_->[0] && $_->[0] eq $spec } @tests);
    };

    *{$pkg.'::Test::ID'} = sub { shift->[0] };
    *{$pkg.'::Test::DESCRIPTION'} = sub { shift->[1] };
    *{$pkg.'::Test::VALID'} = sub { shift->[2] };
    *{$pkg.'::Test::url'} = sub { 
	my ($self,$page) = @_;
	return garble_url("/$id/$page/$self->[0]");
    };
    *{$pkg.'::Test::make_response'} = sub { 
	my ($self,$page,$spec,$rqhdr) = @_;
	return $pkg->make_response($page,$self->[0],$rqhdr);
    };
}

sub make_index_page {
    my ($class,@tests) = @_;
    my $body = <<'BODY';
<!doctype html><html lang=en><body>
<script src=/ping.js></script>
<link rel="stylesheet" href="/stylesheet.css">
BODY
    if ($tests[0]) {
	$body .= "<h1>".$class->SHORT_DESC."</h1>";
	$body .= $class->LONG_DESC_HTML()."<hr>";
    } else {
	# skip header
	shift @tests
    }
    $body .= '<table style="width: 100%; border-style: none; border-spacing: 0px;">';
    for my $test (@tests) {
	if (!blessed($test)) {
	    $body .= "<tr><td colspan=5><h2>$test->[0]</h2></td></tr>";
	    next;
	} 
	my $valid = $test->VALID;
	my $base = $valid>0 ? 'ok' : $valid<0 ? 'warn' : 'bad';
	my $bg = $valid>0 ? '#e30e2c' : $valid<0 ? '#d0cfd1' : '#00e800';
	$body .= "<tr>";
	$body .= "<td>". html_escape($test->DESCRIPTION) ."</td>";
	$body .= "<td><div style='height: 2em; border-style: solid; border-width: 1px; width: 6em; text-align: center; background: $bg url(\"".$test->url("$base.png"). "\");'><span style='vertical-align: middle;'>IMAGE</span></div></td>";
	$body .= "<td><div id='".$test->ID."' style='height: 2em; border-style: solid; border-width: 1px; width: 6em; text-align: center; background: $bg'><span style='vertical-align: middle;'>SCRIPT</span></div></td>";
	$body .= "<td><iframe seamless=seamless scrolling=no style='border-style: solid; border-width: 1px; width: 6em; height: 2em; overflow: hidden;' src=". $test->url("$base.html"). "></iframe></td>";
	$body .= "<td>&nbsp;<a class=button download='eicar.com' href=". $test->url('eicar.txt').">load EICAR</a>&nbsp;</td>";
	# $body .= "<td>&nbsp;<a class=button download='eicar.zip' href=". $test->url('eicar-gz-zip.zip').">load gzjunk+eicar.zip</a>&nbsp;</td>";
	$body .= "</tr>";
	$body .= "<script src=".$test->url("$base.js")."></script>";
	$body .= "<tr><td colspan=5><hr></td></tr>";
    }
    $body .= "</table>";
    $body .= "</body></html>";
    return "HTTP/1.0 200 Ok\r\n".
        "Content-type: text/html\r\n".
        "Content-length: ".length($body)."\r\n\r\n".
        $body;
}

sub garble_url {
    my $url = shift;
    return $url if $NOGARBLE;
    my ($keep,$garble) = $url =~m{^((?:https?://[^/]+)?/)(.+)}
        or return $url;
    my @g = split('',$garble);
    my $g = pack('L',rand(2**32));
    my @r = unpack("aaaa",$g);
    while (@g) {
        $g .= shift(@g) ^ $r[0];
        push @r, shift(@r);
    }
    # url safe base64
    $g = pack('u',$g);
    $g =~s{(^.|\n)}{}mg;
    $g =~tr{` -_}{AA-Za-z0-9\-_};
    if ( my $pad = ( 3 - (4+length($garble)) % 3 ) % 3) {
	substr($g,-$pad) = '=' x $pad;
    }
    return "$keep=$g";
}

sub ungarble_url {
    my $url = shift;
    my ($keep,$u,$rest) = $url =~m{^(.*/)=([0-9A-Za-z_\-]+={0,2})([/? ].*)?$}
        or return $url;
    # url safe base64 -d
    $u =~s{=+$}{};
    $u =~tr{A-Za-z0-9\-_}{`!-_};
    $u =~s{(.{1,60})}{ chr(32 + length($1)*3/4) . $1 . "\n" }eg;
    $u = unpack("u",$u);
    my @r = unpack('aaaa',substr($u,0,4,''));
    my @u = split('',$u);
    $u = '';
    while (@u) {
        $u .= shift(@u) ^ $r[0];
        push @r, shift(@r);
    }
    # make sure we only have valid stuff here
    $u = 'some-binary-junk' if $u =~m{[\x00-\x1f\x7f-\xff]};
    return $keep . $u . ($rest || '');
}


1;
