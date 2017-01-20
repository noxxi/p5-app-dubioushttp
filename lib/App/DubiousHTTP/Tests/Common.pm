use strict;
use warnings;
package App::DubiousHTTP::Tests::Common;
use Compress::Raw::Zlib;
use MIME::Base64 'decode_base64';
use Exporter 'import';
our @EXPORT = qw(
    MUSTBE_VALID SHOULDBE_VALID VALID INVALID UNCOMMON_VALID UNCOMMON_INVALID COMMON_INVALID
    SETUP content html_escape url_encode garble_url ungarble_url bro_compress zlib_compress
    $NOGARBLE $CLIENTIP $TRACKHDR $FAST_FEEDBACK
);
use Scalar::Util 'blessed';

our $CLIENTIP = undef;
our $NOGARBLE = 0;
our $FAST_FEEDBACK = 0;
use constant {
    SHOULDBE_VALID => 3,  # simple chunked, gzip.. - note if blocked
    MUSTBE_VALID => 2,    # no browser should fail on this
    VALID => 1,
    INVALID => 0,
    UNCOMMON_VALID => -1,
    UNCOMMON_INVALID => -2,
    COMMON_INVALID => -3,
};

my $basedir = 'static/';
sub basedir { $basedir = pop }

{
    my %bro = (
	"Don't be afraid to look at this message. It is completely harmless. Really!"
	    => decode_base64('G0oAAIyUq+1oRZSkJ0v1kiZ2hk1hs4NDDti/XVogkErgISv5M41kDrdKRMH7fRK8YAmyXwFNYppR3EBMbVhyBA=='),
	'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
	    => decode_base64('G0MAABQhyezgvJQnNVXciUrtsAEHrvlk0bTzGSRPqOdwPRhITMNtn+G6LB8+EYrC/LjqijSZFRhTlo5XllmqeTHxsABuVSsB'),
    );
    sub bro_compress {
	my $plain = shift;
	$bro{$plain} = shift if @_;
	return $bro{$plain};
    }
}

my %builtin = (
    'novirus.txt' => [ 
	"Content-type: application/octet-stream\r\n".
	"Content-disposition: attachment; filename=\"download.txt\"\r\n",
	"Don't be afraid to look at this message. It is completely harmless. Really!",
    ],
    'eicar.txt' => [ 
	"Content-type: application/octet-stream\r\n".
	"Content-disposition: attachment; filename=\"download.txt\"\r\n",
	'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*',
	'EICAR test virus',
    ],
    # EICAR test virus with junk behind (proper antivirus should not match
    'eicar-junk.txt' => [ 
	"Content-type: application/octet-stream\r\n".
	"Content-disposition: attachment; filename=\"download.txt\"\r\n",
	'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*WHATEVER',
    ],
    # EICAR test virus prefixed with junk (proper antivirus should not match)
    'junk-eicar.txt' => [ 
	"Content-type: application/octet-stream\r\n".
	"Content-disposition: attachment; filename=\"download.txt\"\r\n",
	'WHATEVERX5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*',
    ],
    # zipped novirus
    'novirus.zip' => [ 
	"Content-type: application/octet-stream\r\n".
	"Content-disposition: attachment; filename=\"download.zip\"\r\n",
	decode_base64('UEsDBBQAAAAIAE1900g2ai/1SAAAAEwAAAAJABwAZWljYXIuY29tVVQJAANCoWZXQqFmV3V4CwABBOkDAAAE6QMAAA3JsRGAMAgF0N4pvpVdprCxzQaoaHKCeIEm25vy3VvtXQI7g65G9UQYxOwBBaJUh7I73ZywBQYP0084WDoKNZWxCZlJpM/TD1BLAQIeAxQAAAAIAE1900g2ai/1SAAAAEwAAAAJABgAAAAAAAEAAAC0gQAAAABlaWNhci5jb21VVAUAA0KhZld1eAsAAQTpAwAABOkDAABQSwUGAAAAAAEAAQBPAAAAiwAAAAAA'),
    ],
    # zipped eicar.com
    'eicar.zip' => [ 
	"Content-type: application/octet-stream\r\n".
	"Content-disposition: attachment; filename=\"download.zip\"\r\n",
	decode_base64('UEsDBBQAAgAIABFKjkk8z1FoRgAAAEQAAAAJAAAAZWljYXIuY29tizD1VwxQdXAMiDaJCYiKMDXRCIjTNHd21jSvVXH1dHYM0g0OcfRzcQxy0XX0C/EM8wwKDdYNcQ0O0XXz9HFVVPHQ9tACAFBLAQIUAxQAAgAIABFKjkk8z1FoRgAAAEQAAAAJAAAAAAAAAAAAAAC2gQAAAABlaWNhci5jb21QSwUGAAAAAAEAAQA3AAAAbQAAAAAA'),
	'EICAR test virus as zip file',
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
    'set_success.js' => sub {
	my $spec = shift;
	return [ "Content-type: application/javascript\n", "set_success('$spec','js');" ]
    },
    'parent_set_success.html' => sub {
	my $spec = shift;
	return [ "Content-type: text/html\n", "<script>parent.set_success('$spec','html');</script>" ]
    },
    'stylesheet.css' => [
	"Content-type: text/css\r\n".
	"Expires: Tue, 30 Jul 2033 20:04:02 GMT\r\n",
	<<'STYLESHEET' ],
body { max-width: 55em; line-height: 140%; margin-left: 2em; }
ul { list-style-type: square; padding-left: 2em; }
h1 { font-variant: small-caps; font-size: x-large; }
h2,h3 { font-size: large; }
.runtest { text-align: right; margin-right: 5em; margin-top: 2em; }
.runtest a {
  text-decoration: none;
  background-color: #bfbfbf;
  color: #333333;
  padding: 4px 6px;
  white-space: nowrap;
}
#test_novirus a { background-color: #70e270; padding: 8px 10px; }
#test_virus a { background-color: #ff4d4d; padding: 8px 10px; }

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

    # give the bots something to play with
    'robots.txt' => [
	"Content-type: text/plain\r\n",
	"User-Agent: *\nDisallow: /have-fun-looking-for-goodies/\n"
    ],
    # and a nice favicon
    'favicon.ico' => [ "Content-type: image/vnd.microsoft.icon\r\n", decode_base64(<<'FAVICON') ],
AAABAAEAEBAQAAEABAAoAQAAFgAAACgAAAAQAAAAIAAAAAEABAAAAAAAgAAAAAAAAAAAAAAAEAAA
AAAAAAAAAAAASB3MAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAERAAAAAAAAAREAAAAAAAABAQAAAAAAARER
EQAAAAARAAABEAAAAAAAAAAAAAAAAAERAAAAAAAAABAAAAAAAAAAAAAAAAAAAQAAAQAAAAAREAAR
EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD//wAA//8AAP4/AAD+PwAA/r8AAPgPAADz5wAA//8A
AP4/AAD/fwAA//8AAPvvAADxxwAA//8AAP//AAD//wAA
FAVICON
);


my %cache;
sub content {
    my ($page,$spec) = @_;
    $page =~s{^/+}{};
    if (my $e = $cache{$page}) {
	return @$e;
    }

    my ($hdr,$data,$bad);
    if ( $basedir && -f "$basedir/$page" && open( my $fh,'<',"$basedir/$page" )) {
	$data = do { local $/; <$fh> };
	if ($data =~s{\A((?:\w+(?:-\w*)*:.*\r?\n){1,10})\r?\n}{}) {
	    # assume header + body
	    ( $hdr = $1 ) =~s{\r?\n}{\r\n}g;
	    $bad = $1 if $hdr =~s{^X-Virus:[ \t]*(.*\S)[ \t]*\r?\n}{}mi;
	    # check if we have a brotli compressed version
	    if (open($fh,'<',"$basedir/$page.brotli")
		and my $brotli = do { local $/; <$fh> }) {
		bro_compress($data,$brotli);
	    }
	} else {
	    $hdr =
		$page =~m{\.js$} ? "Content-type: application/javascript\r\n" :
		$page =~m{\.css$} ? "Content-type: text/css\r\n" :
		$page =~m{\.html?$} ? "Content-type: text/html\r\n" :
		$page =~m{\.(gif|png|jpeg)$} ? "Content-type: image/$1\r\n" :
		"Content-type: application/octet-stream\r\n";
	}
	$cache{$page} = [ $hdr,$data,$bad ];
	return ($hdr,$data,$bad);
    }
    if ( my $builtin = $builtin{$page} ) {
	$builtin = $builtin->($spec,"/$page") if ref($builtin) eq 'CODE';
	return @$builtin;
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

sub url_encode {
    local $_ = shift;
    s{([^\w\-&/?=!$~.,;])}{ sprintf("%%%02X",ord($1)) }esg;
    return $_;
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
    *{$pkg.'::Test::LONG_ID'} = sub { "$id-" . shift->[0] };
    *{$pkg.'::Test::NUM_ID'} = sub { _path2num("$id/".shift->[0]) };
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
	    $body .= "<tr><td colspan=6><h2>$test->[0]</h2></td></tr>";
	    next;
	} 
	my $valid = $test->VALID;
	my $base = $valid>0 ? 'ok' : $valid<0 ? 'warn' : 'bad';
	my $bg = $valid>0 ? '#e30e2c' : $valid<0 ? '#d0cfd1' : '#00e800';
	$body .= "<tr>";
	$body .= "<td>". html_escape($test->DESCRIPTION) ."</td>";
	$body .= "<td><div style='height: 2em; border-style: solid; border-width: 1px; width: 6em; text-align: center; background: $bg url(\"".$test->url("$base.png"). "\");'><span style='vertical-align: middle;'>IMAGE</span></div></td>";
	$body .= "<td><div id='".$test->LONG_ID."' style='height: 2em; border-style: solid; border-width: 1px; width: 6em; text-align: center; background: $bg'><span style='vertical-align: middle;'>SCRIPT</span></div></td>";
	$body .= "<td><iframe seamless=seamless scrolling=no style='border-style: solid; border-width: 1px; width: 6em; height: 2em; overflow: hidden;' src=". $test->url("$base.html"). "></iframe></td>";
	$body .= "<td>&nbsp;<a class=button download='eicar.com' href=". $test->url('eicar.txt').">load EICAR</a>&nbsp;</td>";
	$body .= "<td>&nbsp;<a class=button download='eicar.zip' href=". $test->url('eicar.zip').">load eicar.zip</a>&nbsp;</td>";
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
    my $xor = $CLIENTIP ? _ip2bin($CLIENTIP): pack('L',rand(2**32));
    my $g = ($CLIENTIP ? pack('C',length($xor)):'') . $xor . _xorall($garble,$xor);
    # url safe base64
    my $pad = ( 3 - length($g) % 3 ) % 3;
    $g = pack('u',$g);
    $g =~s{(^.|\n)}{}mg;
    $g =~tr{` -_}{AA-Za-z0-9\-_};
    substr($g,-$pad) = '=' x $pad if $pad;
    return $keep . ($CLIENTIP?'-':'=') . $g;
}

sub ungarble_url {
    my $url = shift;
    my ($keep,$type,$u,$rest) = $url =~m{^(.*/)([=-])([0-9A-Za-z_\-]+={0,2})([/? ].*)?$}
        or return $url;
    # url safe base64 -d
    $u =~s{=+$}{};
    $u =~tr{A-Za-z0-9\-_}{`!-_};
    $u =~s{(.{1,60})}{ chr(32 + length($1)*3/4) . $1 . "\n" }eg;
    $u = unpack("u",$u);
    my $size = ($type eq '=') ? 4: unpack('C',substr($u,0,1,''));
    my $xor = substr($u,0,$size,'');
    ${$_[0]} = _bin2ip($xor) if $type ne '=' && @_;
    $u = _xorall($u,$xor);
    # make sure we only have valid stuff here
    $u = 'some-binary-junk' if $u =~m{[\x00-\x1f\x7f-\xff]};
    return $keep . $u . ($rest || '');
}


sub zlib_compress {
    my ($data,$w) = @_;
    my $zlib = Compress::Raw::Zlib::Deflate->new(
	-WindowBits => $w eq 'gzip' ? WANT_GZIP : $w eq 'zlib' ? +MAX_WBITS() : -MAX_WBITS(),
	-AppendOutput => 1,
    );
    my $newdata = '';
    $zlib->deflate( $data, $newdata);
    $zlib->flush($newdata,Z_FINISH);
    return $newdata;
}

{
    my ($path2num,$num2path);
    sub load_nummap {
	my $maxold = @_>1 ? pop(@_) : 9999;
	$num2path = eval(
	    "require App::DubiousHTTP::Tests::TestID;".
	    "App::DubiousHTTP::Tests::TestID->num2path"
	) || {};
	$path2num = { reverse %$num2path };
	my @new;
	for my $mod ( App::DubiousHTTP::Tests->categories ) {
	    my $catid = $mod->ID;
	    for ($mod->TESTS) {
		my $path = "$catid/".$_->ID;
		if (my $n = $path2num->{$path}) {
		    $maxold = $n if !defined $maxold || $maxold<$n;
		} else {
		    push @new,$path;
		}
	    }
	}
	for(@new) {
	    $maxold++;
	    $num2path->{$maxold} = $_;
	    $path2num->{$_} = $maxold;
	}
	return $num2path;
    }
    sub _path2num {
	my $path = shift;
	$path2num || load_nummap;
	return $path2num->{$path};
    }
    sub num2path { _num2path($_[1]) }
    sub _num2path {
	my $num = shift;
	$num2path || load_nummap;
	return $num2path->{$num};
    }
}

sub _xorall {
    my ($data,$xor) = @_;
    my @x = unpack('a' x length($xor),$xor);
    my @c = split('',$data);
    $data = '';
    while (@c) {
	$data .= shift(@c) ^ $x[0];
	push @x, shift(@x);
    }
    return $data;
}

sub _ip2bin {
    my $ip = shift;

    # inet_ntop(AF_INET,...)
    return pack("CCCC",split(m{\.},$1)) 
	if $ip =~m{^(?:::ffff:)?(\d+\.\d+\.\d+\.\d+)$};

    # inet_ntop(AF_INET6,...)
    my @p = split(m{:},$ip);
    $ip = '';
    for(my $i=0;$i<@p;$i++) {
	if ($p[$i] eq '') {
	    $p[$i] = '0';
	    splice(@p,$i,0,'0') while @p<8;
	}
	$ip .= pack("n",hex($p[$i]));
    }
    return $ip;
}

sub _bin2ip {
    my $ip = shift;
    return join('.',unpack('CCCC',$ip)) if length($ip) == 4;
    my @part = unpack("n8",$ip);
    my (@null,$null,$maxnull);
    for( my $i=0;$i<@part;$i++) {
	if (!$part[$i]) {
	    $part[$i] = '0';
	    if ($null) {
		$$null++;
		$maxnull = $#null if !$maxnull || $$null>$maxnull;
	    } else {
		push @null,[$i,1];
		$null = \$null[-1][1];
	    }
	} else {
	    $part[$i] = sprintf("%x",$part[$i]);
	    $null = undef;
	}
    }
    return join(':',@part) if !defined $maxnull;
    my $begin = $null[$maxnull][0];
    my $end = $begin + $null[$maxnull][1]-1;
    return join(':', @part[0 .. $begin-1]).  '::'.  join(':',@part[$end+1 .. $#part]);
}

1;
