use strict;
use warnings;
package App::DubiousHTTP::Tests::Common;
use MIME::Base64 'decode_base64';
use Exporter 'import';
our @EXPORT = qw(SETUP content html_escape);

my $basedir = 'static/';
sub basedir { $basedir = pop }

my %builtin = (
    'eicar.txt' => [ 
	"Content-type: application/octet-stream\r\n".
	"Content-disposition: attachment; filename=\"eicar.txt\"\r\n",
	'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*',
    ],
    # zipped eicar, zip prefixed with dummy gzip
    'eicar-gz-zip.zip' => [ 
	"Content-type: application/octet-stream\r\n".
	"Content-disposition: attachment; filename=\"eicar.zip\"\r\n",
	pack("H*",'1f8b08006d718255000373492c56c82c2e5148cdcc5308492d2e01008b9f3a4b10000000504b03040a0000000000a84ad2463ccf5168440000004400000009001c0065696361722e636f6d55540900036b7182556b71825575780b000104e903000004e903000058354f2150254041505b345c505a58353428505e2937434329377d2445494341522d5354414e444152442d414e544956495255532d544553542d46494c452124482b482a504b01021e030a0000000000a84ad2463ccf51684400000044000000090018000000000001000000b4810000000065696361722e636f6d55540500036b71825575780b000104e903000004e9030000504b050600000000010001004f000000870000000000'),
    ],
    'ok.gif' => [ "Content-type: image/gif\r\n", decode_base64( <<'IMAGE' ) ],
R0lGODdhFAAUAOMMAAC7ABXBFUfOR1fSV2zYbIHdgajoqOH34ev66/H78fL88v7//v//////////
/////ywAAAAAFAAUAAAEPpDJSau9WIKcweaW94GUSJbeOYkjyaqaiWKEjKY3XomFciCsgOHCAiw8
As8gQSyyBCAngOCSnpywF4yh24IiADs=
IMAGE
    'bad.gif' => [ "Content-type: image/gif\r\n", decode_base64( <<'IMAGE' ) ],
R0lGODdhFAAUAKU/ANUAANUBAdUCAtYCAtYDA9YEBNYGBtYHB9YICNcKCtcMDNcODtgQENgSEtkY
GNocHNogINskJNwsLN44ON88POBAQOBBQeBEROFGRuFISOJMTONUVONYWOVgYOVhYeVkZOZra+l8
fOqAgOuEhOyMjO2QkO2UlO6YmO+cnO+goPCkpPGoqPGsrPKurvKwsPO0tPO4uPXAwPXExPbIyPfM
zPfQ0PnY2Pnc3Prg4Pvk5Pzs7P3w8P309P74+P/8/P///ywAAAAAFAAUAAAGp0DAAaD5GY9IFGAJ
mDELNyTSR2EGRkzAR3pcMQUJnITJ2HFnjmUAoPq5siRpqrAUACLHDvNQwhlldFkmRzsRWXctVVkb
PkgxBIeRIY1SMAiRTCJcRzQPmAs8m0c9GJgcfps2GphLCCeoRzEKrIcKcT4ll1kFIBasPHpZCiM6
RioDkYpMGVFINBNZDVkGLKI/LxCRCDXWRjoVSx5LId2EnjkTF2blRl5BADs=
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
	    "<body>ok<script src=/ping.js></script><script>ping_back('/ping?OK:$spec')</script></body>" ]
    },
    'bad.html' =>  sub {
	my $spec = shift;
	return [ "Content-type: text/html\r\n", 
	    "<body>BAD!<script src=/ping.js></script><script>ping_back('/ping?BAD:$spec')</script></body>" ]
    },

    # we hide javascript behind image/gif...GIF87a to work around content filters :)
    'ok.js' => sub {
	my $spec = shift;
	return [ "Content-type: image/gif\r\n",
	    "GIF87a=1;ping_back('/ping?OK:$spec');" ]
    },
    'bad.js' => sub {
	my $spec = shift;
	return [ "Content-type: image/gif\r\n",
	    "GIF87a=1;ping_back('/ping?BAD:$spec');" ]
    },
    '/ping' =>  [ "Content-type: text/plain\r\n", "pong" ],
    '/ping.js' => [ 
	"Content-type: image/gif\r\n".
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
);


sub content {
    my ($page,$spec) = @_;
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
	# good,title,@tests
	my ($good,$title,@tests) = @$t;
	@tests = map { bless [ @$_ ], $pkg.'::Test' } @tests;
	push @tests_only, @tests;
	@$t = ( $good,$title,@tests );
    }

    no strict 'refs';
    *{$pkg.'::ID'} = sub { $id };
    *{$pkg.'::SHORT_DESC'} = sub { $desc };
    *{$pkg.'::LONG_DESC'} = sub { $ldesc };
    *{$pkg.'::TESTS'} = sub { @tests_only };
    *{$pkg.'::make_index_page'} = sub { make_index_page($pkg,@tests) };

    *{$pkg.'::Test::ID'} = sub { shift->[0] };
    *{$pkg.'::Test::DESCRIPTION'} = sub { shift->[1] };
    *{$pkg.'::Test::url'} = sub { 
	my ($self,$page) = @_;
	return "/$id/$page/$self->[0]"
    };
    *{$pkg.'::Test::make_response'} = sub { 
	my ($self,$page,$spec,$rqhdr) = @_;
	return $pkg->make_response($page,$self->[0],$rqhdr);
    };
}

sub make_index_page {
    my $class = shift;
    my $body = <<'BODY';
<!doctype html><html lang=en><body>
<script src=/ping.js></script>
BODY
    $body .= "<pre>".html_escape($class->LONG_DESC())."</pre><hr>";
    $body .= "<table>";
    for(@_) {
	my ($good,$title,@tests) = @$_;
	$body .= "<tr><td colspan=4><hr>$title<hr></td></tr>";
	for my $test (@tests) {
	    my $base = $good ? 'ok':'bad';
	    $body .= "<tr>";
	    $body .= "<td style='border-style:solid; border-width:1px'><img src=". $test->url("$base.gif"). "></td>";
	    $body .= "<td style='border-style:solid; border-width:1px'><iframe style='width: 10em; height: 3em;' src=". $test->url("$base.html"). "></iframe></td>";
	    $body .= "<td>". html_escape($test->DESCRIPTION) ."</td>";
	    $body .= "<td><a href=". $test->url('eicar.txt').">load EICAR</a></td>";
	    $body .= "<td><a href=". $test->url('eicar-gz-zip.zip').">load gzjunk+eicar.zip</a></td>";
	    $body .= "</tr>";
	    $body .= "<script src=".$test->url("$base.js")."></script>";
	}
    }
    $body .= "</table>";
    $body .= "</body></html>";
    return "HTTP/1.0 200 Ok\r\n".
        "Content-type: text/html\r\n".
        "Content-length: ".length($body)."\r\n\r\n".
        $body;
}


1;
