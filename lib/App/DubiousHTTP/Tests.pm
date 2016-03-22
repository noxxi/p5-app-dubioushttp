use strict;
use warnings;
package App::DubiousHTTP::Tests;
use App::DubiousHTTP::Tests::Common;
use App::DubiousHTTP;
use MIME::Base64 'encode_base64';


my @cat;
for my $cat ( qw( Chunked Compressed Clen Broken Mime MessageRfc822 Range ) ) {
    my $mod = 'App::DubiousHTTP::Tests::'.$cat;
    eval "require $mod" or die "cannot load $mod: $@";
    push @cat, $mod;
}

sub categories { @cat }
sub make_response {
    my $page = <<'HTML';
<!doctype html><html><body>
<link rel="stylesheet" href="/stylesheet.css">
<link rel="stylesheet" href="/stylesheet.css">
<link rel="icon" href="/favicon.ico" type="image/vnd.microsoft.icon">
<h1>HTTP standard conformance tests - HTTP evader</h1>

<p>
While HTTP seems to be a simple protocol it is in reality complex enough that
different implementations of the protocol vary how the behave in case of HTTP
responses which are either slightly invalid or valid but uncommon.
These interpretation differences is critical if a firewall behaves
differently then the browser it should protect because it can be abused to
bypass the protection of the firewall.
</p>

<p>
The following tests are intended to test the behavior of browsers regarding
invalid or uncommon HTTP responses. And if there is a firewall or proxy between
the test server and the browser then it can be seen how this affects the results
and if a bypass of the protection would be possible.
More information about bypassing firewalls using interpretation differences can
be found <a href="http://noxxi.de/research/semantic-gap.html">here</a>.
</p>

<ul>
<li><a href=#xhr_eicar>Firewall evasion test - Bulk test with virus payload using XMLHttpRequest</a></li>
<li><a href=#xhr_novirus>Bulk test with innocent payload using XMLHttpRequest</a></li>
<li><a href=#js>Bulk test with innocent payload using script tag</a></li>
<li><a href=#img>Bulk test with innocent payload using img tag</a></li>
<li><a href=#iframe>Bulk test with innocent payload using iframe tag</a></li>
<li><a href=#other>Various non-bulk tests</a></li>
</ul>

<hr>

<a name=xhr_eicar>
<h2>Firewall evasion test - Bulk test with virus payload (XHR)</h2>
</a>

<p>
This bulk test tries to transfer the <a
href="http://www.eicar.org/86-0-Intended-use.html">EICAR test virus</a> from the
server to the client. This test virus is commonly used for basic tests of
antivirus and should be detected by every firewall which does deep
inspection to filter out malware. Since this virus itself is not malicious it is
safe to run this test.
</p><p>
But, the transfer is done with various kinds of uncommon or even invalid HTTP
responses to check if the inspection of the firewall can be bypassed this way.
The response from the server will then compared to the expected payload and
hopefully all transfers will be blocked either by the firewall or are considered
invalid by the browser.
</p><p>
The test uses XMLHttpRequests to issue the request and get the response. In most but
not all cases this shows the same behavior as other HTTP requests by the browser
(i.e. loading image, script,...). But to verify that an evasion is actually
possible with normal download one should use the provided link to actually test
the evasion.
</p>
<p id=test_virus class=runtest><a href="/auto/all/eicar.txt">Run Test with <strong>EICAR test virus</strong> payload</a></p>

<a name=xhr_novirus>
<h2>Bulk test with innocent payload (XHR)</h2>
</a>

<p>
This is the same bulk test as the previous one but this time the payload is
completely innocent. This test can be used to find out the behavior of the
browsers itself, i.e. how uncommon or invalid HTTP responses are handled by the
browser. It can also be used to check if the use of proxies changes this
behavior and if firewalls block innocent payload if it is transferred using an
uncommon or invalid HTTP response.
</p>
<p id=test_novirus class=runtest><a href="/auto/all/novirus.txt">Run Test with <strong>innocent</strong> payload</a></p>

<a name=js>
<h2>Bulk test with innocent Javascript</h2>
</a>

<p>
Contrary to the previous bulk tests this one is not done with XMLHttpRequest but
instead it analyzes which responses will successfully be interpreted as
JavaScript by the browser, i.e. by using the "script" tag.
</p>
<p id=test_js class=runtest><a href="/autojs/all/set_success.js">Run Test with
innocent JavaScript payload</a></p>

<a name=img>
<h2>Bulk test with innocent Image</h2>
</a>

<p>
This bulk test will use "img" tags to download an innocent image to check which
uncommon responses can be used to load images.
</p>
<p id=test_js class=runtest><a href="/autoimg/all/ok.png">Run Test with
innocent image payload</a></p>

<a name=iframe>
<h2>Bulk test with innocent Iframe</h2>
</a>

<p>
This bulk test will use "iframe" tags to download an innocent HTML to check which
uncommon responses can be used to load iframes. <b>Warning!</b>: IE and Edge seem
to have serious problems with some test cases here and will render the page
unresponsive.
</p>
<p id=test_iframe class=runtest><a href="/autohtml/all/parent_set_success.html">Run Test with
innocent iframe payload</a></p>

<a name=other>
<h2>Non-Bulk tests</h2>
</a>

<p>
The following tests analyze the behavior of browsers in specific cases, like
loading an image, loading a script and loading HTML into an iframe. They offer a
download for the EICAR test virus. The subtests in these tests all follow the
same style: If the browser behaves like expected (i.e. fails or succeeds) the
relevant element (IMAGE, SCRIPT or HTML) will turn green, if it behaves
differently it will turn red. Yellow is similar successful as green but marks an
uncommon behavior. If this uncommon behavior is not implemented (i.e. load of
image or script failed) the element will be grey. 
When trying to load HTML into an iframe it can happen that the iframe stays
empty or contains some error message or garbage instead of "HTML". In this case
it failed to load the content.
</p>
<p>
Which behavior is expected can be seen from the header preceding
the relevant section of subtests: if it says that the following requests are
VALID it is expected that loading succeeds, on INVALID requests it is expected
that they fail. In other words: anything turning red is bad and more so if it is
for INVALID requests. Because in this case the browser executes the payload even
if the HTTP response was invalid which might often be used to bypass firewalls
which behave differently.
</p>

HTML
    $page =~s{href="(/[^"]+)"}{ 'href="'. garble_url($1). '"' }eg;
    for( grep { $_->TESTS } @cat ) {
	$page .= "<h3>".html_escape($_->SHORT_DESC)."</h3>";
	$page .= $_->LONG_DESC_HTML;
	$page .= "<p class=runtest><a href=/".$_->ID.">Run Test</a></p>\n";
    }
    $page .= "</body></html>";
    return "HTTP/1.0 200 ok\r\n".
	"Content-type: text/html\r\n".
	"Content-length: ".length($page)."\r\n".
	"\r\n".
	$page;
}

sub auto {
    my $self = shift;
    my $type = shift;
    return $self->auto_xhr(@_) if $type eq 'xhr';
    return $self->auto_js(@_) if $type eq 'js';
    return $self->auto_img(@_) if $type eq 'img';
    return $self->auto_html(@_) if $type eq 'html';
    die;
}

sub auto_xhr {
    my ($self,$cat,$page,$spec,$qstring,$rqhdr) = @_;
    $page ||= 'eicar.txt';
    my $html = _auto_static_html();
    my ($hdr,$body,$isbad) = content($page);
    $html .= "<script>\n";

    if (my ($vendor,$msg) = vendor_notice($CLIENTIP)) {
	warn "VENDOR_NOTICE($CLIENTIP) $vendor\n";
	$msg =~s{(\\|")|(\r)|(\n)|(\t)}{ "\\".($1||($2?'r':$3?'n':'t'))}eg;
	$html .= "vendor_notice(\"$msg\");\n";
    }

    my ($accept) = $rqhdr =~m{^Accept:[ \t]*([^\r\n]+)}mi;
    if ($qstring =~m{(?:^|\&)accept=([^&]*)}) {
	($accept = $1) =~s{(?:%([a-f\d]{2})|(\+))}{ $2 ? ' ' : chr(hex($1)) }esg;
    }
    $html .= "accept = '".quotemeta($accept)."';\n" if $accept;
    $html .= "fast_feedback = 16384;\n" if $FAST_FEEDBACK;
    if ($page eq 'eicar.txt') {
	$html .= "div_title.innerHTML = '<h1>Firewall evasion test with EICAR test virus</h1>';";
    } else {
	$html .= "div_title.innerHTML = '<h1>Browser behavior test with XMLHTTPRequest</h1>';";
    }

    $html .= "expect64 = '".encode_base64($body,'')."';\n";
    $html .= 'results = "V | '.App::DubiousHTTP->VERSION.'\n";' . "\n";
    $isbad ||= '';
    $html .= "isbad ='$isbad';\n";
    if ($isbad) {
	$html .= "expect64_harmless = '".encode_base64( (content('novirus.txt'))[1],'')."';\n";
	$html .= "checks.push({ page:'". garble_url("/clen/novirus.txt/close,clen,content").
	    "', desc:'sanity check without test virus', valid:2, log_header:1, harmless:1, file: 'novirus.txt' });\n";
	$html .= "checks.push({ page:'". garble_url("/clen/$page/close,clen,content").
	    "', desc:'sanity check with test virus', valid:2, expect_bad:1, log_header:1, file: '$page' });\n";
    } else {
	$html .= "checks.push({ page:'". garble_url("/clen/$page/close,clen,content").
	    "', desc:'sanity check', valid:2, log_header:1, file: '$page' });\n";
    }
    for(@cat) {
	next if $cat ne 'all' && $_->ID ne $cat;
	for($_->TESTS) {
	    if ($isbad) {
		$html .= sprintf("checks.push({ page:'%s', desc:'%s', valid:%d, harmless_page: '%s', file: '%s'  });\n",
		    url_encode($_->url($page)), quotemeta(html_escape($_->DESCRIPTION)), $_->VALID, url_encode($_->url('novirus.txt')),'novirus.txt')
	    } else {
		$html .= sprintf("checks.push({ page:'%s', desc:'%s', valid:%d, file:'%s' });\n",
		    url_encode($_->url($page)), quotemeta(html_escape($_->DESCRIPTION)), $_->VALID,$page)
	    }
	}

    }
    $html .= sprintf("reference='%x' + Math.floor(time()/1000).toString(16);\n", rand(2**32));
    $html .= "runtests();\n</script>\n";
    return "HTTP/1.0 200 ok\r\n".
	"Content-type: text/html\r\n".
	"Content-length: ".length($html)."\r\n".
	"ETag: ".App::DubiousHTTP->VERSION."\r\n".
	"\r\n".
	$html;
}

sub auto_img {
    my ($self,$cat) = @_;
    _auto_imgjshtml($cat, 'Browser behavior test with img tag', 'ok.png', sub {
	my ($url,$id) = @_;
	return "<img id='$id' src='$url' onload='set_success(\"$id\",\"img\");' onerror='set_fail(\"$id\",\"img\");' />";
    });
}

sub auto_js {
    my ($self,$cat) = @_;
    _auto_imgjshtml($cat, 'Browser behavior test with script tag', 'set_success.js', sub {
	my ($url,$id) = @_;
	#return "<script id='$id' src='$url' onload='set_load(\"$id\",\"js\");' onerror='set_fail(\"$id\",\"js\");' onreadystatechange='set_load(\"$id\",\"js\");'></script>";
	return <<"JS"
function(div) {
    var s = document.createElement('script');
    s.setAttribute('src','$url');
    s.setAttribute('id','$id');
    s.setAttribute('onload','set_load(\"$id\",\"js\");');
    s.setAttribute('onreadystatechange','set_load(\"$id\",\"js\");');
    s.setAttribute('onerror','set_fail(\"$id\",\"js\");');
    div.appendChild(s);
}
JS
    });
}

sub auto_html {
    my ($self,$cat) = @_;
    _auto_imgjshtml($cat, 'Browser behavior test with iframe including HTML', 'parent_set_success.html', sub {
	my ($url,$id) = @_;
	return "<iframe id='$id' src='$url' onload='set_load(\"$id\",\"html\");' onerror='set_fail(\"$id\",\"html\");' onreadystatechange='set_load(\"$id\",\"html\");'></iframe>";
    });
}

sub _auto_imgjshtml {
    my ($cat,$title,$page,$mkhtml) = @_;

    my $jsglob = '';
    $jsglob .= sprintf("reference='%x' + Math.floor(time()/1000).toString(16);\n", rand(2**32));
    $jsglob .= "fast_feedback = 16384;\n" if $FAST_FEEDBACK;
    my $rand = rand();
    for(@cat) {
	next if $cat ne 'all' && $_->ID ne $cat;
	for($_->TESTS) {
	    my $xid = quotemeta(html_escape($_->LONG_ID));
	    my $url = url_encode($_->url($page));
	    my $html = $mkhtml->("$url?rand=$rand",$xid);
	    $jsglob .= "checks.push({ "
		. "page: '$url', xid: '$xid', "
		. 'desc: "'.quotemeta(html_escape($_->DESCRIPTION)) .'",'
		. 'valid: '.$_->VALID .','
		. 'html: '.($html =~m{^function} ? $html : '"'.quotemeta($html).'"')
		."});\n";
	}
    }
    $jsglob .= "div_title.innerHTML = '<h1>".html_escape($title)."</h1>';";
    $jsglob .= "runtests()\n";

    my $html = _auto_static_html()."<script>$jsglob</script>\n";
    return "HTTP/1.0 200 ok\r\n".
	"Content-type: text/html\r\n".
	"Content-length: ".length($html)."\r\n".
	"ETag: ".App::DubiousHTTP->VERSION."\r\n".
	"\r\n".
	$html;
}

sub _auto_static_html { return <<'HTML'; }
<!doctype html>
<meta charset="utf-8">
<style>
body      { font-family: Verdana, sans-serif; }
#title    { padding: 1em; margin: 1em; border: 1px; border-style: solid; color: #000; background: #eee;  }
#title h1 { font-size: 190%; }
#vendor_notice  { padding: 2em; margin: 1em; background: #000000; color: #ff0000; font-size: 150%; display: none; }
#nobad    { padding: 2em; margin: 1em; background: #ff3333; display: none; }
#nobad div   { font-size: 150%; margin: 0.5em;  }
#noevade  { padding: 1em; margin: 1em; background: green; display: none; }
#overblock { padding: 1em; margin: 1em; background: #ff9933; display: none; }
#evadable { padding: 1em; margin: 1em; background: #ff3333; display: none; }
#urlblock { padding: 1em; margin: 1em; background: #ffff00  ; display: none; }
#urlblock div  { font-size: 150%; margin: 0.5em;  }
#notice   { padding: 1em; margin: 1em; background: #e9f2e1; display: none; }
#warnings { padding: 1em; margin: 1em; background: #e3a79f; display: none; }
#process  { padding: 1em; margin: 1em; background: #f2f299; }
#debug    { padding: 1em; margin: 1em; }
.desc     { font-size: 110%; }
.srclink  { font-variant: small-caps; }
.trylink  { font-variant: small-caps; }
#eicar    { font-family: Lucida Sans Typewriter,Lucida Console,monaco,Bitstream Vera Sans Mono,monospace; padding: 0.5em; margin: 0.5em; border-style: solid; border-width: 1px; }
</style>
<div id=noscript>
You need to have JavaScript enabled to run this tests.
</div>
<div id=title></div>
<div id=vendor_notice> </div>
<div id=nobad> </div>
<div id=urlblock> </div>
<div id=evasions></div>
<div id=process></div>
<div id=evadable> </div>
<div id=overblock> </div>
<div id=noevade> </div>
<div id=warnings><h1>Serious Problems</h1><ul id=ol_warnings></ul></div>
<div id=notice><h1>Behavior in Uncommon Cases</h1><ul id=ol_notice></ul></div>
<div id=debug><h1>Debug</h1></div>
<div id=work style='display:none;'></div>
<script>

var time = Date.now || function() { return +new Date; };

function vendor_notice(msg) {
    var div = document.getElementById('vendor_notice');
    if (!div) return;
    div.innerHTML = msg;
    div.style.display = 'block';
}

function base64_encode(input,urlsafe) {
    var chr1, chr2, chr3, enc1, enc2, enc3, enc4;
    var output = "";
    var chrs = urlsafe
	? "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_="
	: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

    for(var i=0;i<input.length; i+=3) {
	chr1 = input.charCodeAt(i) & 0xff;
	chr2 = input.charCodeAt(i+1) & 0xff;
	chr3 = input.charCodeAt(i+2) & 0xff;

	enc1 = chr1 >> 2;
	enc2 = ((chr1 & 3) << 4) | (chr2 >> 4);
	enc3 = ((chr2 & 15) << 2) | (chr3 >> 6);
	enc4 = chr3 & 63;

	if (input.length>i+2) {
	} else if (input.length>i+1) {
	    enc4 = 64;
	} else {
	    enc3 = enc4 = 64;
	}

	output = output +
	      chrs.charAt(enc1) +
	      chrs.charAt(enc2) +
	      chrs.charAt(enc3) +
	      chrs.charAt(enc4);
    }
    return output;
}

function base64_decode(input) {
    input = input.replace(/[^A-Za-z0-9\+\/\=]/g, "");
    var chrs = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

    var chr = new Array(3);
    var enc = new Array(4);
    var output = "";
    for(var i=0;i<input.length;i+=4) {
	for(var j=0;j<4;j++) {
	    enc[j] = chrs.indexOf(input.charAt(i+j));
	}

        output = output + 
            String.fromCharCode( (enc[0] << 2) | (enc[1] >> 4) )
            + ((enc[2] != 64) ? String.fromCharCode( ((enc[1] & 15) << 4) | (enc[2] >> 2) ) : '')
            + ((enc[3] != 64) ? String.fromCharCode( ((enc[2] & 3) << 6) | enc[3] ) : '');
    }

    return output;
}

/*
 * A JavaScript implementation of the RSA Data Security, Inc. MD5 Message
 * Digest Algorithm, as defined in RFC 1321.
 * Copyright (C) Paul Johnston 1999 - 2000.
 * Updated by Greg Holt 2000 - 2001.
 * See http://pajhome.org.uk/site/legal.html for details.
 */

/*
 * Convert a 32-bit number to a hex string with ls-byte first
 */
var hex_chr = "0123456789abcdef";
function rhex(num)
{
  str = "";
  for(j = 0; j <= 3; j++)
    str += hex_chr.charAt((num >> (j * 8 + 4)) & 0x0F) +
           hex_chr.charAt((num >> (j * 8)) & 0x0F);
  return str;
}

/*
 * Convert a string to a sequence of 16-word blocks, stored as an array.
 * Append padding bits and the length, as described in the MD5 standard.
 */
function str2blks_MD5(str)
{
  nblk = ((str.length + 8) >> 6) + 1;
  blks = new Array(nblk * 16);
  for(i = 0; i < nblk * 16; i++) blks[i] = 0;
  for(i = 0; i < str.length; i++)
    blks[i >> 2] |= str.charCodeAt(i) << ((i % 4) * 8);
  blks[i >> 2] |= 0x80 << ((i % 4) * 8);
  blks[nblk * 16 - 2] = str.length * 8;
  return blks;
}

/*
 * Add integers, wrapping at 2^32. This uses 16-bit operations internally 
 * to work around bugs in some JS interpreters.
 */
function add(x, y)
{
  var lsw = (x & 0xFFFF) + (y & 0xFFFF);
  var msw = (x >> 16) + (y >> 16) + (lsw >> 16);
  return (msw << 16) | (lsw & 0xFFFF);
}

/*
 * Bitwise rotate a 32-bit number to the left
 */
function rol(num, cnt)
{
  return (num << cnt) | (num >>> (32 - cnt));
}

/*
 * These functions implement the basic operation for each round of the
 * algorithm.
 */
function cmn(q, a, b, x, s, t)
{
  return add(rol(add(add(a, q), add(x, t)), s), b);
}
function ff(a, b, c, d, x, s, t)
{
  return cmn((b & c) | ((~b) & d), a, b, x, s, t);
}
function gg(a, b, c, d, x, s, t)
{
  return cmn((b & d) | (c & (~d)), a, b, x, s, t);
}
function hh(a, b, c, d, x, s, t)
{
  return cmn(b ^ c ^ d, a, b, x, s, t);
}
function ii(a, b, c, d, x, s, t)
{
  return cmn(c ^ (b | (~d)), a, b, x, s, t);
}

/*
 * Take a string and return the hex representation of its MD5.
 */
function calcMD5(str)
{
  x = str2blks_MD5(str);
  a =  1732584193;
  b = -271733879;
  c = -1732584194;
  d =  271733878;

  for(i = 0; i < x.length; i += 16)
  {
    olda = a;
    oldb = b;
    oldc = c;
    oldd = d;

    a = ff(a, b, c, d, x[i+ 0], 7 , -680876936);
    d = ff(d, a, b, c, x[i+ 1], 12, -389564586);
    c = ff(c, d, a, b, x[i+ 2], 17,  606105819);
    b = ff(b, c, d, a, x[i+ 3], 22, -1044525330);
    a = ff(a, b, c, d, x[i+ 4], 7 , -176418897);
    d = ff(d, a, b, c, x[i+ 5], 12,  1200080426);
    c = ff(c, d, a, b, x[i+ 6], 17, -1473231341);
    b = ff(b, c, d, a, x[i+ 7], 22, -45705983);
    a = ff(a, b, c, d, x[i+ 8], 7 ,  1770035416);
    d = ff(d, a, b, c, x[i+ 9], 12, -1958414417);
    c = ff(c, d, a, b, x[i+10], 17, -42063);
    b = ff(b, c, d, a, x[i+11], 22, -1990404162);
    a = ff(a, b, c, d, x[i+12], 7 ,  1804603682);
    d = ff(d, a, b, c, x[i+13], 12, -40341101);
    c = ff(c, d, a, b, x[i+14], 17, -1502002290);
    b = ff(b, c, d, a, x[i+15], 22,  1236535329);    

    a = gg(a, b, c, d, x[i+ 1], 5 , -165796510);
    d = gg(d, a, b, c, x[i+ 6], 9 , -1069501632);
    c = gg(c, d, a, b, x[i+11], 14,  643717713);
    b = gg(b, c, d, a, x[i+ 0], 20, -373897302);
    a = gg(a, b, c, d, x[i+ 5], 5 , -701558691);
    d = gg(d, a, b, c, x[i+10], 9 ,  38016083);
    c = gg(c, d, a, b, x[i+15], 14, -660478335);
    b = gg(b, c, d, a, x[i+ 4], 20, -405537848);
    a = gg(a, b, c, d, x[i+ 9], 5 ,  568446438);
    d = gg(d, a, b, c, x[i+14], 9 , -1019803690);
    c = gg(c, d, a, b, x[i+ 3], 14, -187363961);
    b = gg(b, c, d, a, x[i+ 8], 20,  1163531501);
    a = gg(a, b, c, d, x[i+13], 5 , -1444681467);
    d = gg(d, a, b, c, x[i+ 2], 9 , -51403784);
    c = gg(c, d, a, b, x[i+ 7], 14,  1735328473);
    b = gg(b, c, d, a, x[i+12], 20, -1926607734);
    
    a = hh(a, b, c, d, x[i+ 5], 4 , -378558);
    d = hh(d, a, b, c, x[i+ 8], 11, -2022574463);
    c = hh(c, d, a, b, x[i+11], 16,  1839030562);
    b = hh(b, c, d, a, x[i+14], 23, -35309556);
    a = hh(a, b, c, d, x[i+ 1], 4 , -1530992060);
    d = hh(d, a, b, c, x[i+ 4], 11,  1272893353);
    c = hh(c, d, a, b, x[i+ 7], 16, -155497632);
    b = hh(b, c, d, a, x[i+10], 23, -1094730640);
    a = hh(a, b, c, d, x[i+13], 4 ,  681279174);
    d = hh(d, a, b, c, x[i+ 0], 11, -358537222);
    c = hh(c, d, a, b, x[i+ 3], 16, -722521979);
    b = hh(b, c, d, a, x[i+ 6], 23,  76029189);
    a = hh(a, b, c, d, x[i+ 9], 4 , -640364487);
    d = hh(d, a, b, c, x[i+12], 11, -421815835);
    c = hh(c, d, a, b, x[i+15], 16,  530742520);
    b = hh(b, c, d, a, x[i+ 2], 23, -995338651);

    a = ii(a, b, c, d, x[i+ 0], 6 , -198630844);
    d = ii(d, a, b, c, x[i+ 7], 10,  1126891415);
    c = ii(c, d, a, b, x[i+14], 15, -1416354905);
    b = ii(b, c, d, a, x[i+ 5], 21, -57434055);
    a = ii(a, b, c, d, x[i+12], 6 ,  1700485571);
    d = ii(d, a, b, c, x[i+ 3], 10, -1894986606);
    c = ii(c, d, a, b, x[i+10], 15, -1051523);
    b = ii(b, c, d, a, x[i+ 1], 21, -2054922799);
    a = ii(a, b, c, d, x[i+ 8], 6 ,  1873313359);
    d = ii(d, a, b, c, x[i+15], 10, -30611744);
    c = ii(c, d, a, b, x[i+ 6], 15, -1560198380);
    b = ii(b, c, d, a, x[i+13], 21,  1309151649);
    a = ii(a, b, c, d, x[i+ 4], 6 , -145523070);
    d = ii(d, a, b, c, x[i+11], 10, -1120210379);
    c = ii(c, d, a, b, x[i+ 2], 15,  718787259);
    b = ii(b, c, d, a, x[i+ 9], 21, -343485551);

    a = add(a, olda);
    b = add(b, oldb);
    c = add(c, oldc);
    d = add(d, oldd);
  }
  return rhex(a) + rhex(b) + rhex(c) + rhex(d);
}
 
var div_debug = document.getElementById('debug');
var div_notice = document.getElementById('notice');
var div_ol_notice = document.getElementById('ol_notice');
var div_warnings = document.getElementById('warnings');
var div_ol_warnings = document.getElementById('ol_warnings');
var div_nobad = document.getElementById('nobad');
var div_evasions = document.getElementById('evasions');
var div_process = document.getElementById('process');
var div_work = document.getElementById('work');
var div_title = document.getElementById('title');

var fast_feedback = 0;
var checks = [];
var current_test = null;
var results = '';
var done = 0;
var reference;

var expect64;
var expect64_harmless;
var isbad;
var accept = null;

var evasions = 0;
var evasions_blocked = 0;
var overblocked = 0;
var maybe_overblocked = 0;
var browser_invalid = 0;

var rand = Math.random();

var hashes_array = [
"a46bdb2c7009bb77971aacb32d75f26d", "b9a85f4ee98d73eabaf84f15af25b0cb", "4b2b448c57ec103ad4e125abc10ad6b6", "23c6093e64152926aca25e42274f0ac6", "a4073aa95af2b415c4d5ed845f09008f", "c297bbb5596f847aa02fa2c10e65b322", "41f6016857f5b24f05219c842f5c7b86", "faf3e7e3300999d63438085230a3bca8", "4d7e3a820c84820ad1a577962db51e97", "fd873863683fff918eaa9b2b3343d971", "6c5b517aced5dab5f4ec2755d9fb14de", "b073c5c93b2fba15133b7cd5de90cf6b", "a118c223908d7235099f5531a7fd4510", "95df50f596b7db989fe1478fdc50eb24", "a33dcb2407036aee8ded3a1ea16df2f8", "3d921446fac65d3d39388abf4c476e33", "1fc7e9f70883b99d2db72c439c3c7460", "3182e34c7e7c464f3595edff69b35642", "1d9e11b132ee4116f31cb434bdc2beb6", "c97b2d693a8fec628652edbfa5448f0f", "23de1a60cf45dcf375fe76c54afea522", "8e1797b9d7d7839470e72583cedfa6e8", "75e326f68c8647f9425b5561707dbffc", "5d67519d8faf0c7dbb6bf4b4f27585bb", "926fdccbd33ee035e747d82f72f3fbeb", "7b4990681b7b063f5e236d4ea929c167", "3b9c8bea4ee5f04fd744edae00039c09", "0bb63511ba9f25d29930e8a1607e79fe", "3aed14f76b21e83ca24d66768c4295d8", "ed238ed2a93cfd49978ea81b3a7aacc1", "ee5d4e09f4c522ace2fc3160140b5171", "e865aa74b1c5ad568f937c0c319fc0dd", "ffc732c92869f2d3b11d362e27930b3d", "2363df2e7b115d7c0b407cef75d8fbaf", "6490ed68427c02b46b4aae5afc04663c", "953565b672a00fc630682f4b7a5eb62d", "0f140f5bea9b993305c46085ea92f18d", "66b71c54b8ede132c407b3e5d0aea7f2", "fdca8a3f26da9572d1ef49b0086644e6", "9517a36e409769bd2c4fcc00386b4dd7", "e5497d8975643985555cf449bf8b85a4", "728d40313be7f335cece96f25c68c901", "59c44294b157a11b9f2f30be0d543af5", "b84c63792bc55833c12224348224cc43", "79193f97356a4565049e5e1f8052fd93", "fc291266af8f8371bad08877589d174a", "ab4956b3dc37a0645413b8460e151776", "c86cfba3a09fd6c83e8f680fc96d6e2b", "100ffc874c5964dbd2b93798c0413c42", "78bf941d8edccb2a0a8564b460831540", "d0b6b249c1efee993bd2ab620491d561", "d4672721599f69c78385c6f49582c9bb", "314a59c309bdc4d83b6419efa603a769", "c62c153723049a88dbcf91e7c89e79aa", "8f6841889b591319f84014650c2c46c0", "53f3e6d42b0b0083f8f3cdb2bcc41cde", "6f384bb50f0d2a5c754ae0b90c5bd983", "e1ffda74a12ccb1ddf8ad2578b4f1f12", "9e6547c5f175942aee46e324f8f6849d", "cc259e4f58976be261c31ebba2a2032f", "886a41d656a1beec6f4c1d3c64ccd5bd", "27316473dcba481399ba4dccb08920e2", "f085bf7ef12ff7213ff5af90359558d6", "13aee7baf05f8e60f298822922dd5160", "ab4b8fc0e2cfc50de85abfead3b2d3b0", "2c7c2b2f3e40bd4dd6e00deb222dac2e", "e89be54f239c66944ee92bc5b6854027", "8261872e0cb2d505a1b8e1b1a42e81c9", "638a0ef5aca4a561a33de1948ac100c8", "10f2a2c131f1a677152c629c275f1206", "2b88bd3fa7d0c787e3f264cb3701f50f", "8f644527baa74e99558bfd54894bda43", "1087702fc3436bfae7a4bd64abd5ca2b", "905d3fb4f8743e19c3dfa4a20cac9534", "5f1f8f1f2654255ac2021c22647d9a6a", "9140805fc56eb8f7d3c025030a637297", "5db9fa2ae8d059f1de68606551f03c0f", "9a54c1cef7e2f6f95288e56ed6207ea4", "cc5f601725795e54c14aaad141cbd03f", "5a24001cb0fc8c48936d75c859ca0abf", "1cd850621476c1d0ca205019f493faa3", "c0049317c3f175225fab03f2b2260651", "beb3b8c063e564e2c8797f6598a2d45c", "8bcc3005fefb58b315bdd2ab0b021953", "457a9b1480a3b150faa2c0ae3afcde31", "fd367f3310737527343ca40a970a763b", "a031762c1689e9a1b80d08aa621e50c1", "56f6d1a6964bbc6ba5f6ce4cbe6d14a2", "4d0e3717a34afab4e6f677a84e843efc", "c4081c1960d8f86504f042b47e29b9e0", "afe79acd2cf2cc12f8daa12518ffd65a", "497bd2121390b104fb03477a09898144", "4bed2d8ccda3db35e2a7de60f95fd279", "a1769bdcc481a3005d1946ca841a8ffa", "8d87771db7338273bbc367f6acd01e5b", "64c3ad3f4738d06f9724fea1326c6ba7", "a23c642a7d3dbc21a536e4f72a166dee", "92597534c99ff329614f21d889118265", "2de7dae7541e10f161c7df40890e4f80", "962d72d811103f4961ad20e2a0186cde", "54ec62bd79605e8a8a23ad570d0ced17", "9f9dfaeeb3d91f0d977051cedddb5ad8", "90853a460e937aedb3862183e4993dfc", "72033fff1705e3e0feb33da1f9540659", "e4778ab46eca5c2821d54dc9da209385", "0ca3aaed08d6f006ae70a46fa7118fd3", "57baa067f9f3c34c770bb647c1ebc6ba", "2717c2a8fdf37a20b4f2b75eea1460b8", "154696549e92f6d04d659050b5194402", "2162e0377817481f1fba3a55190b45e9", "b9bff9bb7a528ff6a7612d306c21943b", 
"c5b0031e37fd494861d1ea930e66842b", "13458ba22f59665f90f72229807b2dbc", "de125fde9b5e5be667418134ba999d34", "844efa935b8b2755cedc9a4d8cfa2e0d", "816c4c4a061ea35d3bb6ba4b53679655", "17633de7f1c231bab6d916877f3111b6", "8e4b9daa91cb5e329f3469587c782f66", "e712be05fcfde567fee7d0648b360ee9", "2788469b54ec26301b2545e9aa02bb28", "041995b209f351db58b56e7e1f45acea", "3eb3d41b8bbb6ea0642845206e33ad17", "75bdcc6111a18b0eb1f3fef5110ab31b", "a176b2d0db8a795fb7dd3cf570757c8f", "d66c7d80ed3d6d05a1fe48b7eb4c2b56", "0e46d5f0ef451b49fe0ad2ac558f6eb1", "9b73488b7064fd040c0324886cd61b9b", "c0053bda13e6552ce49b32379f133fa8", "60bd6a0b0b59a15a32663718b8c0d481", "d1ce52e14845e6c6109224c41aa717e5", "bdd2beef7025f1eed96ca22961d781f5", "41918f3e5fcf787ce30e50a330154072", "9557863ed5d82e00830e40c32f5c2e9e", "1653aa57598e2e1fc226647e4dbc3f16", "9dbb47bfc24348b4ddff49a28a6fda9e", "141a281a6303c42d97c9d4070b83ef9e", "79bd62f0c92c01cd21f0d347996b0561", "8fe86d28b12366958526a186b03f082e", "90a32efa654fba433a0afdb69f976bf2", "a47dc28aa009eca6e38b95f38107279c", "ddc310b0af9f5ebfd6ca2c7dc5dee14c", "6be6e47924d16116eed6922dc1a341ac", "b996b4a5195b69e1a05cf130745da7c4", "94b4a77a6c7865c274931a6a31e1c700", "7f23a414ada73de1db2f4b18fed39975", "0cef254d8b0ed1ca2cb27b0c93950171", "23df79a84eef3923c2272303b8971c65", "c1dc7ed49eb0fe4c19ecfdfe2b8e4583", "dc11724de2299fc09b9f99868d86616c", "b3acb1ec3fb6b1b25311ced1cbd21617", "2c45b698f05af12e103a5a884558dddb", "f0134579d188307ab2b9732bf0927375", "9de24591a8af6502d9580f1703405835", "02a557c8f6aa2696be971f2e61d93d62", "5d78df180a3280fed1665b6e69871905", "5f276e2d708fd9b3f5467cadd566a2a5", "5dbc4aae8c3029af24a8b30729a78938", "cd068a7e5ebb08b860b94460a0afd439", "f9f66302b968eb7a3b15d4b9f9a82f8b", "d46fb612de43300d61f20908cb2a48e1", "dcd4abb053fd36e493bc90ac11d36dee", "1872cc03a1becc501366ebadb0493e58", "c5f1788d0cf25a9d6762c5f5c042c2cb", "20da8134dca9176a3f9ecbb02c655d48", "c5b9d1d957d240fbcaee35fe325866a6", "732e057999064067f4951c56eaa24f43", "c29a8e87aecd4fd5227b299ae62c8774", "6a1707e833c9a1e27a8d4bcaea955cd9", "096e869a7e2d6c1edcf807b89853e4d4", "5efacf0bec2f8d3680b5f83413521add", "a75c6163ee5069162cb21fddc07e1ffe", "68c285af1080edf2d6404486c21561d5", "75cebb45c6c4b777416ef31e893deabf", "99acec824677817519955b5ff0cbd4d5", "915fe1c4d9d38e5bc44815d395d0e85b", "83ead41637ed5355ccd61d9920212d72", "0d83a8e61d8c2c6bdb4e6825a4a726c2", "3c5b405ad11b9ca17d1f65c540db2325", "5873a9dd21db9a444d4fec00fa6e693c", "db293cfd7a9e3537b93feaaf5cc0be60", "fc257a63db6e526eb3091bb15c4b2774", "ccfc2133da2403bdb3ee896893fe6a22", "2ac91f6762c576c501cd6461ff22f8f6", "e8217dd84ed243dc7f07689b431bec89", "ad1db44d106716ee6afbfb89c5f0edec", "0a175a8feabe7e7ccc8aa5929196775f", "a5defa2e51e3a1349d5ae8cd68520253", "7c21713d6025dfe89f50412a2bc78f5a", "525082addf6134fd00b2de1c9772aa7f", "11696d1cf8ff1f83cfcef70b95b2a5c8", "f471731315398bf518e798e58b0ad357", "86cd052926d668d6f2194b76b64a0c22", "c086de7610e093781f4f2d567226ff33", "c01e14981031ab1355dfc0bc81ce363b", "ce227ef0d7623a33dce4b16486fe1ed7", "68bd10abe467d5e7844c4c48d5842575", "a14b584e9b90008d45f1734878ed9bf6", "7a2b4bc60751071f878bfc947c779c42", "bbae18d0693e04e30d1aabd3850bc7ba", "7782a85f1d3c4f48580af101d0ce4a03", "4df85b3becdaa8842697eb232a4e74e0", "ae651044ced21dd5f395bff25909bd45", "46885f8c6686a9fc87e4e554f92a5eff", "9ba5fcc83421855146ad65cf0c630211", "ee5fe9ac4d9d6718f01d3889c0ef80d5", "f593b47096bb5a5c3f65ea211d6ff804", "fbbf1ecab8b0e5e310043674fa246c3e", "984c23c94bdbc32ca286b7253a1161ee", "eb0176515d20e57ac2b423787ead8731", "bf679388f68998a9ec1281872aa7d6e7", "a2440b5819c891ed597d935a7bec0aec", "0c6fd7ed42555aa6665904687f3533c7", "c95e742f47a46b75714e4f4aa2d7519a", "88e077295f24eb4d27494258376782e7", "7083f9859224ad2acc8da73dffc92d5a", "84badab64ac587af342da03833db7e5e", "8a4b8ed1b66b84ef845dc8ff28a3d405", "f8e10f059babcb64dbd11424362a9338", "88e1b02e602b9c87aeff3475122c4d03", "349c5ec6adc4c05ea720a4ea0e1d20ea", "84c88df3f096a0bb2267ca9c77f1efc6", "5310ea8f933a7f90a9d45ecb1488fb15", 
"5787e285446acc4d8eb56c3bc950a25a", "ce24da29103ca36b5ae0636e3342bf53", "be67bb92088535d918b18cd1f8efdca2", "befa8d19a377b457656b765bfef958c8", "49778270918584bb53a84c715be6efbd", "197427278390efda6de47792fbcd5e75", "849e0e2d6a19dee4dfa6f23b75947e7a", "617f7d52c7494dda856f591425e9e6ff", "581465b443f02279265fd22aa4cb7830", "b416e5239c569534eb8468417e391ed8", "7b11b9a611b5e4499fd93fac3a85e351", "759f0382cd3435141086940a52981b90", "a03d5b2b223a1f67fe76fb1708ff54e3", "51a26d7b61d7f4551142e06af9a6e256", "64566560b8c4ee4224570aa60a768829", "b43a8553c09e5c57b9ac7b2a553f017f", "808b5237eae554de32653d1796a47e6d", "0e70ce8f21d66fb9b7310e85198889df", "1488c8eb52ecb53f69c6f562e81f5aa1", "3289dc144b0445d8a456e393a5d41f20", "ac455a3ac758ebf1d07ecb997c238b96", "953278f9515464da95f5df25c5a6210b", "a7a848cd29c2c3ce5aeca36660592bc6", "bd3d35d384305c62bd5a01912c6aebea", "1d1379c744aabff0ac1840875a546abe", "1cf1f1a94269f140400068f12bf3fb21", "3d058a61e9cc679f736e2c232d4be04c", "5df775b29e01153b669594f35a66b55e", "1c6a68dc33d51b5df095c4e0e444465e", "3751f6277755972adbc8f48d193876f7", "b9d8acbecc1eede625f55b0b16b73a10", "1f582dcb6ae71c07214c564688165308", "eaddcbd271ec6fa28cf0ffdce064d621", "10fb14c5e815a01cc2c2ecb15a7f64c5", "f12f41e1f15f43c1e3dd0c87afe9da82", "743c70a1c06b3dac935cd51321231ab8", "d2172f21eda01091dbc77ea8b161311c", "ad2d81d56a94016fd43fa1ebf5ee6116", "e98c148c42cfb052da2954381f8eaf1c", "8c47c82f6aedb5caf7125ed9dfd45e78", "4386c8b152f0f3a6dc933a21828cb605", "9d9e6382b01cc42585535116f165d071", "3bbefeeac0b79910ee9240254adc61d1", "573eeab0813321d26d7ef0255d323cad", "10f7a79d43b2f725dbf865c955b7cd20", "7f03ecc6e294cd0b7e7c93a93dd14aa9", "a942773c95407c640f23913da5215746", "6780ea94d65ff195f9f37bc5802bca32", "96ff804f9809dc9d2bec9e2579b1239f", "ba861bd03866ab8fb4162e9bc2d25821", "4a30e517bcff764b8b531573c19591a4", "f2058183454a674b70f294c906deb7bc", "82db2fd3fba21f43d58ecfc8ab4fb79d", "71ff7353c0994b8d5f69956b1fe678e3", "ec80c287ba61ab7fb4885301f21e6c13", "2efd0c08dbbc905bed4e938a06523946", "0c6a343d9440c34cbe6fcd30d86eeffc", "19f4a596f437de295743a3866332e27a", "ea3378508b795616637bb5c57a472612", "7c022a61411351eb42f64a833a48d5ff", "c92fdef06ac1861c1f48b932c95d406a", "2c7aa6b10be1676e9b0a16e9883015f1", "b5f0a0d58b7f19affbe22f0e6d1e238a", "9632745e35b5290f5c9205c821bc314a", "7f02041bcfaa2fed00d5ab5c0ac3975a", "0926597532870d7cb5c3d253f4458138", "191f5271b2b5b1e07e41c820c49973ed", "fad59330d4586471884b9c56c7d76c63", "14b231975cf97f3cad225785b52e33c3", "feeeba8f13cdeeb2a97c4f835505c748", "6b693beafe7ec4e19e6fe54bcb1dc175", "513c94cc52b2aaa6e4eca737269d525b", "83db4be00264813b91b6b16853f00b4a", "875bed746b81bc7b66c7e531d6e47b40", "22a296e88d90a98124ea78d0e6d99c8b", "e5d8b24823d7639b3f0603d41ef3143e", "516aad8b04020fca37cb42cfefc89172", "17e45fb4099f7683295c024ad91101da", "15aabf4f5e93a38a63caf82eea022352", "d7c9defcc3c471e3c10e3b60607cad3a", "b62e7a09c0f9875be3fd6bf7aa9bf17c", "0af67e0e26151e8f09062abf3619abba", "727a5b7fca073d9b50e6e4f473656c97", "d0e0bf89bbe46845ac2f4017ee936794", "d29c49fe6cfb497f0c80978f2657063d", "07646cc8be7998e86e0b8b7afa008807", "21acaf5da75e33d45ffd428c9ab5109f", "6cf85d684cc8f42d6bafcf601ab9f499", "cb90bc22cb8fdae3fa2e5a1760e2be78", "19e8a0e9e32de8b9e2d863a470cf65f6", "0b735b63d2781787936845de5157562f", "81ba414b790f7bd5d03c2a9b478e981d", "cb88a10b6bd10c56dc70f72887dad452", "1d545a48bd5189fc1662177c7eccdb53", "9917d98a420e5b8fc8c4cd5a7833f994", "63fdcd1501a1e51891efac2746c6be67", "d3d7dd33c0d93bb11f6ea8f77406b3d3", "0e773b626f5cc20dcd13ed0c10902164", "c13a96044f2f949b12054b8a76e7ab3c", "04e516aa55f028587b74439973d1b4a8", "94450a04ca5a0b8395f04e403972195b", "24b740e2ddd1bcaa69ec98fa34dd42b0", "4489cbb928f53d8208174a6c9bd1a637", "26e0fa66e963cdeb6df3a76f4cd08e9a", "792fb2f0a271bc32bd61fb91af7c4433", "511d2a7adf72f3779dd3388cfe8206da", "c93d07899c3eb4aa2883fae375f1b736", "9a344fc647aa311f2ba0fb978a7cef17", "39be28918fad16b9007027ece6520e60", "77ee404d1632e333617f4258b0a424a2", "0afedf70f0abc511a48e0c69c892eec8",
 "28a8226e928d233bc31bd5534fdf9504", "5f49d69082705a2dbc0745c8c50d7211", "85198a27124d4a378b0b13d1f3a7e995", "55e3d31970d7ba8c29ce7db82d19b1fc", "dbabd5164a0d01aed1b94d6f35ed395f", "427d0b8f0a2e06bdaa9a3d45b32c093f", "8a69fc9e5a14ad21813d24ec0dca709f", "255913ea977c740a717a1dda235f56b6", "cd74fb4cede18ffb94955cd260e82a3e", "a7587bf4dbae0e85ebc1cbdcf1b59e4a", "623ccd2b90e9f707c16004c7a4ecfed6", "73551b57587a1ebad31b95f6be6401db", "37d619d66e0fc8e4107ef5d9d73853f0", "8a5f2f9e672752f75f60a350b4238137", "a5c4ca2f6ca8866978680a13cec97943", "5d4a3413ab4c7fa5ab544991b3d88cb3", "fe853775327f25b8d2d175c44a94d498", "7086ac4f543d8af644c118d32cd8b422", "17a83fa248e9c4e524ae0bbec7515ce5", "46dd34d0b2711371479441c4821940dd", "fe4c2434659c8e2f0f7b3c347ab8fe36", "fd184fc3726f27303def9997e6ef6c53", "532d7dd028fa1647d3eb044abaf02e6c", "3dc8a63e93d07534bac43d24abd353c4", "b16946db2ac3a06284bd00edce31d544", "e410ec616859a198b7dac79f1b3655e3", "644fbd10dabdcbaaf2ec66b770fa5313", "79a1a9874f006e5624103f36a06be574", "dcbeea64affba3df38394f63fb23cfa9", "976ea52102b7a98374fa9c10b530b6f4", "66d738588be53407f6e42f7b73bbc061", "bc5427cd71eca5b19375103aeae5273d", "cc5b912ec57ae08d3eda2c041c79ccb5", "7dee5305b550d7918397c697a983869a", "cbba3edc035434fa11c1736fcd48c73d", "3b347dc5e03ae5e364bd340a23ddf98b", "d86bb50a3fee7c2f2b8a81e21512d1cf", "48cc1cb7d7d412a8817ed6e46ff8dd45", "398335384c3858e6e313fd5b7ca8494a", "26968a071345ccacce4ee4c2dae327d2", "a8229db6bdeac6013b97883305b6f6bd", "13d6800818cd93a504ccb7b5b2c2bc82", "1d0793cd745069ceab69c508137e5045", "531edc50b01ed5bbfc92280484f27f8c", "b34ab31b1ea134ee84c7c7c811d1c2e2", "0d3210b81d4f8f9b1e6fde2786570849", "a970edd6b730e6db4c631b01414f9a77", "05b396f9850c8cb316778e1b7fd5a3e9", "89287e2c4a0e36b4dffc0f0688f6933f", "b3bd1824028064603077218378d4b742", "78441a557719c1fa2f6ca5357f1b9c36", "fbb68ccf7b0f07db7aeacba4183f820f", "e7de815d92852451d8947f836e63d4da", "72be1e068fefe2f38f183e9d9b765b04", "2c7b25c5f17be334f5e05d9683208854", "fb50d68bd120b89208219dab2a111be1", "975d3f29dc2f48e67a9988f1ac6f653d", "fd0feb60ef611141f46f84a97dfba20f", "84ba94578e4d93ae0aa6617bf9062f53", "30d9b8f3c4501d39b5b390c070836357", "8497ad232de859f88ee63ad3d31361a6", "3f4997eba7c6a8551aaaebfcca493b56", "ec8f8250b0d5d52b48ef924bd5121f4d", "2502ebd38abe6fa4ca81a464bb3224e9", "1770249d882766f7490ae8a15d45016f", "bc19fda1ab22414631de7d021a9f6780", "2da442460c556d26b244a5c28e152bdf", "16d209ce2a0d3a71e094e56d474a598b", "c18a3f971e793f2196d1b0d80879f05e", "c8e6159b8e0bf5e0dd332623e22faf49", "2d499240e9017ac1d5144dcb0ec79b6b", "6c5cd84c4d1937624a6ce73989a7e231", "254d5f7c81cbe9ed5577f433c731831f", "f248e00c9a621c2e29db45f15ef453f0", "77a06b5358cd0ac878323706126f8f78", "a6838d763716c06c38ff375a49c2dcf3", "0238d872602cca0b178ac4657546e21d", "be54d83e873f38c0bc10c9167f7fd71a", "dbd33776c79d228709439fb4bfe7713a", "f00620f3ae48f1bbea258ddac3c6318b", "aa2ca6d61d44205c0ba176117ecfa66d", "ad4d9535128b4d311e0859ec443e5489", "e9ac1f64369616ffb6795ba1b2307679", "271cc9dfaaa1c409886090bccaa4919a", "fc8f5daa6661fa572a5174787c14d774", "661fb9da9b2fbf733a1996c183f9f9a9", "6a292a959349dc7da093bbd3400c8c5e", "8f32f84cc4900e870bd63f3d35141ac4", "739fd3bbc31de965b3f14fdac148bca4", "d54760cb27b6146aeee9a0680efd1f54", "912166b3d82394e0e7ad0dbdf4e67380", "065a93fb36af5f5a975e5ef04ca81e52", "ca888b2b8ac3c97bf07a24ac211ecc21", "5c6ea95d91c1fefc3c6efa03316c7c82", "d63234d5b8d060cf3631fa623126731d", "5fd83598897a5051a4f351e963eb59b3", "c6d600a0fc659a743318983b0ebeb8a0", "5ba114366c549f5dacbc5aa7f47ee1e7", "fa58afc66229bee3b670b691d5abe332", "dccbb886255cb44958855d6d0e66701f", "32b6cd544a02e431d1ce231cc89b2b31", "b8bdbaf538272252311d285d593266ca", "5845eb23a40559f024b99ca520946a69", "b917e4f412a7a8634423bbb528c96f80", "b0f455f4e9aea09a983bc954aaaefcb5", "d86385684166aed641d2eadfefd741e3", "fa45271dd080387a9f2ccb84c8713f45", "69269619ff3bc210522b13cf42fc6ad0", "8f56aeb1be63f9024782bb3d3f74484a", "cad4cac35ca6050052b3df9664fe03e0", "b0958827d8b3ef67d93b4dcc7e1d2335",
 "b838828c8c8dc4db7fe137c6254ed6ee", "2717d3a08d9a64d63ecc2d69c265067e", "946628bc20699aa7e490ee3b586d3d40", "76ba3d8d045fdf4002a05114cc795cbc", "13647664fe121294d71f94a932f2feee", "6aa5e645cd205f8afb81a47310c1ce1d", "68bb9fbb31535f7e81edb6ecda40a6ae", "2b6a3f1fd48d43ba4dec54905a60e5cb", "8c9a63d0c56148caba12ab2cb992a89f", "24e17abc35482dfde2cb0b04736d7b76", "5f59dad94764657f8ae7774c1fc7d03d", "d105cf8dbfa73aa29fbc8b6769e7c3cb", "227d7eaf44bbe4aeb87f606137376a7c", "f54e71b133585480253312be07d3ec14", "efe2ada0730190ea31d403948eea7811", "86f6e66337cebccf419494366a7c6bac", "dfa7a9823fd825cbcfaebc43d64d7d56", "3ab70e0a5ab49bcdb3c4f4830003c18e", "351b140c52d15c3abc64aacde04a4cf6", "5aba3d2731d85c6d6c91e92c4af8f5ae", "148e58b40a1e2774e6cd22dcef35893d", "3472a6e1cf0fc6b4e5c5111e578a88c6", "13f00b6de37bf3aa91e01ae2819af265", "6d35081dbffb0d6686d90e01deceebb0", "64a61f7cdf54c3e4b1dc94acbe6f12e9", "98dc615f526dcba17c4b10e9cb0e878c", "08ec2e2ecfb758bb51495def18789f31", "84754c14694955d00c652667a73a2e02", "6d4accf8f53995ed2669295693433fb8", "59abd325cc20fa665c67c34b8fa3ff4e", "295f3924a495b818ec0d458e8b96959a", "090d011ac9065a513efa8a7442ef4ae0", "e1c8fe80a3f07e294705f0115691a041", "c3c1268d2f7ab8aad156ad530311035e", "337664ada3b79c66ce579e06a2ea9e99", "96448c1247860476751ddb91ab683fd4", "63571b48ece0a577f9c815b036ecbfa5", "847525ce43ca6103a2924d772435836f", "b5459d1dd5594c5edcc32f89a4365b7a", "faf5cc2e029a0da39493b4aa4acf4d9e", "53757987532b5e2b489ca289135b849e", "1de80f2998cb541b138ec20ead4c5573", "376a20f6a171e7aaad31a59ab5a22bfb", "c7f59f20d6d0bd69a8e56fc0c2ee571c", "cbe428134f80fddf77e472b544fce919", "94a312a6d457e04b9ccf257b115c51e2", "61e35369bf32514b3570b55e74fed4f5", "ff02b1053336e3b8947f486df8615f9c", "f8d8b0c60ca08ec8f3bae56ba67ba9f4", "1d8431d0c40662463438656612a95f97", "f999dc05a7f55047ab1f1c1e4aff1e2a", "57f471216165bf146f6d75f90796271d", "b8ded016d5703c7d1d9f309e95590772", "d61a259293efc26984f20166313406c5", "31914aec027433c4c0c4a8032fe73e4d", "7e96d77b0b2f26ac66bfe46c80eed008", "e363a7792ecfca6504c532da20dc430e", "32d7554134d51637e54a6b16a5542e95", "fd5e63043d39c100507ee35a566a7bc0", "9cb2db23b6b24d579f0902255529ba07", "6a240b9b45d25178ea14543f0e81f9a7", "29274e263763a9e6ba138444ad04fbda", "977794493741c17d30ae87c82e27e703", "826671175f90f5e6ff204f0de5b823a4", "ddb6723eb019e90e55909f733c8323c2", "f48ed124c958d6aba497220ff8bf1fab", "a353001ac2edc14f7a4188215f7731ef", "029c6c1000c941adfca0a438ffad5da8", "070655050311f116c085d2ce843e6572", "d5b8b583c6b649e87eac53d00ed46971", "8b98da5ebda6a14a2d7c99cf22479988", "afecf8eb45c336920a3884560a8a297c", "33e59d130ae3d5091021c8a212753665", "28576db3a74cacb63dbe0e3b462239aa", "ae9ca5ef368980adaa5f430ea002fd0a", "6e62c118e092220392ddbdff8682a129", "06faa3983bc80b62ce56374e6a45c145", "e6f513a2ad4af5490a03abe328844447", "450b2a11419c002e4b6b699330be3f52", "24501b27715a130fa70d320d2d63abfc", "0d3c00d14f9422148fadf8071285117b", "7cbae3f73c1ca8921634cdd87f275dc3", "7b837f1bff62a98a73edc77170e6c3b2", "ba5da47b08ef1638050e70c31cb8ce8e", "220668d081509fc565443d7b2a835a66", "2ee6b912a494742192d42346132715bd", "4c87c61eb5f7db6d0ea4ef70c380987a", "e7901beaded436f4097c8201fdd228ea", "9bc7b0960184e2d80720528883c30a27", "a6d087c83037db084d7aa076f6055d7b", "a1d34690a517fa9f31ba2d9f5eba45d5", "be56b8beba22ddac985ad7e434f8b1af", "45eea5e33b30cf55cc3c77a918e95ab0", "1883578fb474a229f08e53e1856d3ba4", "078493b0e06359354568af209b7b4b5f", "d2c354b4cc7e0498c0fb3d4dfdd89d0a", "5b4cb0cf13eefe7c06061b57f4b6f22b", "2d30e9f8da618b27e1df8783a8292fe1", "4d9041cce2aab4b3e692e1b0bf4b7132", "9ec58bc125f704e2f2ac3324ada866f2", "25c77c78b7d303585320d5d86c304188", "fce0f704ab4b4ba10fe8cf58c14a6f47", "ac636ce9362eebc961a84d07af7c7680", "72d2c70554a983d011d1d1d936f229eb", "8cc8a057ae88af197ce6611069b0524b", "36a99a80e5d416f569d8958d3fcab6a9", "c54ff201c034459f110eec39f58cbe4d", "04a388b179ca87907114a5b68e4dc4d9", "bc4e79cac7d7b047c88df8fef808fbcc", "0f200fc993a2cd2d4aafac7eb35f17fd", "ef35d88055db24d8fbc0d811750cbe4c", 
 "5c84da9467f5c3fe2f7693c5be1b1fe3", "df49fdb48ec07177f589ae54fb6d3920", "b57525c1f5b03b2bba146b2101c445a5", "6948208bfdd5090481bc542b2dabd130", "b9308c0b57e00b9ab421372b8ce21e87", "45aa773af1155017f2a8d42d0d2f4214", "44c153c9d8cab711f0d04f954f0d62dc", "10c4a46798eb8e44ec81c4a1ecd7f8ca", "ccb492039013c26fd132add139df6b24", "905e2fad8886577b0f1ec332a98f2742", "9d1d3c9b526738cb12373d486b97d645", "15e88f9f5dd65af8f84359cde62caced", "6c14b7c2bf48a6492566b08604e6b24f", "256248574f3826fca13e11b966bd40e5", "8256b57ae4dd32d96a0ab71687f37155", "43ed511f47bea2d5ff653ef047d47629", "21bc9a8b5a4263f0c65e78b7a723ee74", "6ea601b89aa137bd8da9674096c1b5ca", "c0eff661203fd4cd757caa8aadf21ac8", "adc989249b17844db13664d26b761276", "6ff4310de23a06c5d8eb2a546d9165ce", "cde139f0b9dbba5f5937925201172045", "99e81feb1e0b2bc793ae403636874d2f", "6ba34973be467d9434532acd0f599d3c", "3aa1eb522ca225dc9496237a9ec45ad5", "b3dc8301062f7241ceeb4b9312e0cda5", "1282b6340bb96d5ffef2c2b9d7d6f544", "592f853b94f00c6d5221c3291f702094", "c541a7b364eb3a927dc91e9c21713811", "019f1475e9318c2ce41fb8f3d15e88f5", "9ba72d4800eaa4764e3dd1069522c14b", "effe3f31b9c90e9870029f3fb91cfdc2", "3a0e388bc89c41cd9ee2c6cf8b591592", "eef791e798ca10653f716ecfc845ab09", "fb809c3e8b43c65426ea22cc57c6618c", "be8998b89dbb8d21576b639ff7150d64", "cd41251bf5bfb3741c8d4b75cd89d6d4", "e4e6fb777508e56718411416b53da43c", "8aac3859d8ed663baf561568a03e87f5", "a68c7c66094ae12b74712d91d662b0fd", "73d8d109f882222a3b60bd84cbcc0b02", "5ceefe7767316f993a986bb5336591f6", "1e901911cabbbcc5f7c5e18d6602e389", "67e571770cbddb5b568bdb446127887b", "45a15570f2cebc9f8cca8c7466a0e315", "df03a0012186cc529c611d48f8164ee6", "8adee4da6a344393724a0d63162d3424", "667d545bd2d8f9ab78668a7df0cf493e", "3e9f53192c96293b5a97f46523f1ad94", "885420dba4e1ef2235e3fc4bff69490c", "dcb7a31dcfab8e735afbd56cc719a7c0", "df7750182530533af3bdc4733c6aceec", "162a9313296522481f397a3343f31abf", "8f47a9485ce7857acd8a82cefaba74f4", "0d26c541773bc30879367d8c62c8a18c", "f5d05af3814248a2fefce6fb63e0fe0f", "4916556480aeb108f38e8df39d63c908", "a02ec6afb7fe49ede4d2bb1d2069e2af", "10512c05811abe732a50389e215c25d5", "d4231015c2960d9ae4ff25616498bb1c", "2734a29d38fa0e15fc849e4b69cae856", "f6be26f944982ed4c68549ba9d13408c", "ed6fc5f8d3286b696999fc110b915c0e", "9b8bb4ee45baa28dbd91a317ae64477d", "d368894d9e9b7ed8630993657f282b89", "555546bb907c2290f517aec2073c90b1", "c64e5c39c78ad604dab9a9be849cb352", "a6cc5174b9bab573a94d77cb0b16b34e", "39ec8bcb8c25e5a4f930c3a97988e2ef", "c69e140c4f2ea926e2c531d348c07791", "f5094570bbb95514979253307e420ce7", "258f0943c7a19a13afdb4fdbd4ed732f", "6e055efac1fbe3641d76afd0d02a87d7", "60f0cf4ae1967f7545989cbe1eaba090", "c2ccd2e43303ae6ee9830823c90226e4", "90f318260e9068f417f89cf9f92fa2c0", "48df9315f8819b5e9950037008fea49f", "2bf317b5f27ec96735fcf3f193f6eb56", "8dc519f22eb3ca271f63b3e14ec5fd47", "96ac53fda440de2baa17395185560be0", "1c2b077b9845f3e0ab03563b5e9205ed", "02edb0d38d86aef259b0091c276f340b", "87aab7a04c6b1ac33834dc02638b6712", "076879e660517ca5334335bf7c1de763", "820a5f549e88f782fa6d71d6b97b19dc", "351376c1df6f49cfd1667abc7162f823", "31aa8758fd192bbcaffbd1adc24ab14d", "6583d65c3fad726e2fdc6197a09c988c", "8382ae9d518d73683670ee40a1a728c3", "b81815c1223c0936fc6f33284c73de4a", "1da166df3c97766267dae78529a7173a", "dc92bebbd50b62b1908fd1caffddb08a", "7104e734e2c55ec3114cfd1085f0524f", "cc4af400d15da77aa2a68ddbac6b746d", "3abff2a8b54395fc106f6c1847f272cc", "0a977ab9b1ba1ca9e27fab7e6415f57b",
 "37b993d1ca32a31c9e36f41f7b5587ad",
"2eabcf2c0946d8f01a9fa871452bfc96",
"23cf8d0f5a3d37c2c5b598b7fe0708f3",
"500a4a71c6376d9dd79fbd9c1fd10435",
"e89e234df0e790b01fb64adaf0a35e49",
"f24baa0fb37dac309a33fb1e243667e2",
"5e4c0d9f6cae21da70c568ea765a6a5e",
"9b0d0f914a03eedb1c48600e92c2fe52",
"2b8fa0ff960bc0759cdd223b35784a01",
"ef83df5ed07396ec543c4b53ec6ef9a6",
"7ac2a5bc38cc28c4f7e62beedcb5dc57",
"edc1630bc7b1ba892aa19530eea63fbd",
"6bc02c6ec4131ea8931bd727a0a13651",
"40364eac99ecc239f314120c381e7fcb",
"af4358192f3ec676ea7028d56c3f8732",
"81e0898f55bb77c332106a42efb09251",
"e71b500535be0a0e82b6559689febfee",
"d8fa1d8ff7ddf34bc5187991b9a93a96",
"5a4644f3cd9e748d55e98af66893d63a",
"148c25ac947521c26e3b92f4137f5856",
"20c498b3dbf5364a4418d193f814ba57",
"4f5ab1b35831aab0278be539b990ff18",
"46b8a47b436e0f90182d210d7c2bb348",
"554743cc0e95bc0f6d527dd28914cd77",
"9a33955246a9eadf0be03dbf1374e6e2",
"7834ba4b4473ee2cc77e6b9bfc4e24d4",
"020aced7539e7ef240da3cdd01d78070",
"3091b6a974e741b5ecc1b00a63b9c6e9",
"9b7625106e786a46b4854faff8f90a38",
"350e9f4f11fb7a7032d06f4689307a36",
"f00f112498840e4f228144bfdf8b1ed6",
"0e4271de92e61bfc175fec4c70aaad85",
"adc28217b128935deeb9330c9b7e8aba",
"0a9525c3c21411b6c4bb4c2c674be835",
"677b649d4274c0a42ae4401fe443ab22",
"8754424b5bb22cb25d150d4c2024d4e7",
"37ef24f709ac1066985a98b84140038f",
"d94230a952def85bb1957b443397bf50",
"cd07957163cc51d5c25360044235c3bd",
"6683075551904743463067e121c6682e",
"7eb8774c178a529ea99e857c113b4d15",
"f7cac4e696b504156e0120a44fc486c9",
"7b947b6b23efe464311f2cdabab5d0bd",
"d45cb72915facb49276b904eec755e5e",
"9ed112b0a09c4e9e55cc86a317ecad0e",
"6d4ca93b483563fa36e996e59f1474a9",
"165a9227d33ce7eaeb4628926988b9e0",
"a838d575d36fff91ec71d96d2a69f868",
"db16f4e12e368d9a0d413dfef153a051",
"5299733a631dc05c7bff2ab14b805e83",
"1eb321e57211fb7e3c9a8270dde99bb2",
"4b11b63a65c90179abed7aafa8a12347",
"32aadabc662471c9642a05c13105d311",
"b84da26f8c4562ec604ecdf6e5e78af4",
"e0cd8c03b25f56fda389e31aa61e22d3",
"8ac082b3af953b3782c70c12d6818cf1",
"027c786f5d9151d614dc3a79be020d61",
"37b993d1ca32a31c9e36f41f7b5587ad",
"2eabcf2c0946d8f01a9fa871452bfc96",
"3014cca4be7207f153c9765121fa60e6",
"23cf8d0f5a3d37c2c5b598b7fe0708f3",
"ca714640e33fd822e31ccebb225084bf",
"500a4a71c6376d9dd79fbd9c1fd10435",
"e89e234df0e790b01fb64adaf0a35e49",
"0add0cf9774fe828b0d71274f6bac72e",
"0a9525c3c21411b6c4bb4c2c674be835",
"677b649d4274c0a42ae4401fe443ab22",
"8754424b5bb22cb25d150d4c2024d4e7",
"f24baa0fb37dac309a33fb1e243667e2",
"153d3d23798effc8938dd37c4a1722eb",
"37ef24f709ac1066985a98b84140038f",
"d94230a952def85bb1957b443397bf50",
"36e1acaa299b68309837d23806dbe50b",
"ea2ad847daeba7dd8616def0e38aebd8",
"88dcad3ed90a5755a6d4c60c4914f823",
"38ed47ddafb2504b04c6edf0b7edb9fa",
"cd07957163cc51d5c25360044235c3bd",
"6683075551904743463067e121c6682e",
"7eb8774c178a529ea99e857c113b4d15",
"f7cac4e696b504156e0120a44fc486c9",
"980c1d530fd87956add28769baabbeb0",
"50a3aa1cc2df8aad427fdbf2e2f66ff8",
"5e4c0d9f6cae21da70c568ea765a6a5e",
"7b947b6b23efe464311f2cdabab5d0bd",
"9b0d0f914a03eedb1c48600e92c2fe52",
"d45cb72915facb49276b904eec755e5e",
"2b8fa0ff960bc0759cdd223b35784a01",
"875e10a33103313372fcbd25db8b9d97",
"9ed112b0a09c4e9e55cc86a317ecad0e",
"ef83df5ed07396ec543c4b53ec6ef9a6",
"9461fb9e48d51d3767e5075f1f39b2c9",
"6d4ca93b483563fa36e996e59f1474a9",
"165a9227d33ce7eaeb4628926988b9e0",
"7956a85923fa2d3b5d1f359814a9d41e",
"a838d575d36fff91ec71d96d2a69f868",
"f99c42a8165f63ccbd200c9223bf66cb",
"b2535bc3132e22b2564ddf6317bb74c9",
"7ac2a5bc38cc28c4f7e62beedcb5dc57",
"edc1630bc7b1ba892aa19530eea63fbd",
"702a015689385d06876f040e71543ffd",
"25f6e5f43cf88fb58e7bc78b54c7eaa9",
"6bc02c6ec4131ea8931bd727a0a13651",
"40364eac99ecc239f314120c381e7fcb",
"0e83e319393353e59da47aed0b7d4f64",
"5a2b414807c5da7e09ad6ce92ad8b2fd",
"3d7d9eec2d0fab0357d0990387d99959",
"af4358192f3ec676ea7028d56c3f8732",
"81e0898f55bb77c332106a42efb09251",
"e71b500535be0a0e82b6559689febfee",
"d8fa1d8ff7ddf34bc5187991b9a93a96",
"fcbb42ad0c31a2ead5be89cd99e569bb",
"e2d5964fdfd8ffb486d7476a043e33d8",
"db16f4e12e368d9a0d413dfef153a051",
"5299733a631dc05c7bff2ab14b805e83",
"5a4644f3cd9e748d55e98af66893d63a",
"8b70b58092af11d235892e55eb59d5de",
"148c25ac947521c26e3b92f4137f5856",
"66ff703b846952d15365cb38f5d86fbc",
"20c498b3dbf5364a4418d193f814ba57",
"4f5ab1b35831aab0278be539b990ff18",
"896924f4ceebdea2f1822725e89dbbe6",
"ef826aaf8c4ad39a9d6b439aa7753834",
"c736ffe517af7d5b0433d53be54a97c0",
"a2c351f2412e44db07f6dda87d9033d9",
"fa5ef008d31d1b49b2a5a2b628870308",
"5f606afa0e3a8561b5adbb4a9d1b908d",
"348546375cdce82c14c5bb6332380406",
"5359c461f49d24eae284a6cca7ef6b43",
"1916e76effb555fa890f4333404a35d2",
"70205c6bcbce33e29f12e28cb644ab25",
"46b8a47b436e0f90182d210d7c2bb348",
"19ffb52f82ed5bc2a7fc7a573e3bd8c7",
"554743cc0e95bc0f6d527dd28914cd77",
"733a387b13921711bc5d4dfafd307a72",
"1eb321e57211fb7e3c9a8270dde99bb2",
"4b11b63a65c90179abed7aafa8a12347",
"9a33955246a9eadf0be03dbf1374e6e2",
"7834ba4b4473ee2cc77e6b9bfc4e24d4",
"e0d4fc18331f2a225d69dca82d7865c0",
"a494619f49395000ae23ceb52ca9997f",
"3d107ea2a3e65bca0f46fab7ae2d7f21",
"786643aa391a19d570dbbdc50a8eb5aa",
"c5ee3128adc53b2bc4a8db1ad3efd777",
"020aced7539e7ef240da3cdd01d78070",
"3091b6a974e741b5ecc1b00a63b9c6e9",
"9b7625106e786a46b4854faff8f90a38",
"350e9f4f11fb7a7032d06f4689307a36",
"f00f112498840e4f228144bfdf8b1ed6",
"0e4271de92e61bfc175fec4c70aaad85",
"adc28217b128935deeb9330c9b7e8aba",
"5b71c11f7328749c530e3946626f0073",
"b9838984ad00655c1e10145b15bcd4b4",
"120c28610f55854121250ef7096cac70",
"30266d847dcf918ca752579ed3cd2e08",
"c40de4f8f48e06a0696e861a78257272",
"b09e6b647581d5763b210327d3611afc",
"00ecd8ad3c6719179fc2dbccfb84d8de",
"0d7f48c19bcdb2ffb393afc7d8771b60",
"6e8c3be628104555fcb84073bf8c4268",
"0f37b59c56e0fb4a17e8ddac725517cb",
"95afe36055960f7dddec2aece05736de",
"f71ec3d62bb632dd01667f0867d7d86e",
"6f26c76b107bd21eeecab974733256bd",
"4942b4e689705eb34f7396715052ceed",
"68e4c3cb4bbd56ab3d54a7c93eaae0b1",
"39b926530cb65d24bbe534a994b52c5f",
"6e07c29f14a7e776cf364618ca109078",
"a8039e39a6e07a9e1266ecfc784006be",
"9d5af1d705f3710daf7544d112740815",
"01c2f2f62b083736c7d3af47d77c1220",
"e8132fc4a6ae53bf9ff781ad5d796226",
"ccba1c9f3ead38b168ef676c88a27a9c",
"b4b98f9c83386dd30c82e77e58f6dfeb",
"5edf56d55ca98707b4048795c44e8fd6",
"68836265a307df25d1ea3b2f9e5eb21a",
"379778b74af93db3e41727bf58ddcc4a",
"5bd6d5e5407f69ba418f23034c5f5157",
"612d73fdfea7fff046fd1f52ad18b0aa",
"b7e5a39f5cb79048c3d64a1c1cc20c7d",
"9766d1aea9a0254f44e71546a404e5a9",
"9883f74b7a11dd8599a2b8724e6f9b7f",
"9046c7819f3c7fa520c1394491505461",
"79b16f0ff6a2adbeaf2d6e6165582585",
"13d0cb3edb6d64e521f0ed5fd966ac23",
"489751a63c4e4e4bf1a7ab932898777f",
"efeac00ab4228b63be550416b2ba88bc",
"7857bf5da2c31a91b492d4f54b8cddcd",
"7bfd76b7290f4f68fe30f1bdc2a6c294",
"4558a90f4392d6358c67167c08eb0945",
"52f710f8646520438ed1702614f8bc1c",
"2d69736dce3b3cd4e3528778fa47623a",
"8f6279738dfb5fe9855ac7e20b5021a8",
"d904c49b295d8399a611701d170cd4f0",
"141e9f6fd3508cba2187ca3882c35457",
"5b57fac9e6f2942eba0e86679d2799be",
"429869dd854b6a0e0708ea6033c41e6b",
"4626839561ff2401fb1071396d53883c",
"447c98d18358d154936542302fcd5d04",
"c2f1f22b9c67d345a179e3c812c50008",
"8c7d5a5e8f0ef1ad36f689fdd9c12e66",
"ed424003acd156cedd27631d6a485f1e",
"9b892870f17a30743ea22782ac09857f",
"abe60e15738f3c4be44086a8b6859da6",
"163af88feb1cefa08234d52642eb4f38",
"19f54af7f9df2897a4db976aecf6b0d8",
"5dde7081958e6dc9a572ff8f86d2dc4f",
"10910edb7333bab9a57c4afd3196467b",
"2a5c8990f250b401512602aa688b208e",
"3bb323d34f0a24034210f55678da1e31",
"8197705c735c3a63df000c2af9c48be9",
"0b436c9593d2cc502b88579c060c0646",
"d885d4f1705768ea26266834e504885e",
"82f7ff2266e111d8566b13fb91f15e95",
"260bb8053e9dd7d9d76534c1fc67a141",
"a6f2ce9fa53b4ba96b8bd1d3111f3314",
"b92985ab0fb2ec0a3a11150744cd4bf1",
"fbfca89faab13b11d4d3cbdade257343",
"4bf194da83e19133b00fc60353393b89",
"47c56283bf4ff7f022fc63aa5ef173a5",
"e642b70f85fd1c6132ed52c213da999b",
"48ddbd9f11bf1139f9afbcd2e73bc2ba",
"2350d9731831e0330b1157f81367c5dd",
"24e2e36cf25f7c0df97f4dee8e61558b",
"83d4febda70a6de52296d814014c039b",
"9e9bbc17368467e33954b02273f7b38d",
"be334c287555a066f11db57d0c5ed3e6",
"c74b00b2eec3a88282723723489a32aa",
"2e56193abf88fbe8ee54e99a8692ee7b",
"35f78af5a27e00a055b9caf33e606fca",
"a2d461a15123e046addd50503ba5c700",
"04b3f3464cb7f99a497d3db4f2a9240d",
"f266696c954fafcb50c933e7dc35ef79",
"a81969bbef49f401ee03274eb549516c",
"892b99b6dace4998e3acf75c7a149765",
"a5a684473ec128293691c8712da130dc"];


function get_test_number_from_hash( hash_arg ) {

    index = hashes_array.indexOf(hash_arg);

    if( index != -1 ) 
    {
        return index;
    }
    else
    {
        return hash_arg;
    }
}


function add_warning(m,test) {
    div_ol_warnings.innerHTML = div_ol_warnings.innerHTML + "<li>"+ "[" + get_test_number_from_hash( calcMD5(test['desc']) ) + "] [" + m + "] " + " <span class=desc>" + " [" + test['desc'] + "] ["+ "</span>" +
	"&nbsp;<a class=trylink target=_blank download='" + test['file']  + "' href=" + test['page'] + ">try</a>" +
	"&nbsp;<a class=srclink target=_blank href=/src" + test['page'] + ">src</a>" +  "]" +
	"</li>";
    div_warnings.style.display = 'block';
}

function add_notice(m,test) {
    div_ol_notice.innerHTML = div_ol_notice.innerHTML + "<li>"+ "["  + get_test_number_from_hash( calcMD5(test['desc']) ) + "] [" + m + "] " + "<span class=desc>" + " [" + test['desc'] + "] [" + "</span>" +
	"&nbsp;<a class=trylink target=_blank download='" + test['file'] + "' href=" + test['page'] + ">try</a>" +
	"&nbsp;<a class=srclink target=_blank href=/src" + test['page'] + ">src</a>" + "]" +
	"</li>";
    div_notice.style.display = 'block';
}

function add_debug(m,test) {
    div_debug.innerHTML = div_debug.innerHTML + "[" + get_test_number_from_hash( calcMD5(test['desc']) ) + "] [" + m + "] [" + (test ?
	"&nbsp;<a class=trylink target=_blank download='" + test['file'] + "' href=" + test['page'] + ">try</a>" +
	"&nbsp;<a class=srclink target=_blank href=/src" + test['page'] + ">src</a>"
	: "" ) +  "]" + "<br>";
}

function escapeAttribute(attr) {
    return attr
         .replace(/&/g, "&amp;")
         .replace(/</g, "&lt;")
         .replace(/>/g, "&gt;")
         .replace(/"/g, "&quot;")
         .replace(/'/g, "&#039;");
}

function _log(m) {
    try { console.log(m) }
    catch(e) {}
}


function xhr(method,page,payload,callback) {
    var req = null;
    try { req = new XMLHttpRequest(); } 
    catch(e) {
	try { req  = new ActiveXObject("Microsoft.XMLHTTP"); } 
	catch(e) {
	    try { req  = new ActiveXObject("Msxml2.XMLHTTP"); } 
	    catch(e) { req  = null; }
	}
    }
    if (!req) {
	return null;
    }
    try { 
	try { req.overrideMimeType('text/plain; charset=x-user-defined'); } 
	catch(e) { _log("no support for overrideMimeType"); }
	if (callback) {
	    var done = 0;
	    req.ontimeout = function() {
		if (!done) {
		    done = 1;
		    callback(req,'timeout');
		}
	    };
	    req.onreadystatechange = function() {
		if (!done && req.readyState == 4) {
		    done = 1;
		    callback(req);
		}
	    };
	}
	req.open(method, page, true);
	if (accept != null) {
	    try { req.setRequestHeader('Accept',accept); }
	    catch(e) { _log("no support for setRequestHeader") }
	}
	try { req.timeout = 5000; } 
	catch(e) { _log("no support for xhr timeout") }
	req.send(payload);
    } catch(e) {
	_log(e);
	req = null;
    }
    return req;
}

function check_xhr_result(req,test,status) {
    if (!status) {
	status = req.status;
    }

    var header;
    try { header = req.getAllResponseHeaders(); } catch(e) {}
    if (header == undefined || header == null) { header = ''; }

    if (!status) {
	status = 'invalid';
    } else if (status >0) {
	var response;
	try { response = req.responseText }
	catch(e) {}

	if (response == null) {
	    _log("no data for " + test['page']);
	} else {
	    var expect = expect64;
	    if (test['harmless'] || test['harmless_retry']) {
		expect = expect64_harmless;
	    }
	    var result64 = base64_encode(response);
	    if (result64 == expect) {
		status = 'match';
	    } else {
		var pn = response.indexOf(base64_decode(expect));
		if (pn<0) {
		    status = 'change(' + status + ')';
		} else {
		    _log( 'off=' + pn + 'response="' + response + '" expect="' + base64_decode(expect) + '"');
		    status = 'change(' + status + ',off=' + pn + ')';
		}
		    
		results = results + "R | " + test['page'] + " | " + response.length + " | " + base64_encode((header + "--\n" + response).substr(0,1000)) + "\n";
		_log( "len=" + response.length + "   " + test['page'] + ' - ' + test['desc'] );
		_log( "response: " + result64 );
		_log( "expect:   " + expect );
	    }
	}
    }

    if (test['log_header'] && header != '') {
	// i.e. Via added or similar
	results = results + "H | " + test['page'] + " | " + base64_encode(header) + "\n";
    }

    add_debug( test['desc'] + ' - ' + status + ( test['harmless_retry'] ? ' - retry with harmless content':''), test);

    if (test['harmless'] || test['harmless_retry']) {
	// perfectly good response should pass, bad might fail or not
	if (status != 'match') {
	    browser_invalid++;
	    if (test['valid'] == 2) { // no browser should fail on this!
		overblocked++;
		add_warning("Failed to load harmless and perfectly valid response",test);
		results = results + "X | " + status + " | " + test['page'] + " | " + test['desc'] + " | failed harmless but must succeed\n";
		results = results + "T | " + test['page'] + " | " + result64 + "\n";
		var div_urlblock = document.getElementById('urlblock');
		div_urlblock.innerHTML = "<div>" 
		    + "The firewall blocked a harmless and perfectly valid response from the server, which did not contain any kind of evasion attempts.<br>"
		    + "It might be that the firewall blocked the access based on URL filtering and not based on the response at all. "
		    + "This means any results you get during this tests should be considered with great caution because they might not actually reflect "
		    + "the abilities of the firewall to detect malware."
		    + "</div>";
		div_urlblock.style.display = 'block';
	    } else if (test['valid']>0) {
		if (test['valid']==3) {
		    // firewall might have modified request 
		    maybe_overblocked++;
		    add_warning("Failed to load harmless and valid response, maybe the firewall blocked too much",test);
		    results = results + "X | " + status + " | " + test['page'] + " | " + test['desc'] + " | failed harmless but should succeed\n";
		} else {
		    add_notice("Failed to load harmless and valid response, might be browser bug",test);
		    results = results + "X | " + status + " | " + test['page'] + " | " + test['desc'] + " | failed harmless\n";
		}
		results = results + "T | " + test['page'] + " | " + result64 + "\n";
	    } else {
		results = results + "B | " + status + " | " + test['page'] + " | " + test['desc'] + " | failed harmless\n";
	    }
	} else if (test['harmless_retry']) {
	    // in this case an evasion attempt was blocked by the firewall
	    evasions_blocked++;
	    results = results + "Z | " + test['retry4status'] + " | " + test['retry4page'] + " | " + test['desc'] + " | evasion blocked\n";
	}
	return status;
    }


    if (isbad) {
	// check for evasion
	if (status == 'match') {
	    if (test['expect_bad']) {
		// assume no or stupid content filter
		div_nobad.innerHTML = div_nobad.innerHTML + "<div>" +
		    "It looks like no malware filtering is done by the firewall since " + isbad +
		    " could not be detected when transferred using a valid and typical HTTP response.</div><div>" +
		    "The tests will continue but it is assumed that there is no malware filter available. " +
		    "This means no firewall bypasses can be detected (there is nothing to bypass) but instead " +
		    "it will only check the behavior of the browser regarding atypical or malformed responses." +
		    "</div><div>" +
		    "If you feel that your firewall should be able to detect the malware please check your " +
		    "firewall configuration and make sure that antivirus is enabled. This test uses only " + isbad +
		    " which any antivirus product should be able to detect." +
		    "</div>";
		div_nobad.style.display = 'block';
		results = results + "I | " + status + " | " + test['page'] + " | " + test['desc'] + " | no content filter\n";
		isbad = '';
	    } else {
		// possible evasion of content filter
		add_warning("Evasion possible",test);
		results = results + "E | " + status + " | " + test['page'] + " | " + test['desc'] + " | evasion\n";
		evasions++;
	    }
	} else if (test['expect_bad']) {
	    // add answer to results, maybe we can get the type of firewall from the error message
	    results = results + "T | " + test['page'] + " | " + result64 + "\n";
	}

    } else {
	// check for standard conformance
	check_status_noevil(test,status);
    }
    return status;
}

function check_status_noevil(test,status) {
    if (!status) {
	status = test['status'];
    }
    if (status == 'success' || status == 'match') {
	if (test['valid'] == 0) {
	    add_warning("success for bad response",test);
	    results = results + "W | " + status + " | " + test['page'] + " | " + test['desc'] + " | success for bad response\n";
	} else if (test['valid'] == -1) {
	    add_notice("success for valid uncommon response",test);
	    results = results + "N | " + status + " | " + test['page'] + " | " + test['desc'] + " | success for valid uncommon response\n";
	} else if (test['valid']<0) {
	    add_notice("success for invalid uncommon response",test);
	    results = results + "N | " + status + " | " + test['page'] + " | " + test['desc'] + " | success for invalid uncommon response\n";
	} else {
	    results = results + "I | " + status + " | " + test['page'] + " | " + test['desc'] + " | ok\n";
	}
    } else {
	if (test['valid']>0) {
	    add_warning("failure for valid response",test);
	    results = results + "W | " + status + " | " + test['page'] + " | " + test['desc'] + " | failure for valid response\n";
	} else if (test['valid'] == -1) {
	    add_notice("failure for valid uncommon response",test);
	    results = results + "N | " + status + " | " + test['page'] + " | " + test['desc'] + " | failure for valid uncommon response\n";
	} else if (test['valid'] < 0) {
	    add_notice("failure for invalid uncommon response",test);
	    results = results + "N | " + status + " | " + test['page'] + " | " + test['desc'] + " | failure for invalid uncommon response\n";
	} else {
	    results = results + "I | " + status + " | " + test['page'] + " | " + test['desc'] + " | ok\n";
	}
    }
}


function set_success(xid,type) { check_nonxhr_result(xid, type, 'success') }
function set_fail(xid,type)    { check_nonxhr_result(xid, type, 'fail') }
function set_load(xid,type)    { check_nonxhr_result(xid, type) }

var nonxhr_timer;
var open_checks = {};
function check_nonxhr_result(xid,type,val) {
    _log( "xid:" + xid + ", type:" + type + ", val:" + val);
    if (!xid) {
	// final timeout done - mark remaining tests as timeout
	window.clearTimeout(nonxhr_timer);
	add_debug('*final timeout*');
	for(var k in open_checks) {
	    if (open_checks.hasOwnProperty(k)) {
		var test = open_checks[k];
		test['status'] = 'timeout';
		add_debug( "timeout: " + test['desc'], test);
		check_status_noevil(test);
	    }
	}
	runtests(); // submits final result
	return;
    }

    if (current_test && current_test['xid'] == xid) {
	window.clearTimeout(nonxhr_timer);
	test = current_test;
	if (val) {
	    add_debug( val + ": " + test['desc'], test);
	    test['status'] = val;
	    _removeElement(xid);
	    check_status_noevil(test);
	    if (fast_feedback && results.length > fast_feedback) {
		submit_part();
	    }
	} else if (!test['status']) {
	    // no final result, wait some more time
	    _log("defer " + xid);
	    open_checks[xid] = test;
	}
	done++;

	if (checks.length) {
	    runtests();
	    return;
	}

	var open = 0;
	for(var k in open_checks) {
	    if (open_checks.hasOwnProperty(k)) {
		open = 1;
		break;
	    }
	}
	if (!open) {
	    runtests();
	    return;
	}

	// final timeout to wait for open_checks
	nonxhr_timer = window.setTimeout(
	    function() { check_nonxhr_result(); },
	    5000
	);
	return;
    }

    if (open_checks[xid]) {
	test = open_checks[xid];
	if (val) {
	    delete open_checks[xid];
	    add_debug( "delayed " + val + ": " + test['desc'], test);
	    _removeElement(xid);
	    test['status'] = val;
	    check_status_noevil(test);
	    if (fast_feedback && results.length > fast_feedback) {
		submit_part();
	    }
	}
    }
}

function _removeElement(id) {
    var e = document.getElementById(id);
    if (e && e.parent) {
	e.parent.removeChild(e);
    }
}

function runtests() {
    current_test = checks.shift();
    if (current_test) {
	var total = checks.length + done;
	div_process.innerHTML = "Progress: " + (100*done/total).toFixed(1) + "% - " + current_test['desc'];
	if (current_test['html']) {
	    var html = current_test['html'];
	    if (typeof html == 'function') {
		html(div_work);
	    } else {
		div_work.innerHTML = html;
	    }
	    nonxhr_timer = window.setTimeout(
		function() { check_nonxhr_result(current_test['xid'],current_test['type'],'timeout'); },
		5000
	    );

	} else {
	    xhr('GET',current_test['page'] + '?rand=' + rand,null,function(req,status) {
		status = check_xhr_result(req,current_test,status);
		if (isbad && current_test['harmless_page'] && status != 'match') {
		    // malware not found, either because the firewall filtered it
		    // or because the browser did not understand the response.
		    // check for the last by trying with novirus.txt
		    checks.unshift({ page: current_test['harmless_page'], desc: current_test['desc'], valid: current_test['valid'], harmless_retry:1,
			retry4status:status, retry4page: current_test['page']});
		}
		if (fast_feedback && results.length > fast_feedback) {
		    submit_part();
		}
		done++;
		runtests();
	    });
	}
    } else {
	div_process.style.display = 'none';
	add_debug("*DONE*");
	var submit_url;
	if (isbad) {
	    var div;
	    if (evasions == 0 && overblocked == 0) {
		results = results + "NO EVASIONS\n";
		div = document.getElementById('noevade');
		div.innerHTML = "<h1>Congratulations!<br>No evasions detected.</h1>"
		    + evasions_blocked + " evasions attempts were blocked by the firewall and " 
		    + browser_invalid + " attempts failed because the browser considered the response invalid or because the firewall blocks (invalid) responses even if there is no malware payload."
		    + "Please note that these might be considered valid by other browsers and might lead to possible evasions, so better try with other browsers too."
		    + "For this reason I would recommend to check with at least Firefox, Chrome, Safari, Internet Explorer, Edge and Opera because they all behave differently."
		    + "<br><br>To get an overview which products behave that nicely "
		    + "it would be helpful if you provide us with information about the firewall product you use. "
		    + "Please add as much details as you know and like to offer, i.e. model, patch level, specific configurations. ";
	    } else if (evasions == 0) {
		results = results + "NO EVASIONS BUT OVERBLOCKING\n";
		div = document.getElementById('overblock');
		div.innerHTML = "<h1>Suspicious!<br>No evasions detected but it looks like overblocking.</h1>"
		    + evasions_blocked + " evasions attempts were blocked by the firewall but in at least " 
		    + overblocked + " cases the firewall blocked perfectly valid and innocent responses."
		    + browser_invalid + " attempts failed because the browser considered the response invalid or because the firewall blocks (invalid) responses even if there is no malware payload."
		    + "Please note that these might be considered valid by other browsers and might lead to possible evasions, so better try with other browsers too."
		    + "For this reason I would recommend to check with at least Firefox, Chrome, Safari, Internet Explorer, Edge and Opera because they all behave differently."
		    + "<br><br>To get an overview which products behave that nicely "
		    + "it would be helpful if you provide us with information about the firewall product you use. "
		    + "Please add as much details as you know and like to offer, i.e. model, patch level, specific configurations. ";
	    } else {
		div = document.getElementById('evadable');
		div.innerHTML = "<h1>Danger!<br>Possible evasions detected!</h1>"
		    + "The test detected that " + evasions + " evasion attempts were not blocked by the firewall.<br>"
		    + ((overblocked>0) ? "Additionally in " + overblocked + " cases the firewall blocked perfectly valid and innocent responses.<br>" : '' )
		    + evasions_blocked + " evasions attempts were blocked by the firewall and " 
		    + browser_invalid + " attempts failed because the browser considered the response invalid or because the firewall blocks (invalid) responses even if there is no malware payload."
		    + "Please note that these might be considered valid by other browsers and might lead to possible evasions, so better try with other browsers too."
		    + "For this reason I would recommend to check with at least Firefox, Chrome, Safari, Internet Explorer, Edge and Opera because they all behave differently.<br>"
		    + "Since the test differs slightly from a manually triggered download it might be that some of the detected evasions are "
		    + "not usable in reality, so please make sure the evasion works by clicking the [TRY] link "
		    + "and comparing the downloaded file with the EICAR test virus. The file should be 68 byte and contain the string "
		    + "<p><span id=eicar>X5O!P%@AP" + "[4\PZX54(P^)" + "7CC)7}$EICAR-STAND" + "ARD-ANTIVI" + "RUS-TEST-FILE!$H+H*</span></p>"
		    + "To get an overview which products are affected by which evasions and to inform the maker of the product about the problems " 
		    + "it would be helpful if you provide us with information about the firewall product you use. "
		    + "Please add as much details as you know and like to offer, i.e. model, patch level, specific configurations. ";
	    }
	    div.innerHTML += '<br><br><form enctype="multipart/form-data" method=POST action="/submit_details/' + reference + '/evasions=' + evasions + "/evasions_blocked=" + evasions_blocked + '">'
		+ '<textarea name=product cols=80 rows=4>... please add product description here ...</textarea>'
		+ '<br><input type=submit name=Send></form>';
	    div.style.display = 'block';
	    submit_url = '/submit_results/' + reference + '/evasions=' + evasions + "/evasions_blocked=" + evasions_blocked;
	} else {
	    submit_url = '/submit_results/' + reference;
	}

	if (submit_url) {
	    submit_result(submit_url,results);
	    results = null;
	}
    }
}

function submit_result(url,data) {
    xhr('POST', url, data, function(req) {
	var blocked = 1;
	try {
	    if (req.status != 200) {
		_log("bad status from submit: " + req.status);
	    } else if (req.getResponseHeader("X-ID") != url) {
	    	_log("bad response x-id:'" + req.getResponseHeader("X-ID") + "' expect:'" + url +"'");
	    } else {
		_log("submission ok");
		blocked = 0
	    }
	}
	catch(e) { _log(e); }

	// disable - to much false reports. Better use --fast-feedback
	if ( 0 && blocked) {
	    // POST might be blocked, try as lots of GET requests
	    var post = url + "\n" + data;
	    data = null;
	    var i = 0;
	    var submit_part;
	    submit_part = function(req,status) {
		if (!status) status = req.status;
		if (status != 200) {
		    _log("submitting part failed: " + status);
		    return;
		} else if (post == null) {
		    return;
		}

		var buf = post.substr(0,512);
		if (buf.length<512) {
		    post = null;
		} else {
		    post = post.substr(512);
		}
		buf = base64_encode( reference + "\0" + i + "\0" + buf,1);
		i++;
		xhr('GET', '/' + buf, null, submit_part);
	    };
	    submit_part(null,200);
	}
    });
}

var partid = 0;
function submit_part() {
    submit_result("/submit_part/" + reference + "/" + partid++,results);
    results = '';
}

document.getElementById('noscript').style.display = 'none';
</script>
HTML

{

    my (%msg,@map);
    sub vendor_notice {
	my $srcip = shift or return;
	$srcip =~m{:} and return; # IPv6 not handled yet here
	@map || return;
	my $ipn = 0;
	$ipn = 256*$ipn + $_ for split(m{\.+},$srcip);
	for(@map) {
	    next if $ipn<$_->[1];
	    next if $ipn>$_->[2];
	    my $vendor = $_->[0];
	    return ($vendor,$msg{$vendor});
	}
	return;
    }

    # load notice on startup
    if (open(my $fh,'<','vendor_notice.txt')) {
	my $vendor;
	while (<$fh>) {
	    if ($vendor) {
		if (m{^=end\s*$}) {
		    $vendor = undef;
		} else {
		    $msg{$vendor} .= $_;
		}
	    } elsif ( m{^=begin (\S+)}) {
		$vendor = $1;
		die "message for vendor $vendor already loaded"
		    if $msg{$vendor};
	    } elsif (my ($ip0,$net,$ip1,$vendor) =
		m{^=map\s+([\d\.]+)(?:/(\d+)|\s*-\s*([\d\.]+))\s+(\S+)}) {
		for my $ip ($ip0,$ip1) {
		    defined $ip or next;
		    my @ip = split(m{\.+},$ip);
		    push @ip,0 while @ip<4;
		    $ip = 0;
		    $ip = 256*$ip + $_ for @ip;
		}
		$ip1 = $ip0 + (2 << (32-$net)) if defined $net;
		push @map,[ $vendor,$ip0,$ip1 ];
	    } elsif (do { s{#.*}{}; m{\S}}) {
		die "invalid line $_";
	    }
	}
	for my $vendor (keys %msg) {
	    die "no source-ip for $vendor defined"
		if !grep { $_->[0] eq $vendor } @map;
	}
	warn "DEBUG: vendor notice loaded for $_\n" for (sort keys %msg);
    }
}

sub manifest {
    my ($self,$cat,$page,$spec) = @_;
    my $data = "trivial | /clen/$page/close,clen,content | 3 | trivial response for retrieving body\n";
    for(@cat) {
	next if $cat ne 'all' && $_->ID ne $cat;
	for($_->TESTS) {
	    $data .= sprintf("%s | %s | %s | %s\n",
		$_->LONG_ID, $_->url($page), $_->VALID, $_->DESCRIPTION);
	}
    }
    return "HTTP/1.0 200 ok\r\n".
	"Content-type: text/plain\r\n".
	"Content-length: ".length($data)."\r\n".
	"\r\n".
	$data;
}

1;
