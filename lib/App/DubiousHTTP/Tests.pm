use strict;
use warnings;
package App::DubiousHTTP::Tests;
use App::DubiousHTTP::Tests::Common;
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

<h2>Bulk test with innocent payload</h2>

<p>
This bulk test automatically triggers various kinds of strange HTTP responses
which contain an innocent payload and compares the payload it gets in the
browser against the expected payload. It uses XMLHttpRequests for this purpose
which often but not in all cases show the same behavior as other HTTP requests
by the browser (i.e. loading image, script,...). 
In lots of cases the browser will extract the original payload from the response
even the response itself was invalid. On the other hand there are cases were the
browser does not get the expected payload even if the response was valid,
because either the browser or a proxy/firewall in between does not fully
understand legit HTTP or blocked legit but uncommon HTTP for security reasons.
</p>
<p class=runtest><a href="/auto/all/novirus.txt">Run Test</a></p>

<h2>Bulk test with virus payload</h2>

<p>
This is the same bulk test as the previous test with the exception that the
payload is a virus this time. The payload consists of the <a
href="http://www.eicar.org/86-0-Intended-use.html">EICAR test virus</a> which is
commonly used for basic tests of antivirus and which should be detected by every
firewall which does deep inspection to filter out malware. 
</p>
<p>
The goal of this test is to find out if the firewall interprets the HTTP
response in a different way then the browser and if this would allow a critical
bypass of the firewalls protection. Since the EICAR test virus used in this test
is not malicious it is safe to run this test even if the firewall gets
successfully bypassed.
It is important to consider that the XMLHttpRequests used for this tests do 
behave the same as normal download links in most but not all cases. This means
to verify that an evasion is actually possible with a download link one should
use the provided link to actually test the evasion.
</p>
<p class=runtest><a href="/auto/all/eicar.txt">Run Test</a></p>

<h2>Non-Bulk tests</h2>

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
    my ($self,$cat,$page,$spec,$qstring,$rqhdr) = @_;
    $page ||= 'eicar.txt';
    my $html = _auto_static_html();
    my ($hdr,$body,$isbad) = content($page);
    $html .= "<script>\n";

    my ($accept) = $rqhdr =~m{^Accept:[ \t]*([^\r\n]+)}mi;
    if ($qstring =~m{(?:^|\&)accept=([^&]*)}) {
	($accept = $1) =~s{(?:%([a-f\d]{2})|(\+))}{ $2 ? ' ' : chr(hex($1)) }esg;
    }
    $html .= "accept = '".quotemeta($accept)."';\n" if $accept;

    $html .= "expect64 = '".encode_base64($body,'')."';\n";
    $isbad ||= '';
    $html .= "isbad ='$isbad';\n";
    $html .= "var checks = [];\n";
    $html .= "checks.push({ page:'". garble_url("/clen/$page/close,clen,content"). 
	"', desc:'sanity check', valid:1, expect_bad:1 });\n";
    for(@cat) {
	next if $cat ne 'all' && $_->ID ne $cat;
	for($_->TESTS) {
	    $html .= sprintf("checks.push({ page:'%s', desc:'%s', valid:%d });\n",
		$_->url($page), quotemeta($_->DESCRIPTION), $_->VALID)
	}
    }
    $html .= "runtests(checks,0);\n</script>\n";
    return "HTTP/1.0 200 ok\r\n".
	"Content-type: text/html\r\n".
	"Content-length: ".length($html)."\r\n".
	"\r\n".
	$html;
}

sub _auto_static_html { return <<'HTML'; }
<!doctype html>
<meta charset="utf-8">
<style>
body      { font-family: Verdana, sans-serif; }
#nobad    { padding: 1em; margin: 1em; background: red; display: none; }
#noevade  { padding: 1em; margin: 1em; background: green; display: none; }
#notice   { padding: 1em; margin: 1em; background: #e9f2e1; display: none; }
#warnings { padding: 1em; margin: 1em; background: #e3a79f; display: none; }
#process  { padding: 1em; margin: 1em; background: #f2f299; }
#debug    { padding: 1em; margin: 1em; }
.desc     { font-size: 110%; }
.srclink  { font-variant: small-caps; }
.trylink  { font-variant: small-caps; }
</style>
<div id=noscript>
You need to have JavaScript enabled to run this tests.
</div>
<div id=process></div>
<div id=nobad> </div>
<div id=noevade> </div>
<div id=warnings><h1>Serious Problems</h1><ol id=ol_warnings></ol></div>
<div id=notice><h1>Behavior in Uncommon Cases</h1><ol id=ol_notice></ol></div>
<div id=debug><h1>Debug</h1></div>
<script>
function base64_encode(input) {
    var chr1, chr2, chr3, enc1, enc2, enc3, enc4;
    var output = "";
    var chrs = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

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


var div_debug = document.getElementById('debug');
var div_notice = document.getElementById('notice');
var div_ol_notice = document.getElementById('ol_notice');
var div_warnings = document.getElementById('warnings');
var div_ol_warnings = document.getElementById('ol_warnings');
var div_nobad = document.getElementById('nobad');
var div_process = document.getElementById('process');
var expect64;
var isbad;
var results = '';
var accept = null;

function add_warning(m,page,desc) {
    div_ol_warnings.innerHTML = div_ol_warnings.innerHTML + "<li>" + m + ": <span class=desc>" + desc + "</span>" +
	"&nbsp;<a class=trylink target=_blank href=" + page + ">try</a>" +
	"&nbsp;<a class=srclink target=_blank href=/src" + page + ">src</a>" +
	"</li>";
    div_warnings.style.display = 'block';
}

function add_notice(m,page,desc) {
    div_ol_notice.innerHTML = div_ol_notice.innerHTML + "<li>" + m + ": <span class=desc>" + desc + "</span>" +
	"&nbsp;<a class=trylink target=_blank href=" + page + ">try</a>" +
	"&nbsp;<a class=srclink target=_blank href=/src" + page + ">src</a>" +
	"</li>";
    div_notice.style.display = 'block';
}

function add_debug(m) {
    div_debug.innerHTML = div_debug.innerHTML + m + "<br>";
}

function _log(m) {
    try { console.log(m) }
    catch(e) {}
}

var evasions = 0;
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

function check_page(req,test,status) {
    if (!status) {
	status = req.status;
    }
    if (!status) {
	status = 'invalid';
    } else if (status >0) {
	var response;
	try { response = req.responseText }
	catch(e) {}

	if (response == null) {
	    _log("no data for " + test['page']);
	} else {
	    var result64 = base64_encode(response);
	    if (result64 == expect64) {
		status = 'match';
	    } else {
		status = 'change(' + status + ')';
		_log( "len=" + response.length + "   " + test['page'] + ' - ' + test['desc'] );
		_log( "response: " + result64 );
		_log( "expect:   " + expect64 );
	    }
	}
    }
    add_debug( test['desc'] + ' - ' + status );
    if (isbad != '') {
	// check for evasion
	if (status == 'match') {
	    if (test['expect_bad']) {
		// assume no or stupid content filter
		div_nobad.innerHTML = div_nobad.innerHTML + "No content filter detecting " + isbad + ".<br>"
		    + "Assuming no content filter.<br>";
		div_nobad.style.display = 'block';
		results = results + "I | " + status + " | " + test['page'] + " | " + test['desc'] + " | no content filter\n";
		isbad = '';
	    } else {
		// possible evasion of content filter
		add_warning("Evasion possible",test['page'],test['desc']);
		results = results + "E | " + status + " | " + test['page'] + " | " + test['desc'] + " | evasion\n";
		evasions++;
	    }
	} else if (test['expect_bad']) {
	    // add answer to results, maybe we can get the type of firewall from the error message
	    results = results + "T | " + result64 + "\n";
	}
	return;
    }

    // check for standard conformance
    if (status == 'match') {
	if (test['valid'] == 0) {
	    add_warning("success for bad response",test['page'],test['desc']);
	    results = results + "W | " + status + " | " + test['page'] + " | " + test['desc'] + " | success for bad response\n";
	} else if (test['valid'] == -1) {
	    add_notice("success for valid uncommon response",test['page'],test['desc']);
	    results = results + "N | " + status + " | " + test['page'] + " | " + test['desc'] + " | success for valid uncommon response\n";
	} else if (test['valid']<0) {
	    add_notice("success for invalid uncommon response",test['page'],test['desc']);
	    results = results + "N | " + status + " | " + test['page'] + " | " + test['desc'] + " | success for invalid uncommon response\n";
	} else {
	    results = results + "I | " + status + " | " + test['page'] + " | " + test['desc'] + " | ok\n";
	}
    } else {
	if (test['valid']>0) {
	    add_warning("failure for valid response",test['page'],test['desc']);
	    results = results + "W | " + status + " | " + test['page'] + " | " + test['desc'] + " | failure for valid response\n";
	} else if (test['valid'] == -1) {
	    add_notice("failure for valid uncommon response",test['page'],test['desc']);
	    results = results + "N | " + status + " | " + test['page'] + " | " + test['desc'] + " | failure for valid uncommon response\n";
	} else if (test['valid'] < 0) {
	    add_notice("failure for invalid uncommon response",test['page'],test['desc']);
	    results = results + "N | " + status + " | " + test['page'] + " | " + test['desc'] + " | failure for invalid uncommon response\n";
	} else {
	    results = results + "I | " + status + " | " + test['page'] + " | " + test['desc'] + " | ok\n";
	}
    }
}

var rand = Math.random();
function runtests(todo,done) {
    var test = todo.shift();
    if (test) {
	var total = todo.length + done;
	div_process.innerHTML = "Progress: " + done + "/" + total + " - " + test['desc'];
	xhr('GET',test['page'] + '?rand=' + rand,null,function(req,status) {
	    check_page(req,test,status);
	    runtests(todo,done+1);
	});
    } else {
	div_process.style.display = 'none';
	add_debug("*DONE*");
	if (isbad != '') {
	    if (evasions == 0) {
		var div = document.getElementById('noevade');
		div.style.display = 'block';
		div.innerHTML = "<h1>Congratulations!<br>No evasions detected.</h1>";
		results = results + "NO EVASIONS\n";
	    }
	    xhr('POST','/submit_results/evasions=' + evasions ,results, null);
	} else {
	    xhr('POST','/submit_results' ,results, null);
	}
    }
}

document.getElementById('noscript').style.display = 'none';
</script>
HTML


1;
