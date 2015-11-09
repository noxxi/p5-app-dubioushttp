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

    $html .= "expect64 = '".encode_base64($body,'')."';\n";
    $html .= 'results = "V | '.App::DubiousHTTP->VERSION.'\n";' . "\n";
    $isbad ||= '';
    $html .= "isbad ='$isbad';\n";
    $html .= "var checks = [];\n";
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
		    $_->url($page), quotemeta(html_escape($_->DESCRIPTION)), $_->VALID, $_->url('novirus.txt'),'novirus.txt')
	    } else {
		$html .= sprintf("checks.push({ page:'%s', desc:'%s', valid:%d, file:'%s' });\n",
		    $_->url($page), quotemeta(html_escape($_->DESCRIPTION)), $_->VALID,$page)
	    }
	}

    }
    $html .= sprintf("reference='%x' + Math.floor(time()/1000).toString(16);\n", rand(2**32));
    $html .= "runtests(checks,0);\n</script>\n";
    return "HTTP/1.0 200 ok\r\n".
	"Content-type: text/html\r\n".
	"Content-length: ".length($html)."\r\n".
	"\r\n".
	$html;
}

sub auto_img {
    my ($self,$cat) = @_;
    _auto_imgjs($cat, 'ok.png', sub {
	my ($test,$page,$rand) = @_;
	my $url = $test->url($page);
	my $xid = quotemeta(html_escape($test->LONG_ID));
	return "<img src='$url?rand=$rand' onload='set_success(\"$xid\");' onerror='set_fail(\"$xid\");' />\n";
    });
}

sub auto_js {
    my ($self,$cat) = @_;
    _auto_imgjs($cat, 'set_success.js', sub {
	my ($test,$page,$rand) = @_;
	my $url = $test->url($page);
	my $xid = quotemeta(html_escape($test->LONG_ID));
	return "<script src='$url?rand=$rand' onerror='set_fail(\"$xid\");' onload='set_done(\"$xid\");' onreadystatechange='set_done(\"$xid\");'></script>\n";
    });
}

sub _auto_imgjs {
    my ($cat,$page,$mkhtml) = @_;

    my $jsglob = <<'JS';

var fast_feedback = 0;
var tests = [];
var done = 0;
var check_timer;
var timer = 0;
var maxwait = 20;

function set_success(xid) { check_done(xid, 'success') }
function set_fail(xid)    { check_done(xid, 'fail') }
function set_done(xid)    { check_done(xid) }

check_timer = function() {
    timer++;
    if (timer<maxwait) {
	// start timer again
	window.setTimeout(check_timer,1000);
	div_process.innerHTML = "Progress: " + (100*done/tests.length).toFixed(1) + "% - " + "waiting(" + (maxwait-timer) + ")";
	maxwait = 10+(tests.length-done);
	return;
    } else if (timer == maxwait) {
	check_done();
    }
};

function check_done(xid,val) {
    if (xid) {
	timer = 0;
	var desc;
	for(var i=0;i<tests.length;i++) {
	    if (tests[i]['xid'] == xid) {
		desc = tests[i]['desc'];
		add_debug( val + ": " + desc, tests[i]);
		if (!tests[i]['status']) {
		    tests[i]['status'] = val || 'unknown';
		    done++;
		} else if (val) {
		    tests[i]['status'] = val;
		}
		if (val) {
		    check_status_noevil(tests[i]);
		}
		break;
	    }
	}

	if (fast_feedback && results.length > fast_feedback) {
	    submit_part();
	}
	if (done < tests.length) {
	    div_process.innerHTML = "Progress: " + (100*done/tests.length).toFixed(1) + "% - " + desc;
	    return;
	}
    }


    // DONE: remove working node
    var w = document.getElementById('work');
    w.parentNode.removeChild(w);
    div_process.style.display = 'none';
    add_debug("*done*");
    timer = maxwait + 100;

    if (done < tests.length) {
	// fill in the rest
	for(var i=0;i<tests.length;i++) {
	    if (!tests[i]['status']) {
		tests[i]['status'] = 'timeout';
		add_debug( tests[i]['status'] + ": " + tests[i]['desc'], tests[i]);
		check_status_noevil(tests[i]);
	    }
	}
    }

    submit_result('/submit_results/' + reference,results);
}

check_timer();
JS

    $jsglob .= "fast_feedback = 16384;\n" if $FAST_FEEDBACK;
    my $html_tests = '';
    my $rand = rand();
    for(@cat) {
	next if $cat ne 'all' && $_->ID ne $cat;
	for($_->TESTS) {
	    $jsglob .= 'tests.push({ page: "' . $_->url($page)
		. '", xid: "'.quotemeta(html_escape($_->LONG_ID))
		. '", desc: "'.quotemeta(html_escape($_->DESCRIPTION))
		. '", valid: '.$_->VALID ."});\n";
	    $html_tests .= $mkhtml->($_,$page,$rand);
	}
    }

    $jsglob .= sprintf("reference='%x' + Math.floor(time()/1000).toString(16);\n", rand(2**32));
    my $html = _auto_static_html()."<script>$jsglob</script>\n<div id=work style='display:none;'>$html_tests</div>";
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
<div id=vendor_notice> </div>
<div id=nobad> </div>
<div id=urlblock> </div>
<div id=evasions></td>
<div id=process></div>
<div id=evadable> </div>
<div id=overblock> </div>
<div id=noevade> </div>
<div id=warnings><h1>Serious Problems</h1><ol id=ol_warnings></ol></div>
<div id=notice><h1>Behavior in Uncommon Cases</h1><ol id=ol_notice></ol></div>
<div id=debug><h1>Debug</h1></div>
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



var div_debug = document.getElementById('debug');
var div_notice = document.getElementById('notice');
var div_ol_notice = document.getElementById('ol_notice');
var div_warnings = document.getElementById('warnings');
var div_ol_warnings = document.getElementById('ol_warnings');
var div_nobad = document.getElementById('nobad');
var div_evasions = document.getElementById('evasions');
var div_process = document.getElementById('process');
var expect64;
var expect64_harmless;
var isbad;
var results = '';
var reference;
var accept = null;

function add_warning(m,test) {
    div_ol_warnings.innerHTML = div_ol_warnings.innerHTML + "<li>" + m + ": <span class=desc>" + test['desc'] + "</span>" +
	"&nbsp;<a class=trylink target=_blank download='" + test['file'] + "' href=" + test['page'] + ">try</a>" +
	"&nbsp;<a class=srclink target=_blank href=/src" + test['page'] + ">src</a>" +
	"</li>";
    div_warnings.style.display = 'block';
}

function add_notice(m,test) {
    div_ol_notice.innerHTML = div_ol_notice.innerHTML + "<li>" + m + ": <span class=desc>" + test['desc'] + "</span>" +
	"&nbsp;<a class=trylink target=_blank download='" + test['file'] + "' href=" + test['page'] + ">try</a>" +
	"&nbsp;<a class=srclink target=_blank href=/src" + test['page'] + ">src</a>" +
	"</li>";
    div_notice.style.display = 'block';
}

function add_debug(m,test) {
    div_debug.innerHTML = div_debug.innerHTML + m + (test ?
	"&nbsp;<a class=trylink target=_blank download='" + test['file'] + "' href=" + test['page'] + ">try</a>" +
	"&nbsp;<a class=srclink target=_blank href=/src" + test['page'] + ">src</a>"
	: "" ) + "<br>";
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

var evasions = 0;
var evasions_blocked = 0;
var overblocked = 0;
var maybe_overblocked = 0;
var browser_invalid = 0;
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

var rand = Math.random();
function runtests(todo,done) {
    var test = todo.shift();
    if (test) {
	var total = todo.length + done;
	div_process.innerHTML = "Progress: " + (100*done/total).toFixed(1) + "% - " + test['desc'];
	xhr('GET',test['page'] + '?rand=' + rand,null,function(req,status) {
	    status = check_page(req,test,status);
	    if (isbad && test['harmless_page'] && status != 'match') {
		// malware not found, either because the firewall filtered it
		// or because the browser did not understand the response.
		// check for the last by trying with novirus.txt
		todo.unshift({ page: test['harmless_page'], desc: test['desc'], valid: test['valid'], harmless_retry:1,
		    retry4status:status, retry4page: test['page']});
	    }
	    if (fast_feedback && results.length > fast_feedback) {
		submit_part();
	    }
	    runtests(todo,done+1);
	});
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


1;
