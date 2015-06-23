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
    my $page = "<!doctype html><html><body>";
    $page .= "<a href=/auto/all/ok.png>Bulk test browser/proxy behavior</a><br>\n";
    $page .= "<a href=/auto/all/eicar.txt>Bulk test firewall evasion with EICAR test virus</a><br>\n";
    $page .= "<hr>\n";
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

sub auto {
    my ($self,$cat,$page) = @_;
    $page ||= 'eicar.txt';
    my $html = _auto_static_html();
    my ($hdr,$body,$isbad) = content($page);
    $html .= "<script>\n";
    $html .= "expect64 = '".encode_base64($body,'')."';\n";
    $isbad //= '';
    $html .= "isbad ='$isbad';\n";
    $html .= "var checks = [];\n";
    $html .= "checks.push({ page:'/$page', desc:'sanity check', valid:1, expect_bad:1 });\n";
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
#notice   { padding: 1em; margin: 1em; background: #e9f2e1; display: none; }
#warnings { padding: 1em; margin: 1em; background: #e3a79f; display: none; }
#process  { padding: 1em; margin: 1em; background: #f2f299; }
#debug    { padding: 1em; margin: 1em; }
</style>
<div id=noscript>
You need to have JavaScript enabled to run this tests.
</div>
<div id=process></div>
<div id=nobad> </div>
<div id=warnings><h1>Serious Problems</h1></div>
<div id=notice><h1>Behavior in Uncommon Cases</h1></div>
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
var div_warnings = document.getElementById('warnings');
var div_nobad = document.getElementById('nobad');
var div_process = document.getElementById('process');
var expect64;
var isbad;
var results = '';

var warnings = 0;
function add_warning(m,page,desc) {
    warnings++;
    div_warnings.innerHTML = div_warnings.innerHTML + warnings + ". " + m + ": <a href=" + page + ">" + desc + "</a><br>";
    div_warnings.style.display = 'block';
}

var notice = 0;
function add_notice(m,page,desc) {
    notice++;
    div_notice.innerHTML = div_notice.innerHTML + notice + ". " + m + ": <a href=" + page + ">" + desc + "</a><br>";
    div_notice.style.display = 'block';
}

function add_debug(m) {
    div_debug.innerHTML = div_debug.innerHTML + m + "<br>";
}

function xhr(method,page,payload,callback) {
    var req = null;
    try { 
	req = window.XMLHttpRequest 
	    ? new XMLHttpRequest() 
	    : new ActiveXObject("Microsoft.XMLHTTP");
	req.overrideMimeType('text/plain; charset=x-user-defined');
	req.timeout = 2000;
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
	req.send(payload);
    } catch(e) {
	console.log(e);
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
    } else if (status == 200) {
	var result64 = base64_encode(req.responseText);
	if (result64 == expect64) {
	    status = 'match';
	} else {
	    // console.log( "response: " + result64 );
	    // console.log( "expect:   " + expect64 );
	    status = 'change'
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
	    }
	}
	return;
    }

    // check for standard conformance
    if (test['valid']>0 && status != 'match') {
	add_warning("failure for valid response",test['page'],test['desc']);
	results = results + "W | " + status + " | " + test['page'] + " | " + test['desc'] + " | failure for valid response\n";
    } else if (test['valid']<0 && status == 'match') {
	add_notice("success for uncommon response",test['page'],test['desc']);
	results = results + "N | " + status + " | " + test['page'] + " | " + test['desc'] + " | success for uncommon response\n";
    } else if (test['valid'] == 0 && status == 'match') {
	add_warning("success for bad response",test['page'],test['desc']);
	results = results + "W | " + status + " | " + test['page'] + " | " + test['desc'] + " | success for bad response\n";
    } else {
	results = results + "I | " + status + " | " + test['page'] + " | " + test['desc'] + " | ok\n";
    }
}

function runtests(todo,done) {
    var test = todo.shift();
    if (test) {
	var total = todo.length + done;
	div_process.innerHTML = "Progress: " + done + "/" + total + " - " + test['desc'];
	xhr('GET',test['page'],null,function(req,status) {
	    check_page(req,test,status);
	    runtests(todo,done+1);
	});
    } else {
	div_process.style.display = 'none';
	add_debug("*DONE*");
	xhr('POST','/submit_results',results, null);
    }
}

document.getElementById('noscript').style.display = 'none';
</script>
HTML


1;
