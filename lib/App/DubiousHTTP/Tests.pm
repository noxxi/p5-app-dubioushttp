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
    $html .= "isbad ='$isbad';\n";
    $html .= "check('/$page','sanity check',1,1);\n";
    for(@cat) {
	next if $cat ne 'all' && $_->ID ne $cat;
	for($_->TESTS) {
	    $html .= sprintf("check('%s','%s',%d);\n",
		$_->url($page), quotemeta($_->DESCRIPTION), $_->VALID)
	}
    }
    $html .= "</script>\n";

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
#debug    { padding: 1em; margin: 1em; }
</style>
<div id=noscript>
You need to have JavaScript enabled to run this tests.
</div>
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
var expect64;
var isbad;

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

function check(page,desc,valid,expect_isbad) {
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
	return;
    }
    var status;
    try {
	/* req.timeout = 5000; */
	req.overrideMimeType('text/plain; charset=x-user-defined');
	req.open('GET', page, false);
	req.send(null);
	status = req.status;
    } catch(e) { 
	status = 'invalid' 
    }
    if (status == 200) {
	var result64 = base64_encode(req.responseText);
	if (result64 == expect64) {
	    status = 'match';
	} else {
	    // console.log( "response: " + result64 );
	    // console.log( "expect:   " + expect64 );
	    status = 'change'
	}
    }
    add_debug( desc + '-' + status );
    if (isbad != '') {
	// check for evasion
	if (status == 'match') {
	    if (expect_isbad) {
		// assume no or stupid content filter
		div_nobad.innerHTML = div_nobad.innerHTML + "No content filter detecting " + isbad + ".<br>"
		    + "Assuming no content filter.<br>";
		div_nobad.style.display = 'block';
		isbad = '';
	    } else {
		// possible evasion of content filter
		add_warning("Evasion possible",page,desc);
	    }
	}
	return;
    }

    // check for standard conformance
    if (valid>0 && status != 'match') {
	add_warning("failure for valid response",page,desc);
    } else if (valid<0 && status == 'match') {
	add_notice("success for uncommon response",page,desc);
    } else if (valid == 0 && status == 'match') {
	add_warning("success for bad response",page,desc);
    }
}

document.getElementById('noscript').style.display = 'none';
</script>
HTML


1;
