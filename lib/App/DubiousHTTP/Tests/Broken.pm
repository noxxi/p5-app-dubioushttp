use strict;
use warnings;
package App::DubiousHTTP::Tests::Broken;
use App::DubiousHTTP::Tests::Common;
use Compress::Raw::Zlib;

SETUP( 
    'broken',
    "Various broken responses",
    <<'DESC',
This test tries various kinds of broken HTTP responses like
<ul>
<li>invalid characters inside the response header</li>
<li>invalid HTTP versions</li>
<li>invalid status codes or missing information for these status codes (like location with redirects)</li>
</ul>
DESC

    # ------------------------- Tests ----------------------------------------

    [ MUSTBE_VALID,  'ok' => 'VALID: simple request with content-length'],
    [ UNCOMMON_VALID, 'http09' => 'HTTP 0.9 response (no header)'],

    [ 'INVALID: junk data around transfer-encoding' ],
    [ INVALID, 'chunked;177' => 'Transfer-Encoding: chunked\r\n\177\r\n, served chunked' ],
    [ INVALID, 'hdrfirst;space;chunked' => '<space>Transfer-Encoding: chunked as first header line, served chunked' ],
    [ INVALID, 'hdrfirst;tab;chunked' => '<tab>Transfer-Encoding: chunked as first header line, served chunked' ],
    [ INVALID, 'hdrfirst;space;chunked;do_clen' => '<space>Transfer-Encoding: chunked as first header line, not served chunked' ],
    [ INVALID, 'hdrfirst;tab;chunked;do_clen' => '<tab>Transfer-Encoding: chunked as first header line, not served chunked' ],
    [ INVALID, 'hdrfirst;space;chunked;do_close' => '<space>Transfer-Encoding: chunked as first header line, not served chunked and no content-length' ],
    [ INVALID, 'hdrfirst;tab;chunked;do_close' => '<tab>Transfer-Encoding: chunked as first header line, not served chunked and no content-length' ],
    [ INVALID, 'somehdr;space;chunked' => '<space>Transfer-Encoding: chunked as continuation of some header line, served chunked' ],
    [ INVALID, 'somehdr;tab;chunked' => '<tab>Transfer-Encoding: chunked as continuation of some header line, served chunked' ],
    [ UNCOMMON_VALID, 'somehdr;space;chunked;do_clen' => '<space>Transfer-Encoding: chunked as continuation of some header line, not served chunked' ],
    [ UNCOMMON_VALID, 'somehdr;tab;chunked;do_clen' => '<tab>Transfer-Encoding: chunked as continuation of some header line, not served chunked' ],
    [ INVALID, '8bitkey;chunked' => 'line using 8bit field name, followed by TE chunked, served chunked'],
    [ INVALID, '8bitkey;chunked;do_clen' => 'line using 8bit field name, followed by TE chunked, not served chunked'],
    [ INVALID, 'colon;chunked' => 'line with empty field name (single colon on line), followed by TE chunked, served chunked'],
    [ INVALID, 'colon;chunked;do_clen' => 'line with empty field name (single colon on line), followed by TE chunked, not served chunked'],
    [ INVALID, '177;chunked' => 'line \177\r\n, followed by TE chunked, served chunked' ],
    [ INVALID, '177;chunked;do_clen' => 'line \177\r\n, followed by TE chunked, not served chunked' ],
    [ INVALID, 'data:\000;chunked' => 'line \000\r\n, followed by TE chunked, served chunked' ],
    [ INVALID, 'data:\000;chunked;do_clen' => 'line \000\r\n, followed by TE chunked, not served chunked' ],
    [ INVALID, 'junkline;chunked' => 'ASCII junk line w/o colon, followed by TE chunked, served chunked'],
    [ INVALID, 'junkline;chunked;do_clen' => 'ASCII junk line w/o colon, followed by TE chunked, not served chunked'],
    [ INVALID, 'spacehdr;chunked' => 'header containing space, followed by TE chunked, served chunked'],
    [ INVALID, 'spacehdr;chunked;do_clen' => 'header containing space, followed by TE chunked, not served chunked'],
    [ INVALID, 'cr;chunked' => 'line just containing <CR>: \r\r\n, followed by TE chunked'],
    [ INVALID, 'lf;chunked' => 'line just containing <LF>: \n\r\n, followed by TE chunked'],
    [ INVALID, 'crcr;chunked' => 'line just containing <CR><CR>: \r\r\r\n, followed by TE chunked'],
    [ INVALID, 'lfcr;chunked' => 'line just containing <LF><CR>: \n\r\r\n, followed by TE chunked'],
    [ INVALID, 'crcronly;chunked' => 'TE chunked prefixed with <CR><CR>,served chunked' ],
    [ INVALID, 'cr-cronly;chunked' => 'TE chunked prefixed with <CR><space><CR>, served chunked' ],
    [ INVALID, 'crcronly;chunked;do_clen' => 'TE chunked prefixed with <CR><CR>, not served chunked' ],
    [ INVALID, 'cr-cronly;chunked;do_clen' => 'TE chunked prefixed with <CR><space><CR>, not served chunked' ],
    [ INVALID, 'lflfonly;chunked' => 'TE chunked prefixed with <LF><LF>,served chunked' ],
    [ INVALID, 'lf-lfonly;chunked' => 'TE chunked prefixed with <LF><space><LF>, served chunked' ],
    [ INVALID, 'lflfonly;chunked;do_clen' => 'TE chunked prefixed with <LF><LF>, not served chunked' ],
    [ INVALID, 'lf-lfonly;chunked;do_clen' => 'TE chunked prefixed with <LF><space><LF>, not served chunked' ],
    [ INVALID, 'crlf-crlfonly;chunked' => 'TE chunked prefixed with <CR><LF><space><CR><LF>, served chunked' ],
    [ INVALID, 'crlf-crlfonly;chunked;do_clen' => 'TE chunked prefixed with <CR><LF><space><CR><LF>, not served chunked' ],
    [ INVALID, 'te\000:chunked;do_chunked' => '"Transfer-Encoding\000:chunked", served chunked' ],
    [ INVALID, 'te:\000chunked;do_chunked' => '"Transfer-Encoding:\000chunked", served chunked' ],
    [ INVALID, 'te:chunked\000;do_chunked' => '"Transfer-Encoding:chunked\000", served chunked' ],
    [ INVALID, 'te:chu\000nked;do_chunked' => '"Transfer-Encoding:chu\000nked", served chunked' ],
    [ INVALID, 'data:Transfer\000-encoding:chunked\015\012;do_chunked' => '"Transfer\000-Encoding:chunked", served chunked' ],
    [ INVALID, 'data:Transfer\000-encoding:chun\000ked\015\012;do_chunked' => '"Transfer\000-Encoding:chun\000ked", served chunked' ],
    [ INVALID, 'te:\013chunked;do_chunked' => '"Transfer-Encoding:\013chunked", served chunked' ],
    [ INVALID, 'te:\177chunked;do_chunked' => '"Transfer-Encoding:\177chunked", served chunked' ],
    [ INVALID, 'te:chunked\177;do_chunked' => '"Transfer-Encoding:chunked\177", served chunked' ],
    [ INVALID, 'te:chu\177nked;do_chunked' => '"Transfer-Encoding:chu\177nked", served chunked' ],
    [ INVALID, 'te:\357\273\277chunked;do_chunked' => '"Transfer-Encoding:<UTF8-BOM>chunked", served chunked' ],
    [ INVALID, 'te:\302\204chunked;do_chunked' => '"Transfer-Encoding:<UTF8-NBSP>chunked", served chunked' ],

    [ 'INVALID: various broken responses' ],
    [ INVALID, 'emptycont' => 'empty continuation line'],
    [ INVALID, '8bitkey' => 'line using 8bit field name'],
    [ INVALID, 'colon' => 'line with empty field name (single colon on line)'],
    [ INVALID, 'data:\000' => 'line \000\r\n' ],
    [ INVALID, '177' => 'line \177\r\n' ],
    [ INVALID, '177;only' => 'line \177\r\n and then the body, no other header after status line' ],
    [ INVALID, 'junkline' => 'ASCII junk line w/o colon'],
    [ INVALID, 'spacehdr' => 'header containing space'],
    [ INVALID, 'cr' => 'line just containing <CR>: \r\r\n'],
    [ INVALID, 'lf' => 'line just containing <LF>: \n\r\n'],
    [ INVALID, 'crcr' => 'line just containing <CR><CR>: \r\r\r\n'],
    [ INVALID, 'lfcr' => 'line just containing <LF><CR>: \n\r\r\n'],
    [ INVALID, 'code-only' => 'status line stops after code, no phrase'],
    [ INVALID, 'http-lower' => 'version given as http/1.1 instead of HTTP/1.1'],
    [ INVALID, 'proto:HTTP/0.9' => 'version given as HTTP/0.9 instead of HTTP/1.1'],
    [ INVALID, 'proto:HTTP/1.10' => 'version given as HTTP/1.10 instead of HTTP/1.1'],
    [ INVALID, 'proto:HTTP/1.00' => 'version given as HTTP/1.00 instead of HTTP/1.0'],
    [ INVALID, 'proto:HTTP/1.01' => 'version given as HTTP/1.01 instead of HTTP/1.0'],
    [ INVALID, 'proto:HTTP/1.2' => 'version given as HTTP/1.2 instead of HTTP/1.1'],
    [ INVALID, 'proto:HTTP/2.0' => 'version given as HTTP/2.0 instead of HTTP/1.1'],
    [ INVALID, 'proto:HTTP/1.1-space' => 'HTTP/1.1+SPACE: space after version in status line'],
    [ INVALID, 'proto:HTTP/1.1-tab' => 'HTTP/1.1+TAB: tab after version in status line'],
    [ INVALID, 'proto:HTTP/1.1-cr' => 'HTTP/1.1+CR: \r after version in status line'],
    [ INVALID, 'proto:HTTP/1.1-lf' => 'HTTP/1.1+LF: \n after version in status line'],
    [ INVALID, "proto:space-HTTP/1.1" => 'version prefixed with space: SPACE+HTTP/1.1'],
    [ INVALID, 'proto:FTP/1.1' => 'version FTP/1.1 instead of HTTP/1.1'],
    [ INVALID, 'status:HTTP/1.1' => 'HTTP/1.1 without code'],
    [ INVALID, 'status:HTTP/1.1(cr)Transfer-Encoding:chunked;do_clen' => 'HTTP/1.1\rTransfer-Encoding:chunked, not served chunked'],
    [ INVALID, 'status:HTTP/1.1(cr)Transfer-Encoding:chunked;do_chunked' => 'HTTP/1.1\rTransfer-Encoding:chunked, served chunked'],
    [ INVALID, 'status:HTTP/1.1(lf)Transfer-Encoding:chunked;do_clen' => 'HTTP/1.1\nTransfer-Encoding:chunked, not served chunked'],
    [ INVALID, 'status:HTTP/1.1(lf)Transfer-Encoding:chunked;do_chunked' => 'HTTP/1.1\nTransfer-Encoding:chunked, served chunked'],
    [ INVALID, 'status:HTTP/1.1(cr)(lf)Transfer-Encoding:chunked;do_clen' => 'HTTP/1.1\r\nTransfer-Encoding:chunked, not served chunked'],
    [ INVALID, 'status:HTTP/1.1(cr)(lf)Transfer-Encoding:chunked;do_chunked' => 'HTTP/1.1\r\nTransfer-Encoding:chunked, served chunked'],
    [ INVALID, 'status:HTTP/1.1(space)200(cr)Transfer-Encoding:chunked;do_clen' => 'HTTP/1.1 200\rTransfer-Encoding:chunked, not served chunked'],
    [ INVALID, 'status:HTTP/1.1(space)200(cr)Transfer-Encoding:chunked;do_chunked' => 'HTTP/1.1 200\rTransfer-Encoding:chunked, served chunked'],
    [ INVALID, 'status:HTTP/1.1(space)200(lf)Transfer-Encoding:chunked;do_clen' => 'HTTP/1.1 200\nTransfer-Encoding:chunked, not served chunked'],
    [ INVALID, 'status:HTTP/1.1(space)200(lf)Transfer-Encoding:chunked;do_chunked' => 'HTTP/1.1 200\nTransfer-Encoding:chunked, served chunked'],
    [ INVALID, 'status:HTTP/1.1(space)200(space)(cr)Transfer-Encoding:chunked;do_clen' => 'HTTP/1.1 200 \rTransfer-Encoding:chunked, not served chunked'],
    [ INVALID, 'status:HTTP/1.1(space)200(space)(cr)Transfer-Encoding:chunked;do_chunked' => 'HTTP/1.1 200 \rTransfer-Encoding:chunked, served chunked'],
    [ INVALID, 'status:HTTP/1.1(space)200(space)(lf)Transfer-Encoding:chunked;do_clen' => 'HTTP/1.1 200 \nTransfer-Encoding:chunked, not served chunked'],
    [ INVALID, 'status:HTTP/1.1(space)200(space)(lf)Transfer-Encoding:chunked;do_chunked' => 'HTTP/1.1 200 \nTransfer-Encoding:chunked, served chunked'],
    [ INVALID, 'status:HTTP/1.1(space)200(space)ok(cr)Transfer-Encoding:chunked;do_clen' => 'HTTP/1.1 200 ok\rTransfer-Encoding:chunked, not served chunked'],
    [ INVALID, 'status:HTTP/1.1(space)200(space)ok(cr)Transfer-Encoding:chunked;do_chunked' => 'HTTP/1.1 200 ok\rTransfer-Encoding:chunked, served chunked'],
    [ INVALID, 'status:HTTP/1.1(space)200(space)ok(lf)Transfer-Encoding:chunked;do_clen' => 'HTTP/1.1 200 ok\nTransfer-Encoding:chunked, not served chunked'],
    [ INVALID, 'status:HTTP/1.1(space)200(space)ok(lf)Transfer-Encoding:chunked;do_chunked' => 'HTTP/1.1 200 ok\nTransfer-Encoding:chunked, served chunked'],
    [ INVALID, 'status:\000HTTP/1.1(space)200(space)ok(crlf);chunked' => '\000HTTP/1.1 200 ok\r\n and chunked'],
    [ INVALID, 'status:HTT\000P/1.1(space)200(space)ok(crlf);chunked' => 'HTT\000P/1.1 200 ok\r\n and chunked'],
    [ INVALID, 'status:HTTP/1\000.1(space)200(space)ok(crlf);chunked' => 'HTTP/1\000.1 200 ok\r\n and chunked'],
    [ INVALID, 'status:HTTP/1.1\000(space)200(space)ok(crlf);chunked' => 'HTTP/1.1\000 200 ok\r\n and chunked'],
    [ INVALID, 'status:HTTP/1.1(space)2\00000(space)ok(crlf);chunked' => 'HTTP/1.1 2\00000 ok\r\n and chunked'],
    [ INVALID, 'status:HTTP/1.1(space)200\000(space)ok(crlf);chunked' => 'HTTP/1.1 200\000 ok\r\n and chunked'],
    [ INVALID, 'status:HTTP/1.1\000200\000ok(crlf);chunked' => 'HTTP/1.1\000200\000ok\r\n and chunked'],
    [ INVALID, 'status:HTTP/1.1\013200\013ok(crlf);chunked' => 'HTTP/1.1\013200\013ok\r\n and chunked'],
    [ INVALID, 'status:HTTP/1.1foobar(crlf);chunked' => 'HTTP/1.1foobar\r\n and chunked'],
    [ INVALID, 'status:HTTP/1.1foobar(cr)Transfer-Encoding:chunked;do_chunked' => 'HTTP/1.1foobar\r and chunked'],
    [ INVALID, 'status:HTTP/1.foobar(crlf);chunked' => 'HTTP/1.foobar\r\n and chunked'],
    [ INVALID, 'status:HTTP/1foobar(crlf);chunked' => 'HTTP/1foobar\r\n and chunked'],
    [ INVALID, 'status:HTTP/foobar(crlf);chunked' => 'HTTP/foobar\r\n and chunked'],
    [ INVALID, 'status:HTTP/(crlf);chunked' => 'HTTP/\r\n and chunked'],
    [ INVALID, 'status:HTTP(crlf);chunked' => 'HTTP\r\n and chunked'],
    [ INVALID, 'cr-no-crlf' => 'single \r instead of \r\n' ],
    [ INVALID, 'cr-no-crlf;end-crlflf' => 'single \r instead of \r\n, but end \r\n\n' ],
    [ INVALID, 'cr-no-crlf;end-crlfcrlf' => 'single \r instead of \r\n, but end \r\n\r\n' ],
    [ INVALID, 'lf-no-crlf' => 'single \n instead of \r\n' ],
    [ INVALID, 'crcr-no-crlf' => '\r\r instead of \r\n' ],
    [ INVALID, 'lfcr-no-crlf' => '\n\r instead of \r\n' ],
    [ INVALID, 'cr\000lf-no-crlf' => '\r\000\n instead of \r\n' ],
    [ INVALID, 'chunked;cr-no-crlf' => 'single \r instead of \r\n and chunked' ],
    [ INVALID, 'chunked;cr-no-crlf;end-crlflf' => 'single \r instead of \r\n, but end \r\n\n and chunked' ],
    [ INVALID, 'chunked;cr-no-crlf;end-crlfcrlf' => 'single \r instead of \r\n, but end \r\n\r\n and chunked' ],
    [ INVALID, 'chunked;lf-no-crlf' => 'single \n instead of \r\n and chunked' ],
    [ INVALID, 'chunked;crcr-no-crlf' => '\r\r instead of \r\n and chunked' ],
    [ INVALID, 'chunked;crcr-no-crlf;end-crlfcrlf' => '\r\r instead of \r\n, but end \r\n\r\n and chunked' ],
    [ INVALID, 'chunked;lfcr-no-crlf' => '\n\r instead of \r\n and chunked' ],
    [ INVALID, 'chunked;lfcr-no-crlf;end-crlfcrlf' => '\n\r instead of \r\n, but end \r\n\r\n and chunked' ],
    [ INVALID, 'chunked;cr\000lf-no-crlf' => '\r\000\n instead of \r\n and chunked' ],
    [ INVALID, 'end-crcr' => 'header end \r\r' ],
    [ INVALID, 'end-lflf' => 'header end \n\n' ],
    [ INVALID, 'end-lfcrlf' => 'header end \n\r\n' ],
    [ INVALID, 'end-lfcrcrlf' => 'header end \n\r\r\n' ],
    [ INVALID, 'end-crlf\000crlf' => 'header end \r\n\000\r\n' ],
    [ INVALID, 'end-cr\000crlf' => 'header end \r\000\r\n' ],

    [ INVALID, 'end-lf\040lf' => 'header end \n\040\n' ],
    [ UNCOMMON_INVALID, 'end-lf\040lflf' => 'header end \n\040\n\n' ],
    [ UNCOMMON_VALID, 'end-crlf\040crlfcrlf' => 'header end \r\n\040\r\n\r\n' ],
    [ INVALID, 'chunked;end-lf\040lf' => 'header end \n\040\n and chunked' ],
    [ UNCOMMON_INVALID, 'chunked;end-lf\040lflf' => 'header end \n\040\n\n and chunked' ],
    [ UNCOMMON_VALID, 'chunked;end-crlf\040crlfcrlf' => 'header end \r\n\040\r\n\r\n and chunked' ],
    [ INVALID, 'gzip;end-lf\040lf' => 'header end \n\040\n and gzip' ],
    [ UNCOMMON_INVALID, 'gzip;end-lf\040lflf' => 'header end \n\040\n\n and gzip' ],
    [ UNCOMMON_VALID, 'gzip;end-crlf\040crlfcrlf' => 'header end \r\n\040\r\n\r\n and gzip' ],
    [ INVALID, 'end-lf\040.lf' => 'header end \n\040.\n' ],

    [ INVALID, 'end-lf\011lf' => 'header end \n\011\n' ],
    [ UNCOMMON_INVALID, 'end-lf\011lflf' => 'header end \n\011\n\n' ],
    [ UNCOMMON_VALID, 'end-crlf\011crlfcrlf' => 'header end \r\n\011\r\n\r\n' ],
    [ INVALID, 'chunked;end-lf\011lf' => 'header end \n\011\n and chunked' ],
    [ UNCOMMON_INVALID, 'chunked;end-lf\011lflf' => 'header end \n\011\n\n and chunked' ],
    [ UNCOMMON_VALID, 'chunked;end-crlf\011crlfcrlf' => 'header end \r\n\011\r\n\r\n and chunked' ],
    [ INVALID, 'gzip;end-lf\011lf' => 'header end \n\011\n and gzip' ],
    [ UNCOMMON_INVALID, 'gzip;end-lf\011lflf' => 'header end \n\011\n\n and gzip' ],
    [ UNCOMMON_VALID, 'gzip;end-crlf\011crlfcrlf' => 'header end \r\n\011\r\n\r\n and gzip' ],

    [ INVALID, 'end-lf\013lf' => 'header end \n\013\n' ],
    [ UNCOMMON_INVALID, 'end-lf\013lflf' => 'header end \n\013\n\n' ],
    [ UNCOMMON_VALID, 'end-crlf\013crlfcrlf' => 'header end \r\n\013\r\n\r\n' ],
    [ INVALID, 'chunked;end-lf\013lf' => 'header end \n\013\n and chunked' ],
    [ UNCOMMON_INVALID, 'chunked;end-lf\013lflf' => 'header end \n\013\n\n and chunked' ],
    [ UNCOMMON_VALID, 'chunked;end-crlf\013crlfcrlf' => 'header end \r\n\013\r\n\r\n and chunked' ],
    [ INVALID, 'gzip;end-lf\013lf' => 'header end \n\013\n and gzip' ],
    [ UNCOMMON_INVALID, 'gzip;end-lf\013lflf' => 'header end \n\013\n\n and gzip' ],
    [ UNCOMMON_VALID, 'gzip;end-crlf\013crlfcrlf' => 'header end \r\n\013\r\n\r\n and gzip' ],

    [ 'INVALID: redirect without location' ],
    [ INVALID, '300' => 'code 300 without location header'],
    [ INVALID, '301' => 'code 301 without location header'],
    [ INVALID, '302' => 'code 302 without location header'],
    [ INVALID, '303' => 'code 303 without location header'],
    [ INVALID, '305' => 'code 305 without location header'],
    [ INVALID, '307' => 'code 307 without location header'],
    [ INVALID, '308' => 'code 308 without location header'],

    [ 'INVALID: other status codes with invalid behavior' ],
    [ INVALID, '100' => 'code 100 with body'],
    [ INVALID, '101' => 'code 101 with body'],
    [ INVALID, '102' => 'code 102 with body'],
    [ INVALID, '204' => 'code 204 with body'],
    [ INVALID, '205' => 'code 205 with body'],
    [ INVALID, '206' => 'code 206 with body'],
    [ INVALID, '304' => 'code 304 with body'],
    [ INVALID, '401' => 'code 401 with body and no authorization requested'],
    [ INVALID, '407' => 'code 407 with body and no authorization requested'],

    [ 'VALID: other status codes with valid behavior' ],
    [ UNCOMMON_VALID, '400' => 'code 400 with body'],
    [ UNCOMMON_VALID, '403' => 'code 403 with body'],
    [ UNCOMMON_VALID, '404' => 'code 404 with body'],
    [ UNCOMMON_VALID, '406' => 'code 406 with body'],
    [ UNCOMMON_VALID, '500' => 'code 500 with body'],
    [ UNCOMMON_VALID, '502' => 'code 502 with body'],

    [ 'VALID: non-existing status codes' ],
    [ INVALID, '000' => 'code 000 with body'],
    [ INVALID, '600' => 'code 600 with body'],
    [ INVALID, '700' => 'code 700 with body'],
    [ INVALID, '800' => 'code 800 with body'],
    [ INVALID, '900' => 'code 900 with body'],

    [ 'INVALID: malformed status codes' ],
    [ INVALID, '2xx' => 'invalid status code with non-digits (2xx)'],
    [ INVALID, '20x' => 'invalid status code with non-digits (20x)'],
    [ INVALID, '2'   => 'invalid status code, only single digit (2)'],
    [ INVALID, '20'  => 'invalid status code, two digits (20)'],
    [ INVALID, '2000' => 'invalid status code, too much digits (2000)'],
    [ INVALID, '0200' => 'invalid status code, numeric (0200)'],
    [ INVALID, 'space-200' => 'invalid status code, SPACE+200)'],
    [ INVALID, 'tab-200' => 'invalid status code, TAB+200)'],

    [ 'VALID: new lines before HTTP header' ],
    [ UNCOMMON_VALID, 'crlf-header;chunked' => 'single <CR><LF> before header, chunked'],
    [ UNCOMMON_VALID, 'crlf-crlf-header;chunked' => 'double <CR><LF> before header, chunked'],
    [ INVALID, 'space-crlf-header;chunked' => 'space followed by single <CR><LF> before header, chunked'],
    [ INVALID, 'space-tab-crlf-header;chunked' => 'space+TAB followed by single <CR><LF> before header, chunked'],
    [ INVALID, 'space-crlf-tab-crlf-header;chunked' => 'space+CRLF+TAB+CRLF before header, chunked'],
    [ INVALID, 'space-tab-cr-crlf-header;chunked' => 'space+TAB+CR followed by single <CR><LF> before header, chunked'],
    [ INVALID, 'foobar-crlf-header;chunked' => 'junk followed by single <CR><LF> before header, chunked'],
    [ INVALID, 'SIP/2.0-space-200-space-ok-crlf-header;chunked' => '"SIP/2.0 200 ok" followed by single <CR><LF> before header, chunked'],
    [ INVALID, 'space-foobar-crlf-header;chunked' => 'space+junk followed by single <CR><LF> before header, chunked'],
    [ INVALID, 'space-SIP/2.0-space-200-space-ok-crlf-header;chunked' => 'space+"SIP/2.0 200 ok" followed by single <CR><LF> before header, chunked'],
    [ INVALID, 'cr-header;chunked' => 'single <CR> before header, chunked'],
    [ INVALID, 'cr-cr-header;chunked' => 'double <CR> before header, chunked'],
    [ INVALID, 'space-cr-header;chunked' => 'space followed by single <CR> before header, chunked'],
    [ INVALID, 'lf-header;chunked' => 'single <LF> before header, chunked'],
    [ INVALID, 'lf-lf-header;chunked' => 'double <LF> before header, chunked'],
    [ INVALID, 'space-lf-header;chunked' => 'space followed by single <LF> before header, chunked'],
    [ INVALID, 'lfcr-header;chunked' => 'single <LF><CR> before header, chunked'],
);

sub make_response {
    my ($self,$page,$spec) = @_;
    return make_index_page() if $page eq '';
    my ($cthdr,$data) = content($page,$self->ID."-".$spec) or die "unknown page $page";
    my $version = '1.1';
    my $te = 'clen';
    my $only = 0;
    my $code = 200;
    my $prefix = '';
    my $statusline;
    my @transform;
    my $hdr = "Connection: close\r\n";
    my $hdrfirst;
    for (split(';',$spec)) {
	if ( $_ eq 'emptycont' ) {
	    $hdr .= "Foo: bar\r\n \r\n"
	} elsif ( $_ eq '8bitkey' ) {
	    $hdr .= "Löchriger-Häddar: foobar\r\n"
	} elsif ( $_ eq 'spacehdr' ) {
	    $hdr .= "Foo Bar: foobar\r\n"
	} elsif ( $_ eq 'colon' ) {
	    $hdr .= ": foo\r\n"
	} elsif ( $_ eq 'space' ) {
	    $hdr .= " "
	} elsif ( $_ eq 'tab' ) {
	    $hdr .= "\t"
	} elsif ( $_ eq 'somehdr') {
	    $hdr .= "X-Foo: bar\r\n";
	} elsif ( $_ eq 'hdrfirst') {
	    $hdrfirst = 1;
	} elsif ( $_ eq 'junkline' ) {
	    $hdr .= "qutqzdafsdshadsdfdshsdd sddfd\r\n"
	} elsif ( m{^(?:(cr|lf|-)+)(only)?$} ) {
	    s{cr}{\r}g;
	    s{lf}{\n}g;
	    s{-}{ }g;
	    $hdr .= s{only$}{} ? $_ : "$_\r\n";
	} elsif ( $_ eq 'chunked' ) {
	    $te = 'chunked';
	    $hdr .= "Transfer-Encoding: chunked\r\n";
	} elsif ( $_ eq 'gzip' ) {
	    my $zlib = Compress::Raw::Zlib::Deflate->new(
		-WindowBits => WANT_GZIP,
		-AppendOutput => 1,
	    );
	    my $newdata = '';
	    $zlib->deflate( $data, $newdata);
	    $zlib->flush($newdata,Z_FINISH);
	    $data = $newdata;
	    $hdr .= "Content-Encoding: gzip\r\n";
	} elsif ( $_ eq 'do_clen') {
	    $te = 'clen';
	} elsif ( $_ eq 'do_chunked') {
	    $te = 'chunked';
	} elsif ( $_ eq 'do_close') {
	    $te = 'close';
	} elsif ( $_ eq '177' ) {
	    $hdr .= "\177\r\n";
	} elsif ( $_ eq 'only' ) {
	    $only = 1;
	} elsif ( $_ eq 'http09' ) {
	    return $data;
	} elsif ( m{^(space-|tab-)*(\d.*)$} ) {    
	    s{space-}{ }g;
	    s{tab-}{\t}g;
	    $code = $_;
	} elsif ( $_ eq 'code-only' ) {
	    $statusline = "HTTP/$version $code\r\n";
	} elsif ( $_ eq 'http-lower' ) {
	    $statusline = "http/$version $code ok\r\n";
	} elsif ( $_ =~ m{^((?:cr|lf|\\[0-7]{3})+)-no-crlf$} ) {
	    my $w = $1;
	    $w =~s{cr}{\r}g;
	    $w =~s{lf}{\n}g;
	    $w =~s{\\([0-7]{3})}{ chr(oct($1)) }eg;
	    push @transform, sub { $_[0] =~ s{\r?\n}{$w}g }
	} elsif ( $_ =~ m{^end-((?:cr|lf|\\[0-7]{3})+)} ) {
	    my $w = $1;
	    $w =~s{cr}{\r}g;
	    $w =~s{lf}{\n}g;
	    $w =~s{\\([0-7]{3})}{ chr(oct($1)) }eg;
	    push @transform, sub { $_[0] =~ s{(\r|\n|\r\n)\1}{$w} or die }
	} elsif ( m{^proto:(.*)} ) {
	    my $proto = $1;
	    $proto =~s{cr|\\r}{\r}g;
	    $proto =~s{tab|\\t}{\t}g;
	    $proto =~s{lf|\\n}{\n}g;
	    $proto =~s{space}{ }g;
	    $proto =~s{-}{}g;
	    $statusline = "$proto $code ok\r\n";
	} elsif ( m{^status:(.*)} ) {
	    my $line = $1;
	    $line =~s{\Q(cr)}{\r}g;
	    $line =~s{\Q(tab)}{\t}g;
	    $line =~s{\Q(lf)}{\n}g;
	    $line =~s{\Q(space)}{ }g;
	    $line =~s{\\([0-7]{3})}{ chr(oct($1)) }esg;
	    $statusline = "$line\r\n";
	} elsif ( $_ eq 'ok' ) {
	} elsif ( m{^(.*)-header$}) {
	    $prefix = $1;
	    $prefix =~s{cr}{\r}g;
	    $prefix =~s{lf}{\n}g;
	    $prefix =~s{space}{ }g;
	    $prefix =~s{tab}{\t}g;
	    $prefix =~s{-}{}g;
	} elsif (m{^te(.*:.*)}) {
	    (my $d = $1) =~s{\\([0-7]{3})}{ chr(oct($1)) }esg;
	    $hdr .= "Transfer-Encoding$d\r\n";
	} elsif (s{^data:}{}) {
	    s{\\([0-7]{3})}{ chr(oct($1)) }esg;
	    $hdr .= $_;
	} else {
	    die $_
	}
    }
    $data = join('', map { sprintf("%x\r\n%s\r\n", length($_),$_) } ($data =~m{(.{1,4})}sg,''))
	if $te eq 'chunked';
    if (!$only) {
	$hdr .= "Yet-another-header: foo\r\n";
	$hdr .= "Content-length: ".length($data)."\r\n" if $te eq 'clen';
    }
    $statusline ||= "HTTP/$version $code ok\r\n";
    if ($hdrfirst) {
	$hdr .= $cthdr
    } else {
	$hdr = $cthdr . $hdr
    }

    $hdr = "$prefix$statusline$hdr\r\n";
    for(@transform) {
	$_->($hdr,$data);
    }
    return $hdr . $data;
}

1;
