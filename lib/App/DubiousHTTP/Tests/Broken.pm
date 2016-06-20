use strict;
use warnings;
package App::DubiousHTTP::Tests::Broken;
use App::DubiousHTTP::Tests::Common;

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
    [ INVALID, '\012http09' => 'HTTP 0.9 response (no header) prefix with \n'],
    [ INVALID, '\012\012http09' => 'HTTP 0.9 response (no header) prefix with \n\n'],
    [ INVALID, 'HTT\012\012http09' => 'response prefixed with HTT\n\n'],
    [ INVALID, 'HTTP\012\012http09' => 'response prefixed with HTTP\n\n'],
    [ INVALID, 'hTtp\012\012http09' => 'response prefixed with hTtp\n\n'],
    [ INVALID, 'HTTP\012http09' => 'response prefixed with HTTP\n'],
    [ INVALID, 'hTtp\012http09' => 'response prefixed with hTtp\n'],
    [ INVALID, 'HTTP/\012\012http09' => 'response prefixed with HTTP/\n\n'],
    [ INVALID, 'HTTP.\012\012http09' => 'response prefixed with HTTP.\n\n'],
    [ INVALID, 'HTTPx\012\012http09' => 'response prefixed with HTTPx\n\n'],
    [ INVALID, 'HTTP/1.1\040100\040ok\012\012http09' => 'response prefixed with HTTP/1.1 100 ok\n\n'],
    [ INVALID, 'HTTP/1.1\040\053100\040ok\012\012http09' => 'response prefixed with HTTP/1.1 +100 ok\n\n'],

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
    [ COMMON_INVALID, '8bitkey;chunked' => 'line using 8bit field name, followed by TE chunked, served chunked'],
    [ INVALID, '8bitkey;chunked;do_clen' => 'line using 8bit field name, followed by TE chunked, not served chunked'],
    [ COMMON_INVALID, 'data:foo:b\001ar\015\012;chunked' => 'line using binary value, followed by TE chunked, served chunked'],
    [ INVALID, 'data:foo:b\001ar\015\012;chunked;do_clen' => 'line using binary value, followed by TE chunked, not served chunked'],
    [ COMMON_INVALID, 'data:foo:b\000ar\015\012;chunked' => 'line using binary value \000, followed by TE chunked, served chunked'],
    [ INVALID, 'data:foo:b\000ar\015\012;chunked;do_clen' => 'line using binary value \000, followed by TE chunked, not served chunked'],
    [ COMMON_INVALID, 'data:foo:b\200ar\015\012;chunked' => 'line using 8bit value, followed by TE chunked, served chunked'],
    [ INVALID, 'data:foo:b\200ar\015\012;chunked;do_clen' => 'line using 8bit value, followed by TE chunked, not served chunked'],
    [ INVALID, 'colon;chunked' => 'line with empty field name (single colon on line), followed by TE chunked, served chunked'],
    [ INVALID, 'colon;chunked;do_clen' => 'line with empty field name (single colon on line), followed by TE chunked, not served chunked'],
    [ INVALID, '177;chunked' => 'line \177\r\n, followed by TE chunked, served chunked' ],
    [ INVALID, '177;chunked;do_clen' => 'line \177\r\n, followed by TE chunked, not served chunked' ],
    [ INVALID, 'data:\000;chunked' => 'line \000\r\n, followed by TE chunked, served chunked' ],
    [ INVALID, 'data:\000;chunked;do_clen' => 'line \000\r\n, followed by TE chunked, not served chunked' ],
    [ COMMON_INVALID, 'junkline;chunked' => 'ASCII junk line w/o colon, followed by TE chunked, served chunked'],
    [ INVALID, 'junkline;chunked;do_clen' => 'ASCII junk line w/o colon, followed by TE chunked, not served chunked'],
    [ COMMON_INVALID, 'spacehdr;chunked' => 'header containing space, followed by TE chunked, served chunked'],
    [ INVALID, 'spacehdr;chunked;do_clen' => 'header containing space, followed by TE chunked, not served chunked'],
    [ COMMON_INVALID, 'conthdr;chunked' => 'header with continuation line, followed by TE chunked, served chunked'],
    [ INVALID, 'conthdr;chunked;do_clen' => 'header with continuation line, followed by TE chunked, not served chunked'],
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

    [ INVALID, 'te:chu\000nked;do_chunked' => '"Transfer-Encoding:chu\000nked", served chunked' ],
    [ INVALID, 'te:chu\015\012\040nked;do_chunked' => '"Transfer-Encoding:chu\r\n nked", served chunked' ],
    [ INVALID, 'te:chu\015\012\040nked;do_clen' => '"Transfer-Encoding:chu\r\n nked", not served chunked' ],
    [ INVALID, 'te:chu\015\012nked;do_chunked' => '"Transfer-Encoding:chu\r\nnked", served chunked' ],
    [ INVALID, 'te:chu\015\012nked;do_clen' => '"Transfer-Encoding:chu\r\nnked", not served chunked' ],
    [ INVALID, 'data:Transfer\000-encoding:chunked\015\012;do_chunked' => '"Transfer\000-Encoding:chunked", served chunked' ],
    [ INVALID, 'data:Transfer\000-encoding:chun\000ked\015\012;do_chunked' => '"Transfer\000-Encoding:chun\000ked", served chunked' ],
    [ INVALID, 'te\000:chunked;do_chunked' => '"Transfer-Encoding\000:chunked", served chunked' ],
    [ INVALID, 'te\040\011\040\011\040:chunked;do_chunked' => '"Transfer-Encoding \t \t :chunked", served chunked' ],
    [ INVALID, 'te\013:chunked;do_chunked' => '"Transfer-Encoding\v:chunked", served chunked' ],
    [ INVALID, 'te\014:chunked;do_chunked' => '"Transfer-Encoding\f:chunked", served chunked' ],
    [ INVALID, 'te\012\040:chunked;do_chunked' => '"Transfer-Encoding\n :chunked", served chunked' ],
    [ INVALID, 'te\015\040:chunked;do_chunked' => '"Transfer-Encoding\r :chunked", served chunked' ],
    [ INVALID, 'te\015\012\040:chunked;do_chunked' => '"Transfer-Encoding\r\n :chunked", served chunked' ],
    [ INVALID, 'te\015\012\040:\015\012\040chunked;do_chunked' => '"Transfer-Encoding\r\n :\r\n chunked", served chunked' ],
    [ INVALID, 'te\015\012\040\015\012\040:\015\012\040chunked;do_chunked' => '"Transfer-Encoding\r\n \r\n :\r\n chunked", served chunked' ],
    [ INVALID, 'te\012\000:chunked;do_chunked' => '"Transfer-Encoding\n\000:chunked", served chunked' ],
    [ INVALID, 'te:,chunked;do_chunked' => '"Transfer-Encoding:,chunked", served chunked' ],
    [ INVALID, 'te:\073chunked;do_chunked' => '"Transfer-Encoding:;chunked", served chunked' ],
    [ INVALID, 'te:\000chunked;do_chunked' => '"Transfer-Encoding:\000chunked", served chunked' ],
    [ INVALID, 'te:\013chunked;do_chunked' => '"Transfer-Encoding:\vchunked", served chunked' ],
    [ INVALID, 'te:\014chunked;do_chunked' => '"Transfer-Encoding:\fchunked", served chunked' ],
    [ INVALID, 'te:\240chunked;do_chunked' => '"Transfer-Encoding:\240chunked", served chunked' ],
    [ INVALID, 'te:\012\000chunked;do_chunked' => '"Transfer-Encoding:\n\000chunked", served chunked' ],
    [ INVALID, 'te:\012\013chunked;do_chunked' => '"Transfer-Encoding:\n\vchunked", served chunked' ],
    [ INVALID, 'te:\012\014chunked;do_chunked' => '"Transfer-Encoding:\n\fchunked", served chunked' ],
    [ INVALID, 'te:\012\240chunked;do_chunked' => '"Transfer-Encoding:\n\240chunked", served chunked' ],
    [ INVALID, 'te:chunked,;do_chunked' => '"Transfer-Encoding:chunked,", served chunked' ],
    [ INVALID, 'te:chunked\073;do_chunked' => '"Transfer-Encoding:chunked;", served chunked' ],
    [ INVALID, 'te:chunked\000;do_chunked' => '"Transfer-Encoding:chunked\000", served chunked' ],

    [ INVALID, 'te:\177chunked;do_chunked' => '"Transfer-Encoding:\177chunked", served chunked' ],
    [ INVALID, 'te:chunked\177;do_chunked' => '"Transfer-Encoding:chunked\177", served chunked' ],
    [ INVALID, 'te:chu\177nked;do_chunked' => '"Transfer-Encoding:chu\177nked", served chunked' ],
    [ INVALID, 'te:\357\273\277chunked;do_chunked' => '"Transfer-Encoding:<UTF8-BOM>chunked", served chunked' ],
    [ INVALID, 'te:\302\204chunked;do_chunked' => '"Transfer-Encoding:<UTF8-NBSP>chunked", served chunked' ],

    [ INVALID, 'ce:gz\000ip;do_gzip' => '"Content-Encoding:gz\000ip", served gzipped' ],
    [ INVALID, 'data:Content\000-encoding:gzip\015\012;do_gzip' => '"Content\000-Encoding:gzip", served gzipped' ],
    [ INVALID, 'ce\000:gzip;do_gzip' => '"Content-Encoding\000:gzip", served gzipped' ],
    [ INVALID, 'ce\015\012\040:gzip;do_gzip' => '"Content-Encoding\r\n :gzip", served gzipped' ],
    [ INVALID, 'ce\015\012\040:\015\012\040gzip;do_gzip' => '"Content-Encoding\r\n :\r\n gzip", served gzipped' ],
    [ INVALID, 'ce\013:gzip;do_gzip' => '"Content-Encoding\v:gzip", served gzipped' ],
    [ INVALID, 'ce\014:gzip;do_gzip' => '"Content-Encoding\f:gzip", served gzipped' ],
    [ INVALID, 'ce:,gzip;do_gzip' => '"Content-Encoding:,gzip", served gzipped' ],
    [ INVALID, 'ce:\073gzip;do_gzip' => '"Content-Encoding:;gzip", served gzipped' ],
    [ INVALID, 'ce:\000gzip;do_gzip' => '"Content-Encoding:\000gzip", served gzipped' ],
    [ INVALID, 'ce:\013gzip;do_gzip' => '"Content-Encoding:\vgzip", served gzipped' ],
    [ INVALID, 'ce:\014gzip;do_gzip' => '"Content-Encoding:\fgzip", served gzipped' ],
    [ INVALID, 'ce:\240gzip;do_gzip' => '"Content-Encoding:\240gzip", served gzipped' ],
    [ INVALID, 'ce:\012\000gzip;do_gzip' => '"Content-Encoding:\n\000gzip", served gzipped' ],
    [ INVALID, 'ce:\012\013gzip;do_gzip' => '"Content-Encoding:\n\vgzip", served gzipped' ],
    [ INVALID, 'ce:\012\014gzip;do_gzip' => '"Content-Encoding:\n\fgzip", served gzipped' ],
    [ INVALID, 'ce:\012\240gzip;do_gzip' => '"Content-Encoding:\n\240gzip", served gzipped' ],
    [ INVALID, 'ce:gzip,;do_gzip' => '"Content-Encoding:gzip,", served gzipped' ],
    [ INVALID, 'ce:gzip\073;do_gzip' => '"Content-Encoding:gzip;", served gzipped' ],
    [ INVALID, 'ce:gzip\000;do_gzip' => '"Content-Encoding:gzip\000", served gzipped' ],
    [ INVALID, 'ce:gzip\013;do_gzip' => '"Content-Encoding:gzip\v", served gzipped' ],
    [ INVALID, 'ce:gzip\014;do_gzip' => '"Content-Encoding:gzip\f", served gzipped' ],
    [ INVALID, 'ce:gzip\240;do_gzip' => '"Content-Encoding:gzip\240", served gzipped' ],

    [ INVALID, 'ce:def\000late;do_deflate' => '"Content-Encoding:def\000late", served with deflate' ],
    [ INVALID, 'data:Content\000-encoding:deflate\015\012;do_deflate' => '"Content\000-Encoding:deflate", served with deflate' ],
    [ INVALID, 'ce\000:deflate;do_deflate' => '"Content-Encoding\000:deflate", served with deflate' ],
    [ INVALID, 'ce\015\012\040:deflate;do_deflate' => '"Content-Encoding\r\n :deflate", served with deflate' ],
    [ INVALID, 'ce\015\012\040:\015\012\040deflate;do_deflate' => '"Content-Encoding\r\n :\r\n deflate", served with deflate' ],
    [ INVALID, 'ce\013:deflate;do_deflate' => '"Content-Encoding\v:deflate", served with deflate' ],
    [ INVALID, 'ce\014:deflate;do_deflate' => '"Content-Encoding\f:deflate", served with deflate' ],
    [ INVALID, 'ce:,deflate;do_deflate' => '"Content-Encoding:,deflate", served with deflate' ],
    [ INVALID, 'ce:\073deflate;do_deflate' => '"Content-Encoding:;deflate", served with deflate' ],
    [ INVALID, 'ce:\000deflate;do_deflate' => '"Content-Encoding:\000deflate", served with deflate' ],
    [ INVALID, 'ce:\013deflate;do_deflate' => '"Content-Encoding:\vdeflate", served with deflate' ],
    [ INVALID, 'ce:\014deflate;do_deflate' => '"Content-Encoding:\fdeflate", served with deflate' ],
    [ INVALID, 'ce:\240deflate;do_deflate' => '"Content-Encoding:\240deflate", served with deflate' ],
    [ INVALID, 'ce:deflate,;do_deflate' => '"Content-Encoding:deflate,", served with deflate' ],
    [ INVALID, 'ce:\012\000deflate;do_deflate' => '"Content-Encoding:\n\000deflate", served with deflate' ],
    [ INVALID, 'ce:\012\013deflate;do_deflate' => '"Content-Encoding:\n\vdeflate", served with deflate' ],
    [ INVALID, 'ce:\012\014deflate;do_deflate' => '"Content-Encoding:\n\fdeflate", served with deflate' ],
    [ INVALID, 'ce:\012\240deflate;do_deflate' => '"Content-Encoding:\n\240deflate", served with deflate' ],
    [ INVALID, 'ce:deflate\073;do_deflate' => '"Content-Encoding:deflate;", served with deflate' ],
    [ INVALID, 'ce:deflate\000;do_deflate' => '"Content-Encoding:deflate\000", served with deflate' ],
    [ INVALID, 'ce:deflate\013;do_deflate' => '"Content-Encoding:deflate\v", served with deflate' ],
    [ INVALID, 'ce:deflate\014;do_deflate' => '"Content-Encoding:deflate\f", served with deflate' ],
    [ INVALID, 'ce:deflate\240;do_deflate' => '"Content-Encoding:deflate\240", served with deflate' ],

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
    [ INVALID, 'proto:ICY' => 'version ICY instead of HTTP/1.0'],
    [ INVALID, 'proto:ICY;gzip' => 'version ICY instead of HTTP/1.0 compressed with gzip'],
    [ INVALID, 'proto:HTTP\1.1' => 'version HTTP\1.1 instead of HTTP/1.1'],
    [ INVALID, 'proto:HTTP/1.010;chunked' => 'version HTTP/1.010 instead of HTTP/1.1 and chunked'],
    [ INVALID, 'proto:HTTP/1.010;chunked;do_clen' => 'version HTTP/0.010 instead of HTTP/1.1 and TE chunked but not served chunked'],
    [ INVALID, 'proto:HTTP/+1.+1;chunked' => 'version HTTP/+1.+1 instead of HTTP/1.1 and chunked'],
    [ INVALID, 'proto:HTTP/+1.+1;chunked;do_clen' => 'version HTTP/+1.+1 instead of HTTP/1.1 and TE chunked but not served chunked'],
    [ INVALID, 'proto:HTTP/1A.1B;chunked' => 'version HTTP/1A.1B instead of HTTP/1.1 and chunked'],
    [ INVALID, 'proto:HTTP/1A.1B;chunked;do_clen' => 'version HTTP/1A.1B instead of HTTP/1.1 and TE chunked but not served chunked'],
    [ INVALID, 'proto:HTTP/2.B;chunked' => 'version HTTP/2.B instead of HTTP/1.1 and chunked'],
    [ INVALID, 'proto:HTTP/2.B;chunked;do_clen' => 'version HTTP/2.B instead of HTTP/1.1 and TE chunked but not served chunked'],
    [ INVALID, 'proto:HTTP/9.-1;chunked' => 'version HTTP/9.-1 instead of HTTP/1.1 and chunked'],
    [ INVALID, 'proto:HTTP/9.-1;chunked;do_clen' => 'version HTTP/9.-1 instead of HTTP/1.1 and TE chunked but not served chunked'],
    [ INVALID, 'proto:HTTP/1\040.1;chunked' => 'version HTTP/1<space>.1 instead of HTTP/1.1 and chunked'],
    [ INVALID, 'proto:HTTP/1\040.1;chunked;do_clen' => 'version HTTP/1<space>.1 instead of HTTP/1.1 and TE chunked but not served chunked'],
    [ INVALID, 'proto:HTTP/A.B;gzip' => 'version HTTP/A.B instead of HTTP/1.0 and gzipped'],
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
    [ INVALID, 'status:\000HTTP/1.1(space)200(space)ok;chunked' => '\000HTTP/1.1 200 ok\r\n and chunked'],
    [ INVALID, 'status:HTT\000P/1.1(space)200(space)ok;chunked' => 'HTT\000P/1.1 200 ok\r\n and chunked'],
    [ INVALID, 'status:HTTP/1\000.1(space)200(space)ok;chunked' => 'HTTP/1\000.1 200 ok\r\n and chunked'],
    [ INVALID, 'status:HTTP/1.1\000(space)200(space)ok;chunked' => 'HTTP/1.1\000 200 ok\r\n and chunked'],
    [ INVALID, 'status:HTTP/1.1(space)2\00000(space)ok;chunked' => 'HTTP/1.1 2\00000 ok\r\n and chunked'],
    [ INVALID, 'status:HTTP/1.1(space)200\000(space)ok;chunked' => 'HTTP/1.1 200\000 ok\r\n and chunked'],
    [ INVALID, 'status:HTTP/1.1\000200\000ok;chunked' => 'HTTP/1.1\000200\000ok\r\n and chunked'],
    [ INVALID, 'status:HTTP/1.1\013200\013ok;chunked' => 'HTTP/1.1\013200\013ok\r\n and chunked'],
    [ INVALID, 'status:HTTP/1.1(space)-65336(space);chunked' => 'HTTP/1.1 -65336 ok\r\n and chunked'], # uint_16 -> 200
    [ INVALID, 'status:HTTP/1.1foobar;chunked' => 'HTTP/1.1foobar\r\n and chunked'],
    [ INVALID, 'status:HTTP/1.1foobar(cr)Transfer-Encoding:chunked;do_chunked' => 'HTTP/1.1foobar\r and chunked'],
    [ INVALID, 'status:HTTP/1.foobar;chunked' => 'HTTP/1.foobar\r\n and chunked'],
    [ INVALID, 'status:HTTP/1foobar;chunked' => 'HTTP/1foobar\r\n and chunked'],
    [ INVALID, 'status:HTTP/foobar;chunked' => 'HTTP/foobar\r\n and chunked'],
    [ INVALID, 'status:HTTP/;chunked' => 'HTTP/\r\n and chunked'],
    [ INVALID, 'status:HTTP;chunked' => 'HTTP\r\n and chunked'],
    [ INVALID, 'status:HTTP/1.1\011204(space)ok;chunked' => 'HTTP/1.1\t204 ok with chunked content'],
    [ INVALID, 'status:HTTP/1.1\011304(space)ok;chunked' => 'HTTP/1.1\t304 ok with chunked content'],
    [ INVALID, 'status:HTTP/1.1\040\040\040\040204(space)ok;chunked' => 'HTTP/1.1    204 ok with chunked content'],
    [ INVALID, 'status:HTTP/1.1\040\040\040\040304(space)ok;chunked' => 'HTTP/1.1    304 ok with chunked content'],
    [ INVALID, 'status:HTTP\1.1(space)200(space)ok;chunked' => 'HTTP\1.1 instead of HTTP/1.1 with chunked content'],
    [ INVALID, 'status:Transfer-Encoding:chunked;do_clen' => 'no status line but Transfer-Encoding:chunked, not served chunked'],
    [ INVALID, 'status:Transfer-Encoding:chunked;do_chunked' => 'no status line but Transfer-Encoding:chunked, served chunked'],
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
    [ INVALID, 'chunked;lfcrcrlf-no-crlf;end-crlfcrlf' => '\n\r\r\n instead of \r\n as line delimiter, but end \r\n\r\n and chunked' ],
    [ INVALID, 'end-crcr' => 'header end \r\r' ],
    [ INVALID, 'end-crlf\000crlf' => 'header end \r\n\000\r\n' ],
    [ INVALID, 'end-cr\000crlf' => 'header end \r\000\r\n' ],

    [ COMMON_INVALID, 'end-lflf' => 'header end \n\n' ],
    [ UNCOMMON_INVALID, 'end-lflf;chunked' => 'header end \n\n, chunked' ],
    [ UNCOMMON_INVALID, 'end-lflf;gzip' => 'header end \n\n, gzip' ],
    [ UNCOMMON_INVALID, 'end-lfcrlf' => 'header end \n\r\n' ],
    [ UNCOMMON_INVALID, 'end-lfcrlf;chunked' => 'header end \n\r\n, chunked' ],
    [ UNCOMMON_INVALID, 'end-lfcrlf;gzip' => 'header end \n\r\n, gzip' ],
    [ INVALID, 'end-lfcrcrlf' => 'header end \n\r\r\n' ],
    [ INVALID, 'end-lfcrcrlf;chunked' => 'header end \n\r\r\n, chunked' ],
    [ INVALID, 'end-lfcrcrlf;gzip' => 'header end \n\r\r\n, gzip' ],
    [ INVALID, 'end-lfcrcrlfcrlf' => 'header end \n\r\r\n\r\n' ],
    [ INVALID, 'end-lfcrcrlfcrlf;chunked' => 'header end \n\r\r\n\r\n, chunked' ],
    [ INVALID, 'end-lfcrcrlfcrlf;gzip' => 'header end \n\r\r\n\r\n, gzip' ],

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
    [ UNCOMMON_INVALID, '100+' => 'code 100 followed by real response'],
    [ INVALID, '100+b' => 'code 100 with body followed by real response'],
    [ INVALID, '16-100+' => 'code -65436(100) followed by real response'],
    [ INVALID, '16-100+b' => 'code -65436(100) with body followed by real response'],

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

    [ 'INVALID: more variations with status codes' ],
    [ UNCOMMON_VALID, '299' => 'code 299'],
    [ INVALID, '204;chunked' => 'code 204 with chunked body'],
    [ INVALID, '0204' => 'code 0204 with body'],
    [ INVALID, '2040' => 'code 2040 with body'],
    [ INVALID, '304;chunked' => 'code 304 with chunked body'],
    [ INVALID, '0304' => 'code 0304 with body'],
    [ INVALID, '3040' => 'code 3040 with body'],

    [ 'VALID: new lines before HTTP header' ],
    [ UNCOMMON_VALID, 'crlf-header;chunked' => 'single <CR><LF> before header, chunked'],
    [ UNCOMMON_VALID, 'crlf-crlf-header;chunked' => 'double <CR><LF> before header, chunked'],
    [ 'INVALID: other stuff before HTTP header' ],
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
    # chrome accepts up to 4 bytes garbage before HTTP/
    [ INVALID, 'H-header;chunked' => '"H"  before header, chunked'],
    [ INVALID, 'HT-header;chunked' => '"HT"  before header, chunked'],
    [ INVALID, 'HTT-header;chunked' => '"HTT"  before header, chunked'],
    [ INVALID, 'HTTX-header;chunked' => '"HTTX"  before header, chunked'],
    [ INVALID, 'HTTXY-header;chunked' => '"HTTXY"  before header, chunked'],
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
	} elsif ( $_ eq 'conthdr' ) {
	    $hdr .= "FooBar: foobar\r\n     barfoot\r\n"
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
	} elsif ( m{^do_(gzip|deflate)} ) {
	    $data = zlib_compress($data,$1);
	} elsif ( m{^(gzip|deflate)$} ) {
	    $data = zlib_compress($data,$1);
	    $hdr .= "Content-Encoding: $1\r\n";
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
	} elsif ( s{\Aprefix:((?:\w+|\\[0-7]{3})+)\z}{$1} ) {
	    s{\\([0-7]{3})}{ chr(oct($1)) }eg;
	    $prefix = $_;
	} elsif ( m{\A((?:[\w/.]+|\\[0-7]{3})*)http09\z} ) {
	    my $prefix = $1 or return $data;
	    $prefix =~s{\\([0-7]{3})}{ chr(oct($1)) }eg;
	    return $prefix . $data;
	} elsif ( m{^(16-)?(\d+)\+(b?)\z}) { # 100+
	    my $code = $1 ? "-".(65536-$2):$2;
	    $prefix = "HTTP/1.1 $code whatever\r\n";
	    if ($3) {
		my $body = "fooo";
		$prefix .= "Content-length: ".length($body)."\r\n";
		$prefix .= "\r\n";
		$prefix .= $body;
	    } else {
		$prefix .= "\r\n";
	    }
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
	    push @transform, sub { $_[0] =~ s{[\r\n]+\z}{$w} or die }
	} elsif ( m{^proto:(.*)} ) {
	    my $proto = $1;
	    $proto =~s{cr|\\r}{\r}g;
	    $proto =~s{tab|\\t}{\t}g;
	    $proto =~s{lf|\\n}{\n}g;
	    $proto =~s{space}{ }g;
	    $proto =~s{\\([0-7]{3})}{ chr(oct($1)) }esg;
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
	} elsif (m{^ce(.*:.*)}) {
	    (my $d = $1) =~s{\\([0-7]{3})}{ chr(oct($1)) }esg;
	    $hdr .= "Content-Encoding$d\r\n";
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
