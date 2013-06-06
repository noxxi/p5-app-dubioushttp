use strict;
use warnings;
package App::DubiousHTTP::Tests::Common;
use MIME::Base64 'decode_base64';
use Exporter 'import';
our @EXPORT = 'content';

my $basedir = 'static/';
sub basedir { $basedir = pop }

my %builtin = (
    'eicar.txt' => [ 
	"Content-type: application/octet-stream\r\n".
	"Content-disposition: attachment; filename=\"eicar.txt\"\r\n",
	'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*',
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
    'ok.html' =>  [ "Content-type: text/html\r\n", "<body>ok</body>" ],
    'bad.html' => [ "Content-type: text/html\r\n", "<body><strong>BAD!</strong></body>" ],
    'ok.js' =>  [ "Content-type: application/javascript\r\n", "alert('ok')" ],
    'bad.js' => [ "Content-type: application/javascript\r\n", "alert('bad')" ],
);


sub content {
    my $page = shift;
    my ($hdr,$data);
    if ( my $builtin = $builtin{$page} ) {
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

1;
