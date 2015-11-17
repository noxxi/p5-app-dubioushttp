use strict;
use warnings;
use Data::Dumper;
use App::DubiousHTTP::Tests::Common 'ungarble_url';
use Time::Local;
use Getopt::Long qw(:config posix_default bundling);

my $include_all = 1;
my ($input,$output,$update);
GetOptions(
    'a|include-all!' => \$include_all,
    'I|input=s' => \$input,
    'O|output=s' => \$output,
    'u|update' => \$update,
    'h|help' => sub { usage() },
);


sub usage {
    print STDERR <<USAGE;

Normalize log files so it does not matter if the submissions were done with
multiple POST (--fast-feedback) or with GET (if POST failed): it will always
look like a single large POST after this normalization.
Also submission for product details will only include the manually entered
details and not again all the automatic details.

Usage $0 [options]
Options:
    -h|--help       usage
    -I|--input F    input from file F (default stdin)
    -O|--output F   input to file F (default stdout)
    -u|--update     only handle input file if newer than output file
    -a|include-all  include all lines, with --no-include-all only submissions
                    but not other logged lines
Exit codes:
 0: all well and data were written
 1: all well and no data were written (--update)
 2: usage
 anything else: error (die)

USAGE
    exit(2);
}

$|=1 if ! $output;
my %mon2i = qw( jan 0 feb 1 mar 2 apr 3 may 4 jun 5 jul 6 aug 7 sep 8 oct 9 nov 10 dec 11 );

my $outfh = \*STDOUT;
my @input_stat;
my $nextline = do {
    if ($input && $output && $update) {
	my @ist = stat($input);
	my @ost = stat($output);
	exit(1) if @ost && @ist && $ist[9]<=$ost[9];
    }
    my $fh = \*STDIN;
    die "open $input: $!" if $input && ! open($fh,'<',$input);
    die "open $output: $!" if $output && ! open($outfh,'>',$output);
    @input_stat = stat($fh) if $input && $output;
    sub { scalar(<$fh>) }
};

my ($inside,%open_inside,%open_parts,%recent);
while (defined( $_ = $nextline->())) {
    my $orig_line = my $prefix_line = $_;
    my ($time,$id,$rqline,%rqargs);
    
    # Delivery in several parts via GET because POST is blocked or unreliable
    # S|10.1.2.3|1dab793d56338c01|00000|512|/submit_results/....
    if (s{^(S\|([\d.:a-f]+)\|([a-f0-9]+)\|)(\d{5})\|(\d+)\|}{}) {
	($rqline, my $ip,$id, my $index, my $size) = ($1,$2,$3,$4,$5);
	s{[\r\n]+}{}g;
	s{\\(.)}{ $1 eq 'r' ? "\r" : $1 eq 'n' ? "\n" : $1 eq 't' ? "\t" : $1 }esg;
	if ($index == 0) {
	    s{^(/submit_(results|part|details)(?:/\S+)).*\n}{};
	    $prefix_line = $1;
	    $rqargs{part} = $1 if $2 eq 'part' && ($prefix_line||'') =~m{/(\d{1,5})(/|$)};
	    $time = $id =~m{(.{8})$} && hex($1);
	    $prefix_line = localtime($time)." |00000000| $ip | POST $prefix_line HTTP/1.1\n";
	} elsif (my $d = $open_inside{$rqline}) {
	    $d->{all} .= $_;
	    if ($size<512) {
		# last part of submission
		delete $open_inside{$rqline};
		$d->{lines} = [ grep { m{^NO EVASION|[A-Z] \|}} split(m{\r?\n},$d->{all}) ];
		$d->{header} ||= $d->{prefix_line} =~m{ (POST /.*)} && "$1\nUser-Agent: unknown:get\n";
		output($d);
	    }
	    next;
	} else {
	    next;
	}

    # Delivery via POST, either complete or in parts (--fast-feedback)
    # Sat Sep  5 00:48:59 2015 |t2oqpgxK| 10.1.2.3 | POST /submit_results/...
    # Sat Sep  5 00:48:59 2015 |t2oqpgxK| 10.1.2.3 | POST /submit_details/...
    # Sat Sep  5 00:48:59 2015 |t2oqpgxK| 10.1.2.3 | POST /submit_part/...
    } elsif ( (my $date,$rqline,my $what,my $rqargs) 
	= m{^\w+ (.*)\| [a-f0-9:\.]+ \| (POST /submit_(results|details|part)(/\S+)? HTTP/1\.[01])}) {
	$rqargs{part} = $1 if $what eq 'part' && ($rqargs||'') =~m{/(\d{1,5})(/|$)};
	next if ($rqargs||'') =~ m{^/undefined};
	$id = $1 if ($rqargs||'') =~m{^/([a-f0-9]{8,})};
	my ($mon,$day,$h,$m,$s,$y) = split(m{[\s:]+},$date);
	$mon = $mon2i{lc($mon)} // die $mon;
	$time = timelocal($s,$m,$h,$day,$mon,$y);
	if (!$id) {
	    $id = sprintf("%08x",$time);
	    $prefix_line =~s{(/submit_(?:details|results))}{$1/$id} or die $prefix_line;
	    $rqargs{_first_header} = $prefix_line =~m{\| (POST \S+ HTTP/1\.[01])} && $1;
	}
    }

    if ($rqline) {

	# weed out duplicate submissions
	for (keys %recent) {
	    delete $recent{$_} if $recent{$_} +120 < $time;
	}
	if ($recent{$rqline}) {
	    warn "DUP $id $rqline\n";
	    $recent{$rqline} = $time;
	    next;
	}
	$recent{$rqline} = $time;

	if (%open_inside) {
	    # expire unfinished stuff
	    for(keys %open_inside) {
		$open_inside{$_}{time} < $time - 7200 or next;
		my $r = delete $open_inside{$_};
		warn "EXPIRE unfinished submission $r->{id} from ".localtime($r->{time})."\n";
	    }
	}
	my $h = $open_inside{$rqline} = {
	    rqline => $rqline,
	    prefix_line => $prefix_line,
	    time => $time,
	    id => $id,
	    %rqargs,
	    _header => '',

	    # header: header from POST request (from _header when done)
	    # part: part number if used with /submit_part/...
	    # lines: all payload lines when done
	    # _lines: while reading lines in payload, when done -> "lines"
	    # boundary: boundary in multi-part messages (for details)
	    # _partname: name of current part in multi-part messages
	    # _partname: header of current part in multi-part messages
	    # product_parthdr: header when product details are sent
	    # product: contents of product details part
	};
	_expire_unfinished($time) if %open_parts;
	next;
    }


    # intermediate lines
    goto check_openinside if !$inside;

    have_inside:
    # all inside is prefixed with ' '
    goto done if !s{^ }{};

    # all lines look like "I | ... " or "NO EVASIONS" 
    # - only relevant if we have no multi-part request POST
    goto done if !$inside->{boundary} && $inside->{_lines} && $_ && !m{^NO EVASION|[A-Z] \|};

    s{\r?\n\z}{};
    if (defined $inside->{_header}) {
	if ($_ ne '') {
	    $inside->{_header} .= (delete $inside->{_first_header} || $_)."\n";
	} else {
	    $inside->{header} = delete $inside->{_header};
	    if ( $inside->{header} 
		=~m{^Content-Type:\s*multipart/form-data;\s*boundary=(?:\"([^\"]+)\"|\'([^\']+)\'|([^\s\"\';]+))}mi) {
		$inside->{boundary} = $1 || $2 || $3;
	    } else {
		$inside->{_lines} = [];
	    }
	}

    } elsif ($inside->{boundary}
	&& m{^--\Q$inside->{boundary}\E(--)?}) {
	if ($1) { # end
	    $orig_line = $_ = ''; # eat
	    goto done;
	}
	$inside->{_parthdr} = '';
	$inside->{lines} = delete $inside->{_lines} if $inside->{_lines};

    } elsif (defined $inside->{_parthdr}) {
	if ($_) {
	    $inside->{_parthdr} .= $_."\n";
	} elsif ($inside->{_parthdr} =~m{\bname=(?:\"([^\"]+)\"|\'([^\']+)\'|([^\s\"\';]+))}) {
	    $inside->{_partname} = $1 || $2 || $3;
	    if ($inside->{_partname} eq 'results') {
		$inside->{_lines} = [] 
	    } elsif ($inside->{_partname} eq 'product') {
		$inside->{product_parthdr} = $inside->{_parthdr};
	    }
	    delete $inside->{_parthdr};
	} else {
	    die $inside->{_parthdr};
	}

    } elsif ( $inside->{_lines} ) {
	if ($inside->{boundary} || m{^NO EVASION|^[A-Z] \|.*}) {
	    push @{$inside->{_lines}}, $_
	} else {
	    $inside->{lines} = $inside->{_lines};
	    goto done if ! $inside->{boundary};
	}

    } elsif ($inside->{_partname}) {
	$inside->{product} .= $_ if $inside->{_partname} eq 'product';

    } else {
	die "invalid line: ".Dumper([$.,$_,$orig_line,$inside]);
    }

    next;

    done:
    if ($inside->{header}) {
	output($inside);
	$inside = undef;
	# This line does not belong to inside but might belong to
	# the next request already
	$_ = $orig_line;  
    }

    check_openinside:
    if (%open_inside) {
	my $rx = join('|',map { "\Q$_" } keys %open_inside);
	if (m{^ ($rx)}) {
	    $inside = delete $open_inside{$1} or die;
	    goto have_inside;
	}
    }

    print $outfh $orig_line if $include_all;
}

output($inside) if $inside;
_expire_unfinished();

if (@input_stat) {
    close($outfh);
    # update modification time of file to reflect input
    utime($input_stat[9],$input_stat[9],$output);
}

sub _expire_unfinished {
    my $time = shift || time();
    if (%open_parts) {
	# expire submission in parts which was never finished
	for(keys %open_parts) {
	    my $d = $open_parts{$_}[-1];
	    $d->{time} < $time - 7200 or next;
	    warn "EXPIRE unfinished multi-part submission $d->{id}/$d->{part} from ".localtime($d->{time})."\n";
	    delete $open_parts{$_}[-1];
	    output($d,'E');
	}
    }
}

my %done;
sub output {
    my ($data,@missing) = @_;
    if (0 && $done{$data->{id}} && ! $data->{product}) {
	# we have this already - skip
	# warn "XXXX skip duplicate $data->{id}\n";
	warn Dumper($data);
	return;
    }

    # add new part
    if (!@missing && exists $data->{part}) {
	# warn "XXXX new part $data->{id}/$data->{part}\n";
	$open_parts{$data->{id}}[$data->{part}] = $data;
	return;
    }

    # final or only part
    my $parts = delete $open_parts{$data->{id}};
    if ($parts) {
	# warn "XXXX final part $data->{id}\n";
	my @lines;
	my $lp = 0;
	for(@$parts,$data) {
	    my $l = $_ && (delete($_->{lines}) || delete($_->{_lines}));
	    if (!$l) {
		warn "MISSING PART $data->{id}/$lp\n";
		push @missing,$lp;
		$lp++;
		next;
	    }
	    $lp++;
	    push @lines,@$l;
	}
	$data->{lines} = \@lines;
    } else {
	$data->{lines} ||= delete $data->{_lines};
	# warn "XXXX final and only part $data->{id}\n";
    }

    for (keys %done) {
	delete $done{$_} if $done{$_}<$data->{time}+7200;
    }
    $done{$data->{id}} = $data->{time};

    if (@missing) {
	# if we had evasions forward it as incomplete, because it might
	# still be an interesting report
	my $e = my $z = 0;
	return if ! $data->{lines} || ! @{$data->{lines}};
	for(@{$data->{lines}}) {
	    m{^(?:(E)|Z) } or next;
	    if ($1) {
		$e++
	    } else {
		$z++
	    }
	}
	return if !$e && !$z 
	    && $data->{prefix_line} !~ m{/evasions=}
	    && $data->{lines}[-1] !~ m{/range,incomplete \|};
	$data->{incomplete} = join(",",@missing);
	if ($missing[0] eq 'E') {
	    my $ev = ($e||$z) ? "/evasions=$e/evasions_blocked=$z" : "";
	    my $url = "/submit_results/$data->{id}$ev/incomplete=$data->{incomplete}";
	    s{ /submit_part/\S+}{ $url}
		for ($data->{header},$data->{prefix_line});
	} else {
	    s{( /submit_results/\S+)}{$1/incomplete=$data->{incomplete}}
		for ($data->{header},$data->{prefix_line});
	}
    }

    if (defined $data->{boundary}) {
	# show only product details and omit lines since these were already sent
	if (($data->{product}||'') !~m{\S}) {
	    warn "NO DETAILS $data->{id} ".localtime($data->{time})."\n";
	    return;
	}
	print $outfh "---\n".$data->{prefix_line};
	print $outfh " $_\n" for (split(m{\r?\n},$data->{header}));
	print $outfh " \n";
	print $outfh " --$data->{boundary}\n";
	print $outfh " $_\n" for (split(m{\r?\n},$data->{product_parthdr}));
	print $outfh " \n";
	print $outfh " $_\n" for (split(m{\r?\n},$data->{product}));
	print $outfh " --$data->{boundary}--\n";
	print $outfh "\n";

    } else {
	print $outfh "---\n".$data->{prefix_line};
	print $outfh " $_\n" for (split(m{\r?\n},$data->{header}));
	print $outfh " \n";
	print $outfh " ".ungarble_url($_)."\n" for (@{$data->{lines}});
	print $outfh "\n";
    }
}

