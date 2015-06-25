use strict;
use ExtUtils::MakeMaker 6.46;
require 5.8.9;
WriteMakefile(
    NAME => 'App::DubiousHTTP',
    ABSTRACT => 'use ambiguous HTTP to circumvent security systems',
    AUTHOR => 'Steffen Ullrich <sullr@cpan.org>',
    LICENSE => 'perl',
    META_MERGE => {
        resources => {
            license     => 'http://dev.perl.org/licenses/',
            repository  => 'https://github.com/noxxi/p5-app-dubioushttp',
            homepage  => 'https://github.com/noxxi/p5-app-dubioushttp',
            bugtracker  => 'https://rt.cpan.org/Dist/Display.html?Queue=App-DubiousHTTP',
        },
    },
    PREREQ_PM => {
	'Compress::Raw::Zlib' => 2.012,
    }
    VERSION_FROM => 'lib/App/DubiousHTTP.pm',
    EXE_FILES => [ 'bin/dubious_http.pl' ],
);
