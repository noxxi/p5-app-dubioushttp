use strict;
use ExtUtils::MakeMaker 6.46;
require 5.12.4;
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
    VERSION_FROM => 'lib/App/DubiousHTTP.pm',
    PREREQ_PM => {
        'Net::PcapWriter' => 0,
        'AnyEvent' => 6.12,
    },
    EXE_FILES => [ 'bin/dubious_http.pl' ],
);
