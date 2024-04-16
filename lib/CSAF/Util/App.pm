package CSAF::Util::App;

use 5.010001;
use strict;
use warnings;
use utf8;

use Exporter 'import';
our @EXPORT_OK = (qw[cli_error cli_version]);

sub cli_error {
    my ($error) = @_;
    $error =~ s/ at .* line \d+.*//;
    print STDERR "ERROR: $error\n";
}

sub cli_version {

    (my $progname = $0) =~ s/.*\///;

    require CSAF;

    say <<"VERSION";
$progname version $CSAF::VERSION

Copyright 2023-2024, Giuseppe Di Terlizzi <gdt\@cpan.org>

This program is part of the CSAF distribution and is free software;
you can redistribute it and/or modify it under the same terms as Perl itself.

Complete documentation for $progname can be found using 'man $progname'
or on the internet at <https://metacpan.org/dist/CSAF>.
VERSION

    return 0;

}

1;
