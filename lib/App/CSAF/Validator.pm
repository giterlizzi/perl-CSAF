package App::CSAF::Validator;

use 5.010001;
use strict;
use warnings;
use utf8;

use Getopt::Long qw( GetOptionsFromArray :config gnu_compat );
use Pod::Usage;
use Carp;

use CSAF;
use CSAF::Parser;

our $VERSION = $CSAF::VERSION;

sub cli_error {
    my ($error) = @_;
    $error =~ s/ at .* line \d+.*//;
    print STDERR "ERROR: $error\n";
}

sub run {

    my ($class, @args) = @_;

    my %options = ();

    delete $ENV{CSAF_DEBUG};

    GetOptionsFromArray(
        \@args, \%options, qw(
            file|f=s

            help|h
            man
            v
        )
    ) or pod2usage(-verbose => 0);

    pod2usage(-exitstatus => 0, -verbose => 2) if defined $options{man};
    pod2usage(-exitstatus => 0, -verbose => 0) if defined $options{help};

    if (defined $options{v}) {

        (my $progname = $0) =~ s/.*\///;

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

    my $csaf_parser_options = {};

    # Detect input from STDIN
    if (-p STDIN || -f STDIN) {
        $csaf_parser_options->{content} = do { local $/; <STDIN> };
    }

    if (defined $options{file}) {
        $csaf_parser_options->{file} = $options{file};
    }

    if (%{$csaf_parser_options}) {

        my $csaf = eval { CSAF::Parser->new(%{$csaf_parser_options})->parse };

        if ($@) {
            cli_error($@);
            return 255;
        }

        if (my @errors = $csaf->validate) {
            say STDERR $_ for (@errors);
            return 1;
        }

        say STDERR "CSAF Document valid";
        return 0;

    }

    pod2usage(-verbose => 0);
    return 0;

}

1;
