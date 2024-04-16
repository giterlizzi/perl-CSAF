package App::CSAF::Validator;

use 5.010001;
use strict;
use warnings;
use utf8;

use Getopt::Long qw( GetOptionsFromArray :config gnu_compat );
use Pod::Usage;
use Carp;

use CSAF;
use CSAF::Util::App qw(cli_error cli_version);
use CSAF::Parser;

sub run {

    my ($class, @args) = @_;

    my %options = ();

    delete $ENV{CSAF_DEBUG};

    GetOptionsFromArray(
        \@args, \%options, qw(
            file|f=s

            help|h
            man
            version|v
        )
    ) or pod2usage(-verbose => 0);

    pod2usage(-exitstatus => 0, -verbose => 2) if defined $options{man};
    pod2usage(-exitstatus => 0, -verbose => 0) if defined $options{help};

    return cli_version if defined $options{version};

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
