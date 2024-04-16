package App::CSAF::Downloader;

use 5.010001;
use strict;
use warnings;
use utf8;

use Getopt::Long qw( GetOptionsFromArray :config gnu_compat );
use Pod::Usage;
use Carp;
use Log::Any::Adapter;

use CSAF::Util::App qw(cli_error cli_version);
use CSAF::Downloader;

sub run {

    my ($class, @args) = @_;

    my %options = ();

    delete $ENV{CSAF_DEBUG};

    GetOptionsFromArray(
        \@args, \%options, qw(
            url|u=s
            directory|d=s
            insecure|k
            verbose!
            validate:s
            integrity-check
            signature-check

            include=s
            exclude=s

            config|c=s
            parallel-downloads=i

            help|h
            man
            version|v
        )
    ) or pod2usage(-verbose => 0);

    pod2usage(-exitstatus => 0, -verbose => 2) if defined $options{man};
    pod2usage(-exitstatus => 0, -verbose => 0) if defined $options{help};

    return cli_version if defined $options{version};

    if (defined $options{verbose}) {
        Log::Any::Adapter->set('Stderr');
    }

    my $downloader = CSAF::Downloader->new;

    $downloader->options->config_file($options{'config'}) if defined $options{'config'};

    $options{validate} = !!1 if (defined $options{validate} && $options{validate} eq '');

    $downloader->options->url($options{url})                                 if defined $options{url};
    $downloader->options->insecure($options{insecure})                       if defined $options{insecure};
    $downloader->options->directory($options{directory})                     if defined $options{directory};
    $downloader->options->validate($options{validate})                       if defined $options{validate};
    $downloader->options->integrity_check($options{'integrity-check'})       if defined $options{'integrity-check'};
    $downloader->options->signature_check($options{'signature-check'})       if defined $options{'signature-check'};
    $downloader->options->include_pattern($options{include})                 if defined $options{include};
    $downloader->options->exclude_pattern($options{exclude})                 if defined $options{exclude};
    $downloader->options->parallel_downloads($options{'parallel-downloads'}) if defined $options{'parallel-downloads'};

    unless ($downloader->options->url) {
        cli_error("Specify URL");
        return 1;
    }

    unless (-e -d $downloader->options->directory) {
        cli_error "Unknown directory";
        return 1;
    }

    eval { $downloader->mirror($downloader->options->url) };

    if ($@) {
        cli_error($@);
        return 1;
    }

    return 0;

}

1;
