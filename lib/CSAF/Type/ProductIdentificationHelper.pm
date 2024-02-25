package CSAF::Type::ProductIdentificationHelper;

use 5.010001;
use strict;
use warnings;

use CSAF::Type::Hashes;
use CSAF::Type::GenericURIs;

use URI::PackageURL;

use Moo;
extends 'CSAF::Type::Base';

my $PURL_REGEX = qr{^pkg:[A-Za-z\\.\\-\\+][A-Za-z0-9\\.\\-\\+]*/.+};
my $CPE_REGEX
    = qr{^(cpe:2\.3:[aho\*\-](:(((\?*|\*?)([a-zA-Z0-9\-\._]|(\\[\\\*\?!"#\$%&'\(\)\+,/:;<=>@\[\]\^`\{\|\}~]))+(\?*|\*?))|[\*\-])){5}(:(([a-zA-Z]{2,3}(-([a-zA-Z]{2}|[0-9]{3}))?)|[\*\-]))(:(((\?*|\*?)([a-zA-Z0-9\-\._]|(\\[\\\*\?!"#\$%&'\(\)\+,/:;<=>@\[\]\^`\{\|\}~]))+(\?*|\*?))|[\*\-])){4})|([c][pP][eE]:/[AHOaho]?(:[A-Za-z0-9\._\-~%]*){0,6})$};

has cpe => (is => 'rw', predicate => 1, isa => sub { Carp::croak 'Invalid CPE' if $_[0] !~ /$CPE_REGEX/ },);

has purl => (
    is        => 'rw',
    predicate => 1,
    coerce    => sub { ref($_[0]) eq 'URI::PackageURL' ? $_[0]->to_string : $_[0] },
    isa       => sub { Carp::croak 'Invalid purl' if $_[0] !~ /$PURL_REGEX/ }
);

has [qw(sbom_urls serial_numbers skus model_numbers)] => (is => 'rw', predicate => 1, default => sub { [] });

sub hashes {
    my $self = shift;
    $self->{hashes} ||= CSAF::Type::Hashes->new(@_);
}

sub x_generic_uris {
    my $self = shift;
    $self->{x_generic_uris} ||= CSAF::Type::GenericURIs->new(@_);
}

sub TO_BUILD {

    my $self = shift;

    my $output = {};

    $output->{cpe}  = $self->cpe  if $self->has_cpe;
    $output->{purl} = $self->purl if $self->has_purl;

    $output->{skus}           = $self->skus           if @{$self->skus};
    $output->{sbom_urls}      = $self->sbom_urls      if @{$self->sbom_urls};
    $output->{serial_numbers} = $self->serial_numbers if @{$self->serial_numbers};
    $output->{model_numbers}  = $self->model_numbers  if @{$self->model_numbers};

    if (@{$self->x_generic_uris->items}) {
        $output->{x_generic_uris} = $self->x_generic_uris;
    }

    if (@{$self->hashes->items}) {
        $output->{hashes} = $self->hashes->TO_BUILD;
    }

    return $output;

}

1;
