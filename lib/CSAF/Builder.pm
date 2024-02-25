package CSAF::Builder;

use 5.010001;
use strict;
use warnings;

use Carp;

use CSAF::Validator;

use Moo;
extends 'CSAF::Base';

sub build {

    my ($self, $skip_validation) = @_;

    my $document        = $self->csaf->document->TO_BUILD;
    my $vulnerabilities = $self->csaf->vulnerabilities->TO_BUILD;
    my $product_tree    = $self->csaf->product_tree->TO_BUILD;

    my $csaf = {document => $document};

    if (@{$vulnerabilities}) {
        $csaf->{vulnerabilities} = $vulnerabilities;
    }

    if ($product_tree) {
        $csaf->{product_tree} = $product_tree;
    }

    my @errors = ();

    unless ($skip_validation) {

        my $v        = $self->csaf->validator;
        my @messages = $v->validate;

        if (@messages && $v->has_error) {
            Carp::croak 'CSAF Document validation error(s)';
        }

        if (@messages && $v->has_warning) {
            Carp::carp 'CSAF Document validation warning(s)';
        }

    }

    return $csaf;

}

sub TO_JSON { shift->build }

1;
