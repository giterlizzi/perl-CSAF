package CSAF::Builder;

use 5.010001;
use strict;
use warnings;
use utf8;

use Carp;
use CSAF::Validator;

use Moo;
extends 'CSAF::Base';

sub build {

    my ($self, $skip_validation) = @_;

    my $document        = $self->csaf->document->TO_CSAF;
    my $vulnerabilities = $self->csaf->vulnerabilities->TO_CSAF;
    my $product_tree    = $self->csaf->product_tree->TO_CSAF;

    my $csaf = {document => $document};

    if (@{$vulnerabilities}) {
        $csaf->{vulnerabilities} = $vulnerabilities;
    }

    if ($product_tree) {
        $csaf->{product_tree} = $product_tree;
    }

    unless ($skip_validation) {
        $self->csaf->validator->validate;
    }

    return $csaf;

}

sub TO_JSON { shift->build }

1;
