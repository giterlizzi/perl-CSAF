package CSAF::Type::ProductTree;

use 5.010001;
use strict;
use warnings;

use Moo;
extends 'CSAF::Type::Base';

use CSAF::Type::Branches;
use CSAF::Type::FullProductNames;
use CSAF::Type::ProductGroups;
use CSAF::Type::Relationships;


sub branches {
    my ($self, %params) = @_;
    $self->{branches} ||= CSAF::Type::Branches->new(%params);
}

sub full_product_names {
    my ($self, %params) = @_;
    $self->{full_product_names} ||= CSAF::Type::FullProductNames->new(%params);
}

sub product_groups {
    my ($self, %params) = @_;
    $self->{product_groups} ||= CSAF::Type::ProductGroups->new(%params);
}

sub relationships {
    my ($self, %params) = @_;
    $self->{relationships} ||= CSAF::Type::Relationships->new(%params);
}

sub TO_BUILD {

    my $self = shift;

    my $output = {};

    if (@{$self->branches->items}) {
        $output->{branches} = $self->branches->TO_BUILD;
    }

    if (@{$self->relationships->items}) {
        $output->{relationships} = $self->relationships->TO_BUILD;
    }

    if (@{$self->full_product_names->items}) {
        $output->{full_product_names} = $self->full_product_names->TO_BUILD;
    }

    return if not keys %{$output};

    return $output;

}

1;
