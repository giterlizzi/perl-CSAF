package CSAF::Type::ProductStatus;

use 5.010001;
use strict;
use warnings;

use Moo;
use Carp;

extends 'CSAF::Type::Base';

my @ATTRIBUTES = qw(
    first_affected first_fixed fixed known_affected known_not_affected
    last_affected recommended under_investigation
);

has [@ATTRIBUTES] => (
    is  => 'rw',
    isa => sub {
        Carp::croak 'must be an array of products' if (ref $_[0] ne 'ARRAY');
    },
    default => sub { [] }
);

sub TO_BUILD {

    my $self = shift;

    my $output = {};

    for my $attribute (@ATTRIBUTES) {
        $output->{$attribute} = $self->$attribute if (@{$self->$attribute});
    }

    return if (!keys %{$output});

    return $output;

}

1;
