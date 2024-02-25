package CSAF::Type::Relationship;

use 5.010001;
use strict;
use warnings;

use CSAF::Type::FullProductName;

use Moo;
extends 'CSAF::Type::Base';

has category                     => (is => 'rw', required => 1);
has product_reference            => (is => 'rw', required => 1);
has relates_to_product_reference => (is => 'rw', required => 1);

has full_product_name => (
    is        => 'rw',
    predicate => 1,
    coerce    => sub {
        (ref($_[0]) !~ /FullProductName/) ? CSAF::Type::FullProductName->new(shift) : $_[0];
    }
);

sub TO_BUILD {

    my $self = shift;

    my $output = {
        category                     => $self->category,
        full_product_name            => $self->full_product_name,
        product_reference            => $self->product_reference,
        relates_to_product_reference => $self->relates_to_product_reference,
    };

    return $output;

}


1;
