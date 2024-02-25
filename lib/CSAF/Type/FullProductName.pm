package CSAF::Type::FullProductName;

use 5.010001;
use strict;
use warnings;

use CSAF::Type::ProductIdentificationHelper;

use Moo;
extends 'CSAF::Type::Base';

has name => (is => 'rw', required => 1);
has product_id => (is => 'rw', required => 1, trigger => 1);

sub _trigger_product_id {
    my ($self) = @_;
    $CSAF::CACHE->{products}->{$self->product_id} = $self->name;
}

has product_identification_helper => (
    is        => 'rw',
    predicate => 1,
    coerce    => sub {
        (ref($_[0]) !~ /ProductIdentificationHelper/) ? CSAF::Type::ProductIdentificationHelper->new(shift) : $_[0];
    }
);

sub TO_BUILD {

    my $self = shift;

    my $output = {name => $self->name, product_id => $self->product_id};

    $output->{product_identification_helper} = $self->product_identification_helper->TO_BUILD
        if ($self->has_product_identification_helper);

    return $output;

}

1;
