package CSAF::Type::Branch;

use 5.010001;
use strict;
use warnings;

use Moo;
use CSAF::Type::Branches;
use CSAF::Type::Product;

extends 'CSAF::Type::Base';

has [qw(category name)] => (is => 'rw', required => 1);
has product => (is => 'rw', predicate => 1, coerce => sub { CSAF::Type::Product->new(shift) });

sub branches {
    my $self = shift;
    $self->{branches} ||= CSAF::Type::Branches->new(@_);
}

sub TO_BUILD {

    my $self = shift;

    my $output = {category => $self->category, name => $self->name};

    if (@{$self->branches->items}) {
        $output->{branches} = $self->branches;
    }

    $output->{product} = $self->product if ($self->product);

    return $output;

}

1;
