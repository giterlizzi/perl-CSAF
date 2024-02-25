package CSAF::Type::Publisher;

use 5.010001;
use strict;
use warnings;

use Moo;
extends 'CSAF::Type::Base';

my @CATEGORIES = ('coordinator', 'discoverer', 'other', 'translator', 'user', 'vendor');

has ['name', 'namespace'] => (is => 'rw', required => 1);

has category => (
    is       => 'rw',
    required => 1,
    isa      => sub { Carp::croak 'Unknown document "category"' unless grep(/$_[0]/, @CATEGORIES) }
);

has ['contact_details', 'issuing_authority'] => (is => 'rw');

sub TO_BUILD {

    my $self = shift;

    my $output = {category => $self->category, name => $self->name, namespace => $self->namespace};

    $output->{contact_details}   = $self->contact_details   if ($self->contact_details);
    $output->{issuing_authority} = $self->issuing_authority if ($self->issuing_authority);

    return $output;

}

1;
