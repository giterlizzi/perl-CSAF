package CSAF::Type::Acknowledgment;

use 5.010001;
use strict;
use warnings;

use Moo;
extends 'CSAF::Type::Base';

has names        => (is => 'rw', isa => \&_check_isa_array, default => sub { [] });
has urls         => (is => 'rw', isa => \&_check_isa_array, default => sub { [] });
has summary      => (is => 'rw');
has organization => (is => 'rw');

sub _check_isa_array {
    Carp::croak 'must be an array' if (ref $_[0] ne 'ARRAY');
}

sub TO_BUILD {

    my $self = shift;

    my $output = {};

    $output->{summary}      = $self->summary      if ($self->summary);
    $output->{organization} = $self->organization if ($self->organization);

    $output->{names} = $self->names if (@{$self->names});
    $output->{urls}  = $self->urls  if (@{$self->urls});

    return $output;

}

1;
