package CSAF::Type::AggregateSeverity;

use 5.010001;
use strict;
use warnings;

use Moo;
extends 'CSAF::Type::Base';

has text      => (is => 'rw');
has namespace => (is => 'rw');

sub TO_BUILD {

    my $self = shift;

    my $output = {};

    $output->{text}      = $self->text      if ($self->text);
    $output->{namespace} = $self->namespace if ($self->namespace);

    return if (!keys %{$output});

    return $output;

}

1;
