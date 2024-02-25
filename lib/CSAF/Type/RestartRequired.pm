package CSAF::Type::RestartRequired;

use 5.010001;
use strict;
use warnings;

use Moo;
extends 'CSAF::Type::Base';


has category => (is => 'rw', required => 1);
has details  => (is => 'rw');

sub TO_BUILD {

    my $self = shift;

    my $output = {category => $self->category};

    $output->{details} = $self->details if ($self->details);

    return $output;

}

1;
