package CSAF::Type::FileHash;

use 5.010001;
use strict;
use warnings;

use Moo;
extends 'CSAF::Type::Base';

has algorithm => (is => 'rw', required => 1);
has value     => (is => 'rw', required => 1);

sub TO_BUILD {

    my $self = shift;

    my $output = {algorithm => $self->algorithm, value => $self->value};

    return $output;

}

1;
