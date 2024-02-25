package CSAF::Type::ID;

use 5.010001;
use strict;
use warnings;

use Moo;
extends 'CSAF::Type::Base';

has system_name => (is => 'rw', required => 1);
has text        => (is => 'rw', required => 1);

sub TO_BUILD {

    my $self = shift;

    my $output = {system_name => $self->system_name, text => $self->text};

    return $output;

}

1;
