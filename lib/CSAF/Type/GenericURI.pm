package CSAF::Type::GenericURI;

use 5.010001;
use strict;
use warnings;

use Moo;
extends 'CSAF::Type::Base';

has uri       => (is => 'rw', required => 1);
has namespace => (is => 'rw', required => 1);


sub TO_BUILD {
    my $self = shift;
    return {uri => $self->uri, namespace => $self->namespace};
}

1;
