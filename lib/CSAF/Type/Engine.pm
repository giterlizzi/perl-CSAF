package CSAF::Type::Engine;

use 5.010001;
use strict;
use warnings;

use Moo;

extends 'CSAF::Type::Base';

has name    => (is => 'rw', default => 'CSAF Perl Toolkit');
has version => (is => 'rw', default => sub {$CSAF::VERSION});

sub TO_BUILD {

    my $self = shift;

    my $output = {name => $self->name, version => $self->version};

    return $output;

}

1;
