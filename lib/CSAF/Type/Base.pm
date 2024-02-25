package CSAF::Type::Base;

use 5.010001;
use strict;
use warnings;

use Moo;
use Carp;

sub TO_BUILD { Carp::croak 'Method "TO_BUILD" not implemented by subclass' }
sub TO_JSON  { shift->TO_BUILD }

1;
