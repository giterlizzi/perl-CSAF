package CSAF::Renderer::Base;

use 5.010001;
use strict;
use warnings;
use utf8;

use Carp;

use Moo;
extends 'CSAF::Base';

use overload '""' => \&render, fallback => 1;

sub render { Carp::croak 'Method "render" not implemented by subclass' }

1;
