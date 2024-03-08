package CSAF::Renderer::JSON;

use 5.010001;
use strict;
use warnings;
use utf8;

use CSAF::Util qw(JSON);

use Moo;
extends 'CSAF::Renderer::Base';

sub render {

    my $csaf = shift->csaf->builder->build;
    my $json = JSON->encode($csaf);

    return $json;

}

1;
