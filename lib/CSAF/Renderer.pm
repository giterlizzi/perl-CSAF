package CSAF::Renderer;

use 5.010001;
use strict;
use warnings;
use utf8;

use Carp;

use CSAF::Renderer::JSON;
use CSAF::Renderer::HTML;

use Moo;
extends 'CSAF::Renderer::Base';

sub render {

    my ($self, %options) = @_;

    my $format = delete $options{'format'} || 'json';

    my $renderer = {
        json => sub { CSAF::Renderer::JSON->new($self->csaf) },
        html => sub { CSAF::Renderer::HTML->new($self->csaf) },
    };

    if (defined $renderer->{lc $format}) {
        return $renderer->{lc $format}->()->render(%options);
    }

    Carp::croak 'Unknown render format';

}

1;
