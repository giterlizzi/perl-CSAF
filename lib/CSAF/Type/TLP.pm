package CSAF::Type::TLP;

use 5.010001;
use strict;
use warnings;

use Moo;
extends 'CSAF::Type::Base';

my @LABELS = (qw[AMBER GREEN RED WHITE]);

has label => (
    is      => 'rw',
    default => 'WHITE',
    isa     => sub {
        my $test = shift;
        Carp::croak 'Unknown TLP label' unless grep { $test eq $_ } @LABELS;
    },
    coerce => sub { uc $_[0] }
);

has url => (is => 'rw', default => 'https://www.first.org/tlp/');

sub TO_BUILD {

    my $self = shift;

    my $output = {};

    $output->{label} = $self->label;
    $output->{url}   = $self->url if ($self->url);

    return $output;

}

1;
