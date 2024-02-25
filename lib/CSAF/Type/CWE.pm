package CSAF::Type::CWE;

use 5.010001;
use strict;
use warnings;

use Moo;

use CSAF::Util qw(get_weakness_name);

extends 'CSAF::Type::Base';

has id   => (is => 'rw', isa => sub { Carp::croak 'Malformed CWE ID' if ($_[0] !~ /^CWE-\d{0,5}$/) });
has name => (is => 'rw');

sub TO_BUILD {

    my $self = shift;

    my $output = {id => $self->id};

    if (my $name = $self->name) {
        $output->{name} = $name;
    }

    if (!$self->name) {
        $output->{name} = get_weakness_name($self->id);
    }

    return $output;

}

1;
