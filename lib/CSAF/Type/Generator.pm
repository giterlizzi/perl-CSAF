package CSAF::Type::Generator;

use 5.010001;
use strict;
use warnings;

use Moo;
use CSAF::Util qw(check_datetime);
use CSAF::Type::Engine;

extends 'CSAF::Type::Base';

has date => (is => 'rw', predicate => 1, coerce => \&check_datetime);

sub engine {
    my ($self, %params) = @_;
    $self->{engine} ||= CSAF::Type::Engine->new(%params);
}


sub TO_BUILD {

    my $self = shift;

    my $output = {engine => $self->engine};

    if ($self->has_date) {
        $output->{date} = $self->date;
    }

    return $output;

}

1;
