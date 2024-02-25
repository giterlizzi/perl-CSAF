package CSAF::Type::Revision;

use 5.010001;
use strict;
use warnings;

use Moo;
use CSAF::Util qw(check_datetime);

extends 'CSAF::Type::Base';

has date           => (is => 'rw', required => 1, coerce => \&check_datetime);
has legacy_version => (is => 'rw');
has number         => (is => 'rw', required => 1);
has summary        => (is => 'rw', required => 1);

sub TO_BUILD {

    my $self = shift;

    my $output = {date => $self->date, number => $self->number, summary => $self->summary};

    $output->{legacy_version} = $self->legacy_version if ($self->legacy_version);

    return $output;

}

1;
