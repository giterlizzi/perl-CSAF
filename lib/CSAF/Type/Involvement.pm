package CSAF::Type::Involvement;

use 5.010001;
use strict;
use warnings;

use Moo;
use CSAF::Util qw(check_datetime);

extends 'CSAF::Type::Base';


has date    => (is => 'rw', coerce   => \&check_datetime);
has party   => (is => 'rw', required => 1,);
has status  => (is => 'rw', required => 1);
has summary => (is => 'rw');

sub TO_BUILD {

    my $self = shift;

    my $output = {status => $self->status, party => $self->number};

    $output->{date}    = $self->date    if ($self->date);
    $output->{summary} = $self->summary if ($self->summary);

    return $output;

}

1;
