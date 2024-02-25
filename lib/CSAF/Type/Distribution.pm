package CSAF::Type::Distribution;

use 5.010001;
use strict;
use warnings;

use CSAF::Type::TLP;

use Moo;
extends 'CSAF::Type::Base';

has text => (is => 'rw');

sub tlp {
    my ($self, %params) = @_;
    $self->{tlp} ||= CSAF::Type::TLP->new(%params);
}

sub TO_BUILD {

    my $self = shift;

    my $output = {tlp => $self->tlp};

    $output->{text} = $self->text if ($self->text);

    return $output;

}

1;
