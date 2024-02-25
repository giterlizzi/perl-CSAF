package CSAF::Type::Reference;

use 5.010001;
use strict;
use warnings;

use Moo;
extends 'CSAF::Type::Base';

my @CATEGORIES = ('self', 'external');

has summary => (is => 'rw', required => 1);
has url     => (is => 'rw', required => 1);

has category =>
    (is => 'rw', isa => sub { Carp::croak 'Unknown reference "category"' unless grep(/$_[0]/, @CATEGORIES) });

sub TO_BUILD {

    my $self = shift;

    my $output = {summary => $self->summary, url => $self->url};

    $output->{category} = $self->category if ($self->category);

    return $output;

}


1;
