package CSAF::Type::Note;

use 5.010001;
use strict;
use warnings;

use Moo;
extends 'CSAF::Type::Base';

my @CATEGORIES = ('description', 'details', 'faq', 'general', 'legal_disclaimer', 'other', 'summary');

has category => (
    is       => 'rw',
    required => 1,
    isa      => sub { Carp::croak 'Unknown note "category"' unless grep(/$_[0]/, @CATEGORIES) }
);

has text     => (is => 'rw', required => 1);
has audience => (is => 'rw');
has title    => (is => 'rw');


sub TO_BUILD {

    my $self = shift;

    my $output = {category => $self->category, text => $self->text};

    $output->{audience} = $self->audience if ($self->audience);
    $output->{title}    = $self->title    if ($self->title);

    return $output;

}

1;
