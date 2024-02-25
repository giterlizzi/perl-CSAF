package CSAF::Type::ProductGroup;

use 5.010001;
use strict;
use warnings;

use Moo;
extends 'CSAF::Type::Base';


has group_id    => (is => 'rw', required => 1, default => sub { [] });
has product_ids => (is => 'rw', required => 1, default => sub { [] });
has summary     => (is => 'rw');

sub TO_BUILD {

    my $self = shift;

    my $output = {group_id => $self->group_id, product_ids => $self->product_ids};

    $output->{summary} = $self->summary if ($self->summary);

    return $output;

}

1;
