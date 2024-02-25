package CSAF::Type::Notes;

use 5.010001;
use strict;
use warnings;

use Moo;
extends 'CSAF::Type::List';

has item_class_name => (is => 'ro', default => 'CSAF::Type::Note');

sub get_category {

    my ($self, $category) = @_;

    my @items = ();

    foreach ($self->each) {
        push @items, $_ if ($_->category eq $category);
    }

    return \@items;

}

1;
