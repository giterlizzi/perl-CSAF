package CSAF::List;

use 5.010001;
use strict;
use warnings;

use Moo;

has items => (is => 'rw', default => sub { [] });

around BUILDARGS => sub {
    my ($orig, $class, @args) = @_;

    return {items => \@args} if @args > 0;    # TODO
    return $class->$orig(@args);
};

sub size { scalar @{shift->items} }

sub each {

    my ($self, $callback) = @_;

    return @{$self->items} unless $callback;

    my $idx = 0;
    $_->$callback($idx++) for @{$self->items};

    return $self;

}

sub to_array { [@{shift->items}] }

sub item   { push @{shift->items}, shift }
sub append { shift->item(@_) }
sub add    { shift->item(@_) }

sub first { shift->items->[0] }
sub last  { shift->items->[-1] }
sub join  { join($_[1], $_[0]->items) }

sub TO_JSON { [@{shift->items}] }

1;
