package CSAF::Type::List;

use 5.010001;
use strict;
use warnings;

use Moo;
use Carp;

extends 'CSAF::Type::Base';

has item_class      => (is => 'ro', builder  => '_build_item_class', lazy => 1);
has item_class_name => (is => 'ro', required => 1);
has items           => (is => 'rw', default  => sub { [] });

around BUILDARGS => sub {
    my ($orig, $class, @args) = @_;

    return {items => \@args} if @args > 0;    # TODO
    return $class->$orig(@args);
};

sub _build_item_class {

    my $class = shift->item_class_name;

    return $class if ($class->can('new') or eval "require $class; 1");

    Carp::croak "Failed to load item class $class: $@";

}

sub size { scalar @{shift->items} }

sub each {

    my ($self, $callback) = @_;

    return @{$self->items} unless $callback;

    my $idx = 0;
    $_->$callback($idx++) for @{$self->items};

    return $self;

}

sub to_array { [@{shift->items}] }

sub item {

    my ($self, %params) = @_;

    my $item = $self->item_class->new(%params);
    push @{$self->items}, $item;

    return $item;

}

sub append { shift->item(@_) }
sub add    { shift->item(@_) }

sub TO_BUILD {

    my $self   = shift;
    my $output = [];

    foreach my $item (@{$self->items}) {
        if (ref($item) =~ /^CSAF::Type/) {
            push @{$output}, $item->TO_BUILD;
        }
        else {
            push @{$output}, $item;
        }
    }

    return $output;

}

sub TO_JSON { shift->TO_BUILD }

1;
