package CSAF::Base;

use 5.010001;
use strict;
use warnings;

use Carp;
use Moo;

around BUILDARGS => sub {

    my ($orig, $class, @args) = @_;

    return {csaf => $args[0]} if @args == 1;
    return $class->$orig(@args);

};

has csaf => (
    is  => 'ro',
    isa => sub {
        Carp::croak 'Must be an instance of "CSAF"' unless ref($_[0]) eq 'CSAF';
    },
    required => 1
);

1;
