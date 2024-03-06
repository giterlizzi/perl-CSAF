package CSAF::Validator::Base;

use 5.010001;
use strict;
use warnings;

use List::Util qw(first);

use Moo;
extends 'CSAF::Base';

our %TESTS = ();

has messages => (is => 'rw', default => sub { [] });
has summary  => (is => 'ro', default => sub { {} });
has tests    => (is => 'rw', default => sub { [] });

sub validate { Carp::croak 'Method "validate" not implemented by subclass' }

sub has_error {
    (first { $_->type eq 'error' } @{$_[0]->messages}) ? 1 : 0;
}

sub has_warning {
    (first { $_->type eq 'warning' } @{$_[0]->messages}) ? 1 : 0;
}

sub add_message {

    my ($self, $message) = @_;

    $self->{messages} ||= [];
    $self->{summary}->{$message->code} ||= [];

    push @{$self->{messages}},                  $message;
    push @{$self->{summary}->{$message->code}}, $message;

}

sub exec_test {

    my ($self, $test_id) = @_;

    my $test_sub = "TEST_$test_id";
    $test_sub =~ tr/\./_/;

    if (my $code_ref = $self->can($test_sub)) {
        eval { $code_ref->($self) };
        Carp::croak "Failed to execute test $test_id: $@" if ($@);
    }

}

1;
