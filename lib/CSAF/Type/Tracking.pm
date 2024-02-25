package CSAF::Type::Tracking;

use 5.010001;
use strict;
use warnings;
use version;

use Moo;
use CSAF::Type::Generator;
use CSAF::Type::RevisionHistory;
use CSAF::Util qw(check_datetime);

extends 'CSAF::Type::Base';

has ['current_release_date', 'initial_release_date'] => (is => 'rw', required => 1, coerce => \&check_datetime);

has ['id', 'status'] => (is => 'rw', required => 1);

has version => (is => 'rw', required => 1, coerce => sub {"$_[0]"});

has aliases => (is => 'rw', default => sub { [] });

sub generator {
    my ($self, %params) = @_;
    $self->{generator} ||= CSAF::Type::Generator->new(%params);
}

sub revision_history {
    my $self = shift;
    $self->{revision_history} ||= CSAF::Type::RevisionHistory->new(@_);
}

sub TO_BUILD {

    my $self = shift;

    my $output = {
        id                   => $self->id,
        current_release_date => $self->current_release_date,
        initial_release_date => $self->initial_release_date,
        revision_history     => $self->revision_history->TO_BUILD,
        status               => $self->status,
        version              => $self->version,
    };

    $output->{aliases}   = $self->aliases if (@{$self->aliases});
    $output->{generator} = $self->generator;

    return $output;

}

1;
