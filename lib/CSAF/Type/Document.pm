package CSAF::Type::Document;

use 5.010001;
use strict;
use warnings;

use Moo;
use Carp;

use CSAF::Type::AggregateSeverity;
use CSAF::Type::Distribution;
use CSAF::Type::Publisher;
use CSAF::Type::Tracking;
use CSAF::Type::Acknowledgments;
use CSAF::Type::Notes;
use CSAF::Type::References;

extends 'CSAF::Type::Base';

has category     => (is => 'rw', default => 'csaf_base', required => 1);
has csaf_version => (is => 'rw', default => '2.0');
has lang         => (is => 'rw', default => 'en', coerce => sub { (my $lang = $_[0]) =~ tr /_/-/; $lang });
has title        => (is => 'rw');
has source_lang  => (is => 'rw', coerce => sub { (my $lang = $_[0]) =~ tr /_/-/; $lang });

sub aggregate_severity {
    my ($self, %params) = @_;
    $self->{aggregate_severity} ||= CSAF::Type::AggregateSeverity->new(%params);
}

sub distribution {
    my ($self, %params) = @_;
    $self->{distribution} ||= CSAF::Type::Distribution->new(%params);
}

sub tracking {
    my ($self, %params) = @_;
    $self->{tracking} ||= CSAF::Type::Tracking->new(%params);
}

sub publisher {
    my ($self, %params) = @_;
    $self->{publisher} ||= CSAF::Type::Publisher->new(%params);
}

sub acknowledgments {
    my $self = shift;
    $self->{acknowledgments} ||= CSAF::Type::Acknowledgments->new(@_);
}

sub notes {
    my $self = shift;
    $self->{notes} ||= CSAF::Type::Notes->new(@_);
}

sub references {
    my $self = shift;
    $self->{references} ||= CSAF::Type::References->new(@_);
}

sub TO_BUILD {

    my $self = shift;

    # TODO
    Carp::croak 'Missing document title' unless $self->title;

    my $output = {
        category     => $self->category,
        csaf_version => $self->csaf_version,
        distribution => $self->distribution,
        publisher    => $self->publisher,
        title        => $self->title,
        tracking     => $self->tracking,
        lang         => $self->lang,
    };

    if (@{$self->acknowledgments->items}) {
        $output->{acknowledgments} = $self->acknowledgments;
    }

    if (@{$self->notes->items}) {
        $output->{notes} = $self->notes;
    }

    if ($self->aggregate_severity->text || $self->aggregate_severity->namespace) {
        $output->{aggregate_severity} = $self->aggregate_severity;
    }

    if (@{$self->references->items}) {
        $output->{references} = $self->references;
    }

    $output->{source_lang} = $self->source_lang if ($self->source_lang);

    return $output;

}

1;
