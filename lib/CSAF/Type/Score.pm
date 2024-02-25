package CSAF::Type::Score;

use 5.010001;
use strict;
use warnings;

use Moo;
use CSAF::Type::CVSS3;
use CSAF::Type::CVSS2;

extends 'CSAF::Type::Base';

has products => (is => 'rw', default => sub { [] });
has cvss_v2  => (is => 'ro', coerce  => sub { CSAF::Type::CVSS2->new(shift) });
has cvss_v3  => (is => 'ro', coerce  => sub { CSAF::Type::CVSS3->new(shift) });

sub TO_BUILD {

    my $self = shift;

    my $output = {};

    $output->{products} = $self->products if (@{$self->products});

    $output->{cvss_v3} = $self->cvss_v3 if (defined $self->{cvss_v3});
    $output->{cvss_v2} = $self->cvss_v2 if (defined $self->{cvss_v2});

    return $output;

}

1;
