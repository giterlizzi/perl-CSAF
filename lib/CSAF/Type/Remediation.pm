package CSAF::Type::Remediation;

use 5.010001;
use strict;
use warnings;

use CSAF::Util qw(check_datetime);
use CSAF::Type::RestartRequired;

use Moo;
extends 'CSAF::Type::Base';


has category         => (is => 'rw', required => 1);
has date             => (is => 'rw', coerce   => \&check_datetime);
has details          => (is => 'rw', required => 1);
has entitlements     => (is => 'rw', default  => sub { [] });
has group_ids        => (is => 'rw', default  => sub { [] });
has product_ids      => (is => 'rw', default  => sub { [] });
has restart_required => (is => 'ro', coerce   => sub { CSAF::Type::RestartRequired->new(shift) });
has url              => (is => 'rw');

sub TO_BUILD {

    my $self = shift;

    my $output = {category => $self->category, details => $self->details};

    $output->{date}             = $self->date             if ($self->date);
    $output->{entitlements}     = $self->product_ids      if (@{$self->entitlements});
    $output->{group_ids}        = $self->group_ids        if (@{$self->group_ids});
    $output->{product_ids}      = $self->product_ids      if (@{$self->product_ids});
    $output->{restart_required} = $self->restart_required if (defined $self->{restart_required});
    $output->{url}              = $self->url              if ($self->url);

    return $output;

}

1;
