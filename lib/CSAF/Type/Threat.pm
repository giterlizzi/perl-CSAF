package CSAF::Type::Threat;

use 5.010001;
use strict;
use warnings;

use CSAF::Util qw(check_datetime);

use Moo;
extends 'CSAF::Type::Base';


has category    => (is => 'rw', required => 1);
has date        => (is => 'rw', coerce   => \&check_datetime);
has details     => (is => 'rw', required => 1);
has group_ids   => (is => 'rw', default  => sub { [] });
has product_ids => (is => 'rw', default  => sub { [] });


sub TO_BUILD {

    my $self = shift;

    my $output = {category => $self->category, details => $self->details};

    $output->{date}        = $self->date        if ($self->date);
    $output->{group_ids}   = $self->group_ids   if (@{$self->group_ids});
    $output->{product_ids} = $self->product_ids if (@{$self->product_ids});

    return $output;

}

1;
