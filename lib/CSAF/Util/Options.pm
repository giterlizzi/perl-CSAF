package CSAF::Util::Options;

use 5.010001;
use strict;
use warnings;
use utf8;

use YAML::XS 'LoadFile';

use Moo::Role;

$YAML::XS::LoadBlessed = 0;

has config_file =>
    (is => 'rw', isa => sub { Carp::croak "Unable to open configuration file" unless -e $_[0] }, trigger => 1);

sub _trigger_config_file {

    my $self = shift;

    my $config_data = LoadFile($self->config_file);

    foreach my $config_name (keys %{$config_data}) {

        my $config_value = $config_data->{$config_name};

        $config_name =~ s/\-/_/;
        $self->$config_name($config_value) if $self->can($config_name);

    }

}

sub configure {

    my ($self, %args) = @_;

    foreach my $method (keys %args) {
        my $value = $args{$method};
        $self->$method($value) if $self->can($method);
    }

}

sub clone {

    my $self  = shift;
    my $clone = {%$self};

    bless $clone, ref $self;
    return $clone;

}

1;
