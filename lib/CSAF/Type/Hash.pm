package CSAF::Type::Hash;

use 5.010001;
use strict;
use warnings;

use Moo;
extends 'CSAF::Type::Base';

use CSAF::Type::FileHashes;

has filename => (is => 'rw', required => 1);

has file_hashes => (
    is       => 'rw',
    required => 1,
    coerce   => sub {
        (ref($_[0]) !~ /FileHashes/) ? CSAF::Type::FileHashes->new(shift) : $_[0];
    }
);

sub TO_BUILD {

    my $self = shift;

    my $output = {filename => $self->filename, file_hashes => $self->file_hashes->TO_BUILD};

    return $output;

}

1;
