package CSAF;

use 5.010001;
use strict;
use warnings;

use CSAF::Builder;
use CSAF::Writer;
use CSAF::Validator;
use CSAF::Renderer;

use CSAF::Document;

use overload '""' => 'to_string';

our $VERSION = '0.11';

our $CACHE = {};

sub new {

    my $class = shift;

    $CACHE = {};    # Reset Cache

    my $self = {_ => CSAF::Document->new};

    return bless $self, $class;

}

# CSAF document core properties

sub document        { shift->{_}->document }
sub product_tree    { shift->{_}->product_tree }
sub vulnerabilities { shift->{_}->vulnerabilities }

# Helper classes

sub builder   { CSAF::Builder->new(csaf => shift) }
sub renderer  { CSAF::Renderer->new(csaf => shift) }
sub validator { CSAF::Validator->new(csaf => shift) }
sub writer    { CSAF::Writer->new(csaf => shift, @_) }

# Helpers

sub validate { shift->validator->validate }
sub render   { shift->renderer->render(@_) }

sub to_string { shift->renderer->render }
sub TO_JSON   { shift->builder->TO_JSON }

1;
