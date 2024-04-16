package CSAF::Validator::Schema;

use 5.010001;
use strict;
use warnings;
use utf8;

use CSAF::Schema;
use CSAF::Builder;

use Moo;
extends 'CSAF::Validator::Base';

sub validate {

    my ($self) = @_;

    # 9.1.14 Conformance Clause 14: CSAF basic validator

    my $schema = CSAF::Schema->validator('csaf-2.0');
    my @errors = $schema->validate(CSAF::Builder->new(shift->csaf)->build(1));

    foreach my $error (@errors) {
        $self->add_message(category => 'schema', message => $error->message, path => $error->path, code => '9.1.14');
    }

    return @{$self->messages};

}

1;
