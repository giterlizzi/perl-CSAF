package CSAF::Validator;

use 5.010001;
use strict;
use warnings;

use CSAF::Validator::MandatoryTests;
use CSAF::Validator::OptionalTests;
use CSAF::Validator::Schema;
use CSAF::Validator::Message;

use constant DEBUG => $ENV{CSAF_DEBUG};

use Moo;
extends 'CSAF::Validator::Base';

sub validate {

    my $self = shift;

    my @messages = ();

    # 9.1.14 Conformance Clause 14: CSAF basic validator

    my @schema_errors = CSAF::Validator::Schema->new($self->csaf)->validate;
    push @messages, @schema_errors;

    my @mandatory_errors = CSAF::Validator::MandatoryTests->new($self->csaf)->validate;
    push @messages, @mandatory_errors;

    my @optional_warnings = CSAF::Validator::OptionalTests->new($self->csaf)->validate;
    push @messages, @optional_warnings;

    $self->messages(\@messages);

    if (DEBUG && @messages) {
        say STDERR "\nValidation messages(s):";
        say STDERR sprintf('- %s', $_) for (@messages);
        say STDERR "";
    }


    return @{$self->messages};

}

1;
