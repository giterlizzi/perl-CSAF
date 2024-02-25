package CSAF::Validator::Schema;

use 5.010001;
use strict;
use warnings;

use CSAF::Util qw(schema_cache_path);
use CSAF::Builder;
use JSON::Validator;

use Moo;
extends 'CSAF::Validator::Base';

sub validate {

    my ($self) = @_;

    my $jv = JSON::Validator->new;

    $jv->cache_paths([schema_cache_path]);
    $jv->schema('https://docs.oasis-open.org/csaf/csaf/v2.0/os/schemas/csaf_json_schema.json');

    my @errors = $jv->validate(CSAF::Builder->new(shift->csaf)->build(1));

    foreach my $error (@errors) {
        $self->add_message(CSAF::Validator::Message->new(
            context => 'JSON Schema',
            message => $error->message,
            path    => $error->path,
            code    => '9.1.14'
        ));
    }

    return @{$self->messages};

}

1;
