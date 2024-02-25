package CSAF::Validator::Message;

use 5.010001;
use strict;
use warnings;

use Moo;

use overload '""' => \&to_string, bool => sub {1}, fallback => 1;

has message => (is => 'ro', required => 1);
has code    => (is => 'ro');
has path    => (is => 'ro');
has type    => (is => 'ro', default  => 'error');
has context => (is => 'ro', required => 1);

sub to_string {
    sprintf '[%s] %s: %s (%s - %s)', $_[0]->type, $_[0]->path, $_[0]->message, $_[0]->context, $_[0]->code;
}

sub TO_JSON {

    return {
        type    => $_[0]->type,
        context => $_[0]->context,
        message => $_[0]->message,
        path    => $_[0]->path,
        code    => $_[0]->code
    };

}

1;
