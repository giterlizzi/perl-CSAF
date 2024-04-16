package CSAF::Renderer::JSON;

use 5.010001;
use strict;
use warnings;
use utf8;

use Cpanel::JSON::XS;

use Moo;
extends 'CSAF::Renderer::Base';

sub render {

    my $json = Cpanel::JSON::XS->new->utf8->canonical->allow_nonref->allow_unknown->allow_blessed->convert_blessed
        ->stringify_infnan->escape_slash(0)->allow_dupkeys->pretty;

    my $csaf        = shift->csaf->build;
    my $json_string = $json->encode($csaf);

    return $json_string;

}

1;
