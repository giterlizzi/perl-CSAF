#!perl -T

use strict;
use warnings;

use Test::More;

use_ok('CSAF');
use_ok('CSAF::Lite');
use_ok('CSAF::Util');
use_ok('CSAF::Type');
use_ok('CSAF::Builder');

done_testing();

diag("CSAF $CSAF::VERSION, Perl $], $^X");
