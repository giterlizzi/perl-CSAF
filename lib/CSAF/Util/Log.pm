package CSAF::Util::Log;

use 5.010001;
use strict;
use warnings;
use utf8;

use Moo::Role;
use Log::Any;

has log => (
    is      => 'ro',
    default => sub { Log::Any->get_logger(filter => \&CSAF::Util::log_formatter, category => (caller(0))[0]) }
);

1;
