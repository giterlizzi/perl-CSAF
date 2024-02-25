package CSAF::Type::Vulnerabilities;

use 5.010001;
use strict;
use warnings;

use Moo;
extends 'CSAF::Type::List';

has item_class_name => (is => 'ro', default => 'CSAF::Type::Vulnerability');

1;
