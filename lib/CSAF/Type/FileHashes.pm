package CSAF::Type::FileHashes;

use 5.010001;
use strict;
use warnings;

use Moo;
extends 'CSAF::Type::List';

our $ITEM_CLASS_NAME = 'CSAF::Type::FileHash';

has item_class_name => (is => 'ro', default => 'CSAF::Type::FileHash');

1;
