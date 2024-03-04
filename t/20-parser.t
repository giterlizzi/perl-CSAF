#!perl -T

use strict;
use warnings;

use Test::More;
use FindBin '$RealBin';

use CSAF::Parser;

my $validation_errors = 0;

my $parser = CSAF::Parser->new(file => "$RealBin/examples/cisco-sa-20180328-smi2.json");
my $csaf   = $parser->parse;

is(
    $csaf->document->title,
    'Cisco IOS and IOS XE Software Smart Install Remote Code Execution Vulnerability',
    'Test title'
);

is($csaf->document->category, 'Cisco Security Advisory', 'Test category');

my @messages = $csaf->validate;

$validation_errors++ for (@messages);

is($validation_errors, 0, 'No validation error');

done_testing();
