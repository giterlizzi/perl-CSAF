#!perl -T

use strict;
use warnings;

use FindBin '$RealBin';
use Test::More;
use CSAF::Util qw(file_read JSON);
use CSAF::Parser;

use Data::Dumper;

my $testcases = JSON->decode(file_read("$RealBin/official-testcases/testcases.json"));

foreach my $testcase (@{$testcases->{tests}}) {

    my $testcase_id    = $testcase->{id};
    my $testcase_group = $testcase->{group};

    if (defined $ENV{TESTCASE}) {
        next unless ($testcase_id eq $ENV{TESTCASE});
        diag "Test only $ENV{TESTCASE} testcase";
    }

    next if ($testcase_group =~ /(informative|optional)/);

    my @valid_testcases    = @{$testcase->{valid}    || []};
    my @failures_testcases = @{$testcase->{failures} || []};

    my @all_testcases = (@valid_testcases, @failures_testcases);

    foreach my $test (@all_testcases) {

        my $test_name = $test->{name};
        my $is_valid  = $test->{valid};

        diag("[$testcase_id - $testcase_group] Test file: $test_name [valid => $is_valid]");

        my $parser = CSAF::Parser->new(file => "$RealBin/official-testcases/$test_name");
        my $csaf   = $parser->parse;

        diag("[$testcase_id - $testcase_group] " . $csaf->document->title);

        my @messages = $csaf->validate;

        my $n_errors = 0;

        foreach my $message (@messages) {

            next if ($message->category ne 'mandatory');
            next if ($message->code ne $testcase_id);

            diag($message);
            $n_errors++;

        }

        if ($is_valid) {
            is($n_errors, 0, "$n_errors validation error(s) detected");
        }
        else {
            isnt($n_errors, 0, "$n_errors validation error(s) detected");
        }

    }

}

done_testing();
