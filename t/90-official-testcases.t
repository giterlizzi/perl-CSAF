#!perl -T

use strict;
use warnings;

use FindBin '$RealBin';
use Test::More;
use CSAF::Util qw(file_read JSON);
use CSAF::Parser;
use List::Util qw(first);

use constant DEBUG => $ENV{CSAF_TEST_DEBUG};

my $testcases = JSON->decode(file_read("$RealBin/official-testcases/testcases.json"));

my @SKIP_TESTCASES = (
    '6.2.10', # Missing TLP label (CSAF::Type::TLP have default label)
    '6.2.12', # Missing Document Language (CSAF::Document have "en" for default language)
    '6.2.20', # Additional Properties (in CSAF::Document isn't possible add new properties)
);

foreach my $testcase (@{$testcases->{tests}}) {

    my $testcase_id    = $testcase->{id};
    my $testcase_group = $testcase->{group};

    if (defined $ENV{TESTCASE}) {
        next unless ($testcase_id eq $ENV{TESTCASE});
        diag "Test only $ENV{TESTCASE} testcase";
    }

    if (first { $testcase_id eq $_ } @SKIP_TESTCASES) {
        diag "Testcase $testcase_id skipped";
        next;
    }

    next if ($testcase_group =~ /(informative|optional)/);

    my @valid_testcases    = @{$testcase->{valid}    || []};
    my @failures_testcases = @{$testcase->{failures} || []};

    my @all_testcases = (@valid_testcases, @failures_testcases);

    foreach my $test (@all_testcases) {

        my $test_name = $test->{name};
        my $is_valid  = $test->{valid};

        my $parser    = CSAF::Parser->new(file => "$RealBin/official-testcases/$test_name");
        my $csaf      = $parser->parse;
        my $doc_title = $csaf->document->title;

        if ($testcase_group eq 'optional' && $doc_title =~ /failing/) {
            $is_valid = 0;
        }

        DEBUG and diag("[$testcase_id - $testcase_group] Test file: $test_name [valid => $is_valid]");
        DEBUG and diag("[$testcase_id - $testcase_group] $doc_title");

        my @messages = $csaf->validate;

        my $n_errors = 0;

        foreach my $message (@messages) {

            #next if ($message->category ne 'mandatory');
            next if ($message->code ne $testcase_id);

            DEBUG and diag($message);
            $n_errors++;

        }

        if ($is_valid) {
            is($n_errors, 0, "$n_errors validation error(s) detected for '$doc_title'");
        }
        else {
            isnt($n_errors, 0, "$n_errors validation error(s) detected for '$doc_title'");
        }

    }

}

done_testing();
