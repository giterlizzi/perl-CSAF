package CSAF::Validator::OptionalTests;

use 5.010001;
use strict;
use warnings;
use version;

use CSAF::Util qw(get_weakness_name check_purl collect_product_ids schema_cache_path);
use CSAF::Validator::Message;

use List::MoreUtils qw(uniq duplicates);
use List::Util      qw(first);
use JSON::Validator;
use URI::PackageURL;

use Moo;
extends 'CSAF::Validator::Base';

use constant DEBUG => $ENV{CSAF_DEBUG};

my @TESTS = ('6.2.2', '6.2.3', '6.2.4', '6.2.14');

sub validate {

    my $self = shift;

    foreach my $test_id (@TESTS) {

        $self->exec_test($test_id);

        if (DEBUG) {

            state $last_tot_msgs = 0;

            my $tot_msgs      = @{$self->messages};
            my $test_tot_msgs = $tot_msgs - $last_tot_msgs;

            if ($test_tot_msgs > 0) {
                say STDERR sprintf('(W) Optional Test %s --> found %s validation warning(s)', $test_id, $test_tot_msgs);
            }

            $last_tot_msgs = $tot_msgs;

        }

    }

    return @{$self->messages};

}

sub TEST_6_2_2 {

    my $self = shift;

    return unless $self->csaf->vulnerabilities->size;

    my @statuses = qw(first_affected known_affected last_affected under_investigation);

    $self->csaf->vulnerabilities->each(sub {

        my ($vulnerability, $vulnerability_idx) = @_;

        my $product_status = $vulnerability->product_status;

        for my $status (@statuses) {

            my @product_ids = @{$product_status->$status};
            my $product_idx = 0;

            foreach my $product_id (@product_ids) {
                foreach my $remediation ($vulnerability->remediations->each) {
                    if (!first { $product_id eq $_ } @{$remediation->product_ids}) {
                        $self->add_message(CSAF::Validator::Message->new(
                            type     => 'warning',
                            category => 'optional',
                            path     => "/vulnerabilities/$vulnerability_idx/product_status/$status/$product_idx",
                            code     => '6.2.2',
                            message  => 'Missing Remediation'
                        ));
                    }
                }
                $product_idx++;
            }

        }

    });

}

sub TEST_6_2_3 {

    my $self = shift;

    return unless $self->csaf->vulnerabilities->size;

    my @statuses = qw(first_affected known_affected last_affected);

    $self->csaf->vulnerabilities->each(sub {

        my ($vulnerability, $vulnerability_idx) = @_;

        my $product_status = $vulnerability->product_status;

        for my $status (@statuses) {

            my @product_ids = @{$product_status->$status};
            my $product_idx = 0;

            foreach my $product_id (@product_ids) {
                foreach my $score ($vulnerability->scores->each) {
                    if (!first { $product_id eq $_ } @{$score->products}) {
                        $self->add_message(CSAF::Validator::Message->new(
                            type     => 'warning',
                            category => 'optional',
                            path     => "/vulnerabilities/$vulnerability_idx/product_status/$status/$product_idx",
                            code     => '6.2.3',
                            message  => 'Missing Score'
                        ));
                    }
                }
                $product_idx++;
            }

        }

    });

}

sub TEST_6_2_4 {

    my $self = shift;

    my $document_revisions = $self->csaf->document->tracking->revision_history;

    $document_revisions->each(sub {

        my ($revision, $idx) = @_;

        if ($revision->number =~ /\+/) {
            $self->add_message(CSAF::Validator::Message->new(
                type     => 'warning',
                category => 'optional',
                path     => "/document/tracking/revision_history/$idx/number",
                code     => '6.2.4',
                message  => 'Build Metadata in Revision History'
            ));
        }

    });

}

sub TEST_6_2_14 {

    my $self = shift;

    if (my $lang = $self->csaf->document->lang) {

        if ($lang =~ /(q([a-t])([a-z]))/gi) {

            $self->add_message(CSAF::Validator::Message->new(
                type     => 'warning',
                category => 'optional',
                context  => 'Optional Test',
                path     => '/document/lang',
                code     => '6.2.14',
                message  => 'Use of Private Language'
            ));

        }

    }

    if (my $lang = $self->csaf->document->source_lang) {

        if ($lang =~ /(q([a-t])([a-z]))/gi) {

            $self->add_message(CSAF::Validator::Message->new(
                type     => 'warning',
                category => 'optional',
                context  => 'Optional Test',
                path     => '/document/source_lang',
                code     => '6.2.14',
                message  => 'Use of Private Language'
            ));

        }

    }


}


1;
