package CSAF::Validator::OptionalTests;

use 5.010001;
use strict;
use warnings;
use utf8;
use version;

use CSAF::Util::CVSS qw(decode_cvss_vector_string);
use CSAF::Util       qw(tracking_id_to_well_filename);

use File::Basename;
use List::MoreUtils qw(uniq duplicates);
use List::Util      qw(first);
use JSON::Validator;
use URI::PackageURL;
use I18N::LangTags::List;

use Moo;
extends 'CSAF::Validator::Base';

use constant DEBUG => $ENV{CSAF_DEBUG};

my @TESTS = (
    '6.2.1',  '6.2.2',  '6.2.3',  '6.2.4',  '6.2.5',  '6.2.6',  '6.2.7',  '6.2.8',  '6.2.9',  '6.2.10',
    '6.2.11', '6.2.12', '6.2.13', '6.2.14', '6.2.15', '6.2.16', '6.2.17', '6.2.18', '6.2.19', '6.2.20'
);

my $VERS_REGEXP = qr{^vers:[a-z\\.\\-\\+][a-z0-9\\.\\-\\+]*/.+};

sub validate {

    my $self = shift;

    foreach my $test_id (@TESTS) {

        $self->exec_test($test_id);

        if (DEBUG) {

            my $test_messages = scalar @{$self->summary->{$test_id} || []};

            if ($test_messages > 0) {
                say STDERR sprintf('(W) Optional Test %s --> found %s validation warning(s)', $test_id, $test_messages);
            }

        }

    }

    return @{$self->messages};

}

sub TEST_6_2_2 {

    my $self = shift;

    return unless $self->csaf->vulnerabilities->size;

    my @statuses = qw(first_affected known_affected last_affected under_investigation);

    $self->csaf->vulnerabilities->each(sub {

        my ($vulnerability, $vuln_idx) = @_;

        my $product_status = $vulnerability->product_status;

        for my $status (@statuses) {

            my @product_ids = @{$product_status->$status};
            my $product_idx = 0;

            foreach my $product_id (@product_ids) {
                if (!$vulnerability->remediations->size) {
                    $self->add_message(
                        type     => 'warning',
                        category => 'optional',
                        path     => "/vulnerabilities/$vuln_idx/product_status/$status/$product_idx",
                        code     => '6.2.2',
                        message  => 'Missing Remediation'
                    );
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

        my ($vulnerability, $vuln_idx) = @_;

        my $product_status = $vulnerability->product_status;

        for my $status (@statuses) {

            my @product_ids = @{$product_status->$status};
            my $product_idx = 0;

            foreach my $product_id (@product_ids) {
                if (!$vulnerability->scores->size) {
                    $self->add_message(
                        type     => 'warning',
                        category => 'optional',
                        path     => "/vulnerabilities/$vuln_idx/product_status/$status/$product_idx",
                        code     => '6.2.3',
                        message  => 'Missing Score'
                    );
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
            $self->add_message(
                type     => 'warning',
                category => 'optional',
                path     => "/document/tracking/revision_history/$idx/number",
                code     => '6.2.4',
                message  => 'Build Metadata in Revision History'
            );
        }

    });

}

sub TEST_6_2_7 {

    my $self = shift;

    $self->csaf->vulnerabilities->each(sub {

        my ($vulnerability, $vuln_idx) = @_;

        $vulnerability->involvements->each(sub {

            my ($involvement, $involvement_idx) = @_;

            if (!$involvement->date) {
                $self->add_message(
                    type     => 'warning',
                    category => 'optional',
                    path     => "/vulnerabilities/$vuln_idx/involvements/$involvement_idx",
                    code     => '6.2.7',
                    message  => 'Missing Date in Involvements'
                );
            }

        });

    });

}

sub TEST_6_2_10 {

    my $self = shift;

    if (!$self->csaf->document->distribution->tlp->label) {
        $self->add_message(
            type     => 'warning',
            category => 'optional',
            path     => '/document/distribution/tlp/label',
            code     => '6.2.10',
            message  => 'Missing TLP label'
        );
    }

}

sub TEST_6_2_11 {

    my $self = shift;

    my $have_self = 0;

    my $tracking_id  = $self->csaf->document->tracking->id;
    my $doc_filename = tracking_id_to_well_filename($tracking_id);

    $self->csaf->document->references->each(sub {

        my ($reference, $ref_idx) = @_;

        return if (!$reference->category eq 'self');

        $have_self = 1;

        my $url = $reference->url;

        if (!$url =~ /^https\:/) {
            return $self->add_message(
                type     => 'warning',
                category => 'optional',
                path     => "/document/references/$ref_idx",
                code     => '6.2.11',
                message  => 'Missing Canonical URL'
            );
        }

        if (basename($url) ne $doc_filename) {
            return $self->add_message(
                type     => 'warning',
                category => 'optional',
                path     => "document/references/$ref_idx",
                code     => '6.2.11',
                message  => 'Missing Canonical URL'
            );
        }

    });

    if (!$have_self) {
        $self->add_message(
            type     => 'warning',
            category => 'optional',
            path     => '/document/references',
            code     => '6.2.11',
            message  => 'Missing Canonical URL'
        );
    }

}

sub TEST_6_2_12 {

    my $self = shift;

    if (!$self->csaf->document->lang) {
        $self->add_message(
            type     => 'warning',
            category => 'optional',
            path     => '/document/lang',
            code     => '6.2.12',
            message  => 'Missing Document Language'
        );
    }

}

sub TEST_6_2_14 {

    my $self = shift;

    my %check = (
        '/document/lang'        => $self->csaf->document->lang,
        '/document/source_lang' => $self->csaf->document->source_lang
    );

    foreach (keys %check) {

        my $path = $_;
        my $lang = $check{$path};

        next unless $lang;

        # Subtags in official testsuite (optional/oasis_csaf_tc-csaf_2_0-2021-6-2-14-*.json)
        if ($lang =~ /\-(AA|XP|ZZ|QM|QABC)$/i) {
            return $self->add_message(
                type     => 'warning',
                category => 'optional',
                context  => 'Optional Test',
                path     => $path,
                code     => '6.2.14',
                message  => 'Use of Private Language'
            );
        }

        if ($lang =~ /(q([a-t])([a-z]))/gi) {

            return $self->add_message(
                type     => 'warning',
                category => 'optional',
                context  => 'Optional Test',
                path     => $path,
                code     => '6.2.14',
                message  => 'Use of Private Language'
            );

        }

        if (!I18N::LangTags::List::is_decent($lang)) {
            return $self->add_message(
                type     => 'warning',
                category => 'optional',
                context  => 'Optional Test',
                path     => $path,
                code     => '6.2.14',
                message  => 'Use of Private Language'
            );
        }

    }

}

sub TEST_6_2_15 {

    my $self = shift;

    my %check = (
        '/document/lang'        => $self->csaf->document->lang,
        '/document/source_lang' => $self->csaf->document->source_lang
    );

    foreach (keys %check) {

        my $path = $_;
        my $lang = $check{$path};

        next unless $lang;

        if ($lang eq 'i-default') {
            return $self->add_message(
                type     => 'warning',
                category => 'optional',
                context  => 'Optional Test',
                path     => $path,
                code     => '6.2.15',
                message  => 'Use of Default Language'
            );
        }

    }

}

sub TEST_6_2_17 {

    my $self = shift;

    $self->csaf->vulnerabilities->each(sub {

        my ($vulnerability, $vuln_idx) = @_;

        $vulnerability->ids->each(sub {

            my ($id, $id_idx) = @_;

            if ($id->text =~ /^CVE-[0-9]{4}-[0-9]{4,}$/) {
                $self->add_message(
                    type     => 'warning',
                    category => 'optional',
                    path     => "/vulnerabilities/$vuln_idx/ids/$id_idx",
                    code     => '6.2.17',
                    message  => 'CVE in field IDs'
                );
            }

        });

    });

}

sub TEST_6_2_18 {

    my $self = shift;

    return if (not $self->csaf->product_tree);

    $self->_TEST_6_2_18_branches($self->csaf->product_tree->branches, "/product_tree/branches");

}

sub TEST_6_2_19 {

    my $self = shift;

    $self->csaf->vulnerabilities->each(sub {

        my ($vulnerability, $vuln_idx) = @_;

        $vulnerability->scores->each(sub {

            my ($score, $score_idx) = @_;

            my $fixed_products = 0;

            foreach my $product_id (@{$score->products}) {
                $fixed_products = 1 if (first { $product_id eq $_ } @{$vulnerability->product_status->fixed});
                $fixed_products = 1 if (first { $product_id eq $_ } @{$vulnerability->product_status->first_fixed});
            }

            return if (!$fixed_products);

            if (my $cvss = $score->cvss_v2) {

                my $is_invalid = 0;

                if (!$cvss->targetDistribution) {

                    $is_invalid = 1;

                    my $decoded = decode_cvss_vector_string($score->cvss_v2->vectorString);

                    if (!defined($decoded->{targetDistribution})) {
                        $is_invalid = 1;
                    }
                    else {
                        $is_invalid = 0;
                    }

                }

                if ($is_invalid) {
                    $self->add_message(
                        type     => 'warning',
                        category => 'optional',
                        path     => "/vulnerabilities/$vuln_idx/scores/$score_idx/cvss_v2",
                        code     => '6.2.19',
                        message  => 'CVSS for Fixed Products'
                    );
                }
            }

            if (my $cvss = $score->cvss_v3) {

                my $is_invalid = 0;

                if (   !$cvss->modifiedIntegrityImpact
                    || !$cvss->modifiedAvailabilityImpact
                    || !$cvss->modifiedConfidentialityImpact)
                {

                    $is_invalid = 1;

                    my $decoded = decode_cvss_vector_string($score->cvss_v3->vectorString);

                    if (   !defined($decoded->{modifiedIntegrityImpact})
                        || !defined($decoded->{modifiedAvailabilityImpact})
                        || !defined($decoded->{modifiedConfidentialityImpact}))
                    {
                        $is_invalid = 1;
                    }
                    else {
                        $is_invalid = 0;
                    }

                }

                if ($is_invalid) {
                    $self->add_message(
                        type     => 'warning',
                        category => 'optional',
                        path     => "/vulnerabilities/$vuln_idx/scores/$score_idx/cvss_v3",
                        code     => '6.2.19',
                        message  => 'CVSS for Fixed Products'
                    );
                }

            }

        });

    });

}

sub _TEST_6_2_18_branches {

    my ($self, $branches, $path) = @_;

    $branches->each(sub {

        my ($branch, $branch_idx) = @_;

        $self->_TEST_6_2_18_branches($branch->branches, "$path/$branch_idx/branches");

        if ($branch->category eq 'product_version_range') {

            if ($branch->name !~ /$VERS_REGEXP/) {
                $self->add_message(
                    type     => 'warning',
                    category => 'optional',
                    path     => "$path/name",
                    code     => '6.2.18',
                    message  => 'Product Version Range without vers'
                );
            }

        }

    });
}

1;
