package CSAF::Validator::MandatoryTests;

use 5.010001;
use strict;
use warnings;
use version;

use CSAF::Validator::Message;
use CSAF::Util qw(
    get_weakness_name collect_product_ids schema_cache_path
    decode_cvss3_vector_string product_in_group_exists
);

use List::MoreUtils qw(uniq duplicates);
use List::Util      qw(first);
use JSON::Validator;
use URI::PackageURL;

use Moo;
extends 'CSAF::Validator::Base';

use constant DEBUG => $ENV{CSAF_DEBUG};

my @TESTS = (
    '6.1.1',    '6.1.2',    '6.1.3',    '6.1.4',     '6.1.5',     '6.1.6',    '6.1.7',    '6.1.8',
    '6.1.9',    '6.1.10',   '6.1.11',   '6.1.12',    '6.1.13',    '6.1.14',   '6.1.15',   '6.1.16',
    '6.1.17',   '6.1.18',   '6.1.19',   '6.1.20',    '6.1.21',    '6.1.22',   '6.1.23',   '6.1.24',
    '6.1.25',   '6.1.26',   '6.1.27.1', '6.1.27.2',  '6.1.27.3',  '6.1.27.4', '6.1.27.5', '6.1.27.6',
    '6.1.27.7', '6.1.27.8', '6.1.27.9', '6.1.27.10', '6.1.27.11', '6.1.28',   '6.1.29',   '6.1.30',
    '6.1.31',   '6.1.32',   '6.1.33',
);

my $PURL_REGEX = qr{^pkg:[A-Za-z\\.\\-\\+][A-Za-z0-9\\.\\-\\+]*/.+};

my $SEMVER_REGEXP
    = qr{^(?P<major>0|[1-9]\d*)\.(?P<minor>0|[1-9]\d*)\.(?P<patch>0|[1-9]\d*)(?:-(?P<prerelease>(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+(?P<buildmetadata>[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$};


sub validate {

    my $self = shift;

    foreach my $test_id (@TESTS) {

        $self->exec_test($test_id);

        if (DEBUG) {

            my $test_messages = scalar @{$self->summary->{$test_id} || []};

            if ($test_messages > 0) {
                say STDERR sprintf('(E) Mandatory Test %s --> found %s validation error(s)', $test_id, $test_messages);
            }

        }

    }

    return @{$self->messages};

}

sub TEST_6_1_1 {

    my $self = shift;

    my $product_ids = $CSAF::CACHE->{products} || {};

    my @product_statuses = (
        'first_affected',     'first_fixed',   'fixed',       'known_affected',
        'known_not_affected', 'last_affected', 'recommended', 'under_investigation',
    );

    $self->csaf->vulnerabilities->each(sub {

        my ($vulnerability, $vuln_idx) = @_;

        # /vulnerabilities[]/product_status/first_affected[]
        # /vulnerabilities[]/product_status/first_fixed[]
        # /vulnerabilities[]/product_status/fixed[]
        # /vulnerabilities[]/product_status/known_affected[]
        # /vulnerabilities[]/product_status/known_not_affected[]
        # /vulnerabilities[]/product_status/last_affected[]
        # /vulnerabilities[]/product_status/recommended[]
        # /vulnerabilities[]/product_status/under_investigation[]

        foreach my $product_status (@product_statuses) {

            my $method   = $vulnerability->product_status->can($product_status);
            my @products = @{$method->($vulnerability->product_status)};

            foreach my $product (@products) {
                if (!first { $product eq $_ } keys %{$product_ids}) {
                    $self->add_message(CSAF::Validator::Message->new(
                        category => 'mandatory',
                        path     => "/vulnerabilities/$vuln_idx/product_status/$product_status",
                        code     => '6.1.1',
                        message  => "Missing Definition of Product ID ($product)"
                    ));
                }
            }

        }


        # /vulnerabilities[]/scores[]/products[]

        $vulnerability->scores->each(sub {

            my ($score, $score_idx) = @_;

            foreach my $product (@{$score->products}) {
                if (!first { $product eq $_ } keys %{$product_ids}) {
                    $self->add_message(CSAF::Validator::Message->new(
                        category => 'mandatory',
                        path     => "/vulnerabilities/$vuln_idx/scores/$score_idx/products",
                        code     => '6.1.1',
                        message  => "Missing Definition of Product ID ($product)"
                    ));
                }
            }

        });


        # /vulnerabilities[]/remediations[]/product_ids[]

        $vulnerability->remediations->each(sub {

            my ($remediation, $remediation_idx) = @_;

            foreach my $product (@{$remediation->product_ids}) {
                if (!first { $product eq $_ } keys %{$product_ids}) {
                    $self->add_message(CSAF::Validator::Message->new(
                        category => 'mandatory',
                        path     => "/vulnerabilities/$vuln_idx/remediations/$remediation_idx/product_ids",
                        code     => '6.1.1',
                        message  => "Missing Definition of Product ID ($product)"
                    ));
                }
            }

        });


        # /vulnerabilities[]/threats[]/product_ids[]

        $vulnerability->threats->each(sub {

            my ($threat, $threat_idx) = @_;

            foreach my $product (@{$threat->product_ids}) {
                if (!first { $product eq $_ } keys %{$product_ids}) {
                    $self->add_message(CSAF::Validator::Message->new(
                        category => 'mandatory',
                        path     => "/vulnerabilities/$vuln_idx/threats/$threat_idx/product_ids",
                        code     => '6.1.1',
                        message  => "Missing Definition of Product ID ($product)"
                    ));
                }
            }

        });

    });


    # /product_tree/product_groups[]/product_ids[]

    $self->csaf->product_tree->product_groups->each(sub {

        my ($product_group, $product_group_idx) = @_;

        foreach my $product (@{$product_group->product_ids}) {
            if (!first { $product eq $_ } keys %{$product_ids}) {
                $self->add_message(CSAF::Validator::Message->new(
                    category => 'mandatory',
                    path     => "/product_tree/product_groups/$product_group_idx/product_ids",
                    code     => '6.1.1',
                    message  => "Missing Definition of Product ID ($product)"
                ));
            }
        }

    });


    # /product_tree/relationships[]/product_reference
    # /product_tree/relationships[]/relates_to_product_reference

    $self->csaf->product_tree->relationships->each(sub {

        my ($relationship, $rel_idx) = @_;

        if (my $product = $relationship->product_reference) {

            if (!first { $product eq $_ } keys %{$product_ids}) {
                $self->add_message(CSAF::Validator::Message->new(
                    category => 'mandatory',
                    path     => "/product_tree/relationships/$rel_idx/product_reference",
                    code     => '6.1.1',
                    message  => "Missing Definition of Product ID ($product)"
                ));
            }

        }

        if (my $product = $relationship->relates_to_product_reference) {

            if (!first { $product eq $_ } keys %{$product_ids}) {
                $self->add_message(CSAF::Validator::Message->new(
                    category => 'mandatory',
                    path     => "/product_tree/relationships/$rel_idx/relates_to_product_reference",
                    code     => '6.1.1',
                    message  => "Missing Definition of Product ID ($product)"
                ));
            }

        }

    });


}

sub TEST_6_1_2 {

    my $self = shift;

    if ($self->csaf->product_tree->branches->size) {

        my @product_ids = ();

        $self->csaf->product_tree->branches->each(sub {
            my ($branch) = @_;
            push @product_ids, collect_product_ids($branch);
        });

        if (duplicates @product_ids) {

            $self->add_message(CSAF::Validator::Message->new(
                category => 'mandatory',
                path     => '/product_tree/branches[](/branches[])*/product/product_id',
                code     => '6.1.2',
                message  => 'Multiple Definition of Product ID'
            ));

        }

    }

    if ($self->csaf->product_tree->full_product_names->size) {

        my @product_ids = ();

        $self->csaf->product_tree->full_product_names->each(sub {
            my ($product, $idx) = @_;
            push @product_ids, collect_product_ids($product);
        });

        if (duplicates @product_ids) {

            $self->add_message(CSAF::Validator::Message->new(
                category => 'mandatory',
                path     => '/product_tree/full_product_names[]/product_id',
                code     => '6.1.2',
                message  => 'Multiple Definition of Product ID'
            ));

        }

    }

    if ($self->csaf->product_tree->relationships->size) {

        my @product_ids = ();

        $self->csaf->product_tree->relationships->each(sub {

            my ($relationship, $rel_idx) = @_;

            if (my $product_id = $relationship->full_product_name->product_id) {
                push @product_ids, $product_id;
            }

            if (duplicates @product_ids) {

                $self->add_message(CSAF::Validator::Message->new(
                    category => 'mandatory',
                    path     => "/product_tree/relationships/$rel_idx/full_product_name/product_id",
                    code     => '6.1.2',
                    message  => 'Multiple Definition of Product ID'
                ));

            }

        });

    }

}

sub TEST_6_1_3 {

    my $self = shift;

    $self->csaf->product_tree->relationships->each(sub {

        my ($relationship, $rel_idx) = @_;

        if ($relationship->product_reference eq $relationship->full_product_name->product_id) {
            $self->add_message(CSAF::Validator::Message->new(
                category => 'mandatory',
                path     => "/product_tree/relationships/$rel_idx/full_product_name/product_id",
                code     => '6.1.3',
                message  => 'Circular Definition of Product ID'
            ));
        }

        if ($relationship->relates_to_product_reference eq $relationship->full_product_name->product_id) {
            $self->add_message(CSAF::Validator::Message->new(
                category => 'mandatory',
                path     => "/product_tree/relationships/$rel_idx/full_product_name/product_id",
                code     => '6.1.3',
                message  => 'Circular Definition of Product ID'
            ));
        }

    });

}

sub TEST_6_1_4 {

    my $self = shift;

    return unless $self->csaf->vulnerabilities->size;

    my $group_ids = $CSAF::CACHE->{groups} || {};

    $self->csaf->vulnerabilities->each(sub {

        my ($vulnerability, $vuln_idx) = @_;

        $vulnerability->threats->each(sub {

            my ($threat, $threat_idx) = @_;

            foreach my $group_id (@{$threat->group_ids}) {

                if (!first { $group_id eq $_ } keys %{$group_ids}) {

                    $self->add_message(CSAF::Validator::Message->new(
                        category => 'mandatory',
                        path     => "/vulnerabilities/$vuln_idx/threats/$threat_idx/group_ids",
                        code     => '6.1.4',
                        message  => 'Missing Definition of Product Group ID'
                    ));

                }
            }

        });

    });

}

sub TEST_6_1_5 {

    my $self = shift;

    my $check = {};

    $self->csaf->product_tree->product_groups->each(sub {

        my ($group, $group_idx) = @_;

        foreach my $product_id (@{$group->product_ids}) {

            $check->{$product_id}++;

            if ($check->{$product_id} > 1) {
                $self->add_message(CSAF::Validator::Message->new(
                    category => 'mandatory',
                    path     => "/product_tree/product_groups/$group_idx/group_id",
                    code     => '6.1.5',
                    message  => 'Multiple Definition of Product Group ID'
                ));
            }

        }

    });

}

sub TEST_6_1_6 {

    my $self = shift;

    return unless $self->csaf->vulnerabilities->size;

    $self->csaf->vulnerabilities->each(sub {

        my ($vulnerability, $vuln_idx) = @_;

        my $product_status = $vulnerability->product_status;

        my @affected_group = uniq(
            @{$product_status->first_affected},
            @{$product_status->known_affected},
            @{$product_status->last_affected}
        );

        my @not_affected_group        = uniq(@{$product_status->known_not_affected});
        my @fixed_group               = uniq(@{$product_status->first_fixed}, @{$product_status->fixed});
        my @under_investigation_group = uniq(@{$product_status->under_investigation});

        my @check = (@affected_group, @not_affected_group, @fixed_group, @under_investigation_group);

        if (duplicates @check) {

            $self->add_message(CSAF::Validator::Message->new(
                category => 'mandatory',
                path     => "/vulnerabilities/$vuln_idx/product_status",
                code     => '6.1.6',
                message  => 'Contradicting Product Status'
            ));

        }

    });

}

sub TEST_6_1_7 {

    my $self = shift;

    $self->csaf->vulnerabilities->each(sub {

        my ($vulnerability, $vuln_idx) = @_;

        my $check = {};

        $vulnerability->scores->each(sub {

            my ($score, $score_idx) = @_;

            foreach my $product (@{$score->products}) {

                $check->{$product}++;

                if ($check->{$product} > 1) {
                    $self->add_message(CSAF::Validator::Message->new(
                        category => 'mandatory',
                        path     => "/vulnerabilities/$vuln_idx/score/$score_idx/products",
                        code     => '6.1.7',
                        message  => 'Multiple Scores with same Version per Product'
                    ));
                }

            }
        });

    });

}

sub TEST_6_1_8 {

    # /vulnerabilities[]/scores[]/cvss_v2
    # /vulnerabilities[]/scores[]/cvss_v3

    my $self = shift;

    my $SCHEMAS = {
        cvss2 => {'$ref' => 'https://www.first.org/cvss/cvss-v2.0.json'},
        cvss3 => {
            oneOf => [
                {'$ref' => 'https://www.first.org/cvss/cvss-v3.0.json'},
                {'$ref' => 'https://www.first.org/cvss/cvss-v3.1.json'}
            ]
        }
    };

    $self->csaf->vulnerabilities->each(sub {

        my ($vulnerability, $vuln_idx) = @_;

        $vulnerability->scores->each(sub {

            my ($score, $score_idx) = @_;

            if (my $cvss3 = $score->cvss_v3) {

                my $jv = JSON::Validator->new;

                $jv->cache_paths([schema_cache_path]);
                $jv->schema($SCHEMAS->{cvss3});

                my @schema_errors = $jv->validate($cvss3->TO_JSON);

                foreach my $schema_error (@schema_errors) {
                    $self->add_message(CSAF::Validator::Message->new(
                        category => 'mandatory',
                        path     => "/vulnerabilities/$vuln_idx/scores/$score_idx/cvss_v3" . $schema_error->path,
                        code     => '6.1.8',
                        message  => sprintf('Invalid CVSS: %s', $schema_error->message)
                    ));
                }

            }

            if (my $cvss2 = $score->cvss_v2) {

                my $jv = JSON::Validator->new;

                $jv->cache_paths([schema_cache_path]);
                $jv->schema($SCHEMAS->{cvss2});

                my @schema_errors = $jv->validate($cvss2->TO_JSON);

                foreach my $schema_error (@schema_errors) {
                    $self->add_message(CSAF::Validator::Message->new(
                        category => 'mandatory',
                        path     => "/vulnerabilities/$vuln_idx/scores/$score_idx/cvss_v2" . $schema_error->path,
                        code     => '6.1.8',
                        message  => sprintf('Invalid CVSS: %s', $schema_error->message)
                    ));
                }

            }

        });
    });

}

sub TEST_6_1_9 {    # TODO INCOMPLETE

    my $self = shift;

    DEBUG and say STDERR '(W) Incomplete Mandatory Test 6.1.9';

    my $cvss2_severity = {LOW => [0, 3.9], MEDIUM => [4, 6.9], HIGH => [7, 10]};
    my $cvss3_severity = {LOW => [0, 3.9], MEDIUM => [4, 6.9], HIGH => [7, 8.9], CRITICAL => [9, 10]};

    $self->csaf->vulnerabilities->each(sub {

        my ($vulnerability, $vuln_idx) = @_;

        $vulnerability->scores->each(sub {

            my ($score, $score_idx) = @_;

            if (my $cvss3 = $score->cvss_v3) {

                return if (!$cvss3->baseSeverity);

                my ($score_min, $score_max) = @{$cvss3_severity->{$cvss3->baseSeverity}};

                unless ($cvss3->baseScore >= $score_min && $cvss3->baseScore <= $score_max) {
                    $self->add_message(CSAF::Validator::Message->new(
                        category => 'mandatory',
                        path     => "/vulnerabilities/$vuln_idx/score/$score_idx/cvss_v3",
                        code     => '6.1.9',
                        message  => 'Invalid CVSS computation'
                    ));
                }

            }

        });
    });
}

sub TEST_6_1_10 {    # TODO INCOMPLETE

    my $self = shift;

    DEBUG and say STDERR '(W) Incomplete Mandatory Test 6.1.10';

    $self->csaf->vulnerabilities->each(sub {

        my ($vulnerability, $vuln_idx) = @_;

        $vulnerability->scores->each(sub {

            my ($score, $score_idx) = @_;

            # CVSS 2.0

            if (my $cvss = $score->cvss_v2) {
            }

            # CVSS 3.x

            if (my $cvss = $score->cvss_v3) {

                my $vector_string = $cvss->vectorString;

                return unless $vector_string;

                my $decoded_vector_string = decode_cvss3_vector_string($vector_string);

                foreach my $decoded_metric (keys %{$decoded_vector_string}) {

                    my $decoded_value = $decoded_vector_string->{$decoded_metric};
                    my $doc_value     = $cvss->$decoded_metric();

                    if ($doc_value && $doc_value ne $decoded_value) {
                        $self->add_message(CSAF::Validator::Message->new(
                            category => 'mandatory',
                            path     => "/vulnerabilities/$vuln_idx/scores/$score_idx/cvss_v3/$decoded_metric",
                            code     => '6.1.10',
                            message  => 'Inconsistent CVSS'
                        ));
                    }
                }

            }

        });

    });

}

sub TEST_6_1_11 {

    my $self = shift;

    $self->csaf->vulnerabilities->each(sub {

        my ($vulnerability, $vuln_idx) = @_;

        if (my $cwe_id = $vulnerability->cwe->id) {

            if (!get_weakness_name($cwe_id)) {

                $self->add_message(CSAF::Validator::Message->new(
                    category => 'mandatory',
                    path     => "/vulnerabilities/$vuln_idx/cwe/id",
                    code     => '6.1.11',
                    message  => 'Unknown CWE'
                ));

            }

        }

        if (my $cwe_name = $vulnerability->cwe->name) {

            if (get_weakness_name($vulnerability->cwe->id) ne $cwe_name) {

                $self->add_message(CSAF::Validator::Message->new(
                    category => 'mandatory',
                    path     => "/vulnerabilities/$vuln_idx/cwe/name",
                    code     => '6.1.11',
                    message  => 'CWE name differs from the official CWE catalog'
                ));

            }
        }

    });

}

sub TEST_6_1_12 {    # TODO INCOMPLETE

    my $self = shift;

    DEBUG and say STDERR '(W) Incomplete Mandatory Test 6.1.12';

    my $document_lang        = $self->csaf->document->lang;
    my $document_source_lang = $self->csaf->document->source_lang;

    if ($document_lang && $document_lang !~ /[a-z]{2,3}/) {
        $self->add_message(CSAF::Validator::Message->new(
            category => 'mandatory',
            path     => '/document/lang',
            code     => '6.1.12',
            message  => 'Language code is invalid'
        ));
    }

    if ($document_source_lang && $document_source_lang !~ /[a-z]{2,3}/) {
        $self->add_message(CSAF::Validator::Message->new(
            category => 'mandatory',
            path     => '/document/source_lang',
            code     => '6.1.12',
            message  => 'Language code is invalid'
        ));
    }

}

sub TEST_6_1_13 {    # TODO INCOMPLETE

    my $self = shift;

    DEBUG and say STDERR '(W) Incomplete Mandatory Test 6.1.13';

    # /product_tree/branches[](/branches[])*/product/product_identification_helper/purl

    # /product_tree/full_product_names[]/product_identification_helper/purl

    $self->csaf->product_tree->full_product_names->each(sub {

        my ($full_product_name, $idx) = @_;

        return unless $full_product_name->product_identification_helper;

        if (my $purl = $full_product_name->product_identification_helper->purl) {
            $self->_TEST_6_1_13_check_purl($purl,
                "/product_tree/full_product_names/$idx/product_identification_helper/purl");
        }

    });

    # /product_tree/relationships[]/full_product_name/product_identification_helper/purl

    $self->csaf->product_tree->relationships->each(sub {

        my ($relationship, $rel_idx) = @_;

        return unless $relationship->full_product_name;
        return unless $relationship->full_product_name->product_identification_helper;

        if (my $purl = $relationship->full_product_name->product_identification_helper->purl) {
            $self->_TEST_6_1_13_check_purl($purl,
                "/product_tree/relationships/$rel_idx/full_product_name/product_identification_helper/purl");
        }

    });

}

sub TEST_6_1_14 {

    my $self = shift;

    # TODO use semver for non-decimal version

    my $last_rev_version = $self->csaf->document->tracking->revision_history->last->number;
    my $doc_version      = $self->csaf->document->tracking->version;

    my $revision_dates = {};

    foreach my $revision (@{$self->csaf->document->tracking->revision_history->items}) {
        $revision_dates->{$revision->date->epoch} = $revision->number;
    }

    my $prev_revision_number = 0;

    foreach (sort { $a <=> $b } keys %{$revision_dates}) {

        my $revision_number = $revision_dates->{$_};

        eval {
            if ($prev_revision_number && version->parse($prev_revision_number) > version->parse($revision_number)) {

                return $self->add_message(CSAF::Validator::Message->new(
                    category => 'mandatory',
                    path     => '/document/tracking/revision_history',
                    code     => '6.1.14',
                    message  => 'Sorted Revision History'
                ));

            }
        };
        $prev_revision_number = $revision_number;
    }

    eval {

        if (version->parse($last_rev_version) > version->parse($doc_version)) {

            return $self->add_message(CSAF::Validator::Message->new(
                category => 'mandatory',
                path     => '/document/tracking/revision_history',
                code     => '6.1.14',
                message  => 'Sorted Revision History'
            ));

        }

    };

}

sub TEST_6_1_15 {

    my $self = shift;

    if ($self->csaf->document->publisher->category eq 'translator' && !$self->csaf->document->source_lang) {

        $self->add_message(CSAF::Validator::Message->new(
            category => 'mandatory',
            path     => '/document/publisher/category',
            code     => '6.1.15',
            message  => 'Missing "source_lang" for "translator" publisher category'
        ));

    }

}

sub TEST_6_1_16 {

    my $self = shift;

    my $current_version = 0;
    my $last_version    = undef;

    # TODO  Use semver instead of version module
    eval {

        foreach my $revision (@{$self->csaf->document->tracking->revision_history->items}) {
            $last_version = $revision->number if (version->parse($current_version) < version->parse($revision->number));
            $current_version = $revision->number;
        }

        if (version->parse($last_version) > version->parse($self->csaf->document->tracking->version)) {

            $self->add_message(CSAF::Validator::Message->new(
                category => 'mandatory',
                path     => '/document/tracking/version',
                code     => '6.1.16',
                message  => 'Detected newer revision of document'
            ));

        }

    }

}

sub TEST_6_1_17 {

    my $self = shift;

    my $document_version = $self->csaf->document->tracking->version;
    my $document_status  = $self->csaf->document->tracking->status;

    $document_version =~ /$SEMVER_REGEXP/;

    if ($document_status ne 'draft' && ($document_version eq '0' || (%+ && ($+{major} == 0 || $+{prerelease})))) {
        $self->add_message(CSAF::Validator::Message->new(
            category => 'mandatory',
            path     => '/document/tracking/version',
            code     => '6.1.17',
            message  => 'Incompatible document status & version'
        ));
    }

}

sub TEST_6_1_18 {

    my $self = shift;

    my $document_status    = $self->csaf->document->tracking->status;
    my $document_revisions = $self->csaf->document->tracking->revision_history;

    if ($document_status =~ /(final|interim)/) {

        $document_revisions->each(sub {

            my ($revision, $rev_idx) = @_;

            $revision->number =~ /$SEMVER_REGEXP/;

            if ($revision->number eq '0' || (%+ && ($+{major} == 0))) {
                $self->add_message(CSAF::Validator::Message->new(
                    category => 'mandatory',
                    path     => "/document/tracking/revision_history/$rev_idx/number",
                    code     => '6.1.18',
                    message  => 'Incompatible revision number with document status'
                ));
            }

        });

    }

}

sub TEST_6_1_19 {

    my $self = shift;

    my $document_revisions = $self->csaf->document->tracking->revision_history;

    $document_revisions->each(sub {

        my ($revision, $rev_idx) = @_;

        $revision->number =~ /$SEMVER_REGEXP/;

        if (%+ && $+{prerelease}) {
            $self->add_message(CSAF::Validator::Message->new(
                category => 'mandatory',
                path     => "/document/tracking/revision_history/$rev_idx/number",
                code     => '6.1.19',
                message  => 'Revision History contains a pre-release'
            ));
        }

    });

}

sub TEST_6_1_20 {

    my $self = shift;

    my $document_version = $self->csaf->document->tracking->version;
    my $document_status  = $self->csaf->document->tracking->status;

    if ($document_status =~ /(final|interim)/) {

        $document_version =~ /$SEMVER_REGEXP/;

        if (%+ && $+{prerelease}) {
            $self->add_message(CSAF::Validator::Message->new(
                category => 'mandatory',
                path     => '/document/tracking/version',
                code     => '6.1.20',
                message  => qq{Detected a pre-release version with "$document_status" document}
            ));
        }
    }


}

sub TEST_6_1_21 {

    my $self = shift;

    my @revision_numbers = ();

    foreach my $revision (@{$self->csaf->document->tracking->revision_history->items}) {
        push @revision_numbers, $revision->number if ($revision->number =~ /^(\d+)$/);
    }

    my $prev_revision_number = 0;

    foreach my $revision_number (sort @revision_numbers) {
        if (($revision_number - $prev_revision_number) > 1) {
            return $self->add_message(CSAF::Validator::Message->new(
                category => 'mandatory',
                path     => '/document/tracking/revision_history',
                code     => '6.1.21',
                message  => 'Missing Item in Revision History'
            ));
        }
        $prev_revision_number = $revision_number;
    }

}

sub TEST_6_1_22 {

    my $self = shift;

    my $check = {};

    $self->csaf->document->tracking->revision_history->each(sub {

        my ($revision, $rev_idx) = @_;

        $check->{$revision->number}++;

        if ($check->{$revision->number} > 1) {

            $self->add_message(CSAF::Validator::Message->new(
                category => 'mandatory',
                path     => "/document/tracking/revision_history/$rev_idx/number",
                code     => '6.1.22',
                message  => 'Multiple Definition in Revision History'
            ));

        }

    });

}

sub TEST_6_1_23 {

    my $self = shift;

    my $check = {};

    $self->csaf->vulnerabilities->each(sub {

        my ($vulnerability, $vuln_idx) = @_;

        return unless $vulnerability->cve;

        $check->{$vulnerability->cve}++;

        if ($check->{$vulnerability->cve} > 1) {
            $self->add_message(CSAF::Validator::Message->new(
                category => 'mandatory',
                path     => "/vulnerabilities/$vuln_idx/cve",
                code     => '6.1.23',
                message  => sprintf('Multiple Use of Same CVE (%s)', $vulnerability->cve)
            ));
        }

    });

}

sub TEST_6_1_24 {

    my $self = shift;

    $self->csaf->vulnerabilities->each(sub {

        my ($vulnerability, $vuln_idx) = @_;

        return if (!$vulnerability->involvements->size);

        my $check = {};

        foreach my $involvement ($vulnerability->involvements->each) {

            $check->{$involvement->date->epoch} //= {};
            $check->{$involvement->date->epoch}->{$involvement->party} //= 0;
            $check->{$involvement->date->epoch}->{$involvement->party}++;

            if ($check->{$involvement->date->epoch}->{$involvement->party} > 1) {
                return $self->add_message(CSAF::Validator::Message->new(
                    category => 'mandatory',
                    path     => "/vulnerabilities/$vuln_idx/involvements",
                    code     => '6.1.24',
                    message  => 'Multiple Definition in Involvements'
                ));
            }
        }

    });

}

sub TEST_6_1_25 {    # TODO INCOMPLETE

    my $self = shift;

    DEBUG and say STDERR '(W) Incomplete Mandatory Test 6.1.25';

    # /product_tree/branches[](/branches[])*/product/product_identification_helper/hashes[]/file_hashes

    $self->_TEST_6_1_25_branches($self->csaf->product_tree->branches, '/product_tree/branches');

    # /product_tree/relationships[]/full_product_name/product_identification_helper/hashes[]/file_hashes

    # TODO INCOMPLETE TEST

    # /product_tree/full_product_names[]/product_identification_helper/hashes[]/file_hashes

    my $full_product_names = $self->csaf->product_tree->full_product_names;

    $full_product_names->each(sub {

        my ($full_product_name, $idx) = @_;

        return unless $full_product_name->product_identification_helper;

        $full_product_name->product_identification_helper->hashes->each(sub {

            my ($hash, $hash_idx) = @_;

            my $check = {};

            $hash->file_hashes->each(sub {

                my ($file_hash, $file_hash_idx) = @_;

                $check->{$file_hash->algorithm}++;

                if ($check->{$file_hash->algorithm} > 1) {

                    my $path = "/product_tree/full_product_names/$idx/product_identification_helper"
                        . "/hashes/$hash_idx/file_hashes/$file_hash_idx/";

                    $self->add_message(CSAF::Validator::Message->new(
                        category => 'mandatory',
                        path     => $path,
                        code     => '6.1.25',
                        message  => sprintf('Multiple Use of Same Hash Algorithm (%s)', $file_hash->algorithm)
                    ));

                }

            });

        });

    });

}

sub TEST_6_1_26 {

    my $self = shift;

    my $document_category = $self->csaf->document->category;

    if ($document_category
        !~ /(csaf_base|csaf_security_incident_response|csaf_informational_advisory|csaf_security_advisory|csaf_vex)/)
    {

        if ($document_category =~ /^csaf_/i) {
            $self->add_message(CSAF::Validator::Message->new(
                category => 'mandatory',
                path     => '/document/category',
                code     => '6.1.26',
                message  => 'Reserved CSAF document category prefix'
            ));
        }

        my $check_similar_category = 0;

        my @similar_categories = qw(
            informationaladvisory
            securityincidentresponse
            securityadvisory
            vex
        );

        (my $normalized_category = lc $document_category) =~ s/[-_\s]//g;

        if (first { $normalized_category =~ /^$_/ } @similar_categories) {
            $self->add_message(CSAF::Validator::Message->new(
                category => 'mandatory',
                path     => '/document/category',
                code     => '6.1.26',
                message  => 'Prohibited document category'
            ));
        }

    }
}

sub TEST_6_1_27_1 {

    my $self = shift;

    my $document_category = $self->csaf->document->category;
    my $document_notes    = $self->csaf->document->notes->items;

    return if (not $document_category =~ /(csaf_informational_advisory|csaf_security_incident_response)/);

    my $have_valid_category = undef;

    foreach my $note (@{$document_notes}) {
        foreach my $category (qw(description details general summary)) {
            $have_valid_category = 1 if ($note->category eq $category);
        }
    }

    if (not $have_valid_category) {
        $self->add_message(CSAF::Validator::Message->new(
            category => 'mandatory',
            path     => '/document/notes',
            code     => '6.1.27.1',
            message  =>
                'The document notes do not contain an item which has a category of "description", "details", "general" or "summary"'
        ));
    }

}

sub TEST_6_1_27_2 {

    my $self = shift;

    my $document_category   = $self->csaf->document->category;
    my $document_references = $self->csaf->document->references->items;

    return if (not $document_category =~ /(csaf_informational_advisory|csaf_security_incident_response)/);

    my $have_external_references = undef;

    foreach my $reference (@{$document_references}) {
        $have_external_references = 1 if ($reference->category eq 'external');
    }

    if (not $have_external_references) {
        $self->add_message(CSAF::Validator::Message->new(
            category => 'mandatory',
            path     => '/document/references',
            code     => '6.1.27.2',
            message  => 'The document references do not contain any item which has the category "external"'
        ));
    }

}

sub TEST_6_1_27_3 {

    my $self = shift;

    if ($self->csaf->document->category eq 'csaf_informational_advisory' && @{$self->csaf->vulnerabilities->items}) {

        $self->add_message(CSAF::Validator::Message->new(
            category => 'mandatory',
            path     => '/vulnerabilities',
            code     => '6.1.27.3',
            message  =>
                'The "csaf_informational_advisory" profile deals with information that are not classified as vulnerabilities. Therefore, it must not have the "/vulnerabilities" element'
        ));

    }

}

sub TEST_6_1_27_4 {

    my $self = shift;

    my $document_category = $self->csaf->document->category;
    my $product_tree      = $self->csaf->product_tree->TO_CSAF;    # TODO !?

    if ($document_category =~ /(csaf_security_advisory|csaf_vex)/ && !$product_tree) {

        $self->add_message(CSAF::Validator::Message->new(
            category => 'mandatory',
            path     => '/product_tree',
            code     => '6.1.27.4',
            message  => 'The element "/product_tree" does not exist'
        ));

    }

}

sub TEST_6_1_27_5 {

    my $self = shift;

    return if (not $self->csaf->document->category =~ /(csaf_security_advisory|csaf_vex)/);

    $self->csaf->vulnerabilities->each(sub {

        my ($vulnerability, $vuln_idx) = @_;

        if (!$vulnerability->notes->size) {
            $self->add_message(CSAF::Validator::Message->new(
                category => 'mandatory',
                path     => "/vulnerabilities/$vuln_idx",
                code     => '6.1.27.5',
                message  => 'The vulnerability item has no "notes" element'
            ));
        }

    });

}

sub TEST_6_1_27_6 {

    my $self = shift;

    return if (not $self->csaf->document->category eq 'csaf_security_advisory');

    $self->csaf->vulnerabilities->each(sub {

        my ($vulnerability, $vuln_idx) = @_;

        if (!$vulnerability->product_status->TO_CSAF) {
            $self->add_message(CSAF::Validator::Message->new(
                category => 'mandatory',
                path     => "/vulnerabilities/$vuln_idx",
                code     => '6.1.27.6',
                message  => 'The vulnerability item has no "product_status" element'
            ));
        }

    });

}

sub TEST_6_1_27_7 {

    my $self = shift;

    return if (not $self->csaf->document->category eq 'csaf_vex');

    $self->csaf->vulnerabilities->each(sub {

        my ($vulnerability, $vuln_idx) = @_;

        my @check = (
            @{$vulnerability->product_status->fixed},
            @{$vulnerability->product_status->known_affected},
            @{$vulnerability->product_status->known_not_affected},
            @{$vulnerability->product_status->under_investigation}
        );

        unless (@check) {
            $self->add_message(CSAF::Validator::Message->new(
                category => 'mandatory',
                path     => "/vulnerabilities/$vuln_idx/product_status",
                code     => '6.1.27.7',
                message  =>
                    'None of the elements "fixed", "known_affected", "known_not_affected", or "under_investigation" is present in "product_status"'
            ));
        }

    });

}

sub TEST_6_1_27_8 {

    my $self = shift;

    return if (not $self->csaf->document->category eq 'csaf_vex');

    $self->csaf->vulnerabilities->each(sub {

        my ($vulnerability, $vuln_idx) = @_;

        if (!$vulnerability->cve && $vulnerability->ids->size == 0) {
            $self->add_message(CSAF::Validator::Message->new(
                category => 'mandatory',
                path     => "/vulnerabilities/$vuln_idx",
                code     => '6.1.27.8',
                message  => 'None of the elements "cve" or "ids" is present'
            ));
        }

    });

}

sub TEST_6_1_27_9 {

    my $self = shift;

    return if (not $self->csaf->document->category eq 'csaf_vex');
    return unless $self->csaf->vulnerabilities->size;

    my $product_ids = $CSAF::CACHE->{products} || {};

    $self->csaf->vulnerabilities->each(sub {

        my ($vulnerability, $vuln_idx) = @_;

        return unless @{$vulnerability->product_status->known_not_affected};

        my @status_product_ids = @{$vulnerability->product_status->known_not_affected};

        CSAF::Util::List->new(@status_product_ids)->each(sub {

            my ($product_id, $product_id_idx) = @_;

            my $threat_test = 0;
            my $flag_test   = 0;

            $vulnerability->threats->grep(sub { $_->category eq 'impact' })->each(sub {

                my ($threat, $threat_idx) = @_;

                if (first { $product_id eq $_ } @{$threat->product_ids}) {
                    $threat_test = 1;
                    return;
                }

                foreach my $group_id (@{$threat->group_ids}) {

                    if (product_in_group_exists($self->csaf, $product_id, $group_id)) {
                        $threat_test = 1;
                        return;
                    }

                }

                $threat_test = 0;

            });

            $vulnerability->flags->each(sub {

                my ($flag, $flag_idx) = @_;

                if (first { $product_id eq $_ } @{$flag->product_ids}) {
                    $flag_test = 1;
                    return;
                }

                foreach my $group_id (@{$flag->group_ids}) {

                    if (product_in_group_exists($self->csaf, $product_id, $group_id)) {
                        $flag_test = 1;
                        return;
                    }

                }

                $flag_test = 0;

            });

            if (!$flag_test && !$threat_test) {
                $self->add_message(CSAF::Validator::Message->new(
                    category => 'mandatory',
                    path     =>
                        sprintf('/vulnerabilities/%s/product_status/known_not_affected/%s', $vuln_idx, $product_id_idx),
                    code    => '6.1.27.9',
                    message => 'Impact Statement'
                ));
            }

        });

    });

}

sub TEST_6_1_27_10 {

    my $self = shift;

    return if (not $self->csaf->document->category eq 'csaf_vex');
    return unless $self->csaf->vulnerabilities->size;

    my $product_ids = $CSAF::CACHE->{products} || {};

    $self->csaf->vulnerabilities->each(sub {

        my ($vulnerability, $vuln_idx) = @_;

        return unless @{$vulnerability->product_status->known_affected};

        my @status_product_ids = @{$vulnerability->product_status->known_affected};

        CSAF::Util::List->new(@status_product_ids)->each(sub {

            my ($product_id, $product_id_idx) = @_;

            my $threat_test = 0;

            $vulnerability->remediations->each(sub {

                my ($remediation, $remediation_idx) = @_;

                if (first { $product_id eq $_ } @{$remediation->product_ids}) {
                    $threat_test = 1;
                    return;
                }

                foreach my $group_id (@{$remediation->group_ids}) {

                    if (product_in_group_exists($self->csaf, $product_id, $group_id)) {
                        $threat_test = 1;
                        return;
                    }

                }

                $threat_test = 0;

            });

            if (!$threat_test) {
                $self->add_message(CSAF::Validator::Message->new(
                    category => 'mandatory',
                    path     => "/vulnerabilities/$vuln_idx/product_status/known_not_affected/$product_id_idx",
                    code     => '6.1.27.10',
                    message  => 'Action Statement'
                ));
            }

        });

    });

}

sub TEST_6_1_27_11 {

    my $self = shift;

    if (   $self->csaf->document->category =~ /(csaf_security_advisory|csaf_vex)/
        && $self->csaf->vulnerabilities->size == 0)
    {

        $self->add_message(CSAF::Validator::Message->new(
            category => 'mandatory',
            path     => '/vulnerabilities',
            code     => '6.1.27.11',
            message  => 'The element "/vulnerabilities" does not exist'
        ));

    }

}

sub TEST_6_1_28 {

    my $self = shift;

    my $document_lang        = $self->csaf->document->lang;
    my $document_source_lang = $self->csaf->document->source_lang;

    if ($document_lang && $document_source_lang && ($document_lang eq $document_source_lang)) {
        $self->add_message(CSAF::Validator::Message->new(
            category => 'mandatory',
            path     => '/document/lang',
            code     => '6.1.28',
            message  => qq{The document language and the source language have the same value "$document_lang"}
        ));
    }

}

sub TEST_6_1_29 {

    my $self = shift;

    return unless $self->csaf->vulnerabilities->size;

    my $product_ids = $CSAF::CACHE->{products} || {};

    $self->csaf->vulnerabilities->each(sub {

        my ($vulnerability, $vuln_idx) = @_;

        return unless $vulnerability->remediations->size;

        $vulnerability->remediations->each(sub {

            my ($remediation, $remediation_idx) = @_;

            foreach my $product_id (keys %{$product_ids}) {
                if (!first { $product_id eq $_ } @{$remediation->product_ids}) {
                    return $self->add_message(CSAF::Validator::Message->new(
                        category => 'mandatory',
                        path     => "/vulnerabilities/$vuln_idx/remediations/$remediation_idx",
                        code     => '6.1.29',
                        message  => 'Remediation without Product Reference'
                    ));
                }
            }

        });

    });

}

sub TEST_6_1_30 {

    my $self = shift;

    my $document_version   = $self->csaf->document->tracking->version;
    my $document_revisions = $self->csaf->document->tracking->revision_history;

    my $revision_ver_in_semver = 0;
    my $revision_ver_in_int    = 0;

    my $document_ver_in_semver = 0;
    my $document_ver_in_int    = 0;

    $document_revisions->each(sub {

        my ($revision, $rev_idx) = @_;

        if ($revision->number =~ /$SEMVER_REGEXP/) {
            $revision_ver_in_semver++;
        }
        else {
            $revision_ver_in_int++;
        }

    });

    if ($document_version =~ /$SEMVER_REGEXP/) {
        $document_ver_in_semver++;
    }
    else {
        $document_ver_in_int++;
    }

    if ($document_ver_in_int && $revision_ver_in_semver || $document_ver_in_semver && $revision_ver_in_int) {
        $self->add_message(CSAF::Validator::Message->new(
            category => 'mandatory',
            path     => "/document/tracking/version",
            code     => '6.1.30',
            message  => 'Mixed Integer and Semantic Versioning'
        ));
    }

}

sub TEST_6_1_31 {

    my $self = shift;

    return if (not $self->csaf->product_tree);

    $self->_TEST_6_1_31_branches($self->csaf->product_tree->branches, "/product_tree/branches");

}

sub TEST_6_1_32 {

    my $self = shift;

    return unless $self->csaf->vulnerabilities->size;

    my $product_ids = $CSAF::CACHE->{products} || {};

    $self->csaf->vulnerabilities->each(sub {

        my ($vulnerability, $vuln_idx) = @_;

        return unless $vulnerability->flags->size;

        $vulnerability->flags->each(sub {

            my ($flag, $flag_idx) = @_;

            if (!@{$flag->group_ids} && !@{$flag->product_ids}) {
                return $self->add_message(CSAF::Validator::Message->new(
                    category => 'mandatory',
                    path     => "/vulnerabilities/$vuln_idx/flags/$flag_idx",
                    code     => '6.1.32',
                    message  => 'Flag without Product Reference'
                ));
            }

            foreach my $product (keys %{$product_ids}) {

                if (@{$flag->product_ids} && !first { $product eq $_ } @{$flag->product_ids}) {
                    return $self->add_message(CSAF::Validator::Message->new(
                        category => 'mandatory',
                        path     => "/vulnerabilities/$vuln_idx/flags/$flag_idx",
                        code     => '6.1.32',
                        message  => 'Flag without Product Reference'
                    ));
                }

                if (@{$flag->group_ids} && !first { $product eq $_ } @{$flag->group_ids}) {
                    return $self->add_message(CSAF::Validator::Message->new(
                        category => 'mandatory',
                        path     => "/vulnerabilities/$vuln_idx/flags/$flag_idx",
                        code     => '6.1.32',
                        message  => 'Flag without Product Reference'
                    ));
                }
            }

        });

    });

}

sub TEST_6_1_33 {

    my $self = shift;

    return unless $self->csaf->vulnerabilities->size;

    $self->csaf->vulnerabilities->each(sub {

        my ($vulnerability, $vuln_idx) = @_;

        my @product_ids = ();

        $vulnerability->flags->each(sub {

            my ($flag, $flag_idx) = @_;

            foreach my $product_id (@{$flag->product_ids}) {

                if (first { $product_id eq $_ } @product_ids) {
                    return $self->add_message(CSAF::Validator::Message->new(
                        category => 'mandatory',
                        path     => "/vulnerabilities/$vuln_idx/flags/$flag_idx",
                        code     => '6.1.33',
                        message  => 'Multiple Flags with VEX Justification Codes per Product'
                    ));
                }

                push @product_ids, $product_id;

            }

            foreach my $group_id (@{$flag->group_ids}) {

                $self->csaf->product_tree->product_groups->each(sub {

                    my ($group) = @_;

                    if ($group->group_id eq $group_id) {

                        foreach my $product_id (@{$group->product_ids}) {

                            if (first { $product_id eq $_ } @product_ids) {
                                return $self->add_message(CSAF::Validator::Message->new(
                                    category => 'mandatory',
                                    path     => "/vulnerabilities/$vuln_idx/flags/$flag_idx",
                                    code     => '6.1.33',
                                    message  => 'Multiple Flags with VEX Justification Codes per Product'
                                ));
                            }

                            push @product_ids, $product_id;

                        }

                    }

                });

            }

        });

    });

}

sub _TEST_6_1_25_branches {

    my ($self, $branches, $path) = @_;

    $branches->each(sub {

        my ($branch, $branch_idx) = @_;

        $self->_TEST_6_1_25_branches($branch->branches, "$path/$branch_idx/branches");

        if (   $branch->product
            && $branch->product->product_identification_helper
            && $branch->product->product_identification_helper->hashes->size)
        {

            $branch->product->product_identification_helper->hashes->each(sub {

                my ($hash, $hash_idx) = @_;

                my $check = {};

                $hash->file_hashes->each(sub {

                    my ($file_hash, $file_hash_idx) = @_;

                    $check->{$file_hash->algorithm}++;

                    if ($check->{$file_hash->algorithm} > 1) {

                        $self->add_message(CSAF::Validator::Message->new(
                            type => 'Mandatory Test',
                            path =>
                                "/$path/$branch_idx/product_identification_helper/hashes/$hash_idx/file_hashes/$file_hash_idx/",
                            code    => '6.1.25',
                            message => sprintf('Multiple Use of Same Hash Algorithm (%s)', $file_hash->algorithm)
                        ));

                    }

                });

            });

        }

    });
}

sub _TEST_6_1_31_branches {

    my ($self, $branches, $path) = @_;

    my @bad_ranges = qw( < <= > >= );
    my @bad_words  = qw( after all before earlier later prior versions );

    $branches->each(sub {

        my ($branch, $idx) = @_;

        $self->_TEST_6_1_31_branches($branch->branches, "$path/$idx/branches");

        if ($branch->category eq 'product_version') {

            my @branch_name_parts = split /\s/, lc $branch->name;

            foreach my $word (@bad_words) {

                if (first { $word eq $_ } @branch_name_parts) {
                    $self->add_message(CSAF::Validator::Message->new(
                        category => 'mandatory',
                        path     => "$path/name",
                        code     => '6.1.31',
                        message  => 'Version Range in Product Version'
                    ));
                }
            }

            foreach my $range (@bad_ranges) {
                if (lc $branch->name =~ /$range/) {
                    $self->add_message(CSAF::Validator::Message->new(
                        category => 'mandatory',
                        path     => "$path/name",
                        code     => '6.1.31',
                        message  => 'Version Range in Product Version'
                    ));
                }
            }
        }

    });
}

sub _TEST_6_1_13_check_purl {

    my ($self, $purl, $path) = @_;

    my $is_invalid = 0;

    $is_invalid = 1 if $purl !~ /$PURL_REGEX/;

    eval { URI::PackageURL->from_string($purl) };

    if ($@) {
        $is_invalid = 1 if $@;
        DEBUG and say STDERR "$@";
    }

    if ($is_invalid) {
        $self->add_message(CSAF::Validator::Message->new(
            category => 'mandatory',
            path     => $path,
            code     => '6.1.13',
            message  => 'Invalid purl'
        ));
    }

}

1;
