package CSAF::Type;

use 5.010001;
use strict;
use warnings;
use utf8;

use Carp;

use constant TYPE_CLASSES => {
    acknowledgment                => 'CSAF::Type::Acknowledgment',
    acknowledgments               => 'CSAF::Type::Acknowledgments',
    aggregate_severity            => 'CSAF::Type::AggregateSeverity',
    branch                        => 'CSAF::Type::Branch',
    branches                      => 'CSAF::Type::Branches',
    cvss_v2                       => 'CSAF::Type::CVSS2',
    cvss_v3                       => 'CSAF::Type::CVSS3',
    cwe                           => 'CSAF::Type::CWE',
    distribution                  => 'CSAF::Type::Distribution',
    document                      => 'CSAF::Type::Document',
    engine                        => 'CSAF::Type::Engine',
    file_hash                     => 'CSAF::Type::FileHash',
    file_hashes                   => 'CSAF::Type::FileHashes',
    flag                          => 'CSAF::Type::Flag',
    flags                         => 'CSAF::Type::Flags',
    full_product_name             => 'CSAF::Type::FullProductName',
    full_product_names            => 'CSAF::Type::FullProductNames',
    generator                     => 'CSAF::Type::Generator',
    generic_uri                   => 'CSAF::Type::GenericURI',
    generic_uris                  => 'CSAF::Type::GenericURIs',
    hash                          => 'CSAF::Type::Hash',
    hashes                        => 'CSAF::Type::Hashes',
    id                            => 'CSAF::Type::ID',
    ids                           => 'CSAF::Type::IDs',
    note                          => 'CSAF::Type::Note',
    notes                         => 'CSAF::Type::Notes',
    product                       => 'CSAF::Type::Product',
    product_group                 => 'CSAF::Type::ProductGroup',
    product_groups                => 'CSAF::Type::ProductGroups',
    product_identification_helper => 'CSAF::Type::ProductIdentificationHelper',
    product_status                => 'CSAF::Type::ProductStatus',
    product_tree                  => 'CSAF::Type::ProductTree',
    publisher                     => 'CSAF::Type::Publisher',
    reference                     => 'CSAF::Type::Reference',
    references                    => 'CSAF::Type::References',
    relationship                  => 'CSAF::Type::Relationship',
    relationships                 => 'CSAF::Type::Relationships',
    remediation                   => 'CSAF::Type::Remediation',
    remediations                  => 'CSAF::Type::Remediations',
    restart_required              => 'CSAF::Type::RestartRequired',
    revision                      => 'CSAF::Type::Revision',
    revision_history              => 'CSAF::Type::RevisionHistory',
    score                         => 'CSAF::Type::Score',
    scores                        => 'CSAF::Type::Scores',
    threat                        => 'CSAF::Type::Threat',
    threats                       => 'CSAF::Type::Threats',
    tlp                           => 'CSAF::Type::TLP',
    tracking                      => 'CSAF::Type::Tracking',
    vulnerabilities               => 'CSAF::Type::Vulnerabilities',
    vulnerability                 => 'CSAF::Type::Vulnerability',
};


sub new {

    my ($self, %params) = @_;

    my $name  = delete $params{name};
    my $value = delete $params{value};

    return _build(lc $name, $value);

}

sub name {
    my ($self, $name, $value) = @_;
    return _build(lc $name, $value);
}

sub _build {

    my ($name, $value) = @_;

    my $class = TYPE_CLASSES->{$name} or Carp::croak 'Unknown CSAF type';

    if ($class->can('new') or eval "require $class; 1") {
        local $Carp::Internal{caller()} = 1;
        return $class->new($value);
    }

}

1;
