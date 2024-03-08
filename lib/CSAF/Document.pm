package CSAF::Document;

use 5.010001;
use strict;
use warnings;
use utf8;

use CSAF::Type::Document;
use CSAF::Type::ProductTree;
use CSAF::Type::Vulnerabilities;

use Moo;
extends 'CSAF::Type::Base';

sub document {
    my ($self, %params) = @_;
    $self->{document} ||= CSAF::Type::Document->new(%params);
}

sub product_tree {
    my ($self, %params) = @_;
    $self->{product_tree} ||= CSAF::Type::ProductTree->new(%params);
}

sub vulnerabilities {
    my ($self, %params) = @_;
    $self->{vulnerabilities} ||= CSAF::Type::Vulnerabilities->new(%params);
}

1;
