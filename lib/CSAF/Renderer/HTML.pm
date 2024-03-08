package CSAF::Renderer::HTML;

use 5.010001;
use strict;
use warnings;
use utf8;

use CSAF::Util qw(tt_templates_path);
use Template;

use Moo;
extends 'CSAF::Renderer::Base';

sub render {

    my ($self, %options) = @_;

    my $products       = $CSAF::CACHE->{products} || {};
    my $max_base_score = 0;

    $self->csaf->builder->build;

    foreach my $vuln ($self->csaf->vulnerabilities->each) {
        foreach my $score ($vuln->scores->each) {
            if ($score->cvss_v3 && $score->cvss_v3->baseScore && $max_base_score < $score->cvss_v3->baseScore) {
                $max_base_score = $score->cvss_v3->baseScore;
            }
        }
    }

    my $tt = Template->new(
        INCLUDE_PATH => tt_templates_path,
        PRE_CHOMP    => 1,
        TRIM         => 1,
        ENCODING     => 'UTF-8',
        VARIABLES    => {
            document        => $self->csaf->document,
            product_tree    => $self->csaf->product_tree,
            vulnerabilities => $self->csaf->vulnerabilities,
            max_base_score  => $max_base_score,
        },
        FILTERS => {
            product_name => sub {
                my ($product_id) = @_;
                return $products->{$product_id} || $product_id;
            }
        }
    ) or Carp::croak $Template::ERROR;

    my $template = $options{template} || 'default';
    my $vars     = $options{vars}     || {};
    my $output   = undef;

    $tt->process("$template.tt2", $vars, \$output) or Carp::croak $tt->error;

    return $output;

}

1;
