package CSAF::Lite;

use 5.010001;
use strict;
use warnings;

use Moo;

use CSAF;
use CSAF::Builder;

has id        => (is => 'rw', required => 1);
has category  => (is => 'rw', default  => sub {'csaf_base'});
has lang      => (is => 'rw', default  => 'en');
has title     => (is => 'rw');
has severity  => (is => 'rw');
has publisher => (is => 'rw');
has notes     => (is => 'rw');

has initial_release_date => (is => 'rw');
has current_release_date => (is => 'rw');

has tlp_label => (is => 'rw', default => 'WHITE', coerce => sub { uc $_[0] });

my $PRODUCTS        = {};
my @VULNERABILITIES = ();
my @NOTES           = ();

has publisher_name      => (is => 'rw');
has publisher_namespace => (is => 'rw');
has publisher_category  => (is => 'rw');

has engine_name    => (is => 'rw', default => 'CSAF Perl Toolkit (Lite)');
has engine_version => (is => 'rw', default => $CSAF::VERSION);

sub note {

    my ($self, %params) = @_;

    my $category = delete $params{category} || Carp::croak 'Category is required';
    my $title    = delete $params{title};
    my $text     = delete $params{text};

    push @NOTES, {category => $category, title => $title, text => $text};

}

sub description_note      { shift->note(category => 'description',      @_) }
sub details_note          { shift->note(category => 'details',          @_) }
sub faq_note              { shift->note(category => 'faq',              @_) }
sub general_note          { shift->note(category => 'general',          @_) }
sub legal_disclaimer_note { shift->note(category => 'legal_disclaimer', @_) }
sub other_note            { shift->note(category => 'other',            @_) }
sub summary_note          { shift->note(category => 'summary',          @_) }

sub vulnerability {

    my ($self, %params) = @_;

    my $cve    = delete $params{cve}    || Carp::croak 'CVE is required for a vulnerability';
    my $title  = delete $params{title}  || Carp::croak 'Title is required for a vulnerability';
    my $cwe_id = delete $params{cwe_id} || $params{cwe} || $params{weakness};

    my $first_affected      = delete $params{first_affected}      || [];
    my $first_fixed         = delete $params{first_fixed}         || [];
    my $fixed               = delete $params{fixed}               || [];
    my $known_affected      = delete $params{known_affected}      || [];
    my $known_not_affected  = delete $params{known_not_affected}  || [];
    my $last_affected       = delete $params{last_affected}       || [];
    my $recommended         = delete $params{recommended}         || [];
    my $under_investigation = delete $params{under_investigation} || [];

    my $note        = delete $params{note}        || [];
    my $remediation = delete $params{remediation} || [];

    my $vuln = {
        cve    => $cve,
        title  => $title,
        cwe_id => $cwe_id,

        first_affected      => $first_affected,
        first_fixed         => $first_fixed,
        fixed               => $fixed,
        known_affected      => $known_affected,
        known_not_affected  => $known_not_affected,
        last_affected       => $last_affected,
        recommended         => $recommended,
        under_investigation => $under_investigation,

        note        => $note,
        remediation => $remediation,
    };

    push @VULNERABILITIES, $vuln;

}

sub product {

    my ($self, %params) = @_;

    my $vendor            = $params{vendor};
    my $product           = $params{product};
    my $vendor_product_id = $params{id} || _build_product_id($vendor, $product);

    $PRODUCTS->{$vendor_product_id} = \%params;

}

sub generate {

    my ($self) = @_;

    my $csaf = CSAF->new;

    $csaf->document->title($self->title);
    $csaf->document->category($self->category);
    $csaf->document->lang($self->lang);
    $csaf->document->aggregate_severity($self->severity);

    $csaf->document->distribution->tlp_label($self->tlp_label);

    $csaf->document->publisher(%{$self->publisher});

    $self->current_release_date($self->initial_release_date) unless $self->current_release_date;
    $self->initial_release_date($self->current_release_date) unless $self->initial_release_date;

    my $tracking = $csaf->document->tracking(
        id                   => $self->id,
        status               => 'final',
        version              => '1',
        current_release_date => $self->current_release_date,
        initial_release_date => $self->initial_release_date,
    );

    $tracking->revision_history->item(date => $self->initial_release_date, summary => 'First release', number => '1');

    $tracking->generator->engine_name($self->engine_name);
    $tracking->generator->engine_version($self->engine_version);

    foreach my $note (@NOTES) {
        $csaf->document->notes->item(%{$note});
    }

    foreach my $product_id (keys %{$PRODUCTS}) {

        my $vendor   = $PRODUCTS->{$product_id}->{vendor};
        my $product  = $PRODUCTS->{$product_id}->{product};
        my $versions = $PRODUCTS->{$product_id}->{versions};

        my $branches    = $csaf->product_tree->branches;
        my $vendor_item = $branches->item(category => 'vendor', name => $vendor);

        my $vendor_branches = $vendor_item->branches;
        my $product_item    = $vendor_branches->item(category => 'product_name', name => $product);

        my $product_branches = $product_item->branches;

        foreach my $item (@{$versions}) {

            my $product_id           = $item->{id} || _build_product_id($vendor, $product, $item->{version});
            my $product_version_item = {product_id => $product_id, name => $item->{name}};

            if (!defined $item->{name}) {
                $product_version_item->{name} = join(' ', $vendor, $product, $item->{version});
            }

            if ($item->{cpe}) {
                $product_version_item->{product_identification_helper}->{cpe} = $item->{cpe};
            }

            if ($item->{purl}) {
                $product_version_item->{product_identification_helper}->{purl} = $item->{purl};
            }

            $product_branches->item(
                category => 'product_version',
                name     => $item->{version},
                product  => $product_version_item,
            );
        }

    }

    my $vulns = $csaf->vulnerabilities;

    foreach my $vuln (@VULNERABILITIES) {

        my $vuln_item      = $vulns->item(cve => $vuln->{cve}, title => $vuln->{title});
        my $product_status = $vuln_item->product_status;

        $vuln_item->cwe_id($vuln->{cwe_id}) if $vuln->{cwe_id};

        $product_status->first_affected($vuln->{first_affected})           if (@{$vuln->{first_affected}});
        $product_status->first_fixed($vuln->{first_fixed})                 if (@{$vuln->{first_fixed}});
        $product_status->fixed($vuln->{fixed})                             if (@{$vuln->{fixed}});
        $product_status->known_affected($vuln->{known_affected})           if (@{$vuln->{known_affected}});
        $product_status->known_not_affected($vuln->{known_not_affected})   if (@{$vuln->{known_not_affected}});
        $product_status->last_affected($vuln->{last_affected})             if (@{$vuln->{last_affected}});
        $product_status->recommended($vuln->{recommended})                 if (@{$vuln->{recommended}});
        $product_status->under_investigation($vuln->{under_investigation}) if (@{$vuln->{under_investigation}});

        foreach my $note (@{$vuln->{note}}) {
            $vuln_item->notes->item(%{$note});
        }

    }

    return CSAF::Builder->new($csaf);

}

sub TO_JSON { shift->generate }

sub _build_product_id {

    my $product_id = join ':', map { lc $_ } @_;
    $product_id =~ s/\s/_/g;

    return $product_id;

}

1;
