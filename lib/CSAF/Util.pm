package CSAF::Util;

use 5.010001;
use strict;
use warnings;
use utf8;

use Cpanel::JSON::XS;
use Time::Piece;
use File::Basename        qw(dirname);
use File::Spec::Functions qw(catfile);
use List::Util            qw(first);

use Exporter 'import';

our @EXPORT_OK = (qw(
    schema_cache_path resources_path tt_templates_path
    check_datetime tracking_id_to_well_filename dumper
    collect_product_ids file_read JSON product_in_group_exists
    decode_cvss3_vector_string decode_cvss2_vector_string
));

my $PURL_REGEXP = qr{^pkg:[A-Za-z\\.\\-\\+][A-Za-z0-9\\.\\-\\+]*/.+};

sub JSON {
    Cpanel::JSON::XS->new->utf8->canonical->allow_nonref->allow_unknown->allow_blessed->convert_blessed
        ->stringify_infnan->escape_slash->allow_dupkeys->pretty;
}

sub Time::Piece::TO_JSON { shift->datetime }

sub schema_cache_path { catfile(resources_path(),  'cache') }
sub tt_templates_path { catfile(resources_path(),  'template') }
sub resources_path    { catfile(dirname(__FILE__), 'resources') }

sub check_datetime {

    my $datetime = shift;
    return unless $datetime;

    return $datetime if ($datetime->isa('Time::Piece'));

    return Time::Piece->new($datetime) if ($datetime =~ /^([0-9]+)$/);
    return Time::Piece->new            if ($datetime eq 'now');

    return Time::Piece->strptime($1, '%Y-%m-%dT%H:%M:%S') if ($datetime =~ /(\d{4}-\d{2}-\d{2}[T]\d{2}:\d{2}:\d{2})/);
    return Time::Piece->strptime($1, '%Y-%m-%d %H:%M:%S') if ($datetime =~ /(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2})/);
    return Time::Piece->strptime($1, '%Y-%m-%d')          if ($datetime =~ /(\d{4}-\d{2}-\d{2})/);

}

sub tracking_id_to_well_filename {

    my $id = shift;

    $id = lc $id;
    $id =~ s/[^+\-a-z0-9]+/_/g;    # Rif. 5.1 (Additional Conventions - Filename)

    return "$id.json";

}

sub collect_product_ids {

    my $item        = shift;
    my @product_ids = ();

    my $ref_item = ref($item);

    if ($ref_item =~ /Branch$/) {

        if ($item->has_product) {
            push @product_ids, $item->product->product_id;
        }

        foreach (@{$item->branches->items}) {
            push @product_ids, collect_product_ids($_);
        }

    }

    if ($ref_item =~ /FullProductName$/) {
        push @product_ids, $item->product_id;
    }

    return @product_ids;

}

sub product_in_group_exists {

    my ($csaf, $product_id, $group_id) = @_;

    my $exists = 0;

    $csaf->product_tree->product_groups->each(sub {

        my ($group) = @_;

        if ($group->group_id eq $group_id) {
            if (first { $product_id eq $_ } @{$group->product_ids}) {
                $exists = 1;
                return;
            }
        }

    });

    return $exists;

}

sub file_read {

    my ($file) = @_;

    my $content = do {
        open(my $fh, '<', $file) or Carp::croak qq{Failed to read file: $!};
        local $/ = undef;
        <$fh>;
    };

    return $content;

}

sub dumper { Data::Dumper->new([@_])->Indent(1)->Sortkeys(1)->Terse(1)->Useqq(1)->Dump }

1;
