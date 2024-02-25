package CSAF::Writer;

use 5.010001;
use strict;
use warnings;

use Carp;
use CSAF::Util            qw(tracking_id_to_well_filename);
use Digest::SHA           qw(sha256_hex sha512_hex);
use File::Basename        qw(basename dirname);
use File::Path            qw(make_path);
use File::Spec::Functions qw(catfile);
use Tie::File;

use Moo;
extends 'CSAF::Base';

use constant DEBUG => $ENV{CSAF_DEBUG};

use constant TRUE  => !!1;
use constant FALSE => !!0;


has filename  => (is => 'ro', default => sub { tracking_id_to_well_filename($_[0]->csaf->document->tracking->id) });
has directory => (is => 'rw', isa     => sub { Carp::croak qq{Output directory not found} unless -d $_[0] });

has update_index    => (is => 'rw', default => FALSE);
has update_changes  => (is => 'rw', default => FALSE);
has index_file      => (is => 'rw', default => TRUE);
has changes_file    => (is => 'rw', default => TRUE);
has sha256_checksum => (is => 'rw', default => TRUE);
has sha512_checksum => (is => 'rw', default => TRUE);

sub write {

    my ($self) = @_;

    # 7 Distributing CSAF documents

    # 7.1.11 Requirement 11: One folder per year
    # 7.1.12 Requirement 12: index.txt
    # 7.1.13 Requirement 13: changes.csv
    # 7.1.18 Requirement 18: Integrity

    # 7.1.19 Requirement 19: Signatures (TODO)

    my $csaf_json          = $self->csaf->renderer->render;
    my $csaf_directory     = $self->directory;
    my $csaf_filename      = $self->filename;
    my $csaf_file_basename = basename($csaf_filename, '.json');

    my $csaf_file_year            = $self->csaf->document->tracking->initial_release_date->year;
    my $csaf_current_release_date = $self->csaf->document->tracking->current_release_date->datetime;

    my $json_file_path     = catfile($csaf_directory, $csaf_file_year, $csaf_filename);
    my $index_file_path    = catfile($csaf_directory, 'index.txt');
    my $changes_file_path  = catfile($csaf_directory, 'changes.csv');
    my $csaf_document_path = catfile($csaf_file_year, $csaf_filename);
    my $sha256_file_path   = catfile($csaf_directory, $csaf_file_year, $csaf_file_basename) . '.sha256';
    my $sha512_file_path   = catfile($csaf_directory, $csaf_file_year, $csaf_file_basename) . '.sha512';

    if (DEBUG) {
        say STDERR "(I) Destination directory: $csaf_directory";
        say STDERR "(I) CSAF document: $csaf_filename";
        say STDERR "(I) CSAF document path: $json_file_path";
        say STDERR "(I) Index path: $index_file_path";
        say STDERR "(I) Changes path: $changes_file_path";
    }

    make_path(dirname($json_file_path));

    open my $fh, '>', $json_file_path or Carp::croak "Can't open file: $!";
    $fh->autoflush(1);

    print $fh $csaf_json;
    close $fh;

    if ($self->sha256_checksum) {
        open my $fh, '>', $sha256_file_path or Carp::croak "Can't open file: $!";
        print $fh join '  ', sha256_hex($csaf_json), basename($csaf_document_path) . "\n";
        close $fh;
    }

    if ($self->sha512_checksum) {
        open my $fh, '>', $sha512_file_path or Carp::croak "Can't open file: $!";
        print $fh join '  ', sha512_hex($csaf_json), basename($csaf_document_path) . "\n";
        close $fh;
    }

    if ($self->update_index) {
        tie my @index_data, 'Tie::File', $index_file_path or Carp::croak "Unable to write $index_file_path";
        push @index_data, $csaf_document_path unless grep /^$csaf_document_path$/, @index_data;

        @index_data = ((), sort { $b cmp $a } @index_data);
    }

    if ($self->update_changes) {

        my $changes_row = join ',', qq{"$csaf_document_path"}, qq{"$csaf_current_release_date"};

        tie my @changes_data, 'Tie::File', $changes_file_path or Carp::croak "Unable to write $changes_file_path";
        push @changes_data, $changes_row unless grep /^$changes_row$/, @changes_data;

        @changes_data = ((), sort { (split(/\,/, $b))[1] cmp(split(/\,/, $a))[1] } @changes_data);

    }

    return 1;

}

1;
