package CSAF;

use 5.010001;
use strict;
use warnings;
use utf8;

use CSAF::Builder;
use CSAF::Writer;
use CSAF::Validator;
use CSAF::Renderer;

use CSAF::Document;

use overload '""' => \&to_string, fallback => 1;

our $VERSION = '0.13';

our $CACHE = {};

sub new {

    my $class = shift;
    my $self  = {_ => CSAF::Document->new};

    return bless $self, $class;

}

# CSAF document core properties

sub document        { shift->{_}->document }
sub product_tree    { shift->{_}->product_tree }
sub vulnerabilities { shift->{_}->vulnerabilities }

# Helper classes

sub builder   { CSAF::Builder->new(csaf => shift) }
sub renderer  { CSAF::Renderer->new(csaf => shift) }
sub validator { CSAF::Validator->new(csaf => shift) }
sub writer    { CSAF::Writer->new(csaf => shift, @_) }

# Helpers

sub validate { shift->validator->validate }
sub render   { shift->renderer->render(@_) }

sub to_string { shift->renderer->render }
sub TO_JSON   { shift->builder->TO_JSON }

sub DESTROY {
    $CACHE = {};    # Reset Cache
}

1;

__END__

=head1 NAME

CSAF - Common Security Advisory Framework

=head1 SYNOPSIS

    use CSAF;

    my $csaf = CSAF->new;

    $csaf->document->title('Base CSAF Document');
    $csaf->document->category('csaf_security_advisory');
    $csaf->document->publisher(
        category  => 'vendor',
        name      => 'CSAF',
        namespace => 'https://csaf.io'
    );

    my $tracking = $csaf->document->tracking(
        id                   => 'CSAF:2024-001',
        status               => 'final',
        version              => '1.0.0',
        initial_release_date => 'now',
        current_release_date => 'now'
    );

    $tracking->revision_history->add(
        date    => 'now',
        summary => 'First release',
        number  => '1'
    );

    my @errors = $csaf->validate;

    if (@errors) {
        say $_ for (@errors);
        Carp::croak "Validation errors";
    }

    $csaf->writer(directory => '/var/www/html/csaf')->write;


=head1 DESCRIPTION

The Common Security Advisory Framework (CSAF) Version 2.0 is the definitive 
reference for the language which supports creation, update, and interoperable 
exchange of security advisories as structured information on products, 
vulnerabilities and the status of impact and remediation among interested 
parties.

L<https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html>


=head2 CSAF PROPERTIES

=over

=item document

Return L<CSAF::Type::Document>.

=item product_tree

Return L<CSAF::Type::ProductTree>.

=item vulnerabilities

Return L<CSAF::Type::Vulnerabilities>.

=back


=head2 HELPERS

=over

=item TO_JSON

=item builder

Return L<CSAF::Builder>.

=item render

Alias for C<renderer-E<gt>render($format)>.

    my $doc = $csaf->render('html');

=item renderer

Return L<CSAF::Renderer>.

    my $doc = $csaf->renderer->render('html');

=item validate

Alias for C<validator-E<gt>validate>.

=item validator

Return L<CSAF::Validator>.

=item to_string

Render CSAF document.

    my $json = $csaf->to_string;

=item writer

Return L<CSAF::Writer>.

=back


=head1 SUPPORT

=head2 Bugs / Feature Requests

Please report any bugs or feature requests through the issue tracker
at L<https://github.com/giterlizzi/perl-CSAF/issues>.
You will be notified automatically of any progress on your issue.

=head2 Source Code

This is open source software.  The code repository is available for
public review and contribution under the terms of the license.

L<https://github.com/giterlizzi/perl-CSAF>

    git clone https://github.com/giterlizzi/perl-CSAF.git


=head1 AUTHOR

=over 4

=item * Giuseppe Di Terlizzi <gdt@cpan.org>

=back


=head1 LICENSE AND COPYRIGHT

This software is copyright (c) 2023-2024 by Giuseppe Di Terlizzi.

This is free software; you can redistribute it and/or modify it under
the same terms as the Perl 5 programming language system itself.

=cut
