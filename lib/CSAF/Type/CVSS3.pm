package CSAF::Type::CVSS3;

use 5.010001;
use strict;
use warnings;

use Moo;
use Carp;

extends 'CSAF::Type::Base';


# TODO      Parse vector string and set single metrics

has version => (
    is      => 'ro',
    default => '3.1',
    isa     => sub { Carp::croak "CVSS3 version must be 3.0 or 3.1" unless ($_[0] eq '3.0' || $_[0] eq '3.1') }
);

has vectorString => (is => 'rw', required => 1, coerce => sub { uc $_[0] });
has baseScore    => (is => 'rw', required => 1, coerce => sub { ($_[0] + 0) });
has baseSeverity => (is => 'rw', required => 1, coerce => sub { uc $_[0] });

has [qw(
    attackVector
    attackComplexity
    privilegesRequired
    userInteraction
    scope
    confidentialityImpact
    integrityImpact
    availabilityImpact
    exploitCodeMaturity
    remediationLevel
    reportConfidence
    temporalScore
    temporalSeverity
    confidentialityRequirement
    integrityRequirement
    availabilityRequirement
    modifiedAttackVector
    modifiedAttackComplexity
    modifiedPrivilegesRequired
    modifiedUserInteraction
    modifiedScope
    modifiedConfidentialityImpact
    modifiedIntegrityImpact
    modifiedAvailabilityImpact
    environmentalScore
    environmentalSeverity
)] => (is => 'rw', coerce => sub { uc $_[0] });

sub TO_BUILD {

    my $self = shift;

    my $output = {
        version      => $self->version,
        vectorString => $self->vectorString,
        baseScore    => $self->baseScore,
        baseSeverity => $self->baseSeverity
    };


    my @attributes = qw(
        attackVector
        attackComplexity
        privilegesRequired
        userInteraction
        scope
        confidentialityImpact
        integrityImpact
        availabilityImpact
        exploitCodeMaturity
        remediationLevel
        reportConfidence
        temporalScore
        temporalSeverity
        confidentialityRequirement
        integrityRequirement
        availabilityRequirement
        modifiedAttackVector
        modifiedAttackComplexity
        modifiedPrivilegesRequired
        modifiedUserInteraction
        modifiedScope
        modifiedConfidentialityImpact
        modifiedIntegrityImpact
        modifiedAvailabilityImpact
        environmentalScore
        environmentalSeverity
    );

    for my $attribute (@attributes) {
        $output->{$attribute} = $self->$attribute if ($self->$attribute);
    }

    return $output;

}

sub TO_JSON { shift->TO_BUILD }

1;
