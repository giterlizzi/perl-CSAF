package CSAF::Type::CVSS2;

use 5.010001;
use strict;
use warnings;

use Moo;

extends 'CSAF::Type::Base';

has version      => (is => 'ro', default  => '2.0');
has vectorString => (is => 'ro', required => 1);
has baseScore    => (is => 'ro', required => 1, coerce => sub { ($_[0] + 0) });

has [qw(
    accessVector
    accessComplexity
    authentication
    confidentialityImpact
    integrityImpact
    availabilityImpact
    exploitability
    remediationLevel
    reportConfidence
    collateralDamagePotential
    targetDistribution
    confidentialityRequirement
    integrityRequirement
    availabilityRequirement
)] => (is => 'rw', coerce => sub { uc $_[0] });

has ['temporalScore', 'environmentalScore'] => (is => 'rw', coerce => sub { ($_[0] + 0) });


sub TO_BUILD {

    my $self = shift;

    my $output = {version => $self->version, vectorString => $self->vectorString, baseScore => $self->baseScore};

    my @attributes = qw(
        accessVector
        accessComplexity
        authentication
        confidentialityImpact
        integrityImpact
        availabilityImpact
        exploitability
        remediationLevel
        reportConfidence
        temporalScore
        collateralDamagePotential
        targetDistribution
        confidentialityRequirement
        integrityRequirement
        availabilityRequirement
        environmentalScore
    );

    for my $attribute (@attributes) {
        $output->{$attribute} = $self->$attribute if ($self->$attribute);
    }

    return $output;

}

sub TO_JSON { shift->TO_BUILD }

1;
