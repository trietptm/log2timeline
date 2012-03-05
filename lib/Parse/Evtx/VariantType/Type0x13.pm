# Security ID (SID)
package Parse::Evtx::VariantType::Type0x13;
use base qw( Parse::Evtx::VariantType );

use Carp::Assert;
use Math::BigInt;

sub parse_self {
	my $self = shift;
	
	assert($self->{'Length'} >= 8, "packet too small") if DEBUG;
	my $data = $self->{'Chunk'}->get_data($self->{'Start'}, 2);
	my ($Version, $Elements) = unpack("CC", $data);

	assert($Version == 1, "unknown version") if DEBUG;
	$data = $self->{'Chunk'}->get_data($self->{'Start'}+2, 6);
	my ($high, $low) = unpack("Nn", $data);
	my $id = Math::BigInt->new($high)->blsft(16)->bxor($low);
	my $SID = sprintf("S-%d-%s",
		$Version,
		$id->bstr()
	);
	
	assert($self->{'Length'} >= 8 + $Elements*4);
	$data = $self->{'Chunk'}->get_data($self->{'Start'}+8, $Elements*4);
	my @rid = unpack("L*", $data);
	for (my $i = 0; $i < $Elements; $i++) {
		$SID .= sprintf("-%d", $rid[$i]);
	};
	
	$self->{'String'} = $SID;
	$self->{'Length'} = 8 + $Elements*4;
}


sub release {
	my $self = shift;
	
	undef $self->{'String'};
	$self->SUPER::release();
}


1;