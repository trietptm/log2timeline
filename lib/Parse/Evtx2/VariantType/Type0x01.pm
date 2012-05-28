# UCS2-LE string
package Parse::Evtx2::VariantType::Type0x01;
use base qw( Parse::Evtx2::VariantType );

use Carp::Assert;
use Encode;
use Parse::Evtx2::VariantType;


sub parse_self {
	my $self = shift;
	
	my $start = $self->{'Start'};
	if ($self->{'Context'} == 1) {
		# context is SubstArray
		# length is predetermined, no length preceeding string
		$self->{'String'} = decode(
			"UCS2-LE", 
			$self->{'Chunk'}->get_data($start, $self->{'Length'})
		);
	} else {
		# context is Value
		# length (uint16) preceeds string
		assert($self->{'Length'} >= 2,
			"packet too short") if DEBUG;
		my ($length) = unpack("S", $self->{'Chunk'}->get_data($start, 2));
		$length = $length * 2;
		assert($self->{'Length'} >= $length+2,
			"read behind end of data") if DEBUG;
		$self->{'String'} = decode(
			"UCS2-LE", 
			$self->{'Chunk'}->get_data($start+2, $length)
		);
		$self->{'Length'} = $length + 2;	# 2 bytes len, no terminator
	}
}

1;
