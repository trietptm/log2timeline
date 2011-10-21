# ANSI string
package Parse::Evtx::VariantType::Type0x02;
use base qw( Parse::Evtx::VariantType );

use Carp::Assert;
use Carp;
use Parse::Evtx::VariantType;


sub parse_self {
	my $self = shift;

	if ($self->{'Context'} == 1) {
		# context is SubstArray
		# length is predetermined, no length preceeding string
		$self->{'String'} = $self->{'Chunk'}->get_hexdump(
			$self->{'Start'},
			$self->{'Length'}
		);
	} else {
		# context is Value
		# length (uint16) preceeds string		

		carp("VariantType::Type0x02 is untested in a value context.");
	
		assert($self->{'Length'} >= 2, "packet too short") if DEBUG;
		my $start = $self->{'Start'};
		my ($length) = unpack("S", $self->{'Chunk'}->get_data($start, 2));
		assert($self->{'Length'} >= $length+2,
			"read behind end of data") if DEBUG;
		$self->{'String'} = $self->{'Chunk'}->get_data($start+2, $length);
		$self->{'Length'} = $length + 2;	# 2 bytes len, no terminator
	}
}

1;