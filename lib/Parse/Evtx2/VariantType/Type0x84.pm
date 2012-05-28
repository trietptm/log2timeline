# array of unsigned byte
package Parse::Evtx2::VariantType::Type0x84;
use base qw( Parse::Evtx2::VariantType );

use Carp::Assert;


sub parse_self {
	my $self = shift;
	
	my $start = $self->{'Start'};
	
	my $data;
	assert($self->{'Context'} == 1, "not tested in value context. Please submit a sample.") if DEBUG;
	if ($self->{'Context'} == 1) {
		# context is SubstArray
		# length is predetermined, no length will preceed the data
		assert($self->{'Length'} >= 1, "packet too small") if DEBUG;
		$data = $self->{'Chunk'}->get_data($start, $self->{'Length'});
	} else {
		# context is Value
	}

	my $i;
	my $elements = $self->{'Length'};		# element size 1 byte!
	my @data;
	for ($i=0; $i<$elements; $i++ ) {
		$data[$i] = sprintf("[%u] %u",
		 	$i,
			unpack("S", substr($data, $i, 1))
		);
	}	
	$self->{'String'} = join("\n", @data);
	
}

1;
