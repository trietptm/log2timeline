# array of single precision float
package Parse::Evtx::VariantType::Type0x8b;
use base qw( Parse::Evtx::VariantType );

use Carp::Assert;

sub parse_self {
	my $self = shift;
	
	my $start = $self->{'Start'};
	
	my $data;
	assert($self->{'Context'} == 1, "not tested in value context. Please submit a sample.") if DEBUG;
	if ($self->{'Context'} == 1) {
		# context is SubstArray
		# length is predetermined, no length will preceed the data
		assert($self->{'Length'} >= 4, "packet too small") if DEBUG;
		assert($self->{'Length'} % 4 == 0, "unexpected length") if DEBUG;		
		$data = $self->{'Chunk'}->get_data($start, $self->{'Length'});
	} else {
		# context is Value
	}
	
	my $i;
	my $elements = $self->{'Length'} / 4;
	my @data;
	for ($i=0; $i<$elements; $i++ ) {
		$data[$i] = sprintf("[%u] %e", 
			$i, 
			unpack("f", substr($data, $i*4, 4))
		);
	}	
	$self->{'String'} = join("\n", @data);

}

1;