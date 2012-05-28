# array of GUID
package Parse::Evtx2::VariantType::Type0x8f;
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
		assert($self->{'Length'} >= 16, "packet too small") if DEBUG;
		assert($self->{'Length'} % 16 == 0, "unexpected length") if DEBUG;		
		$data = $self->{'Chunk'}->get_data($start, $self->{'Length'});
	} else {
		# context is Value
	}
	
	my $i;
	my $elements = $self->{'Length'} / 16;
	my @data;
	for ($i=0; $i<$elements; $i++ ) {
		
		my @GUID = unpack("h8h4h4H4H12", substr($data, $i*16, 16));
		my $g;
		# reverse the leading three groups
		for ($g=0; $g<=2; $g++) {
			$GUID[$g] = reverse($GUID[$g]);
		}
		# convert hex strings to uppercase
		for ($g=0; $g<=5; $g++) {
			$GUID[$g] =~ tr/a-f/A-F/;
		}
		
		$data[$i] = sprintf("[%u] {%8s-%4s-%4s-%4s-%12s}", 
			$i, 
			@GUID
		);
	}	
	$self->{'String'} = join("\n", @data);

}

1;
