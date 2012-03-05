# array of SYSTEMTIME
package Parse::Evtx::VariantType::Type0x92;
use base qw( Parse::Evtx::VariantType );

use Carp::Assert;
use DateTime;

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
		my ($year, $month, $dow, $day, $h, $m, $s, $ms) = 
			unpack("s8", substr($data, $i*16, 16));
		$data[$i] = sprintf("[%u] %04d-%02d-%02dT%02d:%02d:%02d.%04dZ",
		 	$i,
			$year, $month, $day, $h, $m, $s, $ms
		);
	}	
	$self->{'String'} = join("\n", @data);
}

1;