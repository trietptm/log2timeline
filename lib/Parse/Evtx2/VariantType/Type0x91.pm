# array of FILETIME
package Parse::Evtx2::VariantType::Type0x91;
use base qw( Parse::Evtx2::VariantType );

use Carp::Assert;
use Math::BigInt;
use DateTime;

sub parse_self {
	my $self = shift;
	
	my $start = $self->{'Start'};
	
	my $data;
	assert($self->{'Context'} == 1, "not tested in value context. Please submit a sample.") if DEBUG;
	if ($self->{'Context'} == 1) {
		# context is SubstArray
		# length is predetermined, no length will preceed the data
		assert($self->{'Length'} >= 8, "packet too small") if DEBUG;
		assert($self->{'Length'} % 8 == 0, "unexpected length") if DEBUG;
		$data = $self->{'Chunk'}->get_data($start, $self->{'Length'});
	} else {
		# context is Value
	}
	
	my $i;
	my $elements = $self->{'Length'} / 8;
	my @data;
	for ($i=0; $i<$elements; $i++ ) {
		my ($low, $high) = unpack("LL", substr($data, $i*8, 8));

		my $filetime = Math::BigInt->new($high)->blsft(32)->bxor($low);
		$filetime /= 1000;
		$filetime -= 116444736000000;
		my $seconds = $filetime / 10000;
		my $fraction = $filetime - $seconds*10000;
		my $datetime = DateTime->from_epoch(epoch => $seconds->numify(), time_zone => 'UTC');
		
		$data[$i] = sprintf("[%u] %s.%sZ",
		 	$i,
			$datetime, $fraction->numify()
		);
	}	
	$self->{'String'} = join("\n", @data);
}


sub release {
	my $self = shift;
	
	undef $self->{'String'};
	$self->SUPER::release();
}


1;
