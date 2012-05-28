# array of signed int64
package Parse::Evtx2::VariantType::Type0x89;
use base qw( Parse::Evtx2::VariantType );

use Carp::Assert;
use Math::BigInt;

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
		my ($low, $high) = unpack("Ll", substr($data, $i*8, 8));
		my $int64 = Math::BigInt->new($high)->blsft(32)->bxor($low);
		$data[$i] = sprintf("[%u] %s", $i, $int64->bstr());
	}	
	$self->{'String'} = join("\n", @data);

}


sub release {
	my $self = shift;
	
	undef $self->{'String'};
	$self->SUPER::release();
}


1;
