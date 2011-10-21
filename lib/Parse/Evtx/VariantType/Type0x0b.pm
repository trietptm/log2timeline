# single precision float
package Parse::Evtx::VariantType::Type0x0b;
use base qw( Parse::Evtx::VariantType );

use Carp::Assert;

sub parse_self {
	my $self = shift;
	
	assert($self->{'Length'} >= 4);
	my ($data) = unpack("f", 
		$self->{'Chunk'}->get_data($self->{'Start'}, 4));
	$self->{'String'} = sprintf("%f", $data);
	$self->{'Length'} = 4;
};

1;