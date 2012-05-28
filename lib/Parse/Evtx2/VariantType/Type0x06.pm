# unsigned int16
package Parse::Evtx2::VariantType::Type0x06;
use base qw( Parse::Evtx2::VariantType );

use Carp::Assert;

sub parse_self {
	my $self = shift;
	
	assert($self->{'Length'} >= 2);
	my ($data) = unpack("S", $self->{'Chunk'}->get_data($self->{'Start'}, 2));
	$self->{'String'} = sprintf("%u", $data);
	$self->{'Length'} = 2;
};

1;
