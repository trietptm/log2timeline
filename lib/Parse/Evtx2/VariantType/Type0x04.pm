# unsigned byte
package Parse::Evtx2::VariantType::Type0x04;
use base qw( Parse::Evtx2::VariantType );

use Carp::Assert;


sub parse_self {
	my $self = shift;
	
	assert($self->{'Length'} >= 1, "packet too small") if DEBUG;
	my ($data) = unpack("C", $self->{'Chunk'}->get_data($self->{'Start'}, 1));
	$self->{'String'} = sprintf("%u", $data);
	$self->{'Length'} = 1;
}

1;
