# signed byte
package Parse::Evtx::VariantType::Type0x03;
use base qw( Parse::Evtx::VariantType );

use Carp::Assert;


sub parse_self {
	my $self = shift;
	
	assert($self->{'Length'} >= 1, "packet too small") if DEBUG;
	my ($data) = unpack("c", $self->{'Chunk'}->get_data($self->{'Start'}, 1));
	$self->{'String'} = sprintf("%d", $data);
	$self->{'Length'} = 1;
}

1;