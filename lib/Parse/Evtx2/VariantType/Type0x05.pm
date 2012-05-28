# signed int16
package Parse::Evtx2::VariantType::Type0x05;
use base qw( Parse::Evtx2::VariantType );

use Carp::Assert;


sub parse_self {
	my $self = shift;
	
	assert($self->{'Length'} >= 2, "packet too small") if DEBUG;
	my ($data) = unpack("s", $self->{'Chunk'}->get_data($self->{'Start'}, 2));
	$self->{'String'} = sprintf("%d", $data);
	$self->{'Length'} = 2;
}

1;
