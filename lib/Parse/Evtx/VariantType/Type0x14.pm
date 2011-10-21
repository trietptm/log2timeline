# HexInt32
package Parse::Evtx::VariantType::Type0x14;
use base qw( Parse::Evtx::VariantType );

use Carp::Assert;

sub parse_self {
	my $self = shift;
	
	assert($self->{'Length'} >= 4);
	my $data = $self->{'Chunk'}->get_data($self->{'Start'}, 4);
	$self->{'String'} = sprintf(
		"0x%s", scalar reverse unpack("h*", $data)
	);
	$self->{'Length'} = 4;
};

1;