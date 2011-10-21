# HexInt64
package Parse::Evtx::VariantType::Type0x15;
use base qw( Parse::Evtx::VariantType );

use Carp::Assert;

sub parse_self {
	my $self = shift;
	
	assert($self->{'Length'} >= 8);
	my $data = $self->{'Chunk'}->get_data($self->{'Start'}, 8);
	$self->{'String'} = sprintf(
		"0x%s", scalar reverse unpack("h*", $data)
	);
	$self->{'Length'} = 8;
};

1;