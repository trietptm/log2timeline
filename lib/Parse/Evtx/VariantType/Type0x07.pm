# signed int32
package Parse::Evtx::VariantType::Type0x07;
use base qw( Parse::Evtx::VariantType );

use Carp::Assert;

sub parse_self {
	my $self = shift;
	
	assert($self->{'Length'} >= 4);
	my ($data) = unpack("l", $self->{'Chunk'}->get_data($self->{'Start'}, 4));
	$self->{'String'} = sprintf("%d", $data);
	$self->{'Length'} = 4;
};

1;