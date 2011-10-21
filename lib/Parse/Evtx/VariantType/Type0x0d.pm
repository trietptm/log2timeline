# boolean
package Parse::Evtx::VariantType::Type0x0d;
use base qw( Parse::Evtx::VariantType );

use Carp::Assert;

sub parse_self {
	my $self = shift;
	
	assert($self->{'Length'} >= 4);
	my $data = unpack("l", 
		$self->{'Chunk'}->get_data($self->{'Start'}, 4));
	$self->{'String'} = ($data > 0) ? 'true' : 'false';
	$self->{'Length'} = 4;
};

1;