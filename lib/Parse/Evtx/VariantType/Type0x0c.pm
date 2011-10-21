# double precision float
package Parse::Evtx::VariantType::Type0x0c;
use base qw( Parse::Evtx::VariantType );

use Carp::Assert;

sub parse_self {
	my $self = shift;
	
	assert($self->{'Length'} >= 8);
	my ($data) = unpack("d", 
		$self->{'Chunk'}->get_data($self->{'Start'}, 8));
	$self->{'String'} = sprintf("%f", $data);
	$self->{'Length'} = 8;
};

1;