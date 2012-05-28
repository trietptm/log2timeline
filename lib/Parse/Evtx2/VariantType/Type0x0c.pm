# double precision float
package Parse::Evtx2::VariantType::Type0x0c;
use base qw( Parse::Evtx2::VariantType );

use Carp::Assert;

sub parse_self {
	my $self = shift;
	
	assert($self->{'Length'} >= 8);
	my ($data) = unpack("d", 
		$self->{'Chunk'}->get_data($self->{'Start'}, 8));
	$self->{'String'} = sprintf("%e", $data);
	$self->{'Length'} = 8;
};

1;
