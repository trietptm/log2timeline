# null type - indicates a non-existing element
package Parse::Evtx::VariantType::Type0x00;
use base qw( Parse::Evtx::VariantType );

use Carp::Assert;


sub parse_self {
	my $self = shift;
	
	$self->{'String'} = '';
	
	if ($self->{'Context'} == 1 ) {
		# in a SubstArray
		
		# Do NOT trim the length to 0 bytes. 
		# NullTypes may contain data, for whatever reason!
	} else {
		assert($self->{'Lenth'} == 0,
			"object too large when in value context") if DEBUG;
		# $self->{'Length'} = 0;
	}
}

1;