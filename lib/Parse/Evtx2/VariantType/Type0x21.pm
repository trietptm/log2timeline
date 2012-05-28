# Binary XML 
# This type is not documented in _EVT_VARIANT_TYPE.
package Parse::Evtx2::VariantType::Type0x21;
use base qw( Parse::Evtx2::VariantType );

use Carp::Assert;

sub get_xml {
	my $self = shift;
	
	return $self->{'Pointer'}->get_xml(@_);
};

sub parse_self {
	my $self = shift;
	
	my $Root = Parse::Evtx2::BXmlNode::Root->new(
		'Chunk' => $self->{'Chunk'},
		'Parent' => $self,
		'Start' => $self->{'Start'},
		'Length' => $self->{'Length'},
	);
	
	assert(defined($Root));
	
	$Root->parse_self();
	$Root->parse_down();
	
	$self->{'Pointer'} = $Root;
};


sub release {
	my $self = shift;
	
	undef $self->{'Pointer'};
	$self->SUPER::release();
}


1;
