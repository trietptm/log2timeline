# unsigned int64
package Parse::Evtx::VariantType::Type0x09;
use base qw( Parse::Evtx::VariantType );

use Carp::Assert;
use Math::BigInt;

sub parse_self {
	my $self = shift;
	
	assert($self->{'Length'} >= 8);
	my ($low, $high) = unpack("LL", 
		$self->{'Chunk'}->get_data($self->{'Start'}, 8));
	my $int64 = Math::BigInt->new($high)->blsft(32)->bxor($low);
	$self->{'String'} = $int64->bstr();
	$self->{'Length'} = 8;
};

1;