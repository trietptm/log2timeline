# size_t
package Parse::Evtx::VariantType::Type0x10;
use base qw( Parse::Evtx::VariantType );

use Carp;
use Carp::Assert;
use Math::BigInt;

sub parse_self {
	my $self = shift;
	
	# guess sizeof(size_t)
	my $size = $self->{'Length'};
	assert(($size == 4) or ($size == 8));
	my ($low, $high);
	if ($size == 4) {
		($low) = unpack("L", 
			$self->{'Chunk'}->get_data($self->{'Start'}, 4));
		$high = 0;
	} elsif ($size == 8) {
		($low, $high) = unpack("LL",
			$self->{'Chunk'}->get_data($self->{'Start'}, 8));
	};
	my $int64 = Math::BigInt->new($high)->blsft(32)->bxor($low);
	$self->{'String'} = $int64->numify();
};


sub release {
	my $self = shift;
	
	undef $self->{'String'};
	$self->SUPER::release();
}



1;