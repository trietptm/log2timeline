# FILETIME, epoch 1601-01-01 00:00:00, resolution 100ns
package Parse::Evtx::VariantType::Type0x11;
use base qw( Parse::Evtx::VariantType );

use Carp::Assert;
use Math::BigInt;
#use DateTime;  # removed by Kristinn (log2timeline compatability)

#perl2exe_include "DateTime/Locale/en.pm"

sub parse_self {
	my $self = shift;
	
	assert($self->{'Length'} >= 8);
	my $data = $self->{'Chunk'}->get_data($self->{'Start'}, 8);
	my ($low, $high) = unpack("LL", $data);

	my $filetime = Math::BigInt->new($high)->blsft(32)->bxor($low);
	$filetime /= 1000;
	$filetime -= 116444736000000;
	my $seconds = $filetime / 10000;
	my $fraction = $filetime - $seconds*10000;
	#my $datetime = DateTime->from_epoch(epoch => $seconds->numify(), time_zone => 'UTC');
	#$self->{'String'} = sprintf("%s.%sZ", $datetime, $fraction->numify());
  $self->{'String'} = $seconds->numify();
};


sub release {
	my $self = shift;
	
	undef $self->{'String'};
	$self->SUPER::release();
}


1;
