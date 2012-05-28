# GUID
package Parse::Evtx2::VariantType::Type0x0f;
use base qw( Parse::Evtx2::VariantType );

use Carp::Assert;

sub parse_self {
	my $self = shift;
	
	assert($self->{'Length'} >= 16);
	my $data = $self->{'Chunk'}->get_data($self->{'Start'}, 16);
	my @GUID = unpack("h8h4h4H4H12", $data);
	
	my $i;
	# reverse the leading three groups
	for ($i=0; $i<=2; $i++) {
		$GUID[$i] = reverse($GUID[$i]);
	}
	# convert hex strings to uppercase
	for ($i=0; $i<=5; $i++) {
		$GUID[$i] =~ tr/a-f/A-F/;
	}
	
	$self->{'String'} = sprintf("{%8s-%4s-%4s-%4s-%12s}", @GUID);
	$self->{'Length'} = 16;
}

1;
