# binary
package Parse::Evtx::VariantType::Type0x0e;
use base qw( Parse::Evtx::VariantType );

use Carp::Assert;

sub parse_self {
	my $self = shift;

	my $data;
	if ($self->{'Context'} == 1) {
		# context is SubstArray
		$data = $self->{'Chunk'}->get_data($self->{'Start'}, $self->{'Length'});
	} else {
		# context is Value
		
		carp("VariantType::Type0x0e is untested in a value context.");
		
		assert($self->{'Length'} >= 4);
		my ($length) = unpack("L", 
			$self->{'Chunk'}->get_data($self->{'Start'}, 4));
		
		assert($self->{'Length'} >= 2+$length);
		$data = $self->{'Chunk'}->get_data($self->{'Start'}+2, $length);
		$self->{'Length'} = 2 + $length;
	};
	
	my $string = unpack("H*", $data);
	$string =~ tr/a-f/A-F/;
	$self->{'String'} = $string;
};

1;