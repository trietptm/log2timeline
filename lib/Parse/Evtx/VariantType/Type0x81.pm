# array of UCS2-LE strings
package Parse::Evtx::VariantType::Type0x81;
use base qw( Parse::Evtx::VariantType );

use Carp::Assert;
use Encode;

sub parse_self {
	my $self = shift;

	my $start = $self->{'Start'};
	
	my $string;
	if ($self->{'Context'} == 1) {
		# context is SubstArray
		# length is predetermined, no length will preceed the string
		$string = decode(
			"UCS2-LE", 
			$self->{'Chunk'}->get_data($start, $self->{'Length'})
		);
	} else {
		# context is Value
		# length (uint16) preceeds string
		assert($self->{'Length'} >= 2);
		my ($length) = unpack("S", $self->{'Chunk'}->get_data($start, 2));
		$length = $length * 2;
		assert($self->{'Length'} >= $length+2);
		$string = decode(
			"UCS2-LE", 
			$self->{'Chunk'}->get_data($start+2, $length)
		);
		$self->{'Length'} = $length + 2;	# 2 bytes len, no terminator
	}
	
	my @strings = split(/\000/, $string);
	my $i = 1;
	$string = sprintf("[%d] %s", 0, $strings[0]);
	while ($i <= $#strings) {
		$string .= sprintf("\n[%d] %s", $i, $strings[$i]);
		$i++;
	};
	$self->{'String'} = $string;
}

1;