# End-of-Stream
package Parse::Evtx::BXmlNode::Node0x00;
use base qw( Parse::Evtx::BXmlNode );

use Carp::Assert;

sub get_xml {
	my $self = shift;
	
	return '';
}

sub parse_down {
	# End-of-Steam has no children
}

sub parse_self {
	my $self = shift;
		
	assert($self->{'Length'} >= 1, "packet too short") if DEBUG;
	my $data = $self->{'Chunk'}->get_data($self->{'Start'}, 1);
	my ($opcode) = unpack("C", $data);
	$opcode = $opcode & 0x0f;	
	assert($opcode == 0x00, "bad opcode, expected 0, got $opcode") if DEBUG;
	$self->{'Length'} = 1;
	$self->{'EndOfStream'} = $self->{'Start'} + $self->{'Length'};		
}

1;