# close start element tag
package Parse::Evtx::BXmlNode::Node0x02;
use base qw( Parse::Evtx::BXmlNode );

use Carp::Assert;


sub get_xml {
	my $self = shift;
	
	return ">";
}

sub parse_down {
	# this node has no children
}

sub parse_self {
	my $self = shift;
	assert($self->{'Length'} >= 1, "packet too short") if DEBUG;
	my $data = $self->{'Chunk'}->get_data($self->{'Start'}, 1);
	my ($opcode) = unpack("C", $data); 
	$opcode = $opcode & 0x0f;	
	assert($opcode == 0x02, "bad opcode, expected 2, got $opcode") if DEBUG;
	$self->{'Length'} = 1;
	
	$self->{'Chunk'}->set_tag_state(0);
}

1;