# end element tag
package Parse::Evtx2::BXmlNode::Node0x04;
use base qw(Parse::Evtx2::BXmlNode);

use Carp::Assert;


sub get_xml {
	return '';
}

sub parse_down {
	# this node has no children
}

sub parse_self {
	my $self = shift;
	
	assert($self->{'Length'} >= 1, "packet too short") if DEBUG;
	my $data = $self->{'Chunk'}->get_data($self->{'Start'}, 1);
	my ($opcode) = unpack("C", $data); 
	my $Flags = $opcode >> 4;
	assert($Flags == 0, "unexpected flag") if DEBUG;
	$opcode = $opcode & 0x0f;	
	assert($opcode == 0x04, "bad opcode, expected 4, got $opcode") if DEBUG;
	$self->{'Length'} = 1;
	$self->{'TagLength'} = 1;
	$self->{'DataLength'} = 0;
	$self->{'Chunk'}->set_tag_state(0);
		
	# remove element from stack
	my $element = $self->{'Chunk'}->pop_element();
	$element->set_element_type(1);
}

1;
