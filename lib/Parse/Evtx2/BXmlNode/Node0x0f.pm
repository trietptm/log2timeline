# Start-of-Stream
package Parse::Evtx2::BXmlNode::Node0x0f;
use base qw( Parse::Evtx2::BXmlNode );

use Carp::Assert;

sub get_xml {
	return ''; 
};

sub parse_self {
	my $self = shift;
	
	assert($self->{'Length'} >= 3, "packet too short") if DEBUG;
	my $data = $self->{'Chunk'}->get_data($self->{'Start'}, 4);
	my ($opcode, $unknown1, $unknown2) = unpack("CCS", $data);
	my $Flags = $opcode >> 4;
	assert($Flags == 0, "unexpected flag") if DEBUG;
	$opcode = $opcode & 0x0f;	
	assert($opcode == 0x0f, "bad opcode, expected 0x0f, got $opcode") if DEBUG;
	assert($unknown1 == 1, "unknown1 expected 1, got $unknown1") if DEBUG;
	assert($unknown2 == 1, "unknown2 expected 1, got $unknown2") if DEBUG;
	
	$self->{'Length'} = 4;
	$self->{'TagLength'} = 4;
	$self->{'DataLength'} = 0;
};

sub parse_down {
	# this node has no children
};

1;
