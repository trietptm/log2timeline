# Processing Instruction Data
package Parse::Evtx::BXmlNode::Node0x0b;
use base qw( Parse::Evtx::BXmlNode );

use Carp::Assert;
use Encode;


sub get_xml {
	my $self = shift;
	
	if ($self->{'String'} ne '') {
		return sprintf(" %s?> ", $self->{'String'}); 
	} else {
		return "?>";
	}
}


sub parse_self {
	my $self = shift;
	
	assert($self->{'Length'} >= 3, "packet too short") if DEBUG;
	my $data = $self->{'Chunk'}->get_data($self->{'Start'}, 3);
	my ($opcode, $strlength) = unpack("CS", $data);
	my $Flags = $opcode >> 4;
	assert(($Flags & 0x00) == 0, "unexpected flag") if DEBUG;
	$opcode = $opcode & 0x0f;	
	assert($opcode == 0x0b, "bad opcode") if DEBUG;
		
	$self->{'TagLength'} = 3;
	# each character is 2 bytes wide; 
	# the length uint16 is part of the tag, not data
	$self->{'DataLength'} = $strlength * 2;
	$self->{'Flags'} = $Flags;
}


sub parse_down {
	my $self = shift;
	
	if ($self->{'DataLength'} > 0) {	
		$self->{'String'} = decode(
			"UCS2-LE", 
			$self->{'Chunk'}->get_data(
				$self->{'Start'} + $self->{'TagLength'}, 
				$self->{'DataLength'}-4
			)
		);	
	} else {
		$self->{'String'} = '';
	}
	$self->{'Length'} = $self->{'TagLength'} + $self->{'DataLength'};	
}


1;