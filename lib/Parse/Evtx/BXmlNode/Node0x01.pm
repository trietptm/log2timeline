# open start element tag
package Parse::Evtx::BXmlNode::Node0x01;
use base qw( Parse::Evtx::BXmlNode );

require Parse::Evtx::BXmlNode::NameString;
use Carp::Assert;

sub get_xml {
	my $self = shift;
	
	my $string = $self->{'Chunk'}->get_string($self->{'Pointer'});
	my $xml = "\n<";
	$xml .= $string->get_xml();
	
	# iterate through children
	$xml .= $self->SUPER::get_xml(@_); 
	
	# close element
	if ($self->{'ElementType'} == 0) {
		$xml .= " />";
	} elsif ($self->{'ElementType'} == 1) {
		$xml .= sprintf("</%s>", $string->get_xml(@_));
	}
}

sub parse_self {
	my $self = shift;
	
	assert($self->{'Length'} >= 11, "packet too short") if DEBUG;
	my $data = $self->{'Chunk'}->get_data($self->{'Start'}, 11);
	my ($opcode, $unknown1, $Length, $Pointer) = unpack("CSLL", $data);
	my $Flags = $opcode >> 4;
	assert (($Flags & 0xb) == 0, "unknown flag $Flag") if DEBUG;
	$opcode = $opcode & 0x0f;
	assert($opcode == 0x01, "bad opcode, expected 1, got $opcode") if DEBUG;
	
	$self->{'TagLength'} = 11;
	$self->{'Length'} = $Length + 6;
	$self->{'DataLength'} = $self->{'Length'} - 11;
	$self->{'Flags'} = $Flags;
	$self->{'Pointer'} = $Pointer;
	
	$self->{'Chunk'}->set_tag_state(1);
	
	# push element ptr on element stack
	$self->{'Chunk'}->push_element($self);
	$self->{'Depth'} = $self->{'Chunk'}->get_depth();
}


sub parse_down {
	my $self = shift;

	my $string;
	if ($self->{'Pointer'} < $self->{'Start'}) {
		# name string is expected to already exist
		# $string = $self->{'Chunk'}->get_string($self->{'Pointer'}); 
		if ($self->{'Flags'} & 4) {
			$self->{'TagLength'} += 4;	
		}
	} else {
		# create new name string
		$string = Parse::Evtx::BXmlNode::NameString->new(
			'Chunk' => $self->{'Chunk'},
			'Parent' => $self,
			'Start' => $self->{'Pointer'},
			'Length' => $self->{'DataLength'},
		);
		# insert in string table
		$self->{'Chunk'}->set_string($self->{'Pointer'}, $string);
		$string->parse_self();
		$string->parse_down();
		if ($self->{'Flags'} & 4) {
			$self->{'TagLength'} += $string->get_length() + 4;	
		} else {
			$self->{'TagLength'} += $string->get_length();
		}
	}	
	
	$self->{'DataLength'} = $self->{'Length'} - $self->{'TagLength'};
	$self->SUPER::parse_down();
}


sub release {
	my $self = shift;
	
	undef $self->{'Pointer'};
	$self->SUPER::release();
}

sub set_element_type {
	my $self = shift;
	my $type = shift;
	
	$self->{'ElementType'} = $type;
}

1;