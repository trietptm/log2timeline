# Processing Instruction target
package Parse::Evtx2::BXmlNode::Node0x0a;
use base qw( Parse::Evtx2::BXmlNode );

require Parse::Evtx2::BXmlNode::NameString;
use Carp::Assert;


sub get_xml {
	my $self = shift;
	
	my $string = $self->{'Chunk'}->get_string($self->{'Pointer'});
	assert(defined $string, "unable to retrieve NameString") if DEBUG;
	my $xml = sprintf("<?%s", $string->get_xml());
	
	return $xml;
}


sub parse_self {
	my $self = shift;
	
	assert($self->{'Length'} >= 5, "packet too short") if DEBUG;
	my $data = $self->{'Chunk'}->get_data($self->{'Start'}, 5);
	my ($opcode, $Pointer) = unpack("CL", $data);
	my $Flags = $opcode >> 4;
	assert(($Flags & 0x00) == 0, "unexpected flag") if DEBUG;
	# Flag 0x40 was observed in a record that contained a split string 
	# (string, entity ref, string)
	$opcode = $opcode & 0x0f;	
	assert($opcode == 0x0a, "bad opcode, expected 9, got $opcode") if DEBUG;
		
	$self->{'TagLength'} = 5;
	$self->{'DataLength'} = $self->{'Length'} - 5;
	$self->{'Flags'} = $Flags;
	$self->{'Pointer'} = $Pointer;
}


sub parse_down {
	my $self = shift;

	my $string;
	if ($self->{'Pointer'} < $self->{'Start'}) {
		# name string is expected to already exist
		# $string = $self->{'Chunk'}->get_string($self->{'Pointer'}); 
		$self->{'DataLength'} = 0;
	} else {
		# create new name string
		$string = Parse::Evtx2::BXmlNode::NameString->new(
			'Chunk' => $self->{'Chunk'},
			'Parent' => $self,
			'Start' => $self->{'Pointer'},
			'Length' => $self->{'DataLength'},
		);
		assert(defined($string), "NameString creation failed") if DEBUG;	
		# insert in string table
		$self->{'Chunk'}->set_string($self->{'Pointer'}, $string);
		$string->parse_self();
		$string->parse_down();
		$self->{'DataLength'} = $string->get_length();
	}	

	$self->{'Length'} = $self->{'TagLength'} + $self->{'DataLength'};
}	


sub release {
	my $self = shift;
	
	undef $self->{'Pointer'};
	$self->SUPER::release();
}


1;
