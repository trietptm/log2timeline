# value
package Parse::Evtx2::BXmlNode::Node0x05;
use base qw( Parse::Evtx2::BXmlNode );

require Parse::Evtx2::VariantType;
use Carp::Assert;


sub get_xml {
	my $self = shift;	
	my %args = (
	   'Values' => 1,
	   @_,
	);		

	my $fmt = ($self->{'TagState'}) ? '="%s"' : '%s';
	my $xml = $self->{'Chunk'}->get_defered_output();
	if ($args{'Values'}) {
		$xml .= sprintf($fmt, $self->{'Pointer'}->get_xml(@_));
	} else {
		$xml .= sprintf($fmt, '...');
	}
	return $xml;
}


sub parse_self {
	my $self = shift;
	
	assert($self->{'Length'} >= 2, "packet too short") if DEBUG;
	my $data = $self->{'Chunk'}->get_data($self->{'Start'}, 2);
	my ($opcode, $Type) = unpack("CC", $data);
	my $Flags = $opcode >> 4;
	assert(($Flags & 0x0b) == 0, "unexpected flag") if DEBUG;
	# Flag 0x40 was observed in a record that contained a split string 
	# (string, entity ref, string)
	$opcode = $opcode & 0x0f;	
	assert($opcode == 0x05, "bad opcode, expected 5, got $opcode") if DEBUG;
	
	$self->{'TagLength'} = 2;
	$self->{'DataLength'} = $self->{'Length'} - 2;
	$self->{'Type'} = $Type;
	$self->{'TagState'} = $self->{'Chunk'}->get_tag_state();	
}


sub parse_down {
	my $self = shift;
	
	my $Type = $self->{'Type'};
	my $Pointer;
	$Pointer = Parse::Evtx2::VariantType::new_variant(
		$Type,
		$self->{'Chunk'},
		$self->{'Start'} + 2,
		$self->{'DataLength'},
		0
	);
	assert(defined($Pointer), "undefined pointer to VariantType") if DEBUG;	
	$Pointer->parse_self();
	$Pointer->parse_down();

	$self->{'DataLength'} = $Pointer->get_length();
	$self->{'Pointer'} = $Pointer;
	$self->{'Length'} = $self->{'TagLength'} + $self->{'DataLength'};	
}

1;
