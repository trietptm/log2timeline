# value
package Parse::Evtx::BXmlNode::Node0x05;
use base qw( Parse::Evtx::BXmlNode );

require Parse::Evtx::VariantType;
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
	$Pointer = Parse::Evtx::VariantType::new_variant(
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