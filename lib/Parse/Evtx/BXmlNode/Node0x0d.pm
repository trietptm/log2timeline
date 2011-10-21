# normal substitution
package Parse::Evtx::BXmlNode::Node0x0d;
use base qw( Parse::Evtx::BXmlNode );

require Parse::Evtx::VariantType;
use Carp::Assert;

sub get_xml {
	my $self = shift;
	my %args = (
	   'Substitution' => 1,
	   @_,
	);	
	
	my $fmt;
	if ($args{'Substitution'}) {
		$fmt = ($self->{'TagState'}) ? '="%s"' : '%s';
	} else {
		$fmt = ($self->{'TagState'}) ? '="#%d (type %d)#"' : '#%d (type %d)#';
	}
	my $xml = $self->{'Chunk'}->get_defered_output();
	
	if ($args{'Substitution'}) {
		$xml .= sprintf($fmt, 
			$self->{'Parent'}->get_substitute(
				$self->{'Index'},
				$self->{'Type'},
				0
			)
		);
	} else {
		$xml .= sprintf($fmt, 
				$self->{'Index'},
				$self->{'Type'}
		);
	}

	return $xml;
}


sub parse_self {
	my $self = shift;
	
	assert($self->{'Length'} >= 4, "packet too short") if DEBUG;
	my $data = $self->{'Chunk'}->get_data($self->{'Start'}, 4);
	my ($opcode, $Index, $Type) = 
		unpack("CSC", $data); 
	$opcode = $opcode & 0x0f;		
	assert($opcode == 0x0d, "bad opcode, expected 0x0d, got $opcode") if DEBUG;	
	
	$self->{'TagLength'} = 4;
	$self->{'DataLength'} = 0;
	$self->{'Length'} = 4;
	$self->{'Index'} = $Index;
	$self->{'Type'} = $Type;	
	$self->{'TagState'} = $self->{'Chunk'}->get_tag_state();
}

1;