# conditional substitution
package Parse::Evtx::BXmlNode::Node0x0e;
use base qw( Parse::Evtx::BXmlNode );

use Carp::Assert;

sub get_xml {
	my $self = shift;
	my %args = (
	   'Substitution' => 1,
	   @_,
	);

	my $subst;
	my $fmt = ($self->{'TagState'}) ? '="%s"' : '%s';

	if ($args{'Substitution'}) {
		$subst = $self->{'Parent'}->get_substitute(
			$self->{'Index'},
			$self->{'Type'},
			0
		);
	} else {
		$subst = sprintf("#%d (type %d, optional)#",
			$self->{'Index'},
			$self->{'Type'}
		);
	}

	my $xml = $self->{'Chunk'}->get_defered_output();
	
	if ($subst eq '') {
		return '';
	} else {
		$xml .= sprintf($fmt, $subst);
		return $xml;
	};
};


sub parse_self {
	my $self = shift;
	
	assert($self->{'Length'} >= 4, "packet too short") if DEBUG;
	my $data = $self->{'Chunk'}->get_data($self->{'Start'}, 4);
	my ($opcode, $Index, $Type) = 
		unpack("CSC", $data); 
	$opcode = $opcode & 0x0f;		
	assert($opcode == 0x0e, "bad opcode, expected 0x0e, got $opcode") if DEBUG;
	$self->{'TagLength'} = 4;
	$self->{'DataLength'} = 0;
	$self->{'Length'} = 4;	
	$self->{'Index'} = $Index;
	$self->{'Type'} = $Type;	
	$self->{'TagState'} = $self->{'Chunk'}->get_tag_state();
};

1;