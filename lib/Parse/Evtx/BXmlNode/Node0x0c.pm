# template instance
package Parse::Evtx::BXmlNode::Node0x0c;
use base qw( Parse::Evtx::BXmlNode );

require Parse::Evtx::BXmlNode::Template;
use Carp::Assert;

sub get_xml {
	my $self = shift;
	
	my $template = $self->{'Chunk'}->get_template($self->{'Pointer'});
	assert(defined($template), "template not defined") if DEBUG;
	
	return $template->get_xml(@_);
}

sub parse_self {
	my $self = shift;
	
	assert($self->{'Length'} >= 10, "packet too short") if DEBUG;
	my $data = $self->{'Chunk'}->get_data($self->{'Start'}, 10);
	my ($opcode, $unknown1, $TemplateId, $Pointer) = 
		unpack("CCLL", $data); 
	my $Flags = $opcode >> 4;
	assert($Flags == 0, "unexpected flag") if DEBUG;
	$opcode = $opcode & 0x0f;
	assert($opcode == 0x0c, "bad opcode, expected 0x0c, got $opcode") if DEBUG;
	assert($unknown1 == 1, "unknown1 expected 1, got $unknown1") if DEBUG;	
	$self->{'TagLength'} = 10;
	$self->{'DataLength'} = $self->{'Length'} - $self->{'TagLength'};
	$self->{'TemplateId'} = $TemplateId;
	$self->{'Pointer'} = $Pointer;
}

sub parse_down {
	my $self = shift;
	
	if ($self->{'Pointer'} < $self->{'Start'}) {
		# template is expected to already exist 
		my $template = $self->{'Chunk'}->get_template($self->{'Pointer'});
		assert(defined($template), "undefined template") if DEBUG;
		assert($template->get_template_id() == $self->{'TemplateId'},
			"retrieved wrong template") if DEBUG; 
		$self->{'DataLength'} = 0;
		# check if referenced template sets "EndOfStream" mark
		my $eos = $template->get_end_of_stream();
		if ((defined $eos) && ($eos > 0)) {
			# set EoS mark right behind pointer
			$self->{'EndOfStream'} = $self->{'Start'} + $self->{'TagLength'};
		}
	} else {
		# create new template
		my $template = Parse::Evtx::BXmlNode::Template->new(
			'Chunk' => $self->{'Chunk'},
			'Parent' => $self,
			'Start' => $self->{'Pointer'},
			'Length' => $self->{'DataLength'},
		);
		# insert into template table
		$self->{'Chunk'}->set_template($self->{'Pointer'}, $template);
		$template->parse_self();
		$template->parse_down();
		$self->{'DataLength'} = $template->get_length();
		$self->{'EndOfStream'} = $template->get_end_of_stream();
	}
	$self->{'Length'} = $self->{'TagLength'} + $self->{'DataLength'};
}


sub release {
	my $self = shift;
	
	undef $self->{'Pointer'};
	$self->SUPER::release();
}


1;