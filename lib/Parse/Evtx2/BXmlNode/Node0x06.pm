# attribute
package Parse::Evtx2::BXmlNode::Node0x06;
use base qw( Parse::Evtx2::BXmlNode );

require Parse::Evtx2::BXmlNode::NameString;
use Carp::Assert;

sub get_xml {
	my $self = shift;
	
	my $string = $self->{'Chunk'}->get_string($self->{'Pointer'});
	assert(defined $string, "unable to retrieve NameString") if DEBUG;
	my $xml = sprintf(" %s", $string->get_xml(@_));
	
	$self->{'Chunk'}->set_defered_output($xml);
		
	return '';
}

sub parse_self {
	my $self = shift;
	
	assert($self->{'Length'} >= 5, "packet too short") if DEBUG;
	my $data = $self->{'Chunk'}->get_data($self->{'Start'}, 5);
	my ($opcode, $Pointer) = unpack("CL", $data);
	my $Flags = $opcode >> 4;
	assert (($Flags & 0xb) == 0, "unknown flag $Flag") if DEBUG;
	$opcode = $opcode & 0x0f;	
	assert($opcode == 0x06, "bad opcode, expected 6, got $opcode") if DEBUG;
	
	$self->{'Pointer'} = $Pointer;
	$self->{'TagLength'} = 5;
	$self->{'DataLength'} = $self->{'Length'} - $self->{'TagLength'};
#	if ($Flags != 0) {
#		print $self->{'Chunk'}->get_hexdump($self->{'Start'}, $self->{'DataLength'});
#	}
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
		# insert in string table
		assert(defined($string), "undefined pointer to string") if DEBUG;
		$self->{'Chunk'}->set_string($self->{'Pointer'}, $string);
		$string->parse_self();
		$string->parse_down();
		$self->{'DataLength'} = $string->get_length();
	};	
	$self->{'Length'} = $self->{'TagLength'} + $self->{'DataLength'};
}


sub release {
	my $self = shift;
	
	undef $self->{'Pointer'};
	$self->SUPER::release();
}

1;
