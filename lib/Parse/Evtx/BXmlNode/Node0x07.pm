# CDATA section
package Parse::Evtx::BXmlNode::Node0x07;
use base qw( Parse::Evtx::BXmlNode );

use Carp::Assert;
use Encode;


sub get_xml {
	my $self = shift;
	
	my $xml = sprintf("<![CDATA[%s]]>", $self->{'String'});
	return $xml;
}


sub parse_self {
	my $self = shift;
	
	assert($self->{'Length'} >= 3, "packet too short") if DEBUG;
	my $data = $self->{'Chunk'}->get_data($self->{'Start'}, 3);
	my ($opcode, $strlength) = unpack("CS", $data);
	my $Flags = $opcode >> 4;
	assert(($Flags & 0x00) == 0, "unexpected flag") if DEBUG;
	$opcode = $opcode & 0x0f;	
	assert($opcode == 0x07, "bad opcode") if DEBUG;
		
	$self->{'TagLength'} = 3;	
	$self->{'DataLength'} = $strlength * 2;
	$self->{'Flags'} = $Flags;
}


sub parse_down {
	my $self = shift;
	
	$self->{'String'} = decode(
		"UCS2-LE", 
		$self->{'Chunk'}->get_data(
			$self->{'Start'} + $self->{'TagLength'}, 
			$self->{'DataLength'}-2
		)
	);	
	$self->{'Length'} = $self->{'TagLength'} + $self->{'DataLength'};	
}


1;