# XML template
package Parse::Evtx::BXmlNode::Template;

use base qw( Parse::Evtx::BXmlNode );
use Carp::Assert;

sub get_xml {
	my $self = shift;
	my %args = (
			@_,
		);
	return 	$self->SUPER::get_xml(@_);
}


sub parse_self {
	my $self = shift;

	assert($self->{'Length'} >= 24);
	
	# start parsing the template header
	my $data = $self->{'Chunk'}->get_data($self->{'Start'}, 8);
	my ($Next, $TemplateId) = unpack("LL", $data);
	$self->{'Next'} = $Next;
	$self->{'TemplateId'} = $TemplateId;
		
	# read template GUID
	$data = $self->{'Chunk'}->get_data($self->{'Start'}+4, 16);
	my @GUID = unpack("h8h4h4H4H12", $data);
	my $i;
	# reverse the leading three groups
	for ($i=0; $i<=2; $i++) {
		$GUID[$i] = reverse($GUID[$i]);
	}
	$self->{'GUID'} = sprintf("{%8s-%4s-%4s-%4s-%12s}", @GUID);
	# convert hex strings to uppercase
	$self->{'GUID'} =~ tr/a-f/A-F/;
		
	$self->{'TagLength'} = 24;
	
	$data = $self->{'Chunk'}->get_data($self->{'Start'}+20, 4);
	my $length = unpack("L", $data);
	$self->{'DataLength'} = $length;
	
	$self->{'Length'} = $self->{'TagLength'} + $self->{'DataLength'};
}


sub get_template_guid {
	my $self = shift;	
	return $self->{'GUID'};
}

sub get_template_id {
	my $self = shift;
	return $self->{'TemplateId'};
}

1;