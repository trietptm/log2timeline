# XML template
package Parse::Evtx::BXmlNode::Template;

use base qw( Parse::Evtx::BXmlNode );
use Carp::Assert;

sub parse_self {
	my $self = shift;

	assert($self->{'Length'} >= 24);
	my $data = $self->{'Chunk'}->get_data($self->{'Start'}, 24);
	my ($unknown1, 
		$TemplateId, 
		$unknown2, $unknown3, $unknown4, 
		$length) = unpack("LLLLLL", $data);
	$self->{'TemplateId'} = $TemplateId;
	$self->{'TagLength'} = 24;
	$self->{'DataLength'} = $length;
	$self->{'Length'} = $self->{'TagLength'} + $self->{'DataLength'};
};

sub get_template_id {
	my $self = shift;
	
	return $self->{'TemplateId'};
};

1;