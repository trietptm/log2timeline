package Parse::Evtx::BXmlNode::NameString;
use base qw( Parse::Evtx::BXmlNode );

use Carp::Assert;
use Encode;
use Encode::Unicode;

sub get_xml {
	my $self = shift;

	return $self->{'String'};	
}

sub parse_self {
	my $self = shift;
	
	assert($self->{'Length'} >= 10, "packet too short") if DEBUG;
	my $data = $self->{'Chunk'}->get_data($self->{'Start'}, 8);
	my ($backlink, 
		$hash, 
		$Length) = unpack("LSS", $data);
	$self->{'TagLength'} = 8;
	$self->{'DataLength'} = ($Length+1) * 2;	# this could be dangerous!
	$self->{'String'} = decode(
		"UCS2-LE", 
		$self->{'Chunk'}->get_data($self->{'Start'}+8, $Length*2)
	);
	$self->{'Length'} = $self->{'TagLength'} + $self->{'DataLength'};	
}

sub parse_down {
	# a NameString has no children
}

1;