# root node
package Parse::Evtx::BXmlNode::Root;
use base qw( Parse::Evtx::BXmlNode )
;
require Parse::Evtx::BXmlNode::SubstArray;
use Carp::Assert;

sub get_substitute {
	my $self = shift;

	$self->{'SubstArray'}->get_substitute(@_);
};


sub get_array_obj {
	my $self = shift;
	
	return $self->{'SubstArray'};
};


sub get_xml {
	my $self = shift;
	
	# change root context
	$self->{'Chunk'}->push_root($self);
	my $xml = $self->SUPER::get_xml(@_);
	# restore root context
	my $root = $self->{'Chunk'}->pop_root();
	assert($root == $self, "root is not self") if DEBUG;
	return $xml;
};


sub parse_self {
	my $self = shift;
	
	# the root node has no tag, so there's not much to be done here
	$self->{'TagLength'} = 0; 
	$self->{'DataLength'}  = $self->{'Length'};
};

sub parse_down {
	my $self = shift;
	
	# get the XML stream
	$self->SUPER::parse_down();
		
	# the remainder is the substitution array
	my $array = Parse::Evtx::BXmlNode::SubstArray->new(
		'Chunk' => $self->{'Chunk'},
		'Parent' => $self,
		'Start' => $self->{'EndOfStream'},
		'Length' => $self->{'Length'} 
		  - $self->{'EndOfStream'} 
		  + $self->{'Start'},
	);
	assert(defined $array, "there is no substitution array") if DEBUG;
	$array->parse_self();
	$array->parse_down();
	$self->{'SubstArray'} = $array;
};

1;