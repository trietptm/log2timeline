package Parse::Evtx::BXmlNode;

require Parse::Evtx::BXmlNode::NameString;
require Parse::Evtx::BXmlNode::Node0x00;
require Parse::Evtx::BXmlNode::Node0x01;
require Parse::Evtx::BXmlNode::Node0x02;
require Parse::Evtx::BXmlNode::Node0x03;
require Parse::Evtx::BXmlNode::Node0x04;
require Parse::Evtx::BXmlNode::Node0x05;
require Parse::Evtx::BXmlNode::Node0x06;
require Parse::Evtx::BXmlNode::Node0x0c;
require Parse::Evtx::BXmlNode::Node0x0d;
require Parse::Evtx::BXmlNode::Node0x0e;
require Parse::Evtx::BXmlNode::Node0x0f;
require Parse::Evtx::BXmlNode::Root;
require Parse::Evtx::BXmlNode::SubstArray;
require Parse::Evtx::BXmlNode::Template;

use Carp;
use Carp::Assert;


sub new {
	my $class = shift;
	my $self = {
	    @_,
	};
	bless $self, $class;
	
	# additional parameters
    assert(defined $self->{'Chunk'});   # current chunk
    assert(defined $self->{'Parent'});  # parent object
    assert(defined $self->{'Start'});   # start offset within chunk
    assert(defined $self->{'Length'});  # length of tag, will be trimmed down later
	assert($self->{'Length'} > 0);
	assert($self->{'Length'} <= 0xffff - 0x0200);
	assert($self->{'Start'} + $self->{'Length'} <= 0xffff);
	
	# additional variables
	$self->{'TagLength'} = 0;
	$self->{'DataLength'} = 0;
	$self->{'Children'} = [];			# list of child objects	
	$self->{'EndOfStream'} = 0;			# subtree reached End-of-Stream

	return $self;
}


sub new_subnode {
	my $self = shift;
	my $Start = shift;
	my $Length = shift;

	my ($opcode) = unpack("C", $self->{'Chunk'}->get_data($Start, 1));
	$opcode = $opcode & 0x0f; 
	my $child;
	if	($opcode == 0x00) {
		$child = Parse::Evtx::BXmlNode::Node0x00->new(
			'Chunk' => $self->{'Chunk'},
			'Parent' => $self,
			'Start' => $Start,
			'Length' => $Length,
		);
	} elsif ($opcode == 0x01) {
		$child = Parse::Evtx::BXmlNode::Node0x01->new(
			'Chunk' => $self->{'Chunk'},
			'Parent' => $self,
			'Start' => $Start,
			'Length' => $Length,
		);
	} elsif ($opcode == 0x02) {
		$child = Parse::Evtx::BXmlNode::Node0x02->new(
			'Chunk' => $self->{'Chunk'},
			'Parent' => $self,
			'Start' => $Start,
			'Length' => $Length,
		);
	} elsif ($opcode == 0x03) {
		$child = Parse::Evtx::BXmlNode::Node0x03->new(
			'Chunk' => $self->{'Chunk'},
			'Parent' => $self,
			'Start' => $Start,
			'Length' => $Length,
		);	
	} elsif ($opcode == 0x04) {
		$child = Parse::Evtx::BXmlNode::Node0x04->new(
			'Chunk' => $self->{'Chunk'},
			'Parent' => $self,
			'Start' => $Start,
			'Length' => $Length,
		);		
	} elsif ($opcode == 0x05) {
		$child = Parse::Evtx::BXmlNode::Node0x05->new(
			'Chunk' => $self->{'Chunk'},
			'Parent' => $self,
			'Start' => $Start,
			'Length' => $Length,
		);		
	} elsif ($opcode == 0x06) {
		$child = Parse::Evtx::BXmlNode::Node0x06->new(
			'Chunk' => $self->{'Chunk'},
			'Parent' => $self,
			'Start' => $Start,
			'Length' => $Length,
		);	
	} elsif ($opcode == 0x0c) {
		$child = Parse::Evtx::BXmlNode::Node0x0c->new(
			'Chunk' => $self->{'Chunk'},
			'Parent' => $self,
			'Start' => $Start,
			'Length' => $Length,
		);		
	} elsif ($opcode == 0x0d) {
		$child = Parse::Evtx::BXmlNode::Node0x0d->new(
			'Chunk' => $self->{'Chunk'},
			'Parent' => $self,
			'Start' => $Start,
			'Length' => $Length,
		);	
	} elsif ($opcode == 0x0e) {
		$child = Parse::Evtx::BXmlNode::Node0x0e->new(
			'Chunk' => $self->{'Chunk'},
			'Parent' => $self,
			'Start' => $Start,
			'Length' => $Length,
		);		
	} elsif ($opcode == 0x0f) { 
		$child = Parse::Evtx::BXmlNode::Node0x0f->new(
			'Chunk' => $self->{'Chunk'},
			'Parent' => $self,
			'Start' => $Start,
			'Length' => $Length,
		); 
	} else {
		# die on unknown opcode
		$self->{'Chunk'}->get_hexdump($Start, 16);
		confess("new_subnode: unknown opcode.");
	};
	return $child;
}


sub parse_self {
	my $self = shift;
	
	# abstract method
	$self->{'TagLength'} = 0;
	$self->{'DataLength'} = $self->{'Length'};
}


sub parse_down {
	# splits the remainder among the childs
	my $self = shift;
	
	my $DataPos = $self->{'Start'} + $self->{'TagLength'};
	my $DataLen = $self->{'DataLength'};
	
	while (($DataLen > 0) & ($self->{'EndOfStream'} <= 0)) {				
		my $child = $self->new_subnode($DataPos, $DataLen);
		if (defined($child)) { 
			push @{$self->{'Children'}}, $child;
			$child->parse_self();
			$child->parse_down();
			$self->{'EndOfStream'} = $child->get_end_of_stream();		
			$DataPos += $child->get_length();
			$DataLen -= $child->get_length();
		} else { 
			last; 
		}
	}
}


sub get_end_of_stream {
	my $self = shift;

	return $self->{'EndOfStream'};
}


sub get_length {
	my $self = shift;
	
	return $self->{'Length'};
}


sub get_xml {
	my $self = shift;
	
	my $result = '';
	my $child;
	# iterate through all children
	foreach $child (@{$self->{'Children'}}) {
		$result .= $child->get_xml(@_);
	}
	return $result;
}


sub get_substitute {
	my $self = shift;
	
	my $root = $self->{'Chunk'}->get_root();
	assert(defined($root), 
		"undefined root element") if DEBUG;
	return $root->get_substitute(@_);
}

1;