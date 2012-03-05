package Parse::Evtx::BXmlNode;

require Parse::Evtx::BXmlNode::NameString;
require Parse::Evtx::BXmlNode::Node0x00;	# End of stream
require Parse::Evtx::BXmlNode::Node0x01;	# Open start element tag
require Parse::Evtx::BXmlNode::Node0x02;	# Close start element tag
require Parse::Evtx::BXmlNode::Node0x03;	# Close empty element tag
require Parse::Evtx::BXmlNode::Node0x04;	# End element tag
require Parse::Evtx::BXmlNode::Node0x05;	# Value
require Parse::Evtx::BXmlNode::Node0x06;	# Attribute
require Parse::Evtx::BXmlNode::Node0x07;	# CDATA
							 # Node0x08 
require Parse::Evtx::BXmlNode::Node0x09;	# Entity reference
require Parse::Evtx::BXmlNode::Node0x0a;	# PItarget
require Parse::Evtx::BXmlNode::Node0x0b;	# PIdata 
require Parse::Evtx::BXmlNode::Node0x0c;	# Template instance
require Parse::Evtx::BXmlNode::Node0x0d;	# Normal substitution
require Parse::Evtx::BXmlNode::Node0x0e;	# Conditional substitution
require Parse::Evtx::BXmlNode::Node0x0f;	# Stream opening sequence
require Parse::Evtx::BXmlNode::Root;
require Parse::Evtx::BXmlNode::SubstArray;
require Parse::Evtx::BXmlNode::Template;

use Carp;
use Carp::Assert;

use version; our $VERSION = qv('1.1.1');


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
	
	# register as an object
	$self->{'Chunk'}->push_object($self);

	return $self;
}


sub release {
	my $self = shift;
	
	undef $self->{'Chunk'};
	undef $self->{'Parent'};
	undef $self->{'Start'};
	undef $self->{'Length'};
	undef $self->{'TagLength'};
	undef $self->{'DataLength'};
	my $child;
	foreach $child (@{$self->{'Children'}}) {
		$child->release();
		undef $child;
	}
	undef $self->{'Children'};
	undef $self->{'EndOfStream'};
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
	} elsif ($opcode == 0x07) {
		$child = Parse::Evtx::BXmlNode::Node0x07->new(
			'Chunk' => $self->{'Chunk'},
			'Parent' => $self,
			'Start' => $Start,
			'Length' => $Length,
		);	
	} elsif ($opcode == 0x09) {
		$child = Parse::Evtx::BXmlNode::Node0x09->new(
			'Chunk' => $self->{'Chunk'},
			'Parent' => $self,
			'Start' => $Start,
			'Length' => $Length,
		);	
	} elsif ($opcode == 0x0a) {
		$child = Parse::Evtx::BXmlNode::Node0x0a->new(
			'Chunk' => $self->{'Chunk'},
			'Parent' => $self,
			'Start' => $Start,
			'Length' => $Length,
		);		
	} elsif ($opcode == 0x0b) {
		$child = Parse::Evtx::BXmlNode::Node0x0b->new(
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
		print "\nPlease submit the following information\n";
		print "to bugs-evtxparser\@forensikblog.de\n";
		print "Earlier data:\n";
		print $self->{'Chunk'}->get_hexdump($Start-64, 64);
		print "\nCurrent data:\n";
		print $self->{'Chunk'}->get_hexdump($Start, $Length);
		confess("new_subnode: unknown opcode $opcode.");
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


sub get_hexdump {
	my $self = shift;
	my %args = (@_);
	
	assert(defined $self->{'Chunk'}, "Chunk undefined") if DEBUG;
	assert(defined $self->{'Start'}, "Start undefied") if DEBUG;
	assert(defined $self->{'Length'}, "Length undefined") if DEBUG;
	$self->{'Chunk'}->get_hexdump($self->{'Start'}, $self->{'Length'});
}


sub get_length {
	my $self = shift;
	
	return $self->{'Length'};
}


sub get_xml {
	my $self = shift;
	my %args = (@_);
	
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
	my %args = (@_);
	
	my $root = $self->{'Chunk'}->get_root();
	assert(defined($root), 
		"undefined root element") if DEBUG;
	return $root->get_substitute(@_);
}

1;