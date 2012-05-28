# substitution array
package Parse::Evtx2::BXmlNode::SubstArray;
use base qw( Parse::Evtx2::BXmlNode );

require Parse::Evtx2::VariantType;
use Carp::Assert;


sub get_xml {
	my $self = shift;
	
	use Carp;
	confess('get_xml called on BXmlNode::SubstArray');
}

sub get_substitute {
	my $self = shift;
	
	# parameters
	my $index = shift;
	my $type = shift;
	my $optional = shift;
	
	assert($index < $self->{'ElementCount'}, "index out of bounds") if DEBUG;
	my @ElementType = @{$self->{'ElementType'}};
	my @Children = @{$self->{'Children'}};
		
	my $xml = '';
	$xml = $Children[$index]->get_xml(1);
	
	return $xml;
}


sub parse_self {
	my $self = shift;
	
	$self->{'ElementSize'} = [];
	$self->{'ElementType'} = [];
	
	# read element count
	assert($self->{'Length'} >= 2, "packet too short") if DEBUG;
	my $DataPos = $self->{'Start'};
	my $DataLen = $self->{'Length'};
	my $ElementCount = 
		unpack("L", $self->{'Chunk'}->get_data($DataPos, 4));
	$DataPos += 4;
	$DataLen -= 4;
	$self->{'ElementCount'} = $ElementCount;
	
	# read array index
	assert($DataLen >= 4*$ElementCount, "packet too short") if DEBUG;
	for (my $i = 0; $i < $ElementCount; $i++) {
		my ($Size, $Type, $unknown) =
			unpack("SCC", $self->{'Chunk'}->get_data($DataPos, 4));
		$DataPos += 4;
		@{$self->{'ElementSize'}}[$i] = $Size;
		@{$self->{'ElementType'}}[$i] = $Type;
	
	}
	$DataLen -= 4*$ElementCount;
	$self->{'DataLength'} = $DataLen;
	$self->{'TagLength'} = $DataPos - $self->{'Start'};
}

sub parse_down {
	my $self = shift;
	
	# fill array, convert data into printable form
	my $ElementCount = $self->{'ElementCount'};
	my $DataPos = $self->{'Start'} + $self->{'TagLength'};
	my $DataLen = $self->{'DataLength'};
	for (my $i = 0; $i < $ElementCount; $i++) {
		my $child = Parse::Evtx2::VariantType::new_variant(
			@{$self->{'ElementType'}}[$i],
			$self->{'Chunk'},
			$DataPos,
			@{$self->{'ElementSize'}}[$i],
			1
		);
		$child->parse_self();
		assert($child->get_length() == @{$self->{'ElementSize'}}[$i],
			"child has wrong size") if DEBUG;
		$DataPos += $child->get_length();
		$DataLen -= $child->get_length();
		@{$self->{'Children'}}[$i] = $child;			
	}
}

1;
