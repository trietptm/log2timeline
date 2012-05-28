package Parse::Evtx2::Event;

# This object represents an event log record. For more information 
# about its format please consult my blog post at:
# http://computer.forensikblog.de/en/2007/07/evtx_event_record.html

use Parse::Evtx2::BXmlNode 1.1.1;
use Parse::Evtx2::BXmlNode::Root;
use Math::BigInt;
use DateTime;
use Carp::Assert;

#perl2exe_include "DateTime/Locale/en.pm"

use version; our $VERSION = qv('1.1.1');


sub new {
	my $class = shift;
	my $self = {
	    @_,
	};
	assert(defined $self->{'Chunk'}, "undefined chunk") if DEBUG;
	assert(defined $self->{'Start'}, "undefined offset") if DEBUG;
	bless $self, $class;

	# cache frequently used values
	my $chunk = $self->{'Chunk'};
	my $start = $self->{'Start'};

	# read record header
	my ($Magic) = unpack('L', $chunk->get_data($start, 4));
	return undef if ($Magic != 0x00002a2a);

	my ($Length1, 
		$RecNumLow, $RecNumHigh, 
		$TimeCreatedLow, $TimeCreatedHigh) = 
		unpack('LLLLL', $chunk->get_data($start+4, 20));
		
	$self->{'RecordId'} = 
		Math::BigInt->new($RecNumHigh)->blsft(32)->bxor($RecNumLow);
		
	my $filetime = Math::BigInt->new($TimeCreatedHigh)->blsft(32)->bxor($TimeCreatedLow);
	$filetime /= 1000;
	$filetime -= 116444736000000;
	my $seconds = $filetime / 10000;
	my $fraction = $filetime - $seconds*10000;
	my $datetime = DateTime->from_epoch(epoch => $seconds->numify(), time_zone => 'UTC');
	$self->{'TimeCreated'} = sprintf("%s.%sZ", $datetime, $fraction->numify());
			
	my $Length2 = unpack("L", $chunk->get_data($self->{'Start'}+$Length1-4, 4));

	# Mismatching Length fields indicate an incomplete record.
	# This is commonly to be found at the end of a chunk.
	# Return "undef", so the parser can advance to the next chunk.
	return undef unless ($Length1 == $Length2);
	
	$self->{'Length'} = $Length1;	
	
	my $Root = Parse::Evtx2::BXmlNode::Root->new(
		'Chunk' => $chunk,
		'Parent' => $self,
		'Start' => $self->{'Start'} + 24,
		'Length' => $self->{'Length'} - 28
	);
	assert(defined($Root), "undefined root") if DEBUG;
	$self->{'Root'} = $Root;
	$Root->parse_self();
	$Root->parse_down();
	
	return $self;
}


sub release {
	my $self = shift;
	
	undef $self->{'Chunk'};
	undef $self->{'Length'};
	undef $self->{'RecordId'};
	undef $self->{'Root'};
	undef $self->{'Start'};
	undef $self->{'TimeCreated'};
}


sub get_length {
	my $self = shift;
	
	return $self->{'Length'};
}


sub get_start {
	my $self = shift;
	
	return $self->{'Start'};
}


sub get_record_id {
	my $self = shift;
	
	return $self->{'RecordId'}->numify();
}


sub get_root_obj {
	my $self = shift;
	
	return $self->{'Root'};
}


sub get_time_created {
	my $self = shift;
	
	return $self->{'TimeCreated'};
}


sub get_xml {
	my $self = shift;
	
	$self->{'Root'}->get_xml(@_);
}

1;
