package Parse::Evtx2::Chunk;

# This object represents a 64kB chunk of an event log file.
# For more information about its header please see my blog post:
# http://computer.forensikblog.de/en/2007/07/evtx_chunk_header.html

use Parse::Evtx2::Const 1.0.4 qw(:checks);
use Parse::Evtx2::Event;
use Parse::Evtx2::BXmlNode::Template;
use Digest::CRC qw(crc32);
use Math::BigInt;
use Fcntl qw(:seek);
use Carp::Assert;

use version; our $VERSION = qv('1.1.1');


sub new {
	my $class = shift;
	my $self = {
	    'Start' => 0,
	    @_,
	};
	assert(defined $self->{'FH'}, "undefined file handle") if DEBUG;
	bless $self, $class;

	# cache chunk
	$self->{'Length'} = 0x10000;
	$self->{'FH'}->binmode;
	$self->{'FH'}->seek($self->{'Start'}, SEEK_SET);
	$self->{'FH'}->read($self->{'DATA'}, $self->{'Length'});
	return undef unless (substr($self->{'DATA'}, 0, 8) eq "ElfChnk\000");
	
	# parse chunk header
	my ($NumFirstLow, $NumFirstHigh, $NumLastLow, $NumLastHigh) = 
		unpack("LLLL", substr($self->{'DATA'}, 8, 16));
	$self->{'NumFirst'} = 
		Math::BigInt->new($NumFirstHigh)->blsft(32)->bxor($NumFirstLow);
	$self->{'NumLast'} = 
		Math::BigInt->new($NumLastHigh)->blsft(32)->bxor($NumLastLow);

	my ($NumFirstFileLow, $NumFirstFileHigh, $NumLastFileLow, $NumLastFileHigh) = 
		unpack("LLLL", substr($self->{'DATA'}, 0x18, 16));
	$self->{'NumFirstFile'} = 
		Math::BigInt->new($NumFirstFileHigh)->blsft(32)->bxor($NumFirstFileLow);
	$self->{'NumLastFile'} = 
		Math::BigInt->new($NumLastFileHigh)->blsft(32)->bxor($NumLastFileLow);
		
	$self->{'OfsNextRec'} = unpack('V', substr($self->{'DATA'}, 0x30, 4));
		
	# fetch check sums
	$self->{'Crc32Data'} = unpack('V', substr($self->{'DATA'}, 0x34, 4));	
	$self->{'Crc32Header'} = unpack('V', substr($self->{'DATA'}, 0x7c, 4));
		
	return $self;	
}


sub release {
	my $self = shift;
	
	undef $self->{'Crc32Data'};
	undef $self->{'Crc32Header'};
	undef $self->{'Event'};
	undef $self->{'Length'};
	undef $self->{'NumFirst'};
	undef $self->{'NumLast'};
	undef $self->{'NumFirstFile'};
	undef $self->{'NumLastFile'};
	undef $self->{'OfsNextRec'};
	undef $self->{'Start'};
	undef $self->{'TagState'};
	
	foreach $object (@{$self->{'OBJECTSTACK'}}) {
		$object->release();
		undef $object;
	}

	undef $self->{'DATA'};	
	undef $self->{'DEFERED_OUTPUT'};
	undef $self->{'ELEMENTSTACK'};
	undef $self->{'FH'};
	undef $self->{'OBJECTSTACK'};
	undef $self->{'ROOTSTACK'};
	undef $self->{'STRINGS'};
	undef $self->{'TEMPLATES'};
}


sub push_object {
	my $self = shift;
	my $object = shift;
	
	push @{$self->{'OBJECTSTACK'}}, $object;	
}


sub check {
	my $self = shift;
	
	my $result = 0;
	
	# check header CRC
	my $data = substr($self->{'DATA'}, 0, 0x78);
	$data .= substr($self->{'DATA'}, 0x80, 0x180);
	$crc32 = crc32($data);
	if ($crc32 != $self->{'Crc32Header'}) {
		$result |= $EVTX_CHECK_HEADERCRC;
	}
	
	# check data CRC
	$data = substr($self->{'DATA'}, 0x200, $self->{'OfsNextRec'}-0x200);
	my $crc32 = crc32($data);
	if ($crc32 != $self->{'Crc32Data'}) {
		$result |= $EVTX_CHECK_DATACRC;
	}
	
	return $result;
}


sub get_data {
	my $self = shift;
	my $start = shift;
	my $length = shift;

	assert(($start+$length) <= $self->{'Length'}, "") if DEBUG;
	return substr($self->{'DATA'}, $start, $length);
}


sub get_hexdump {
	my $self = shift;
	my $start = shift;
	my $length = shift;

	assert(($start+$length) <= $self->{'Length'}) if DEBUG;
	
	use Data::Hexify;
	return Hexify($self->{'DATA'}, {start => $start, length => $length});
}


sub push_element {
	my $self = shift;
	my $element = shift;
	
	push @{$self->{'ELEMENTSTACK'}}, $element;
}


sub get_depth {
	my $self = shift;
	
	return $#{$self->{'ELEMENTSTACK'}};
}


sub get_element {
	my $self = shift;
	
	return @{$self->{'ELEMENTSTACK'}}[get_depth()];
}


sub pop_element {
	my $self = shift;
	
	return pop @{$self->{'ELEMENTSTACK'}};
}


sub push_root {
	my $self = shift;
	my $root = shift;
	
	unshift @{$self->{'ROOTSTACK'}}, $root;
}


sub pop_root {
	my $self = shift;
	
	shift @{$self->{'ROOTSTACK'}};
}


sub get_root {
	my $self = shift;
	
	return  @{$self->{'ROOTSTACK'}}[0];
}


sub get_start {
	my $self = shift;
	
	return $self->{'Start'};
}


sub get_length {
	my $self = shift;
	
	return $self->{'Length'};
}


sub get_defered_output {
	my $self = shift;
	
	my $xml = $self->{'DEFERED_OUTPUT'};
	$self->{'DEFERED_OUTPUT'} = '';
	
	return $xml;	
}


sub set_defered_output {
	my $self = shift;
	
	# additional parameters
	my $xml = shift;
	
	$self->{'DEFERED_OUTPUT'} .= $xml;
}


sub get_string {
	my $self = shift;
	my $address = shift;
	
	return $self->{'STRINGS'}{$address};
}


sub set_string {
	my $self = shift;
	my $address = shift;
	my $string = shift;
	
	assert($address > 0x0080, 
		"address too low, minimum is 0x80, got $address") if DEBUG;
	assert($address <= $self->{'Length'}, 
		"address behind data") if DEBUG;
	assert(defined $string, 
		"attempting to store undefined string") if DEBUG;
	$self->{'STRINGS'}{$address} = $string;
}


sub get_tag_state {
	my $self = shift;
	
	return $self->{'TagState'};
}


sub set_tag_state {
	my $self = shift;
	
	$self->{'TagState'} = shift;
}


sub collect_templates {
	my $self = shift;
	
	# find and load all NameStrings
	my $BUCKETS = 64;
	my $data = $self->get_data(0x80, 4*$BUCKETS);
	my @bucket = unpack("L*", $data);
	my ($i, $next, $result);
	for ($i=0; $i<$BUCKETS; $i++) {
		$next = $bucket[$i];
		while($next > 0) {
			my $length = $self->{'OfsNextRec'} - $next;
			my $name = Parse::Evtx2::BXmlNode::NameString->new(
				'Chunk' => $self,
				'Parent' => $self,
				'Start' => $next,
				'Length' => $length,
			);
			assert(defined $name, "unable to create NameString at offset $next") if DEBUG;
			$name->parse_self();
			$name->parse_down();
			$self->set_string($next, $name);
			$self->push_object($name);
			$next = $name->{'Next'};
		}
	}
	
	# find and load all templates
	$BUCKETS = 32;
	$data = $self->get_data(0x180, 4*$BUCKETS);
	@bucket = unpack("L*", $data);
	for ($i=0; $i<$BUCKETS; $i++) {
		$next = $bucket[$i];
		while ($next > 0) {
			# sanity check
			my ($opcode, $unknown1, $TemplateId, $Pointer) = 
				unpack("CCLL", $self->get_data($next-10, 10)); 
			if (($opcode != 0x0c) or ($Pointer != $next)) {
				# printf "WARNING! opcode=0x%x (expected 0xc), expected pointer 0x%x, got 0x%x\n", $opcode, $next, $Pointer;
				$next = 0;
				next;
			}
			
			# create template object
			my $length = $self->{'OfsNextRec'} - $next;
			my $template = Parse::Evtx2::BXmlNode::Template->new(
				'Chunk' => $self,
				'Parent' => $self,
				'Start' => $next,
				'Length' => $length,
			);
			assert(defined $template, "unable to create template at offset $next") if DEBUG;
			$template->parse_self();
			$template->parse_down();
			$self->set_template($next, $template);
			$self->push_object($template);
			$next = $template->{'Next'};				
		}
	}	
}


sub get_template {
	my $self = shift;
	my $address = shift;
	
	return $self->{'TEMPLATES'}{$address};
}


sub get_templates {
	my $self = shift;
	
	# return sorted list of template base addresses
	return sort { $a<=>$b } keys %{$self->{'TEMPLATES'}};
}



sub set_template {
	my $self = shift;
	my $address = shift;
	my $template = shift;	

	assert($address > 0x0080, 
		"address too low, minimum is 0x80, got $address") if DEBUG;
	assert($address <= $self->{'Length'},
		"address behind data") if DEBUG;
	assert(defined $template, 
		"attempting to store undefined template") if DEBUG;
	$self->{'TEMPLATES'}{$address} = $template;
}


sub get_first_event {
	my $self = shift;
	
	my $event = Parse::Evtx2::Event->new(
	   'Chunk' => $self, 
	   'Start' => 0x200,
	);
	$self->{'Event'} = $event;
	$self->push_object($event);
	return $event;
}


sub get_next_event {
	my $self = shift;
	
	my $start = $self->{'Event'}->get_start() + 
        $self->{'Event'}->get_length();
	
	# signal "end of chunk"
	if ($start >= $self->{'OfsNextRec'}) {
		return undef;
	}
	
	my $event = Parse::Evtx2::Event->new(
	   'Chunk' => $self, 
	   'Start' => $start,
	);
	$self->{'Event'} = $event;
	$self->push_object($event);
	return $event;
}


1;

__END__

=head1 NAME

Parse::Evtx2::Chunk - parses a chunk of a Microsoft Windows Vista event log 
file (.evtx)

=head1 SYNOPSIS

	use Parse::Evtx2::Chunk;
	
    # create an object for your event log file
    my $fh = IO::File->new('justachunk.bin', "r");
    
    # create a chunk object
    my $parser = Parse::Evtx2::Chunk->new('FH' => $fh);

    # iterate through all event records
    my $event = $parser->get_first_event();
    while (defined $event) {
        print $event->get_xml();
        $event = $file->get_next_event();
    };
    
    # all done, close the file handle
    $fh->close();	
	
=head1 DESCRIPTION

Microsoft Windows Vista records events in a proprietary binary file format. 
An object of this class represents a parser for a chunk of a Vista event log 
file. A chunk is a block of 64 kiB of data, that consists of header 
information, internal tables and event data. The main purpose of this modules 
is to translate event log files from their native binary form into textual 
XML.

The chunk object provides central services to other classes, e.g. stacks
for elements, strings and XML templates.

=head1 METHODS

=head2 new

This is the constructor for the parser class.

=head3 Parameters

=over

=item FH 

This is a handle object for the event log file. The object is required to be a
descendant of IO::File.

=item Start

Offset into the file handle where the chunk is expected to start. This 
parameter is optional; it defaults to 0.

=back

=head2 check

This method checks the chunk for certain errors and marks them in a
return code. Right now, only the CRC32 check of the chunk header is
implemented.

=head2 get_first_event

This method retrieves the first event record from a file. It returns an 
L<Parse::Evtx2::Event> object on success and C<undef> on failure. Note that 
get_first_event changes the file pointer in the associated file handle object.

=head2 get_next_event

This method retrieves the next event record from a file. It returns an 
L<Parse::Evtx2::Event> object on success and C<undef> on failure. Note that 
get_next_event changes the file pointer in the associated file handle object.

=head2 get_start

Returns the offset into the file

=head2 get_length

Returns the lengths of the section of the log file that corresponds with the
chunk object.

=head1 DIAGNOSTICS

B<new> returns C<undef>, if it doesn't recognize the format of the file.

Other errors will be signalled through assertions and die().

=head1 DEPENDENCIES

This module depends on the following non-standard modules, which are also not 
part of this package:

=over

=item Carp::Assert

=item Data::Hexify 

=item Digest::Crc32

=item Math::BigInt

=back

=head1 SEE ALSO

evtxdump.pl, evtxtemplates.pl, Parse::Evtx2, Parse::Evtx2::Event

=head1 HISTORY

=over

=item v1.0.0 (2007-08-10) Initial release.
=item v1.0.1 (2009-12-21) Bugfixes, improved parsing of header.
=item v1.0.3 (2010-02-11) Implemented CRC32 check of chunk header.
=item v1.0.4 (2010-03-24) Added CRC32 check of event data.
=item v1.1.1 (2011-11-17) Fixed memory leaks.

=back

=head1 AUTHOR

Andreas Schuster (schuster@cpan.org)

=head1 LICENSE AND COPYRIGHT

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2, or (at your option)
any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software Foundation,
Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307, USA.

=cut
