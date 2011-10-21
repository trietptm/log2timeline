package Parse::Evtx;

# This object represents an event log file. For more information
# about the file header please see my blog post at:
# http://computer.forensikblog.de/en/2007/07/evtx_file_header.html

use Parse::Evtx::Const 1.0.4 qw(:checks);
use Parse::Evtx::Chunk;
use Parse::Evtx::BXmlNode;
use Digest::CRC;
use Math::BigInt;
use Fcntl qw( :seek );
use Carp::Assert;

use version; our $VERSION = qv('1.0.5');

#perl2exe_include "Math/BigInt.pm";
#perl2exe_include "Math/BigInt/Calc.pm";
#perl2exe_include "Math/BigInt/FastCalc.pm";


sub new {
	my $class = shift;
	my $self = {
	    @_,
	};
	assert(defined $self->{'FH'});
	bless $self, $class;
	
	# cache file header
	$self->{'FH'}->binmode();
	$self->{'FH'}->seek(0x0, SEEK_SET);
	$self->{'FH'}->read($self->{'DATA'}, 0x80);

    # signal an improper file format to caller by returning 'undef'
    return undef if (substr($self->{'DATA'}, 0, 8) ne "ElfFile\000");
	
	# parse header fields
	
	my ($NumCurrentChunkLow, $NumCurrentChunkHigh) = 
		unpack("LL", substr($self->{'DATA'}, 0x10, 8));
	$self->{'CurrentChunk'} = 
		Math::BigInt->new($NumCurrentChunkHigh)->blsft(32)->bxor($NumCurrentChunkLow);	
		
	# This is the next record number if a new chunk was added - Rob Hulley	
	my ($NumNextRecLow, $NumNextRecHigh) = 
		unpack("LL", substr($self->{'DATA'}, 0x18, 8));
	$self->{'NextRecord'} = 
		Math::BigInt->new($NumNextRecHigh)->blsft(32)->bxor($NumNextRecLow);
	
	(
		$self->{'HeaderPart1Len'},
		$self->{'VersionMinor'},
		$self->{'VersionMajor'},
		$self->{'HeaderLen'},
		$self->{'ChunkCount'},
	) = unpack('Vvvvv', substr($self->{'DATA'}, 0x20, 12));

	# check for file version 3.1
	assert($self->{'VersionMajor'} == 3);
	assert($self->{'VersionMinor'} == 1);
    # check that only the first 128 bytes are used	
	assert($self->{'HeaderPart1Len'} == 0x80);
	
	(
		$self->{'Flags'},
		$self->{'Checksum'},
	) = unpack('VV', substr($self->{'DATA'}, 0x78, 8));
	
	assert($self->{'HeaderLen'} == 0x1000);
	$self->{'Length'} = 0x1000;		# length of file header
		
	return $self;		
}


sub check {
	my $self = shift;
	
	my $result = 0;
	
	# calculate CRC32
	my $crc32 = crc32(substr($self->{'DATA'}, 0, 0x78));
	if ($crc32 != $self->{'Checksum'}) {
		$result |= $EVTX_CHECK_HEADERCRC;
	}
	
	return $result;
}



sub get_current_chunk {
	my $self = shift;
	
	return $self->{'Chunk'};
}


sub get_first_chunk {
	my $self = shift;

	# the first chunk starts right behind the file header
	assert(defined $self->{'FH'});
	$self->{'Chunk'} = Parse::Evtx::Chunk->new(
		'FH' => $self->{'FH'}, 
		'Start' => $self->{'Length'},
	);
	return $self->{'Chunk'};
}


sub get_next_chunk {
	my $self = shift;

	assert(defined $self->{'Chunk'});
	return undef unless (defined $self->{'Chunk'});
	my $newstart = $self->{'Chunk'}->get_start() + 
		$self->{'Chunk'}->get_length();
	my $chunk = Parse::Evtx::Chunk->new(
		'FH' => $self->{'FH'}, 
		'Start' => $newstart,
    );
	$self->{'Chunk'} = $chunk;
	return $chunk;
}


sub get_first_event {
	my $self = shift;
	
	# create first chunk
	$self->get_first_chunk();
	assert(defined $self->{'Chunk'});
	
	# now get first record
	return $self->{'Chunk'}->get_first_event();	
}


sub get_next_event {
	my $self = shift;
	
	# request next event object from chunk
	assert(defined $self->{'Chunk'});
	my $event = $self->{'Chunk'}->get_next_event();
	
	if (!defined($event)) {
		# chunk reached its end, create next one
		$self->{'Chunk'} = $self->get_next_chunk();
		return undef unless (defined $self->{'Chunk'});
		$event = $self->{'Chunk'}->get_first_event();
	}
	
	return $event;
}


sub get_checksum {
    my $self = shift;
    
    return $self->{'Checksum'};
}

1;

__END__

=head1 NAME

Parse::Evtx - parses a Microsoft Windows Vista event log file (.evtx)

=head1 SYNOPSIS

    use Parse::Evtx;
	
    # create an object for your event log file
    my $fh = IO::File->new('Application.evtx', "r");
    
    # create a parser object
    my $parser = Parse::Evtx->new('FH' => $fh);

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
An object of this class represents a parser for a Vista event log file. 
The main purpose of this modules is to translate event log files from their 
native binary form into textual XML.

The Evtx object instantiates chunk objects as needed.

=head1 METHODS

=head2 new

This is the constructor for the parser class.

=head3 Parameters

=over

=item FH 

This is a handle object for the event log file. The object is required to be a
descendant of B<IO::File>.

=back

=head2 check

This method checks the file for certain errors and marks them in a
return code. Right now, only the CRC32 check of the file header is
implemented. 

=head2 get_current_chunk

This method returns a pointer to the current B<Parse::Evtx::Chunk> object.

=head2 get_first_chunk

This method retrieves the first chunk from a file. A prior call to 
B<get_first_chunk> must have succeeded. The method then returns a
B<Parse::Evtx> object on success and C<undef> on failure. Note, that 
get_first_chunk changes the file pointer in the associated file handle object.
A pointer to the chunk object is stored in the Evtx object and can be 
retrieved by calling B<get_current_chunk>.

=head2 get_next_chunk

This method retrieves the next chunk from a file. It returns a 
B<Parse::Evtx> object on success and C<undef> on failure. Note, that 
get_next_chunk changes the file pointer in the associated file handle object.
A pointer to the chunk object is stored in the Evtx object and can be 
retrieved by calling B<get_current_chunk>.

=head2 get_first_event

This method retrieves the first event record from a file. It returns a 
B<Parse::Evtx::Event> object on success and C<undef> on failure. Note that 
get_first_event changes the file pointer in the associated file handle object.
As a side effect the method will instantiate the first chunk object.

=head2 get_next_event

This method retrieves the next event record from a file. It returns a 
B<Parse::Evtx::Event> object on success and C<undef> on failure. Note that 
get_next_event changes the file pointer in the associated file handle object.
The methods loads new chunks as needed.

=head1 DIAGNOSTICS

B<new> returns C<undef>, if it doesn't recognize the format of the file. 
If you are attempting to parse a single chunk from a corrupted file, then 
create an instance of B<Parse::Evtx::Chunk> instead.

Other errors will be signalled through assertions and make the parser die().

=head1 DEPENDENCIES

This module depends on the following non-standard modules, which are not 
part of this package:

=over

=item Carp::Assert

=item Data::Hexify 

=item Digest::Crc32

=item Math::BigInt

=back

=head1 SEE ALSO

evtxdump.pl, evtxtemplates.pl, L<Parse::Evtx::Chunk>, L<Parse::Evtx::Event>

=head1 HISTORY

=over

=item v1.0.0 (2007-08-10) Initial release.
=item v1.0.1 (2009-12-21) Bugfixes, improved parsing of header.
=item v1.0.3 (2010-02-11) implemented CRC32 check.
=item v1.0.4 (2010-03-23) updated CRC32 header check.

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