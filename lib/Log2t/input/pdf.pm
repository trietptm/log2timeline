#################################################################################################
#			PDF
#################################################################################################
# This script is a part of the log2timeline framework for timeline creation and analysis.
# This script implements an input module, or a parser capable of parsing a single log file (or 
# directory) and creating a hash that is returned to the main script.  That hash is then used
# to create a body file (to create a timeline) or a timeline (directly).
#
# This input module is designed to read few of the metadata options that are stored inside
# PDF documents
#
# Specifications for the PDF document format can be found here:
# 	http://www.adobe.com/devnet/pdf/pdf_reference.html
# 
# Author: Kristinn Gudjonsson
# Version : 0.3
# Date : 01/05/11
#
# Copyright 2009-2011 Kristinn Gudjonsson (kristinn ( a t ) log2timeline (d o t) net)
#
#  This file is part of log2timeline.
#
#    log2timeline is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    log2timeline is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with log2timeline.  If not, see <http://www.gnu.org/licenses/>.
package Log2t::input::pdf;

use strict;
use Log2t::base::input; # the SUPER class or parent
use Log2t::Common ':binary';
use Log2t::Time;	# to manipulate time
#use Log2t::Win;	# Windows specific information
#use Log2t::Numbers;	# to manipulate numbers
use Log2t::BinRead;	# methods to read binary files (it is preferable to always load this library)
#use Log2t::Network;	# information about network traffic 
use Encode;

# define the VERSION variable
use vars qw($VERSION @ISA);

# inherit the base input module, or the super class.
@ISA = ( "Log2t::base::input" );

# indicate the version number of this input module
$VERSION = '0.3';

# default constructor
sub new()
{
        my $class = shift;

        # bless the class ;)
        my $self = $class->SUPER::new();

	# indicate that we would like to return a single hash reference (container)
        $self->{'multi_line'} = 0;

	bless($self,$class);

        return $self;
}

#       get_description
# A simple subroutine that returns a string containing a description of 
# the funcionality of the format file. This string is used when a list of
# all available format files is printed out
#
# @return A string containing a description of the format file's functionality
sub get_description()
{
	return "Parse some of the available PDF document metadata"; 
}

sub get_time
{
	my $self = shift;

	# reset variables
	$self->{'container'} = undef;
	$self->{'cont_index'} = 0;
	$self->{'lines'} = 0;

        # get the filehandle 
        my $fh = $self->{'file'};

	# read all lines
	while( <$fh> )
	{
		$_ =~ s/\n//g;
		$_ =~ s/\r//g;

		if( /\/Creator\s?\(([^\)]+)\)/i )
		{
			# /Creator (stuff)
			$self->{'creator'} = $1;
			print STDERR "[PDF] Found creator: [$1]\n" if $self->{'debug'};		
		}
		if( /\/CreationDate\s?\(([^\)]+)\)/i )
		{
			$self->{'creationdate'} = $1;
			$self->{'lines'}++;
			push( @{$self->{'dates'}}, 'creationdate' );
			print STDERR "[PDF] Found creation date: $1\n" if $self->{'debug'};		
		}

		if( /\/ModDate\s?\(([^\)]+)\)/i )
		{
			$self->{'moddate'} = $1;
			$self->{'lines'}++;
			push( @{$self->{'dates'}}, 'moddate' );
			print STDERR "[PDF] Found mod date: $1\n" if $self->{'debug'};		
		}

		if( /\/Producer\s?\(([^\)]+)\)/i )
		{
			$self->{'producer'} = $1;
			print STDERR "[PDF] Found producer: $1\n" if $self->{'debug'};		
		}

		if( /\/LastModified\s?\(([^\)]+)\)/i )
		{
			$self->{'lastmodified'} = $1;
			push( @{$self->{'dates'}}, 'lastmodified' );
			$self->{'lines'}++;
			print STDERR "[PDF] Found last modified: $1\n" if $self->{'debug'};		
		}

		if( /\/Author\s?\(([^\)]+)\)/i )
		{
			$self->{'author'} = $1;
			print STDERR "[PDF] Found author: $1\n" if $self->{'debug'};		
		}

		if( /\/Title\s?\(([^\)]+)\)/i )
		{
			$self->{'title'} = $1;
			print STDERR "[PDF] Found title: $1\n" if $self->{'debug'};		
		}
	}

	# go through each date object
	for ( my $i = 0; $i < $self->{'lines'}; $i++ )
	{
		my $text;
		my $date = 0;
		my $d_type = pop( @{$self->{'dates'}} );
		my $type;

		$date = Log2t::Time::pdf_to_date( $self->{"$d_type"} );

		print STDERR "[PDF] Parsing $d_type [$date]\n" if $self->{'debug'};

		# check for valid dates
		next unless defined $date;

		# check date stuff
		$type = 'File created' if( $d_type eq 'creationdate' );
		$type = 'File modified' if( $d_type eq 'moddate' );
		$type = 'File modified' if( $d_type eq 'lastmodified' );

		$text = $type . '.';

		if( defined $self->{'title'} )
		{
			$text .= ' Title : (' . $self->{'title'}. ')';
		}

		if( defined $self->{'author'} )
		{
			$self->{'username'} = $self->{'author'};
			$text .= ' Author: [' . $self->{'author'}. ']';
		}

		if( defined $self->{'creator'} )
		{
			$text .= ' Creator: [' . $self->{'creator'}  .']';
		}

		if( defined $self->{'producer'} )
		{
			$text .= ' produced by: [' . $self->{'producer'} . ']';
		}
	
		$text = encode( 'utf-8', $text );

        	# content of array t_line ([optional])
        	# %t_line {        #       time
        	#               index
        	#                       value
        	#                       type
        	#                       legacy
        	#       desc
        	#       short
        	#       source
        	#       sourcetype
        	#       version
        	#       [notes]
        	#       extra
        	#               [filename]
        	#               [md5]
        	#               [mode]
        	#               [host]
        	#               [user]
        	#               [url]
        	#               [size]
        	#               [...]
        	# }
	
	        # create the t_line variable
	        $self->{'container'}->{$self->{'cont_index'}++} = {
	                'time' => { 0 => { 'value' => $date, 'type' => $d_type, 'legacy' => 15 } },
	                'desc' => $text,
	                'short' => $type,
	                'source' => 'PDF',
	                'sourcetype' => 'PDF Metadata',
	                'version' => 2,
	                'extra' => { 'user' => $self->{'username'},  }
	        };
	}

#	printf STDERR "[PDF] There are %d timestamps parsed.\n", $self->{'cont_index'};

	return $self->{'container'};
}

#       get_version
# A simple subroutine that returns the version number of the format file
# There shouldn't be any need to change this routine, it serves its purpose 
# just the way it is defined right now.
#
# @return A version number
sub get_version()
{
        return $VERSION;
}



#       get_help
#
# A simple subroutine that returns a string containing the help 
# message for this particular format file.
#
# @return A string containing a help file for this format file
sub get_help()
{
	return "An input module that parses some of the metadata content that is stored
inside PDF documents.\n";

}

#       verify
#
# This function takes as an argument the file name to be parsed (file/dir/artifact) and
# verifies it's structure to determine if it is really of the correct format.
#
# This is needed since there is no need to parse the file if this file/dir is not the file
# that this input module is designed to parse
#
# It is also important to validate the file since the scanner function will try to 
# parse every file it finds, and uses this verify function to determine whether or not
# a particular file/dir/artifact is supported or not. It is therefore very important to 
# implement this function and make it verify the file structure without false positives and
# without taking too long time
#
# @return A reference to a hash that contains an integer indicating whether or not the 
#	file/dir/artifact is supporter by this input module as well as a reason why 
#	it failed (if it failed) 
sub verify
{
	my $self = shift;

	# define an array to keep
	my %return;
	my $vline;

	# default values
	$return{'success'} = 0;
	$return{'msg'} = 'success';

        return \%return unless -f ${$self->{'name'}};

        # start by setting the endian correctly
        Log2t::BinRead::set_endian( LITTLE_E );

	my $ofs = 0;

	# open the file (at least try to open it)
	eval
	{
		unless( $self->{'quick'} )
		{
			# the first letter should be %, let's check for that
			seek($self->{'file'},0,0);
			read($self->{'file'},$vline,1);
			$return{'msg'} = 'Wrong magic value';
			return \%return unless $vline eq '%';
		}

		# read a line from the file as it were a binary file
		# it does not matter if the file is ASCII based or binary, 
		# lines are read as they were a binary one, since trying to load up large
		# binary documents using <FILE> can cause log2timeline/timescanner to 
		# halt for a long while before dying (memory exhaustion)
		$vline = Log2t::BinRead::read_ascii_until( $self->{'file'}, \$ofs, "\n", 50 );
	};
	if ( $@ )
	{
		$return{'success'} = 0;
		$return{'msg'} = "Unable to open file";
	}

	if( lc( $vline ) =~ m/\%pdf-1\.\d/ )
	{
		$return{'success'} = 1;
	}
	else
	{
		$return{'success'} = 0;
		$return{'msg'} = 'Not the correct magic value';
	}

	return \%return;
}

1;


__END__

=pod

=head1 NAME

B<structure> - an input module B<log2timeline> that parses X 

=head1 SYNOPSIS

	my $format = structure;
	require $format_dir . '/' . $format . ".pl" ;

	$format->verify( $log_file );
	$format->prepare_file( $log_file, @ARGV )

        $line = $format->load_line()

	$t_line = $format->parse_line();

	$format->close_file();

=head1 DESCRIPTION

An input module 

=head1 SUBROUTINES

=over 4

=item get_version()

Return the version number of the input module

=item get_description()

Returns a string that contains a short description of the functionality if the input module.  When a list of all available input modules is printed using B<log2timeline> this string is used.  So this string should be a very short description, mostly to say which type of log file/artifact/directory this input module is designed to parse.

=item prepare_file( $file, @ARGV )

The purpose of this subfunction is to prepare the log file or artifact for parsing. Usually this involves just opening the file (if plain text) or otherwise building a structure that can be used by other functions.

This function accepts the path to the log file/directory/artifact to parse as well as an array containing the parameters passed to the input module. These parameters are used to adjust settings of the input module, such as to provide a username and a hostname to include in the timeline.

The function returns an integer indicating whether or not it was successful at preparing the input file/directory/artifact for further processing.

=item load_line()

This function starts by checking if there are any lines in the log file/artifacts that have a date variable inside that needs to be parsed.  It then loads the line (or an index value) in a global variable that can be read by the function parse_line and returns the value 1 to the main script, indicating that a line has been loaded.

When all of the lines in the log file/directory/artifact have been parsed a zero is returned to the main script, indicating that there are no more lines to parse

=item close_file()

A subroutine that closes the file, after it has been parsed and performs any additional operations needed to close the file/directory/artifact that was parsed (such as to disconnect any database connections)

The subroutine returns an integer indicating whether or not it was successful at closing the file.

=item parse_line()

This is the main subroutine of the format file (or often it is).  It depends on the subroutine load_line that loads a line of the log file into a global variable and then parses that line to produce the hash t_line, which is read and sent to the output modules by the main script to produce a timeline or a bodyfile.

The content of the hash t_line is the following:

	%t_line {
		md5,		# MD5 sum of the file
		name,		# the main text that appears in the timeline
		title,		# short description used by some output modules
		source,		# the source of the timeline, usually the same name or similar to the name of the package
		user,		# the username that owns the file or produced the artifact
		host,		# the hostname that the file belongs to
		inode,		# the inode number of the file that contains the artifact
		mode,		# the access rights of the file
		uid,		# the UID of the user that owns the file/artifact
		gid,		# the GID of the user that owns the file/artifact
		size,		# the size of the file/artifact
		atime,		# Time in epoch representing the last ACCESS time
		mtime,		# Time in epoch representing the last MODIFICATION time
		ctime,		# Time in epoch representing the CREATION time (or MFT/INODE modification time)
		crtime		# Time in epoch representing the CREATION time
	}

The subroutine return a reference to the hash (t_line) that will be used by the main script (B<log2timeline>) to produce the actual timeline.  The hash is processed by the main script before forwarding it to an output module for the actual printing of a bodyfile.

=item get_help()

A simple subroutine that returns a string containing the help message for this particular input module. This also contains a longer description of the input module describing each parameter that can be passed to the subroutine.  It sometimes contains a list of all dependencies and possibly some instruction on how to install them on the system to make it easier to implement the input module.

=item verify( $log_file )

This subroutine takes as an argument the file name to be parsed (file/dir/artifact) and verifies it's structure to determine if it is really of the correct format.

This is needed since there is no need to try to parse the file/directory/artifact if the input module is unable to parse it (if it is not designed to parse it)

It is also important to validate the file since the scanner function will try to parse every file it finds, and uses this verify function to determine whether or not a particular file/dir/artifact is supported or not. It is therefore very important to implement this function and make it verify the file structure without false positives and without taking too long time

This subroutine returns a reference to a hash that contains two values
	success		An integer indicating whether not the input module is able to parse the file/directory/artifact
	msg		A message indicating the reason why the input module was not able to parse the file/directory/artifact

=back

=head1 AUTHOR

Kristinn Gudjonsson <kristinn (a t) log2timeline ( d o t ) net> is the original author of the program.

=head1 COPYRIGHT

The tool is released under GPL so anyone can contribute to the tool. Copyright 2009.

=head1 SEE ALSO

L<log2timeline>

=cut

