#################################################################################################
#		ff_bookmark
#################################################################################################
# This script is a part of the log2timeline framework for timeline creation and analysis.
# This script implements an input module, or a parser capable of parsing a single log file (or 
# directory) and creating a hash that is returned to the main script.  That hash is then used
# to create a body file (to create a timeline) or a timeline (directly).
# 
# https://developer.mozilla.org/en/XUL_Tutorial/RDF_Datasources
#
# http://kb.mozillazine.org/Bookmarks.html
# 
# Author: Kristinn Gudjonsson
# Version : 0.3
# Date : 25/04/11
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
package Log2t::input::ff_bookmark;

use strict;
use Log2t::base::input; # the SUPER class or parent
use Log2t::Common ':binary';
#use Log2t::Time;	# to manipulate time
#use Log2t::Numbers;	# to manipulate numbers
use Log2t::BinRead;	# methods to read binary files
#use Log2t::Network;	# information about network traffic 
use HTML::Parser;
use Encode;

# define the VERSION variable
use vars qw($VERSION @ISA);

# inherit the base input module, or the super class.
@ISA = ( "Log2t::base::input" );

# indicate the version number of this input module
$VERSION = '0.3';

# other global variables that are needed for this input module
my @lines;
my %records;
my $object;	# storing the self variable

# the constructor...
sub new()
{
        my $class = shift;

        # bless the class ;)
        my $self = $class->SUPER::new(); 

	# we have a file that will be returned as a single object, not parsed line-by-line
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
	return "Parse the content of a Firefox bookmark file"; 
}

#	init
#
# Initialize the needed variables
sub init
{
	# read the paramaters passed to the script
	my $self = shift;

	# start by checking out the username
        # check if we need to "guess" the username of the user
	$self->{'username'} = Log2t::Common::get_username_from_path( ${$self->{'name'}} );

	# initialize variables
	%records = undef;
	$self->{'index'} = 0;

	$object = $self;

	return 1;
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



sub get_time
{
	my $self = shift;

	# the container that stores all the timestamp objects
	my %container = undef;
	my $ret = 1;

	# now we reinitialize the index variable
	$self->{'index'} = 0;

	print STDERR "[FF_BOOKMARK] Starting the parser.\n" if $self->{'debug'};

	# prepare the parsing
	$self->{'parser'} = HTML::Parser->new( 
		api_version => 3,
		start_h     => [\&_do_parse,"tagname, attr, text "],
		#start_h     => [\$self->_do_parse,"tagname, attr, text "],
		#default_h   => [sub {print "PARSING: ", shift, "\n" }, "text"],
		#default_h   => [\@lines, "text"],
		default_h   => [\&_parse_default, "text"],
	);

	print STDERR "[FF_BOOKMARK] Done setting up the parser, start to parse the file itself.\n" if $self->{'debug'};

	$self->{'parser'}->parse_file( $self->{'file'} ) or $ret = 0;
	
	print STDERR "[FF_BOOKMARK] The file has been parsed.\n" if $self->{'debug'};

	if( $ret eq 0 )
	{
		# an error has occured
		print STDERR "[FF BOOKMARK] Error occured: $!\n";
		return 0;
	}

	print STDERR "[FF_BOOKMARK] Number of entries parsed: " . $self->{'index'} . "\n" if $self->{'debug'};

	# go through each of the timestamps
	for ( my $i = 0; $i < $self->{'index'} ; $i++ )
	{
		# set the current record parsing
		$self->{'current_index'} = $i;

		$container{$i} = $self->_parse_timestamp;
	#	print STDERR "[FF_BOOKMARK] Going through: " . $self->{'index'} . "\n" if $self->{'debug'};
	}

	return \%container;
}

sub _parse_default()
{
	my $text = shift;

	# remove end of line
	$text =~ s/\n//g;
	$text =~ s/\r//g;

	# remove double spaces
	$text =~ s/\s+/ /g;

	if( $text ne ' ' && $text ne '' )
	{
		push( @lines, $text );
	}

}

sub _do_parse()
{
	my ($tag, $attr, $origtext) = @_;
	my $date;
	my $text;
	my $type;

	# check if we have H1, which means possibly the main file itself
	if( $tag eq 'h1' )
	{
		# check the date
		$date = $attr->{last_modified};

		$records{$object->{'index'}++} = {
			'name' => 'Bookmark file last modified',
			'date' => $date,
			'dtype' => 'm',
			'type' => 'file'
		};

		#print STDERR "Bookmark file last modified ($date)\n";
	}
	elsif( $tag eq 'meta' )
	{
		# we want to get the file encoding
		$text = $attr->{'content'};
		($date,$object->{'encoding'}) = split( /charset=/, $text);

		#print STDERR "ENCODING [$self->{'encoding'}]\n";
	}
	elsif( $tag eq 'h3' )
	{
		# here we have a folder strcture (and some dates associated with it)

		# add date variables
		if( defined $attr->{'add_date'} )
		{
			$records{$object->{'index'}++} = {
				'date' => $attr->{'add_date'},
				'dtype' => 'c',
				'type' => 'folder',
				'encoding' => $attr->{'last_charset'},
				'line' => $#lines+1
			};
		}
		if( defined $attr->{'last_modified'} )
		{
			$records{$object->{'index'}++} = {
				'date' => $attr->{'last_modified'},
				'dtype' => 'm',
				'type' => 'folder',
				'encoding' => $attr->{'last_charset'},
				'line' => $#lines+1
			};
		}
	}
	elsif( $tag eq 'a' )
	{
		# here we have the records themselves

		# assign variables
		$text = $attr->{'href'};
		
		#print STDERR "TEXT IS [$text] (" . $attr->{'href'} . ")\n";
		# add date attributes
		if( defined $attr->{'add_date'} )
		{
			$records{$object->{'index'}++} = {
				'href' => $text,
				'date' => $attr->{'add_date'},
				'dtype' => 'c',
				'type' => 'bookmark',
				'line' => $#lines+1,
				'encoding' => $attr->{'last_charset'}
			};
		}

		if( defined $attr->{'last_visit'} )
		{
			$records{$object->{'index'}++} = {
				'name' => $text,
				'date' => $attr->{'last_visit'},
				'dtype' => 'a',
				'type' => 'bookmark',
				'line' => $#lines+1,
				'encoding' => $attr->{'last_charset'}
			};
		}
	}
}

#       close_file
# A subroutine that closes the file, after it has been parsed
#
# @return An integer indicating that the close operation was successful
sub end
{
	my $self = shift;

	$self->{'parser'}->eof if defined $self->{'parser'};

	return 1;
}

#       parse_line
#
# This is the main "juice" of the format file.  It depends on the subfunction
# load_line that loads a line of the log file into a global variable and then
# parses that line to produce the hash t_line, which is read and sent to the
# output modules by the main script to produce a timeline or a bodyfile
# 
# @return Returns a reference to a hash containing the needed values to print a body file
sub _parse_timestamp
{
	my $self = shift;
	# timestamp object
	my %t_line;
	my $text;
	my $date;
	my $coding;
	my $type;

	# fix the encoding
	$coding = $records{$self->{'current_index'}}->{'encoding'} eq '' ? $self->{'encoding'} : $records{$self->{'current_index'}}->{'encoding'};

	$date = $records{$self->{'current_index'}}->{'date'};

	if( $records{$self->{'current_index'}}->{'dtype'} eq 'm' )
	{
		# we have modified a record
		$type .= 'modified';
	}
	elsif( $records{$self->{'current_index'}}->{'dtype'} eq 'a' )
	{
		# we have visited a URL
		$type .= 'visited';
	}
	elsif( $records{$self->{'current_index'}}->{'dtype'} eq 'c' )
	{
		# we've created
		$type .= 'created';
	}

	# check the type
	if( $records{$self->{'current_index'}}->{'type'} eq 'file' )
	{
		$text .= 'file';
	}
	elsif( $records{$self->{'current_index'}}->{'type'} eq 'folder' )
	{
		# need to know the folder name
		$text .= $lines[$records{$self->{'current_index'}}->{'line'}];
		$type = 'folder ' . $type;

		#$text .= 'the bookmark folder [' . encode( $coding, $lines[$records{$self->{'current_index'}}->{'line'}])  . ']';
		#print STDERR "LINE " . $lines[$records{$self->{'current_index'}}->{'line'}] . " was encoded according to : $coding [$self->{'encoding'}]\n";
	}
	elsif( $records{$self->{'current_index'}}->{'type'} eq 'bookmark' )
	{
		# we need to read a line number
		$text .= $lines[$records{$self->{'current_index'}}->{'line'}]. ' [' . $records{$self->{'current_index'}}->{'href'} . ']' unless $records{$self->{'current_index'}}->{'dtype'} eq 'a';
		$text .= $lines[$records{$self->{'current_index'}}->{'line'}] if $records{$self->{'current_index'}}->{'dtype'} eq 'a';

		#$text .= 'the bookmark ' . encode( $coding, $lines[$records{$self->{'current_index'}}->{'line'}] ). ' [' . $records{$self->{'current_index'}}->{'href'} . ']' unless $records{$self->{'current_index'}}->{'dtype'} eq 'a';
		#$text .= 'the bookmark [' . encode( $coding,  $lines[$records{$self->{'current_index'}}->{'line'}]) . ']' if $records{$self->{'current_index'}}->{'dtype'} eq 'a';
		#print STDERR "LINE " . $lines[$records{$self->{'current_index'}}->{'line'}] . " was encoded according to : $coding [$self->{'encoding'}]\n";
	}

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
        %t_line = (
                'time' => { 0 => { 'value' => $date, 'type' => 'bookmark ' . $type, 'legacy' => 15 } },
                'desc' => $text,
	      	'short' => 'File ' . $lines[$records{$self->{'current_index'}}->{'line'}] . '(' . $records{$self->{'current_index'}}->{'dtype'} . ')',
                'source' => 'WEBHIST',
                'sourcetype' => 'Firefox',
                'version' => 2,
                'extra' => { 'user' => $self->{'username'} }
        );

        # check the existence of a default browser for this particular user
        if( defined $self->{'defbrowser'}->{lc($self->{'username'})} )
        {   
                $t_line{'notes'} = $self->{'defbrowser'}->{$self->{'username'}} =~ m/firefox/i ? 'Default browser for user' : 'Not the default browser (' . $self->{'defbrowser'}->{$self->{'username'}} . ')';
        }   
        elsif ( $self->{'defbrowser'}->{'os'} ne '' )
        {   
                # check the default one (the OS)
                $t_line{'notes'} = $self->{'defbrowser'}->{'os'} =~ m/firefox/ ? 'Default browser for system' : 'Not the default system browser (' . $self->{'defbrowser'}->{'os'} . ')';
        } 


	return \%t_line;
}

#       get_help
#
# A simple subroutine that returns a string containing the help 
# message for this particular format file.
#
# @return A string containing a help file for this format file
sub get_help
{
	return "This input module parses the bookmarks.html document that Firefox 
version 2.x and older use to store their bookmarks in.  The bookmarks.html is stored
in the Firefox user's profile.

As of version 3.0, Firefox does not longer keep their bookmarks in this file, it has
moved bookmarks into the SQLite database places.sqlite.  Please use the input module
firefox3 to parse the content of the places.sqlite database, which will parse not only
the content of the bookmarks but also the web history of that particular user.\n";

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
	my $line;

	# default values
	$return{'success'} = 0;
	$return{'msg'} = 'success';

        return \%return unless -f ${$self->{'name'}};

        # start by setting the endian correctly
        Log2t::BinRead::set_endian( LITTLE_E );

	my $ofs = 0;

	# we don't need more than 30 chars	
	$line = Log2t::BinRead::read_ascii_until( $self->{'file'}, \$ofs, "\n", 50 );

	# check the loaded line
	if( $line =~ m/NETSCAPE-Bookmark-file-1/ )
	{
		$return{'success'} = 1;
	}
	else
	{
		$return{'success'} = 0;
		$return{'msg'} = 'Not the correct format';
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

