#################################################################################################
#		squid
#################################################################################################
# this script is a part of the log2timeline program.
# 
# This is a format file that implements a parser for squid access files.  It parses the file
# and provides the main script with enough information to provide a body file that can be
# used in a timeline analysis
# 
# Author: Kristinn Gudjonsson
# Version : 0.5
# Date : 03/05/11
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

package Log2t::input::squid;

use strict;
use Log2t::base::input; # the SUPER class or parent
use Log2t::BinRead;
use Log2t::Common ':binary';

use vars qw($VERSION @ISA);

# inherit the base input module, or the super class.
@ISA = ( "Log2t::base::input" );

# version number
$VERSION = '0.5';

# 	get_version
# A simple subroutine that returns the version number of the format file
# @return A version number
sub get_version()
{
	return $VERSION;
}

# 	get_description
# A simple subroutine that returns a string containing a description of 
# the funcionality of the format file. This string is used when a list of
# all available format files is printed out
# @return A string containing a description of the format file's functionality
sub get_description()
{
	return 'Parse the content of a Squid access log (http_emulate off)';
}

#	get_time
# This is the main "juice" of the format file.  It takes a line from the log file
# and parses it to produce an array containing all the needed values to print a 
# body file.
# 
# The default structure of Squid log file is:
# timestamp elapsed IP/Client Action/Code Size Method URI Ident Hierarchy/From Content
#
# @param LINE a string containing a single line from the access file
# @return Returns a array containing the needed values to print a body file
sub get_time
{
	my $self = shift;
	# log file variables
	my $timestamp;
	my $ip;
	my $action;
	my $size;
	my $method;
	my $uri;
	my $ident;
	my $from;
	my $content;
	my $elapsed;
	my @date; 

	# timestamp object
	my %t_line;

        # get the filehandle and read the next line
        my $fh = $self->{'file'};
        my $line = <$fh> or return undef;

	# remove spaces from line
	$line =~ s/\s+/ /g;
	
	# split the string into variables
	( $timestamp, $elapsed, $ip, $action, $size, $method, $uri, $ident, $from, $content ) = split( / /, $line );

	# fix the timestamp variable
	@date = split( /\./, $timestamp );

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
                'time' => { 0 => { 'value' => $date[0], 'type' => 'Entry written', 'legacy' => 15 } },
                'desc' => $ip . ' connected to \'' . $uri . '\' using ' . $method . ' [' . $action . '] from ' . $from . ', content ' . $content,
                'short' => $ip . " connected to '$uri'",
                'source' => 'NET',
                'sourcetype' => 'Squid access log',
                'version' => 2,
                'extra' => { 'user' => $ip, 'host' => $ip, 'src-ip' => $ip, 'size' => $size }
        );

	return \%t_line;
}

#	get_help
# A simple subroutine that returns a string containing the help 
# message for this particular format file.
# @return A string containing a help file for this format file
sub get_help()
{
	return "----------------------------------------------------
	SQUID ACCESS LOG PARSER
----------------------------------------------------
Read squid access logs with the emulate_httpd_log off - use the script
with the FILE option as access.log file\n
\t$0 -f squid access.log
Format of the Squid access file is:
timestamp elapsed IP/Client Action/Code Size Method URI Ident Hierarchy/From Content
	";
}

#	verify
# A subroutine that reads a single line from the log file and verifies that it is of the
# correct format so it can be further processed.
# The correct format of a Squid access file (with httpd_emulate equal to off) is:
# timestamp elapsed IP/Client Action/Code Size Method URI Ident Hierarchy/From Content
# @return An array containing an integer and a string.  The integer indicates a success or failure and the
#	string is the error message (if the file is not correctly formed)
sub verify
{
	# define an array to keep
	my %return;
	my $line;
	my @words;

	my $self = shift;

	# default values
	$return{'success'} = 0;
	$return{'msg'} = 'success';

        # depending on which type you are examining, directory or a file
        return \%return unless -f ${$self->{'name'}};

	my $ofs = 0;
        # start by setting the endian correctly
        Log2t::BinRead::set_endian( LITTLE_E );

	# open the file (at least try to open it)
	eval
	{
		unless( $self->{'quick'} )	
		{
			# a line should start with a number, let's verify
			seek($self->{'file'},0,0);
			read($self->{'file'},$line,1);
			$return{'msg'} = 'Wrong magic value';

			if( $line !~ m/[0-9]/ )
			{
				return \%return; 
			}
		}

		$line = Log2t::BinRead::read_ascii_until( $self->{'file'}, \$ofs, "\n", 200 );
	};
	if ( $@ )
	{
		$return{'success'} = 0;
		$return{'msg'} = "Unable to open file ($@)";
	}
	# now we have one line of the file, let's read it and verify
	# remove unneeded spaces
	$line =~ s/\s+/ /g;
	@words = split(/\s/, $line );
	
	# word count should be 9
	if( $#words eq 9 )
	{
		# verify one variable in the log file, the IP address
		if( $words[2] =~ m/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/ )
		{
			# the IP address is correctly formed, let's assume other fields are too
			$return{'success'} = 1;
		}
		else
		{
			$return{'error'} = 'IP address field [' .$words[2] . "] not correctly formatted\n";
			$return{'success'} = 0;
		}
	}
	else
	{
		$return{'error'} = 'There should be 9 words per line, instead there are ' . "$#words\n";
		$return{'success'} = 0;
	}

	return \%return;
}

1;
