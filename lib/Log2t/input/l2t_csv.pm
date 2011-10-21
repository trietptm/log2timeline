#################################################################################################
#			CSV
#################################################################################################
# This script reads in a bodyfile that is saved using the CSV format of log2timeline
#
# The script then converts that to what ever output the tool is capable of 
# 
# Author: Kristinn Gudjonsson
# Version : 0.1
# Date : 13/06/11
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
package Log2t::input::l2t_csv;

use strict;
use Log2t::base::input; # the SUPER class or parent
use Log2t::Time;
use Log2t::BinRead;
use Log2t::Common ':binary';

use vars qw($VERSION @ISA);

# inherit the base input module, or the super class.
@ISA = ( "Log2t::base::input" );

# version number
$VERSION = '0.1';

#       get_description
# A simple subroutine that returns a string containing a description of 
# the funcionality of the format file. This string is used when a list of
# all available format files is printed out
#
# @return A string containing a description of the format file's functionality
sub get_description()
{
	return "Parse the content of a body file in the l2t CSV format"; 
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



#       get_time
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
	# timestamp object
	my %t_line;
	my $text;

        # get the filehandle and read the next line
        my $fh = $self->{'file'};
        my $line = <$fh> or return undef;

	# remove the new line character
	$line =~ s/\n//g;
	$line =~ s/\r//g;

        if( $line =~ m/^#/ )
        {
                # we have a comment
                return \%t_line;
        }
	elsif ( $line =~ m/^date,time/ )
	{
		# we have a header
		return \%t_line;
	}

	# let's split the line into an array
	my @bits = split( /,/, $line );

	# the structure of the format
	# date,time,timezone,MACB,source,sourcetype,type,user,host,short,desc,version,filename,inode,notes,format,extra
	# 	0 => date,
	#	1 => time,
	#	2 => timezone,
	#	3 => MACB,
	#	4 => source,
	#	5 => sourcetype,
	#	6 => type,
	#	7 => user,
	#	8 => host,
	#	9 => short,
	#	10 => desc,
	#	11 => version,
	#	12 => filename,
	#	13 => inode,
	#	14 => notes,
	#	15 => format,
	#	16 => extra
	my $epoch = Log2t::Time::csv2epoch( $bits[0] . ' ' . $bits[1], $bits[2] );

	# convert MACB to a number
	#	M	1
	#	A	2
	#	C	4
	#	B	8
	my $legacy = 0;	
	$legacy += 1 if $bits[3] =~ m/M/;
	$legacy += 2 if $bits[3] =~ m/A/;
	$legacy += 4 if $bits[3] =~ m/C/;
	$legacy += 8 if $bits[3] =~ m/B/;

        # create the t_line variable
        %t_line = (
                'time' => { 
                        0 => { 'value' => $epoch, 'type' => $bits[6], 'legacy' => $legacy },
                },  
                'desc' => $bits[10],
                'short' => $bits[9],
                'source' => $bits[4],
                'sourcetype' => $bits[5],
		'notes' => $bits[14],
                'version' => 2,
                'extra' => { 'user' => $bits[7], 'host' => $bits[7], 'filename' => $bits[12], 'inode' => $bits[13], 'format' => $bits[15] }
        );

	# process the extra field
	unless( $bits[16] eq '' or $bits[16] eq '-' )
	{
		# now we have a field to populate further
		my @split = split( /:/, $bits[16] );

		if( $#split gt 1 )
		{
			my $key = $split[0];
			# we need to split further
			for ( my $i = 1; $i < $#split -1 ; $i++ )
			{	
				# now 
				#	split[i] = VALUE OF LAST KEY
				#	split[i+1]
	
				# need to check if i+1 exists (or this is the last stuff)
				if ( $#split == $i + 1)
				{
					# the last one
					# check if key is set
					if ( $key eq '' )
					{
						# then this is simple
						$t_line{'extra'}->{$split[$i]} = $split[$i+1];
					}
					else
					{
						my @a = split( /\s/, $split[$i] );
						my $almost = $#a - 1;
						$t_line{'extra'}->{$key} = join( ' ', $a[0..$almost] );
						$key = $a[$#a];
						$t_line{'extra'}->{$key} = $split[$#split];
					}
				}
				else
				{
					# 
					my @a = split( /\s/, $split[$i] );
					my $almost = $#a - 1;
					$t_line{'extra'}->{$key} = join( ' ', $a[0..$almost] );
					$key = $a[$#a];
				}
			}
		}
		else
		{
			# simple split	
			$t_line{'extra'}->{$split[0]} = $split[1];
		}
	}

	return \%t_line;
}

#       get_help
# A simple subroutine that returns a string containing the help 
# message for this particular format file.
# @return A string containing a help file for this format file
sub get_help()
{
	return "
This input module parses the CSV input module produced by log2timeline.

The reason this input module exists is to be able to among other things convert a CSV file into another output.
Use cases might be, creating a CSV bodyfile, analyze using a spreadsheet, export fields of interest and then 
parse that output (the lines of interest) into a new CSV file, run log2timeline against it and convert it to a
visual timeline (for reporting or just visualization)
	";
}

#       verify
# A subroutine that verifies if we are examining a prefetch directory so it can be further 
# processed.  The correct format is a directory that consists of a folder that contains
# several files that end with a .pf ending.  Then one file in the folder is named Layout.ini
# @return An array containing an integer and a string.  The integer indicates a success or failure and the
#       string is the error message (if the file is not correctly formed)
sub verify
{
	# define an array to keep
	my %return;
	my $line;
	my @words;
	my $tag;

	my $self = shift;

        return \%return unless -f ${$self->{'name'}};

	# this defines the maximum amount of lines that we read in the file before finding a line
	# that does not contain comments
	my $max = 10;
	my $i = 0;

	# default values
	$return{'success'} = 0;
	$return{'msg'} = 'success';

        # start by setting the endian correctly
        Log2t::BinRead::set_endian( LITTLE_E );

	# the structure of the CSV file is the following:
	# date,time,timezone,MACB,source,sourcetype,type,user,host,short,desc,version,filename,inode,notes,format,extra

	my $ofs = 0;
	# open the file (at least try to open it)
	eval
	{
		# let's continue
		$tag = 1;
		while( $tag )
		{
                        $tag = 0 unless $line =  Log2t::BinRead::read_ascii_until( $self->{'file'}, \$ofs, "\n", 800 );
                        next unless $tag;

                        # check max value
                        $tag = 0 if( $i++) eq $max;
                        next unless $tag;

			$tag = 0 if $line !~ m/^#/;
		}

		# now we should have a line identical to this one:
		# date,time,timezone,MACB,source,sourcetype,type,user,host,short,desc,version,filename,inode,notes,format,extra

		$line =~ s/\n//g;
		$line =~ s/\r//g;

		if ( $line ne "date,time,timezone,MACB,source,sourcetype,type,user,host,short,desc,version,filename,inode,notes,format,extra" )
		{
			# then this is not a CSV file
			$return{'msg'} = 'Does not contain a valid header';
			$return{'success'} = 0;

			return \%return;
		}
		else
		{
			# this was a valid header, let's move on to determine the first line
			$line = Log2t::BinRead::read_ascii_until( $self->{'file'}, \$ofs, "\n", 800 );
		}

		# split the line
		@words = split( /,/, $line );

		# check the count
		if( $#words eq 16 )
		{
			# now we take one examle field to confirm

			# check the first field (date)
			if( $words[0] =~ m/^\d{2}\/\d{2}\/\d{4}$/ )
			{
				# now we have a correctly formed date field, check another field
				if( $words[11] == 2 )
				{
					$return{'success'} = 1;
				}
				else
				{
					$return{'success'} = 0;
					$return{'msg'} = 'The timestamp object version was wrong (should be equal to 2 not ' . $words[11] . ')';
				}
				
			}
			else
			{
				$return{'success'} = 0;
				$return{'msg'} = 'Not the correct date format (should be MM/DD/YYYY not [' . $words[0] . '])';
			}
		}
		else
		{
			$return{'success'} = 0;
			$return{'msg'} = "The file is not of the correct format (" . sprintf "%d",$#words+1 . " fields instead of 17)";
		}

		# verify that this line is of correct value
	};
	if ( $@ )
	{
		$return{'success'} = 0;
		$return{'msg'} = "Unable to open file ($@)";
	}

	# now we have one line of the file, let's read it and verify
	# and here we have an error checking routine... (witch success = 1 if we are able to verify)

	return \%return;
}

1;
