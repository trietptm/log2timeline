#################################################################################################
#		MCAFEE
#################################################################################################
# This script is a part of the log2timeline framework for timeline creation and analysis.
# This script implements an input module, or a parser capable of parsing a single log file (or 
# directory) and creating a hash that is returned to the main script.  That hash is then used
# to create a body file (to create a timeline) or a timeline (directly).
# 
# Author: Kristinn Gudjonsson
# Version : 0.3
# Date : 03/05/11
#
# Updated 07/26/11 by anonymous donator 
# Added:
#  Newline check to verify function. Added code is marked with BEGIN UPDATE and END UPDATE
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

package Log2t::input::mcafee;

use strict;
use Log2t::base::input; # the SUPER class or parent
use Log2t::Common ':binary';
use Log2t::Time;	# to manipulate time
#use Log2t::Win;	# Windows specific information
#use Log2t::Numbers;	# to manipulate numbers
use Log2t::BinRead;	# methods to read binary files (it is preferable to always load this library)
#use Log2t::Network;	# information about network traffic 

# define the VERSION variable
use vars qw($VERSION @ISA);

#####BEGIN UPDATE#####
# the maximum number of newlines to read before verification fails
use constant NEWLINELIMIT => 20;
#####END UPDATE#####

# inherit the base input module, or the super class.
@ISA = ( "Log2t::base::input" );

# indicate the version number of this input module
$VERSION = '0.3';

# ------------------------------------------------------------------------------------------------ 
# 			AccessProtectionLog (one line per event)
# ------------------------------------------------------------------------------------------------ 
# DATE (day/month/year) 	TIME 	WHAT 	USER 	WHERE	PROGRAM	DESCRIPTION	ACTION
# 
# each line is a new event 
# starts with a magic value
# type 1
#
# ------------------------------------------------------------------------------------------------ 
# 				OnDemandScanLog
# ------------------------------------------------------------------------------------------------ 
# (not with the magic value) possible multiple lines each event, same timestamp on each entry
# The multiple lines use the following ACTION field:
#	Engine version
#	Scan Summary 
#
# Some lines are empty
#
# Events:
# Date (day/month/year)	TIME	ACTION	USER	FILE	WHAT
#
#
# ------------------------------------------------------------------------------------------------ 
# 				OnAccessScanLog
# ------------------------------------------------------------------------------------------------ 
# Date (day/month/year) 	TIME	TEXT	USER	FILE	FILE
#
# some lines are empty 
# starts with a magic value
# multiple lines per event (same date and timestamp for all the entries)
#

# the constructor...
sub new()
{
        my $class = shift;

        # bless the class ;)
        my $self = $class->SUPER::new();

	# the available log types
	$self->{'types'} = {
		1 => 'AccessProtectionLog',
		2 => 'OnAccessScanLog',
		3 => 'OnDemandScanLog'
	};

        bless($self,$class);

        return $self;
}



#       get_version
# A simple subroutine that returns the version number of the format file
#
# @return A version number
sub get_version()
{
	return $VERSION;
}

#       get_description
# A simple subroutine that returns a string containing a description of 
# the funcionality of the format file. This string is used when a list of
# all available format files is printed out
#
# @return A string containing a description of the format file's functionality
sub get_description()
{
	return "Parse the content of log files from McAfee AV engine"; 
}

#       init
#
# The purpose of this subfunction is to prepare the log file or artifact for parsing
# Usually this involves just opening the file (if plain text) or otherwise building a 
# structure that can be used by other functions
#
# This function also accepts parameters for processing (for changing some settings in
# the input module)
#
# @params A path to the artifact/log file/directory to prepare 
# @params The rest of the ARGV array containing parameters to be passed to the input module
# @return An integer is returned to indicate whether the file preparation was 
#       successful or not.
sub init
{
	# read the paramaters passed to the script
	my $self = shift;

	# initialize variables
	$self->{'old_date'} = undef;
	$self->{'line_loaded'} = 0;
	$self->{'eof'} = 0;
	$self->{'first_line'} = 1;

	print STDERR "[McAfee] Type " . $self->{'type'} . ": " . $self->{'types'}->{$self->{'type'}} . "\n" if $self->{'debug'};

	return 1;
}

#       get_time
#
# This is the main "juice" of the format file.  It depends on the subfunction
# load_line that loads a line of the log file into a global variable and then
# parses that line to produce the hash t_line, which is read and sent to the
# output modules by the main script to produce a timeline or a bodyfile
# 
# @return Returns a reference to a hash containing the needed values to print a body file
sub get_time
{
	my $self = shift;
	# timestamp object
	my %t_line;
	my @fields;
	my $text;
	my $title;
	my $date = undef;
	my %d;	# the current date
	my $line;
	my $fh = $self->{'file'};

	# check if there is a line already loaded up and ready to be parsed
	if( $self->{'line_loaded'} )
	{
		return undef if $self->{'eof'};

		$self->{'line_loaded'} = 0;
		$line = $self->{'line'};
	}

	# check if we have a magic in the beginning of the file, let's skip it
	if( ( $self->{'type'} == 1 or $self->{'type'} == 2 ) && ( $self->{'first_line'} ) )
	{
		# check for magic value and the first line
		my $ofs = 3;
		$line = Log2t::BinRead::read_ascii_until( $self->{'file'}, \$ofs, "\n", 400 );
		$self->{'first_line'} = 0;
	}
	else
	{
		# get the filehandle and read the next line
		$line = <$fh> or return undef; 
	}

	@fields = split( /\t/, $line );

	$self->_populate_date(\%d,\@fields);

	# parse the date
	$date = Log2t::Time::hash_to_date( \%d, $self->{'tz'} ) if( defined $d{'month'} and defined $d{'time'} );

	print STDERR "[MCAFEE] Parsing line with date $date\n" if $self->{'debug'};

	# check if we have a valid date
	return \%t_line unless defined $date;

	$text ='';
	# first we check if the date/time has been mixed
	if( $d{'m'} eq 0 && $d{'t'} eq 1 )
	{
		# set the title (short text)
		$title = 'Line from ' . $self->{'types'}->{$self->{'type'}};

		# check the type
		if( $self->{'type'} == 1 )
		{
			# we have AccessProtectionLog
			# each line here is a new event
# ------------------------------------------------------------------------------------------------ 
# 			AccessProtectionLog (one line per event) 	=> 1
# ------------------------------------------------------------------------------------------------ 
#	(8 fields)
# DATE (day/month/year) 	TIME 	WHAT 	USER 	WHERE	FILE	DESCRIPTION	ACTION
#	(6 fields)
# DATE	TIME	WHAT	PROGRAM		DESCRIPTION	IP:PORT
# 
# each line is a new event 
# starts with a magic value
# Fields are either 5 or 7 (meaning 6 or 8)
#
			$text .= 'AccessProtection: ';

			if( $#fields eq 5 )
			{
				my( $ip, $port ) = split( /:/, $fields[5] );
				$text .= 'IP: ' . $ip . ' port ' . $port . ' - ' . $fields[2] . ' by ' . $fields[3] . ' [' . $fields[4] . ']';
			}
			elsif( $#fields eq 7 )
			{
				$text .= $fields[2] . ' action taken ' . $fields[7] . ' file:' . $fields[5] . ' [' . $fields[4] . '] - ' . $fields[5];
				$self->{'username'} = $fields[3];
			}
			
		}
		elsif( $self->{'type'} == 2 )
		{
			print STDERR "[MCAFEE] Now we have an OnAcessScanLog file\n" if $self->{'debug'};
# ------------------------------------------------------------------------------------------------ 
# 				OnAccessScanLog				=> 2
# ------------------------------------------------------------------------------------------------ 
# some lines are empty 
# starts with a magic value
# multiple lines per event (same date and timestamp for all the entries)
# Fields are in the range from 1-10,12,15
# Values of five and seven are the majority of the file
#
#	(5 fields) - GROUP EVENT
# DATE	TIME	NOTHING	VARIABLE	VALUE
#
#	(3 fields)
# DATE	TIME	WHAT
# IF WHAT EQ Statistics: THEN WE HAVE A GROUP EVENT FOLLOWED BY 4 FIELDS
#	(4 fields) followed by Statistics: 3 fields
# DATE	TIME	VARIABLE	VALUE
#
# 	(7 fields) - MIGHT SUPERSEED THE 3 FIELDS CONTAINING INFORMATION ABOUT EVENT (GROUP EVENT)
# DATE	TIME	ACTION	USER	FILE1	FILE2	VIRUS NAME
# or
# FILE1 DATE	TIME	VIRUSNAME	VARIABLE	FILE2	VALUE
#
#	TREAT THIS IS AS A SEPARATE EVENT (7 fields separate)
#
#	(9 fields) - treated as separate event
# DATEDATE	NOTHING	TIME	TIME	ACTION	VARIABLE	NOTHING	VALUE	NOTHING
# 
# 	(6 and 8 fields)
# VALUE DIFFERS, CHECK EACH FIELD, IF THERE IS BOTH A DATE AND A TIME THEN GO AHEAD, ELSE SKIP
#
# Value of 1 (zero) and 2, can be skipped
			# check the number of fields
			$text .= 'OnAccessScan: ';

			if( $#fields eq 6 )
			{
				print STDERR "[MCAFEE] We have a six field line\n" if $self->{'debug'};
				# separate event
				$text .= $fields[6] eq '' ? ' action: ' . $fields[2] . ' - file ' . $fields[4] . ' - ' . $fields[5] : ' action: ' . $fields[2] . ' - Virus: ' . $fields[6]. ' - file ' . $fields[4] . ' - ' . $fields[5];

				$self->{'username'} = $fields[3];
			}
			else
			{
				# here we could have a group event
				$self->{'old_date'} = $date;
	
				my $temp;
				# go through each line until we hit a new event
				while( $self->{'old_date'} eq $date )
				{
					# parse the line
					$temp = shift( @fields );
					$temp = shift( @fields );
					$text .= join( ' ', @fields );
						
					print STDERR "[MCAFEE] Loading a new line\n" if $self->{'debug'};

					# load a new line and process it (we may have reached the end of file)
					$line = <$fh> or $self->{'eof'} = 1;
					$date = undef if $self->{'eof'};
					next if $self->{'eof'};

					# split the fields and populate the date
					@fields = split(/\t/,$line);
					$self->_populate_date(\%d,\@fields);
					$date = Log2t::Time::hash_to_date( \%d, $self->{'tz'} ) if( defined $d{'month'} and defined $d{'time'} );

					print STDERR "[McAfee] New date: $date while the old one is " . $self->{'old_date'} . "\n" if $self->{'debug'};
				}
				# now we have a new line to parse
				$self->{'line_loaded'} = 1;
				$self->{'line'} = $line;
				$date = $self->{'old_date'};
			}
		}
		elsif( $self->{'type'} == 3 )
		{
			# OnDemandScanLog
# ------------------------------------------------------------------------------------------------ 
# 				OnDemandScanLog				=> 3
# ------------------------------------------------------------------------------------------------ 
# (not with the magic value) possible multiple lines each event, same timestamp on each entry
# The multiple lines use the following ACTION field:
#	Engine version
#	Scan Summary 
#
# Some lines are empty
# No magic value
# Number of fields: 0, 3, 5 and 6
#
# Events:
# 	(3 fields) - GROUP EVENT 
# DATE	TIME	INFORMATION
# INFORMATION FIELD IS A "VARIABLE = VALUE"
#
#	(5 fields) 
# DATE	TIME	ACTION	USER	INFORMATION
#	GROUP EVENT IF ACTION = "Scan Summary"
#	OTHER POSSIBILITIES INCLUDE: "Scan Started"
#
#	(6 fields)
# Date (day/month/year)	TIME	ACTION	USER	FILE	WHAT
#
			# check for an empty line
			return \%t_line if( $#fields eq 0 or $#fields eq 1 );

			if( $#fields eq 5 )
			{
				# single event
				$text .= ' action: ' . $fields[2] . ' - ' . $fields[5] . ' file: ' . $fields[4];
				$self->{'username'} = $fields[3];
			}
			elsif( $#fields eq 2 )
			{
				$self->{'old_date'} = $date;

                                my $temp;
                                # go through each line until we hit a new event
                                while( $self->{'old_date'} eq $date )
                                {
                                        # parse the line
                                        $temp = shift( @fields );
                                        $temp = shift( @fields );
					$text .= $fields[2] . ' - '; 

                                        print STDERR "[MCAFEE] Loading a new line\n" if $self->{'debug'};

                                        # load a new line and process it (we may have reached the end of file)
                                        $line = <$fh> or $self->{'eof'} = 1;
                                        $date = undef if $self->{'eof'};
                                        next if $self->{'eof'};

                                        # split the fields and populate the date
                                        @fields = split(/\t/,$line);
                                        $self->_populate_date(\%d,\@fields);
                                        $date = Log2t::Time::hash_to_date( \%d, $self->{'tz'} ) if( defined $d{'month'} and defined $d{'time'} );

                                        print STDERR "[McAfee] New date: $date while the old one is " . $self->{'old_date'} . "\n" if $self->{'debug'};
                                }
                                # now we have a new line to parse
                                $self->{'line_loaded'} = 1;
				$self->{'line'} = $line;
                                $date = $self->{'old_date'};
			}
			else
			{
				# we need to examine the line a bit better, to check for a single or group event
				if( $fields[2] =~ m/Scan Summary/ )
				{
					# load the next line there (don't need the title)
					$line = <$fh>;
					$text .= ' Scan Summary: ';
 	                               	my $temp;
					$self->{'old_date'} = $date;

 	                               	# go through each line until we hit a new event
 	                               	while( $self->{'old_date'} eq $date )
 	                               	{
 	                                       # parse the line
						$temp = $fields[4];
						$temp =~ s/\s+/ /g;
				
						$text .= $temp . ' - ';
	
	                                        print STDERR "[MCAFEE] Loading a new line\n" if $self->{'debug'};
	
	                                        # load a new line and process it (we may have reached the end of file)
	                                        $line = <$fh> or $self->{'eof'} = 1;
	                                        $date = undef if $self->{'eof'};
	                                        next if $self->{'eof'};
	
	                                        # split the fields and populate the date
	                                        @fields = split(/\t/,$line);
	                                        $self->_populate_date(\%d,\@fields);
	                                        $date = Log2t::Time::hash_to_date( \%d,$self->{'tz'} ) if( defined $d{'month'} and defined $d{'time'} );
	
	                                        print STDERR "[McAfee] New date: $date while the old one is " . $self->{'old_date'} . "\n" if $self->{'debug'};
	                                }
        	                        # now we have a new line to parse
        	                        $self->{'line_loaded'} = 1;
					$self->{'line'} = $line;
        	                        $date = $self->{'old_date'};

				}
				else
				{
					# single event
					$text .= ' action: ' . $fields[2] . ' -' . $fields[4];
					$self->{'username'} = $fields[3];
				}
			}
			
		}
		else
		{
			$text = '';
			$title = '';
		}
	}
	else
	{
		# we have a line with a valid time and date, but not in the correct position, so we will improvise
		$text .= $self->{'types'}->{$self->{'type'}} . ' - ' . $line;
		$text =~ s/\t/-/g;

		$title = 'Line from ' . $self->{'types'}->{$self->{'type'}};
	}

	# fix potential new line characters in text
	$text =~ s/\n//g;
	$text =~ s/\r//g;
	$text =~ s/\s+/ /g;
	
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
                'time' => { 0 => { 'value' => $date, 'type' => 'Entry written', 'legacy' => 15 } },
                'desc' => $text,
                'short' => $title,
                'source' => 'AV',
                'sourcetype' => 'McAfee AV Log',
                'version' => 2,
                'extra' => { 'user' => $self->{'username'},  }
        );

	return \%t_line;
}

#       get_help
#
# A simple subroutine that returns a string containing the help 
# message for this particular format file.
#
# @return A string containing a help file for this format file
sub get_help()
{
	return "This is a plugin of unknown origin.  It parses a log file and contains no requirements or 
any other relevant options or possibilites, use with care...";

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
	my $ofs;
	my $temp;

	# define an array to keep
	my %return;
	my $vline;
	my @words;

	# default values
	$return{'success'} = 0;
	$return{'msg'} = 'success';
	$ofs = 0;

        return \%return unless -f ${$self->{'name'}};

        # start by setting the endian correctly
        Log2t::BinRead::set_endian( BIG_E );

	# open the file (at least try to open it)
	eval
	{
		# read the first two bytes
		$vline = Log2t::BinRead::read_16( $self->{'file'}, \$ofs );

	};
	if ( $@ )
	{
		$return{'success'} = 0;
		$return{'msg'} = "Unable to read from file ($@)";
	}

# ------------------------------------------------------------------------------------------------ 
# 			AccessProtectionLog (one line per event) 	=> 1
# ------------------------------------------------------------------------------------------------ 
#	(8 fields)
# DATE (day/month/year) 	TIME 	WHAT 	USER 	WHERE	FILE	DESCRIPTION	ACTION
#	(6 fields)
# DATE	TIME	WHAT	PROGRAM		DESCRIPTION	IP:PORT
# 
# each line is a new event 
# starts with a magic value
# Fields are either 5 or 7 (meaning 6 or 8)
#
# ------------------------------------------------------------------------------------------------ 
# 				OnDemandScanLog				=> 3
# ------------------------------------------------------------------------------------------------ 
# (not with the magic value) possible multiple lines each event, same timestamp on each entry
# The multiple lines use the following ACTION field:
#	Engine version
#	Scan Summary 
#
# Some lines are empty
# No magic value
# Number of fields: 0, 3, 5 and 6
#
# Events:
# 	(3 fields) - GROUP EVENT 
# DATE	TIME	INFORMATION
# INFORMATION FIELD IS A "VARIABLE = VALUE"
#
#	(5 fields) 
# DATE	TIME	ACTION	USER	INFORMATION
#	GROUP EVENT IF ACTION = "Scan Summary"
#	OTHER POSSIBILITIES INCLUDE: "Scan Started"
#
#	(6 fields)
# Date (day/month/year)	TIME	ACTION	USER	FILE	WHAT
#
#
# ------------------------------------------------------------------------------------------------ 
# 				OnAccessScanLog				=> 2
# ------------------------------------------------------------------------------------------------ 
# some lines are empty 
# starts with a magic value
# multiple lines per event (same date and timestamp for all the entries)
# Fields are in the range from 1-10,12,15
# Values of five and seven are the majority of the file
#
#	(5 fields) - GROUP EVENT
# DATE	TIME	NOTHING	VARIABLE	VALUE
#
#	(3 fields)
# DATE	TIME	WHAT
# IF WHAT EQ Statistics: THEN WE HAVE A GROUP EVENT FOLLOWED BY 4 FIELDS
#	(4 fields) followed by Statistics: 3 fields
# DATE	TIME	VARIABLE	VALUE
#
# 	(7 fields) - MIGHT SUPERSEED THE 3 FIELDS CONTAINING INFORMATION ABOUT EVENT (GROUP EVENT)
# DATE	TIME	ACTION	USER	FILE1	FILE2	VIRUS NAME
# or
# FILE1 DATE	TIME	VIRUSNAME	VARIABLE	FILE2	VALUE
#
#	TREAT THIS IS AS A SEPARATE EVENT (7 fields separate)
#
#	(9 fields) - treated as separate event
# DATEDATE	NOTHING	TIME	TIME	ACTION	VARIABLE	NOTHING	VALUE	NOTHING
# 
# 	(6 and 8 fields)
# VALUE DIFFERS, CHECK EACH FIELD, IF THERE IS BOTH A DATE AND A TIME THEN GO AHEAD, ELSE SKIP
#
# Value of 1 (zero) and 2, can be skipped


	# check for magic value: 0x ef bb bf
	if( $vline eq 0xefbb )
	{
		$ofs--;
		$vline = Log2t::BinRead::read_16( $self->{'file'}, \$ofs );
		
		if( $vline eq 0xbbbf )
		{
			#####BEGIN UPDATE#####
			
			# correct magic value, read another byte to do some further checks
			$vline = Log2t::BinRead::read_8( $self->{'file'}, \$ofs );
			
			# figure out if we just read a new line
			my	$newlinecount = 0;
			while( ($vline eq 0x0a || $vline eq 0x0d) && $newlinecount < NEWLINELIMIT)
			{
				$newlinecount++;
				# keep reading until there are no more new lines or there is nothing left to read
				$vline = Log2t::BinRead::read_8( $self->{'file'}, \$ofs );
				#print "vline = $vline\n";
			}
			
			# the correct starting location is one less than the current file offset
			$ofs--;
		
			#####END UPDATE#####
		
			# correct magic value, let's continue and read a line to find out if this truly is a McAfee log file and which type it is
			$vline = Log2t::BinRead::read_ascii_until( $self->{'file'}, \$ofs, "\n", 400 );
			
			# split the sentence into fields
			@words = split( /\t/, $vline );
			
			# check the date field (Paul Bobby, paul.bobby at lmco dot com added the d{1,2} for the month value)
			if( $words[0] =~ m/\d{1,2}\/\d{1,2}\/\d{4}/ )
			{
				# verify the second field
				if( $words[1] =~ m/\d{1,2}:\d{2}:\d{2}/ )
				{
					# both the date and time stamp are OK, let's detect types shall we...
					$return{'success'} = 1;

					if( $#words eq 5 or $#words eq 7 )
					{
						# possible AccessProtectionLog
						# DATE (day/month/year) 	TIME 	WHAT 	USER 	WHERE	FILE	DESCRIPTION	ACTION
						# DATE	TIME	WHAT	PROGRAM		DESCRIPTION	IP:PORT
						# verify the IP:PORT if eq 5 and USER if eq 7
						$self->{'type'} = 1;
						if( $#words eq 5 && $words[5] =~ m/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+/ )
						{
							$self->{'type'} = 1;
							$return{'success'} = 1;
						}
						elsif( $#words eq 7 && $words[3] =~ m/.+\\.+/ )
						{
							$self->{'type'} = 1;
							$return{'success'} = 1;
						}
						else
						{
							$return{'success'} = 0;
							$return{'msg'} = 'Not the correct format, incorrect fields';
						}
					}
					elsif( $#words ge 2 and $#words le 8 )
					{
						# OnAccessScanLog
						$self->{'type'} = 2;

						# check the line
						if( $vline =~ m/Engine|AntiVirus|Statistics|McAfee/ )
						{
							$return{'success'} = 1;
						}
						else
						{
							$return{'success'} = 0;
							$return{'msg'} = 'Not the correct format of an OnAccessScanLog';
						}
					}
					else
					{
						$return{'success'} = 0;
						$return{'msg'} = 'Wrong number of fields (' . $#words . ')';
					}
				}
				else
				{
					$return{'success'} = 0;
					$return{'msg'} = 'The time field is not correctly formed';
				}
			}
			else
			{
				$return{'msg'} = 'The date field is not correctly formed (' . $words[0] .')';
				$return{'success'} = 0;
			}
		}
		else
		{
			$return{'success'} = 0;
			$return{'msg'} = sprintf 'Wrong magic value (0x%x)', $vline;
		}
	}
	else
	{
		# check the third type (OnDemandScanLog)

		unless( $self->{'quick'} )
		{
			# it should start with a date (so we have a number)
			seek($self->{'file'},0,0);
			read($self->{'file'},$ofs,1);
			$return{'msg'} = 'Wrong magic value';

			if( $ofs !~ m/[0-9]/ )
			{
				return \%return;
			}
		}

		$ofs = 0;
		$vline = Log2t::BinRead::read_ascii_until( $self->{'file'}, \$ofs, "\n", 400 );

		# split the sentence into fields
		@words = split( /\t/, $vline );

		# check the number of fields
		if( $#words ge 2 )
		{
			# check the date field
			if( $words[0] =~ m/\d{1,2}\/\d{2}\/\d{4}/ )
			{
				# verify the second field
				if( $words[1] =~ m/\d{1,2}:\d{1,2}:\d{2}/ )
				{
					$self->{'type'} = 3;
					# check the line
					if( $vline =~ m/Engine|AntiVirus|Statistics|McAfee/ )
					{
						$return{'success'} = 1;
					}
					else
					{
						$return{'success'} = 0;
						$return{'msg'} = 'Not the correct format of an OnDemandScanLog';
					}
				}
				else
				{
					$return{'success'} = 0;
					$return{'msg'} = 'The time field is not correctly formed';
				}
			}
			else
			{
				$return{'msg'} = 'The date field is not correctly formed';
				$return{'success'} = 0;
			}
		}
		else
		{
			$return{'success'} = 0;
			$return{'msg'} = 'Wrong magic value or not the correct format';
		}
	}
	
	return \%return;
}


# the populate_date is a small function to get the date from a log file
sub _populate_date( $$ )
{
	my $self = shift;
	my $ref = shift;
	my $ar = shift;
	
	my $i = 0;

	# find the date fields
	foreach( @{$ar} )
	{
		$_ =~ s/\n//g;
		$_ =~ s/\r//g;

		next if $_ eq '';

		print STDERR "[MCAFEE] Populating the date object, or testing date <$_>\n" if $self->{'debug'};
		if( /\d{1,2}\/\d{1,2}\/\d{4}/ )
		{
			# then we have a month
			$ref->{'month'} = $_;
			$ref->{'m'} = $i;
		}
		elsif( /\d{1,2}:\d{1,2}:\d{1,2}/ )
		{
			# we have a timestamp
			$ref->{'time'} = $_;
			$ref->{'t'} = $i;
		}
		# increment counter
		$i++;
	}
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

