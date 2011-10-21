#################################################################################################
#		MCAFEE FIRE AND UPDATE LOGS
#################################################################################################
# this script is a part of the log2timeline program.
# 
# This file implements a parser for the FireTray, FireSvc, FireEpo and UpdateLog files
#
#
# Author: anonymous donator 
# Version : 0.1
# Date : 7/26/2011
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

package Log2t::input::mcafeefireup;

use strict;
use Log2t::base::input; # the SUPER class or parent
#use Log2t::Numbers;	# work with numbers, round-up, etc...
#use Log2t::Network;	# some routines that deal with network information
use Log2t::BinRead;	# to work with binary files (during verification all files are treaded as such)
use Log2t::Common ':binary';
#use Log2t::Time;	# for time manipulations
#use Log2t:Win;		# for few Windows related operations, GUID translations, etc..
#use Log2t:WinReg;	# to recover deleted information from registry
use vars qw($VERSION @ISA);

# the maximum number of newlines to read before verification fails
use constant NEWLINELIMIT => 60;

# inherit the base input module, or the super class.
@ISA = ( "Log2t::base::input" );

# version number
$VERSION = '0.1';

# by default these are the global varibles that get passed to the module
# by the engine.
# These variables can therefore be used in the module without needing to 
# do anything to initalize them.
#
#	$self->{'debug'}	- (int) Indicates whether or not debug is turned on or off
#	$self->{'quick'} 	- (int) Indicates if we will like to do a quick verification
#	$self->{'tz'}		- (string) The timezone that got passed to the tool
#	$self->{'temp'}		- (string) The name of the temporary directory that can be used
#	$self->{'text'}		- (string) The path that is possible to add to the input (-m parameter) 
#	$self->{'sep'} 		- (string) The separator used (/ in Linux, \ in Windows for instance)
#


#	new
# this is the constructor for the subroutine.  
#
# If this input module uses all of the default values and does not need to define any new value, it is best to 
# skip implementing it altogether (just remove it), since we are inheriting this subroutine from the SUPER
# class
sub new()
{
	my $class = shift;

	# now we call the SUPER class's new function, since we are inheriting all the 
	# functions from the SUPER class (input.pm), we start by inheriting it's calls
	# and if we would like to overwrite some of its subroutines we can do that, otherwise
	# we don't need to include that subroutine
        my $self = $class->SUPER::new();
					
	# the available log types
	$self->{'types'} = {
		1 => 'Fire',
		2 => 'Update'
	};

    # bless the class ;)
    bless($self,$class);

	return $self;
}

# 	init
#
# The init call resets all variables that are global and might mess up with recursive
# scans.  
#
# This subroutine is called after the file has been verified, and before it is parsed.
#
# If there is no need for this subroutine to do anything, it is best to skip implementing
# it altogether (just remove it), since we are inheriting this subroutine from the SUPER
# class
sub init()
{
	my $self = shift;

	return 1;
}


# 	get_version
# A simple subroutine that returns the version number of the format file
# There shouldn't be any need to change this routine, it serves its purpose 
# just the way it is defined right now. (so it shouldn't be changed)
#
# @return A version number
sub get_version()
{
	return $VERSION;
}

# 	get_description
# A simple subroutine that returns a string containing a description of 
# the funcionality of the format file. This string is used when a list of
# all available format files is printed out
#
# @return A string containing a description of the input module
sub get_description()
{
	# change this value so it reflects the purpose of this module
	return "Parse the content of an XeXAMInventory or AeXProcessList log file";
}

#	end
# A subroutine that closes everything, remove residudes if any are left
#
# If there is no need for this subroutine to do anything, it is best to skip implementing
# it altogether (just remove it), since we are inheriting this subroutine from the SUPER
# class
sub end()
{
	my $self = shift;
	
	return 1;
}

#	get_time
# This is the main "juice" of the input module. It parses the input file
# and produces a timestamp object that get's returned (or if we said that
# self->{'multi_line'} = 0 it will return a single hash reference that contains
# multiple timestamp objects within it.
# 
# This subroutine needs to be implemented at all times
sub get_time()
{
	my $self = shift;

	# the timestamp object
	my %t_line;
	my $text;
	my $date=-1;

	# get the filehandle and read the next line
	my $fh = $self->{'file'};
	my $line = <$fh> or return undef;
	
	# check if we read in only a newline, if so, read the next line (and keep doing this until EOF or !\n)
	while($line eq "\n")
	{$line = <$fh>;}
	
	# first remove any newlines
	$line =~ s/\r|\n//g;
	
	# now split the line into usable groups
	# fire logs have the form:
	# Date[mm/dd/YYYY] | Time[HH:MM:SS] | Name of throwing file/service | [TAB] | Event Type | Message
	# 02/20/2009 09:40:14 ENTCPWRK[1024]	WARNING  Failed to find the UI window, err=0
	# Known event types: CRITICAL|WARNING|ERROR
	if($line =~ /(\d{2}\/\d{2}\/\d{4} \d{2}:\d{2}:\d{2}) (.*?)\t(.*?)\s+(.*?)\s*$/)
	{
		my $parser = DateTime::Format::Strptime->new(pattern => '%m/%d/%Y %H:%M:%S', time_zone => $self->{'tz'});
		my $dt = $parser->parse_datetime($1);

		$date = $dt->epoch();
		
		$text = 'Name: '.$2.' | Event type: '.$3.' | Message: '.$4;
		#print "text is $text\n";
		# create the t_line variable
        %t_line = (
                'time' => { 0 => { 'value' => $date, 'type' => 'Entry Written', 'legacy' => 15 } },
                'desc' => $text,
                'short' => 'McAfee Fire event',
                'source' => 'McAfee Fire Log',
                'sourcetype' => 'HIPS',
                'version' => 2,
                #'extra' => { 'user' => $user, 'host' => $host } 
        );
	}
	# update logs
	# 6/15/2010	5:22:00 PM	Daff\administrator 	Update is cancelled by the user.
	# 7/6/2010	13:09:44	ADMIN\Belloa.Bob 	Starting task: AutoUpdate
	elsif($line =~ /(\d{1,2}\/\d{1,2}\/\d{4})\t(\d{1,2}:\d{2}:\d{2}) ?(AM|PM)?\t(.*?\\.*?)\t(.*?)$/ )
	{		
		my ($month,$day,$year) = split(/\//,$1);
		my ($hour,$min,$sec) = split(/:/,$2);
		
		#print "3 = $3\n";
		
		if($3 eq 'AM' || $3 eq 'PM')
		{
			$hour += 12 unless $hour == 12;
		}
		elsif($3 ne '')
		{
			print STDERR "Unexpected time field!\n" if ($self->{'debug'});
			return \%t_line;
		}
		
		$date = DateTime->new( 
			year => $year,
			month => $month,
			day => $day,
			hour => $hour,
			minute => $min,
			second => $sec,
			time_zone => $self->{'tz'}
		);

		$date = $date->epoch();
		
		$text = $5;
		#print "text is $text\n";
		# create the t_line variable
        %t_line = (
                'time' => { 0 => { 'value' => $date, 'type' => 'Entry Written', 'legacy' => 15 } },
                'desc' => $text,
                'short' => 'McAfee Update event',
                'source' => 'McAfee Update Log',
                'sourcetype' => 'HIPS',
                'version' => 2,
                'extra' => { 'user' => $4 } 
        );
	}
	#else{return \%t_line;}# sometimes lines are just periods or something else. just return a blank a hash
	
	#print "t_line time is ".$t_line{'time'}->{0}->{'value'};
	
	return \%t_line;
}

#	get_help
# A simple subroutine that returns a string containing the help 
# message for this particular format file.
# @return A string containing a help file for this input module
sub get_help()
{
	# this message contains the full message that gest printed 
	# when the user calls for a help on a particular module.
	# 
	# So this text that needs to be changed contains more information
	# than the description field.  It might contain information about the
	# path names that the file might be found that this module parses, or
	# URLs for additional information regarding the structure or forensic value of it.
	return "This parser parses McAfee fire logs.";
}

#	verify
# This subroutine is very important.  Its purpose is to check the file or directory that is passed 
# to the tool and verify its structure. If the structure is correct, then this module is suited to 
# parse said file or directory.
#
# This is most important when a recursive scan is performed, since then we are comparing all files/dir
# against the module, making it vital for it to be both accurate and optimized.  Slow verification 
# subroutine means the tool will take considerably longer time to complete, too vague confirmation
# could also lead to the module trying to parse files that it is not capable of parsing.
#
# The subroutine returns a reference to a hash that contains two keys, 
#	success		-> INT, either 0 or 1 (meaning not the correct structure, or the correct one)
#	msg		-> A short description why the verification failed (if the value of success
#			is zero that is).
sub verify
{
	my $self = shift;

	# define an array to keep
	my %return;
	my $line;

	$return{'success'} = 0;
	$return{'msg'} = 'success';

	# to make things faster, start by checking if this is a file or a directory, depending on what this
	# module is about to parse (and to eliminate shortcut files, devices or other non-files immediately)
	return \%return unless -f ${$self->{'name'}};

    # start by setting the endian correctly
    Log2t::BinRead::set_endian( BIG_E );

	my $ofs = 0;
	
	# now we try to read from the file
	eval
	{
		# try to read two bytes
		$line = Log2t::BinRead::read_16( $self->{'file'}, \$ofs );
	};
	if ( $@ )
	{
		$return{'success'} = 0;
		$return{'msg'} = "Unable to process file ($@)";
	}
	
	chomp($line);
	
	# check for magic value: 0x ef bb bf
	if( $line eq 0xefbb )
	{
		$ofs--;
		$line = Log2t::BinRead::read_16( $self->{'file'}, \$ofs );
		
		if( $line eq 0xbbbf )
		{# McAfee log magic value
			# correct magic value, read another byte to do some further checks
			$line = Log2t::BinRead::read_8( $self->{'file'}, \$ofs );
			
			# figure out if we just read a new line
			my	$newlinecount = 0;
			while( ($line eq 0x0a || $line eq 0x0d) && $newlinecount < NEWLINELIMIT)
			{
				$newlinecount++;
				# keep reading until there are no more new lines or there is nothing left to read
				$line = Log2t::BinRead::read_8( $self->{'file'}, \$ofs );
				#print "line = $line\n";
			}
			
			# the correct starting location is the one less than the current file offset
			$ofs--;
		
			# correct magic value, let's continue and read a line to find out if this truly is a McAfee log file
			$line = Log2t::BinRead::read_ascii_until( $self->{'file'}, \$ofs, "\n", 400 );
			
			# split the sentence into fields
			my @words = split( /\t/, $line );
			
			# there must be four fields in a McAfee Update log
			if($#words==3)
			{
				$return{'success'} = 0;
				$return{'msg'} = 'Incorrect number of fields!.';
			}
			
			#print 'There are '.$#words.' words in the line ||'.$line."\n";
			# check the date field
			if( $words[0] =~ /\d{1,2}\/\d{1,2}\/\d{4}/ )
			{
				# verify the second field (time)
				if( $words[1] =~ /\d{1,2}:\d{2}:\d{2}/ )
				{
					#print "word0 = $words[0], word1 = $words[1], word2 = $words[2], word3 = $words[3]\n";
					# check the user
					if($words[2] =~ /.*?\\.*?/)
					{
						# check the message
						if($words[3] =~ /^[a-zA-Z]+/)
						{
							print STDERR "McAfee update log found!\n" if ($self->{'debug'});
							$return{'success'} = 1;
							$self->{'type'} = 1;
						}
					}
					else
					{
						$return{'success'} = 0;
						$return{'msg'} = 'Incorrect user format.';
					}
				}
			}
			else
			{
				$return{'success'} = 0;
				$return{'msg'} = 'Incorrect date format!.';
			}
		}
		else
		{
			$return{'success'} = 0;
			$return{'msg'} = 'Wrong magic value.';
		}
	}
	else
	{#check for a McAfee Fire* log
		$ofs = 0;
		$line = Log2t::BinRead::read_8( $self->{'file'}, \$ofs );
			
		# figure out if we just read a new line
		my	$newlinecount = 0;
		while( ($line eq 0x0a || $line eq 0x0d) && $newlinecount < NEWLINELIMIT)
		{
			$newlinecount++;
			# keep reading until there are no more new lines or there is nothing left to read
			$line = Log2t::BinRead::read_8( $self->{'file'}, \$ofs );
			#print "line = $line\n";
		}
		
		# the real location we want to start at is one previous to the current location
		$ofs--;
		
		# read a hopefully useful line
		$line = Log2t::BinRead::read_ascii_until( $self->{'file'}, \$ofs, "\n", 400 );
			
		# does the format follow what we are expecting?
		if($line =~ /^\d{2}\/\d{2}\/\d{4} \d{2}:\d{2}:\d{2} .*?\t(?:(?:WARNING|ERROR))\s+.*?/)
		{
			print STDERR "Found McAfee Fire log\n" if $self->{'debug'};
			$return{'success'} = 1;
			$self->{'type'} = 2;
		}
		else
		{
			$return{'success'} = 0;
			$return{'msg'} = 'Wrong magic value or format';
		}
	}

	return \%return;
}

1;

__END__

=pod

=head1 NAME

structure - An example input module for log2timeline

=head1 METHODS

=over 4

=item new

A default constructor for the input module. There are no parameters passed to the constructor, however it defines the behaviour of the module.  That is to say it indicates whether or not this module parses a file or a directory, and it also defines if this is a log file that gets parsed line-by-line or a file that parses all the timestamp objects and returns them all at once.

=item init

A small routine that takes no parameters and is called by the engine before a file is parsed.  This routine takes care of initializing global variables, so that no values are stored from a previous file that got parsed by the module to avoid confusion.

=item end

Similar to the init routine, except this routine is called by the engine when the parsing is completed.  The purpose of this routine is to close all database handles or other handles that got opened by the module itself (excluding the file handle) and to remove any temporary files that might still be present.

=item get_time

This is the main routine of the module.  This is the routine that parses the actual file and produces timestamp objects that get returned to the main engine for further processing.  The routine reads the file or directory and extracts timestamps and other needed information to create a timestamp object that then gets returned to the engine, either line-by-line or all in one (as defined in the constructor of the module).

=item verify

The purpose of this routine is to verify the structure of the file or directory being passed to the module and tell the engine whether not this module is capable of parsing the file in question or not. This routine is therfore very important for the recursive search of the engine, and it is very important to make this routine as compact and optimized as possible to avoid slowing the tool down too much.

=item get_help()

Returns a string that contains a longer version of the description of the output module, as well as possibly providing some assistance in how the module should be used.

=item get_version()

Returns the version number of the module.

=item get_description()

Returns a string that contains a short description of the module. This short description is used when a list of all available modules is printed out.

=back

=cut

