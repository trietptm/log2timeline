#################################################################################################
#		PROFTPD XFERLOG
#################################################################################################
# this script is a part of the log2timeline program.
# 
# This is a format file that implements a parser for ProFTPd xferlog log files.  It parses the file
# and provides the main script with enough information to provide a body file that can be
# used in a timeline analysis
#
# Standard Format:
#
# http://www.castaglia.org/proftpd/doc/xferlog.html
#
# Author: Willi Ballenthin
# Version : 0.1
# Date : 27/10/11
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

package Log2t::input::proftpd_xferlog;

use strict;
use Log2t::base::input; # the SUPER class or parent
use DateTime;	
use Log2t::Common ':binary';
use Log2t::BinRead;

use vars qw($VERSION @ISA);

# inherit the base input module, or the super class.
@ISA = ( "Log2t::base::input" );

# version number
$VERSION = '0.1';

my %struct;

############## PARSING MODULE CLASS #########################
sub new()
{
        my $class = shift;
        my $self = $class->SUPER::new();

        $self->{'multi_line'} = 1;

	bless($self, $class);
        return $self;
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


# 	get_description
# A simple subroutine that returns a string containing a description of 
# the funcionality of the format file. This string is used when a list of
# all available format files is printed out
# @return A string containing a description of the format file's functionality
sub get_description()
{
	return "Parse the content of a ProFTPd xferlog log file";
}

#	get_time
# This is the main "juice" of the format file.  It takes a line from the log file
# and parses it to produce an array containing all the needed values to print a 
# body file.
#
# @param LINE a string containing a single line from the access file
# @return Returns a array containing the needed values to print a body file
sub get_time()
{
	my $self = shift;

	my @date_t; 
	my @date_m; 
	my %li;
	my %date;
	my $date_e;
	my $date_s;

	my %t_line;
	my $text;
	my $uri;

        # get the filehandle and read the next line
        my $fh = $self->{'file'};
        my $line = <$fh> or return undef;
	$line =~ s/\s+/ /g;

	# empty lines, skip them
	if( $line =~ m/^$/ or $line =~ m/^\s+$/ )
        {
                return \%t_line;
        }

	#
	# the log file consists of the following fields 
        #
        # current-time   
        # transfer-time   
        # remote-host   
        # file-size   
        # filename   
        # transfer-type   
        # special-action-flag   
        # direction   
        # access-mode   
        # username   
        # service-name   
        # authentication-method   
        # authenticated-user-id  
        # completion-status
        #
        #     Day      Month   Day#   hr     min    sec     year    time    r-ip    size   name   ascii?  action    in?    anon?    user    service auth?    uid   complete?
        # /^([^\s]+) ([^\s]+) (\d+) (\d\d):(\d\d):(\d\d) (\d\d\d\d) (\d) ([\d\.]+) (\d+) ([^\s]+) ([ab]) ([CUT_]) ([oid]) ([agr]) ([^\s]+) ([^\s]+) ([01]) ([^\s]+) ([ci])/

	if ($line =~ /^([^\s]+) ([^\s]+) (\d+) (\d\d):(\d\d):(\d\d) (\d\d\d\d) (\d+) ([\d\.]+) (\d+) ([^\s]+) ([ab]) ([CUT_]) ([oid]) ([agr]) ([^\s]+) ([^\s]+) ([01]) ([^\s]+) ([ci])\s*/)
	{
		$li{'day-word'} = $1;
		$li{'month'} = $2;
		$li{'day-num'} = $3;		
		$li{'hour'} = $4;
		$li{'minute'} = $5;
		$li{'second'} = $6;
		$li{'year'} = $7;
		$li{'time'} = $8;
		$li{'r-ip'} = $9;
		$li{'size'} = $10;
		$li{'name'} = $11;
		$li{'ascii?'} = $12;
		$li{'action'} = $13;
		$li{'in?'} = $14;
		$li{'anon?'} = $15;
		$li{'user'} = $16;
		$li{'service'} = $17;
		$li{'auth?'} = $18;
		$li{'uid'} = $19;
		$li{'complete?'} = $20;
        
                if ($li{'ascii?'} eq 'a')
                {
                    $li{'ascii?'} = 'ASCII';
                }
                else {
                    $li{'ascii?'} = 'Binary';
                }
                if ($li{'action'} eq 'C')
                {
                    $li{'action'} = 'Compressed';                    
                }
                elsif ($li{'action'} eq 'U') {
                    $li{'action'} = 'Uncompressed';                                        
                }
                elsif ($li{'action'} eq 'T') {
                    $li{'action'} = 'TARed';                                        
                }
                elsif ($li{'action'} eq '_') {
                    $li{'action'} = 'No action';                                        
                }
                if ($li{'in?'} eq 'i')
                {
                    $li{'in?'} = 'Incoming';                    
                }
                elsif ($li{'in?'} eq 'o') {
                    $li{'in?'} = 'Outgoing';                                        
                }
                elsif ($li{'in?'} eq 'd') {
                    $li{'in?'} = 'Deleted';                                        
                }
                if ($li{'anon?'} eq 'a')
                {
                    $li{'anon?'} = 'Anonymous';                    
                }
                elsif ($li{'anon?'} eq 'g')
                {
                    $li{'anon?'} = 'Guest';                    
                }
                elsif ($li{'anon?'} eq 'r')
                {
                    $li{'anon?'} = 'Real user';                    
                }
                if ($li{'auth?'} eq '1')
                {
                    $li{'auth?'} = 'Authenticated';                    
                }
                elsif ($li{'auth?'} eq '0')
                {
                    $li{'auth?'} = 'Unauthenticated';                    
                }
                if ($li{'complete?'} eq 'c')
                {
                    $li{'complete?'} = 'Complete';                    
                }
                elsif ($li{'complete?'} eq 'i')
                {
                    $li{'complete?'} = 'Incomplete';                    
                }

                print STDERR "[PROFTPD XFERLOG] DAY: $li{'day-word'} MONTH: $li{'month'} DAY: $li{'day-num'} HOUR: $li{'hour'} MINUTE: $li{'minute'} SECOND: $li{'second'} YEAR: $li{'year'} TIME: $li{'time'} IP: $li{'r-ip'} SIZE: $li{'size'} NAME: $li{'name'} ASCII: $li{'ascii?'} ACTION: $li{'action'} DIRECTION: $li{'in?'} USER TYPE: $li{'anon?'} USERNAME: $li{'user'} SERVICENAME: $li{'service'} AUTHENTICATED: $li{'auth?'} USER ID: $li{'uid'} COMPLETED: $li{'complete?'} \n" if $self->{'debug'};


		if ($li{'month'} eq 'Jan') {
			$li{'month'} = 1;
		}
		elsif ($li{'month'} eq 'Feb') {
			$li{'month'} = 2;
		}
		elsif ($li{'month'} eq 'Mar') {
			$li{'month'} = 3;
		}
		elsif ($li{'month'} eq 'Apr') {
			$li{'month'} = 4;
		}
		elsif ($li{'month'} eq 'May') {
			$li{'month'} = 5;
		}
		elsif ($li{'month'} eq 'Jun') {
			$li{'month'} = 6;
		}
		elsif ($li{'month'} eq 'Jul') {
			$li{'month'} = 7;
		}
		elsif ($li{'month'} eq 'Aug') {
			$li{'month'} = 8;
		}
		elsif ($li{'month'} eq 'Sep') {
			$li{'month'} = 9;
		}
		elsif ($li{'month'} eq 'Oct') {
			$li{'month'} = 10;
		}
		elsif ($li{'month'} eq 'Nov') {
			$li{'month'} = 11;
		}
		elsif ($li{'month'} eq 'Dec') {
			$li{'month'} = 12;
		}
		else
		{	
			print STDERR "[PROFTPD XFERLOG] Not a valid month: $li{'month'}\n" if $self->{'debug'};
			return \%t_line;
		}

		%date = (
			year	=>	$li{'year'}, 
			month	=>	$li{'month'},
			day	=>	$li{'day-num'},
			hour	=>	$li{'hour'},
			minute	=>	$li{'minute'},
			time_zone => 	$self->{'tz'},
			second 	=> 	$li{'second'}
		);

		$date_s = DateTime->new( \%date );
		$date_e = $date_s->epoch;

		print STDERR "[PROFTPD XFERLOG] Date after calculation (epoch) $date_e - month: $li{'month'}\n" if $self->{'debug'};

                $text = "$li{'in?'} $li{'complete?'} transfer of $li{'name'} of $li{'size'} bytes from $li{'r-ip'} using $li{'auth?'} $li{'anon?'} $li{'user'} in $li{'ascii?'} $li{'action'} mode";

                %t_line = (
                  'time' => { 0 => { 'value' => $date_e, 'type' => 'Entry written', 'legacy' => 15 } },
                  'desc' => $text,
                  'short' => "$li{'r-ip'} $li{'in?'} $li{'name'}",
                  'source' => 'ProFTPd_xferlog',
                  'sourcetype' => 'ProFTPd xferlog log file',
                  'version' => 2,
                  'extra' => { 'ip' => $li{'r-ip'},'size' => $li{'size'},'name' => $li{'name'},'ascii' => $li{'ascii?'},'action' => $li{'action'},'direction' => $li{'in?'},'anonymous' => $li{'anon?'},'username' => $li{'user'},'servicename' => $li{'service'},'authenticated' => $li{'auth?'},'userid' => $li{'uid'},'complete' => $li{'complete?'}}
                );
		return \%t_line;
	}
	else 
	{
		print STDERR "Error, not correct structure ($line)\n" if $self->{'debug'};
	}
	return;
}

#	get_help
# A simple subroutine that returns a string containing the help 
# message for this particular format file.
# @return A string containing a help file for this format file
sub get_help()
{
	return "This parser parses the ProFTPd xferlog log file. To see the definition of the 
log format, please see:
http://www.castaglia.org/proftpd/doc/xferlog.html
Use with the FILE option as the ProFTPd xferlog log file\n
\t$0 -f proftpd_xferlog ex...log

This format file depends upon the library
	DateTime
for converting date variables to epoch time. Possible to install using
perl -MCPAN -e shell
(when loaded)
install DateTime\n";

}

#	verify
# A subroutine that reads a single line from the log file and verifies that it is of the
# correct format so it can be further processed.
# The correct format of an ProFTPd xferlog file can be found at:
# http://www.castaglia.org/proftpd/doc/xferlog.html
# @return An array containing an integer and a string.  The integer indicates a success or failure and the
#	string is the error message (if the file is not correctly formed)
sub verify
{
	my $self = shift;

	my %return;
	my $line;
	my @words;
	my $tag;
	my $c_ip = 2;
	my $temp;
	my @fields;

	my $max = 15;
	my $i = 0;
	
	$return{'success'} = 0;
	$return{'msg'} = 'success';

        # depending on which type you are examining, directory or a file
        return \%return unless -f ${$self->{'name'}};

	my $ofs = 0;
        Log2t::BinRead::set_endian( LITTLE_E );

	$tag = 1;
	$ofs = 0;
	while( $tag )
	{
		$tag = 0 unless $line = Log2t::BinRead::read_ascii_until( $self->{'file'}, \$ofs, "\n", 400 );
		next if ( $line =~ m/^#/ or $line =~ m/^$/ );
		$tag = 0 if $i++ eq $max;
		next unless $tag;
			
                if ($line =~ /^[^\s]+ ([^\s]+) (\d+) (\d\d):(\d\d):(\d\d) (\d\d\d\d) (\d+) ([\d\.]+) (\d+) ([^\s]+) ([ab]) ([CUT_]) ([oid]) ([agr]) ([^\s]+) ([^\s]+) ([01]) ([^\s]+) ([ci])/)
		{
			$return{'success'} = 1;
			return \%return;
		}
	}
	$return{'msg'} = "None of the first $max lines fit the format of ProFTPd xferlog logs.";
	$return{'success'} = 0;

	return \%return;
}

1;
