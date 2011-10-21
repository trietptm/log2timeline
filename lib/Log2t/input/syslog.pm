#################################################################################################
#		LINUX SYSLOG
#################################################################################################
# this script is a part of the log2timeline program.
# 
# This is a format file that implements a parser for syslog log files.  It parses the file
# and provides the main script with enough information to provide a body file that can be
# used in a timeline analysis
#
# Standard Format:
#
# Date Time System-name Facility: Message
#
# My understanding of the syslog format is empirical, however. There seems to be
# a good amount of variation across syslog messages, so I'll try to catch messages
# as I can define them.
#
# Facilities
#LOG_AUTH
#    security/authorization messages (DEPRECATED Use LOG_AUTHPRIV instead) 
#LOG_AUTHPRIV
#    security/authorization messages (private) 
#LOG_CRON
#    clock daemon (cron and at) 
#LOG_DAEMON
#    system daemons without separate facility value 
#LOG_FTP
#    ftp daemon 
#LOG_KERN
#    kernel messages 
#LOG_LOCAL0 through LOG_LOCAL7
#    reserved for local use 
#LOG_LPR
#    line printer subsystem 
#LOG_MAIL
#    mail subsystem 
#LOG_NEWS
#    USENET news subsystem 
#LOG_SYSLOG
#    messages generated internally by syslogd 
#LOG_USER (default)
#    generic user-level messages 
#LOG_UUCP
#    UUCP subsystem 
#
# Log levels:
# LOG_EMERG
#     system is unusable 
# LOG_ALERT
#     action must be taken immediately 
# LOG_CRIT
#     critical conditions 
# LOG_ERR
#     error conditions 
# LOG_WARNING
#     warning conditions 
# LOG_NOTICE
#     normal, but significant, condition 
# LOG_INFO
#     informational message 
# LOG_DEBUG
#     debug-level message 
#
#
# Author: Willi Ballenthin
# Version : 0.2
# Date : 03/05/11
#
# Changes made to the script by Kristinn, bug fix plus making it conform to the 0.6x API
#
# Copyright 2009-2010 Kristinn Gudjonsson (kristinn ( a t ) log2timeline (d o t) net)
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

package Log2t::input::syslog;

use strict;
use DateTime;		# to modify time stamp
use Log2t::base::input; # the SUPER class or parent
use Log2t::Common ':binary';
use Log2t::BinRead;
use Log2t::Time;
use File::stat;

use vars qw($VERSION @ISA);

# inherit the base input module, or the super class.
@ISA = ( "Log2t::base::input" );

# version number
$VERSION = '0.2';

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
	return "Parse the content of a Linux Syslog log file";
}

#	init
# This subroutine prepares the log file.  It opens the log file and gives the 
# script a handle to the file for further processing.
# @params One parameter is defined, the name and path of the log file to be 
#	parsed.
# @return An integer is returned to indicate whether the file preparation was 
#	successful or not.
sub init
{
	my $self = shift;

	# -> perhaps it's also good to introduce a parameter that can define the year
	# 	for instance when examining an older syslog file (and of course in the 
	# 	beginning of a new year that might be a problem) -> need to verify 
	#	reliability of this approach

	# TODO make year resolution even more robust
	# for example, the log may wrap around years
	my $fs = stat(${$self->{'name'}});
	$self->{'year'}  = (localtime($fs->mtime))[5] + 1900;

	return 1;
}

#	get_year
# Returns the year of the given log file. By default, the current year is used.
# The year should be specified along with the Linux syslog log file.
# @return An integer representing the year.
sub _get_year()
{
	my @date = localtime(time);
	my $year = $date[5];
	$year = $year + 1900;
	return $year;
}

#	get_time
# This is the main "juice" of the format file.  It takes a line from the log file
# and parses it to produce an array containing all the needed values to print a 
# body file.
#
# @param LINE a string containing a single line from the syslog file
# @return Returns a array containing the needed values to print a body file
sub get_time
{
	my $self = shift;

	# log file variables
	my @date_t; 
	my @date_m; 
	my %li;
	my %date;
	my $date_e;
	my $date_s;

	# the timestamp object
	my %t_line;
	my $text;
	my $uri;

	# get the filehandle and read the next line
	my $fh = $self->{'file'};
	my $line = <$fh> or return undef; 

	# check for an emtpy line
	if( $line =~ m/^$/ )
	{
		return \%t_line;
	}

	# substitute multiple spaces with one for splitting the string into variables
	$line =~ s/\s+/ /g;


	#
	# the log file consists of the following fields:
	#
	# Date	date	The date on which the activity occurred.	Y
	# Time	time	The time, in coordinated universal time (UTC), at which the activity occurred.	Y
	# Host host	The host on which the message was generated.
	# Facility	facility The facility argument is used to specify what type of program is logging the message. Y
	# Category category The program or subfacility that generated the message. N
	# Message message The contents of the message.

	# The default variables are therefore:
	#
	#   date
	#	time
	#	host
	#	facility
	#	message


	##################################################################################
	#
	#	Some messages we really should capture, and my Regex worksheet
	#
	#
	#
	# Jul 12 06:47:03 widgetco CRON[25163]: pam_unix(cron:session): session closed for user root
	# Jul  2 08:26:33 widgetco kernel: [   16.294065] ACPI: AC Adapter [ACAD] (on-line)
	# Jul 16 08:15:32 willi-mandiant-laptop sudo: pam_sm_authenticate: /home/willi is already mounted
	# Jul 12 06:31:54 widgetco syslogd 1.5.0#1ubuntu1: restart.
	# Jul 12 06:26:51 widgetco -- MARK --

	# Jul 19 21:11:23 willi-desktop kernel: [   18.910523] type=1505 audit(1279588283.595:5):  operation="profile_load" pid=1010 name="/usr/s..."
	# Jul 19 21:11:23 willi-desktop kernel: [   19.051022] ADDRCONF(NETDEV_UP): wlan0: link is not ready
	# Jul 19 21:11:23 willi-desktop kernel: [   19.223988] [fglrx] IRQ 29 Enabled
	# Jul 19 21:11:30 willi-desktop nautilus: [N-A] Nautilus-Actions Menu Extender 2.30.2 initializing...
	# Jul 19 21:42:31 willi-desktop rsyslogd: [origin software="rsyslogd" swVersion="4.2.0" x-pid="970" x-info="http://www.rsyslog.com"] rsyslogd w...
	# Jul 19 21:11:23 willi-desktop kernel: [    0.665174] pci 0000:01:00.0: PME# disabled


	##############################################################################
	#\w\w\w \d\d \d\d:\d\d:\d\d [^\s]+ [^:]+:
	#\w\w\w \d\d \d\d:\d\d:\d\d [^\s]+ \-\- MARK \-\-
	#
	#
	# pam_unix(cron:session): session closed for user root
	# [   16.294065] ACPI: AC Adapter [ACAD] (on-line)
	# pam_sm_authenticate: /home/willi is already mounted
	# restart.
	# [   18.910523] type=1505 audit(1279588283.595:5):  operation="profile_load" pid=1010 name="/usr/s..."
	# [   19.051022] ADDRCONF(NETDEV_UP): wlan0: link is not ready
	# [   19.223988] [fglrx] IRQ 29 Enabled
	# [N-A] Nautilus-Actions Menu Extender 2.30.2 initializing...
	# [origin software="rsyslogd" swVersion="4.2.0" x-pid="970" x-info="http://www.rsyslog.com"] rsyslogd w...
	# [    0.665174] pci 0000:01:00.0: PME# disabled



	###################################################################
	# (\[\s\d\.]+\] )?(\[^\]]+\] )?
	#
	#
	# pam_unix(cron:session): session closed for user root
	# ACPI: AC Adapter [ACAD] (on-line)
	# pam_sm_authenticate: /home/willi is already mounted
	# restart.
	# type=1505 audit(1279588283.595:5):  operation="profile_load" pid=1010 name="/usr/s..."
	# ADDRCONF(NETDEV_UP): wlan0: link is not ready
	# IRQ 29 Enabled
	# Nautilus-Actions Menu Extender 2.30.2 initializing...
	# rsyslogd w...
	# pci 0000:01:00.0: PME# disabled

	###################################################################
	#                    ':' not surrounded by spaces (e.g. IP addr. or Resource string)
	#   Possible          |
	#   Subfacility       |        Any final string
	#   |                 |        |
	#   V            wwwwwwwwwww   V
	# ((.*): )?[^:]*([^:][^:\s]:)*[^:]+$
	#
	#
	# POSSIBLE SUBFACILITY:			MESSAGE:
	# -------------------------------       ------------------------------------
	# pam_unix(cron:session): 		session closed for user root
	# ACPI: 				AC Adapter [ACAD] (on-line)
	# pam_sm_authenticate: 			/home/willi is already mounted
	# 					restart.
	# type=1505 audit(1279588283.595:5):  	operation="profile_load" pid=1010 name="/usr/s..."
	# ADDRCONF(NETDEV_UP): wlan0: 		link is not ready
	# 					IRQ 29 Enabled
	# 					Nautilus-Actions Menu Extender 2.30.2 initializing...
	# 					rsyslogd w...
	# pci 0000:01:00.0: 			PME# disabled


	########################################################################
	#
	#	This leaves...
	#
	# ^(\w+) (\d+) (\d+):(\d+):(\d+) ([^\s]+) ([^:]+): (\[([\s\d\.]+)\] )?(\[([^\]]+)\] )?((.*): )?([^:]*([^:][^:\s]:)*[^:]+)$



	if ($line =~ /^(\w+)\s+(\d+) (\d+):(\d+):(\d+) ([^\s]+) ([^:]+): (\[([\s\d\.]+)\] )?(\[([^\]]+)\] )?((.*): )?([^:]*([^:][^:\s]:)*[^:]+)$/ )
	{
		#print "\n" . $line . "\n";
		$li{'month'} = $1;
		$li{'day'} = $2;
		$li{'year'} = $self->{'year'};
		$li{'hour'} = $3;
		$li{'min'} = $4;
		$li{'sec'} = $5;
		$li{'host'} = $6;
		$li{'facility'} = $7;
		#$li{'boot-time'} = $8;
		$li{'boot-time'} = $9;

		#the following two are mutually exclusive
		if ( length($11) > length($12) ) {
			#$li{'subfacility'} = $10;
			$li{'subfacility'} = $11;
		}
		else {
			#$li{'subfacility'} = $12;
			$li{'subfacility'} = $13;
		}
		
		$li{'message'} = $14;
	}
	elsif ($line =~ /^(\w+)\s+(\d+) (\d+):(\d+):(\d+) ([^\s]+) \-\- MARK \-\-.*$/)
	{
		return;
		$li{'month'} = $1;
		$li{'day'} = $2;
		$li{'year'} = $self->{'year'};
		$li{'hour'} = $3;
		$li{'min'} = $4;
		$li{'sec'} = $5;
		$li{'host'} = $6;
		$li{'facility'} = $7;
		$li{'message'} = "Mark";
	}
	else 
	{
		#print "\n$line\n";
		print STDERR "Error, not correct structure\n";
		return \%t_line; 
	}


	# TODO
	#$li{'sec'} = Log2t::roundup( $li{'sec'} );\

	# now to make some checks
	return \%t_line unless ( $li{'day'} < 32 && $li{'day'} > 0  );
	return \%t_line unless ( $li{'hour'} < 25 && $li{'hour'} > -1  );
	return \%t_line unless ( $li{'min'} < 61 && $li{'min'} > -1  );
	return \%t_line unless ( $li{'sec'} < 61 && $li{'sec'} > -1  );

	# construct a hash of the date
	%date = (
		year	=>	$li{'year'}, 
		month	=>	Log2t::Time::month2int( $li{'month'} ),
		day	=>	$li{'day'},
		hour	=>	$li{'hour'},
		minute	=>	$li{'min'},
		time_zone => 	$self->{'tz'}, # current time zone as supplied to the tool
		second => 	$li{'sec'}
	);

	$date_s = DateTime->new( \%date );
	$date_e = $date_s->epoch;

	$text  = "[$li{'facility'}] log event on [$li{'host'}] ";
	if ( length($li{'subfacility'}) > 0 ) 
	{
		$text .= "by [$li{'subfacility'}] ";
	}

	if (length($li{'boot-time'}) > 0)
	{
		$text .= "$li{'boot-time'} secs after boot ";
	}

	$text .= ": \"$li{'message'}\"";

    # content of array t_line ([optional])
    # %t_line {
    #       time
    #       index
    #       value
    #       type
    #       legacy
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
            'time' => { 0 => { 'value' => $date_e, 'type' => 'Entry written', 'legacy' => 15 } },
            'desc' => $text,
            'short' => 'Facility: ' . $li{'facility'},
            'source' => 'LOG',
            'sourcetype' => 'Linux Syslog Log File',
            'version' => 2,
            'extra' => { 'host' => $li{'host'}, 'facility' => $li{'facility'}, 'subfacility' => $li{'subfacility'}, 'message' => $li{'message'}}
    );

	return \%t_line;
}

#	get_help
# A simple subroutine that returns a string containing the help 
# message for this particular format file.
# @return A string containing a help file for this format file
sub get_help()
{
	return "This parser parses the Linux syslog log file. To see the definition of the 
log format, please see:

http://linux.about.com/od/commands/l/blcmdl3_syslog.htm

Use with the FILE option as the Linux Syslog log file\n
\t$0 -f syslog ex...log

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
# The correct format of an Linux Syslog file can be found at:
# http://linux.about.com/od/commands/l/blcmdl3_syslog.htm
# which  is
# ip/userid/authorized-user/date/request/code/size/referer/useragent
# @return An array containing an integer and a string.  The integer indicates a success or failure and the
#	string is the error message (if the file is not correctly formed)
sub verify
{
	my $self = shift;

	# define an array to keep
	my %return;
	my $line;
	my @words;
	my $tag;
	my $c_ip = 2;
	my $temp;
	my @fields;

	# defines the maximum amount of lines that we read until we determine that we do not have a Linux syslog file
	my $max = 15;
	my $i = 0;
	
	$return{'success'} = 0;
	$return{'msg'} = 'success';

        return \%return unless -f ${$self->{'name'}};

	my $ofs = 0;
        # start by setting the endian correctly
        Log2t::BinRead::set_endian( LITTLE_E );

	# now we need to continue testing our file
	$tag = 1;
	$ofs = 0;
	# begin with finding the line that defines the fields that are contained
	while( $tag )
	{
		$tag = 0 unless $line = Log2t::BinRead::read_ascii_until( $self->{'file'}, \$ofs, "\n", 200 );
		next if ( $line =~ m/^#/ or $line =~ m/^$/ );
		$tag = 0 if $i++ eq $max;	# check if we have reached the end of our attempts
		next unless $tag;

		# HACK. There was maybe some problem with my binary read and missing the 'r]' at the end
		# of [error] on my Ubuntu 10.04, Perl v5.10.1 box, so this match is loosened slightly
		#                                                                    |
		#                
		if ($line =~ /^(\w+)\s+(\d+) (\d+):(\d+):(\d+) ([^\s]+) ([^:]+): (\[([\s\d\.]+)\] )?(\[([^\]]+)\] )?((.*): )?([^:]*([^:][^:\s]:)*[^:]+)$/  ||
			$line =~ /^(\w+)\s+(\d+) (\d+):(\d+):(\d+) ([^\s]+) \-\- MARK \-\-.*$/  )
		{

			# ok we are here... now try to match the content.... the syslog is set up int he following fashion:
			# DATE MESSAGE - whereas DATE is a textual representation of the date MONTH_ABBREVIATED DAY HOUR:MINUTE:SECOND
			# verify the date and the day
			if( Log2t::Time::month2int( $1) )
			{
				# we have a match
				#print "MONTH IS A MATCH\n";
				if( $2 > -1 && $2 < 32 )
				{
					# the day is correct
					$return{'success'} = 1;
				}
				else
				{
					$return{'msg'} = 'Incorrect day, not between 0 and 31 (' . "$2)\n";
				}
			}
			else
			{
				$return{'msg'} = "Not the correct format of an abbreviated month ($1)\n";
			}
 
			return \%return;
		}
	}

	$return{'msg'} = "None of the first $max lines fit the format of Linux syslog logs.";
	$return{'success'} = 0;

	return \%return;
}

1;
