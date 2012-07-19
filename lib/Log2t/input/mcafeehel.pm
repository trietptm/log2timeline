#################################################################################################
#    MCAFEE HIPS EVENT LOG
#################################################################################################
# This script is a part of the log2timeline framework for timeline creation and analysis.
# This script implements an input module, or a parser capable of parsing a single log file (or
# directory) and creating a hash that is returned to the main script.  That hash is then used
# to create a body file (to create a timeline) or a timeline (directly).
#
# Author: anonymous donator
# Version : 0.1
# Date : 7/8/2011
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

# NOTE: There doesn't seem to be any standard layout of data for the McAfee HIPS event.log file.
# Only the event type is the same in every file.
# It's not stored in the file and even McAfee recommends not reading this file directly but
# to use the agent to export it (since then the layout can be determined from somewhere) into a readable format.
#
# AFAIK, there is no parser available other than this.
#
# What this means, is that while this parser will try its best to parse everything it can from an event.log file,
# it was built using templates generated from numerous logs and will probably not get everything all of the time (so update it!).
#
#
# Events 6 (Intrusion), 7 (Traffic), 8 (Process), and 10 (Entercept) are the only custom templates implemented.
# Other events will either get logged by the standard template or the default template.

package Log2t::input::mcafeehel;

use strict;
use Log2t::base::input;    # the SUPER class or parent
use Log2t::Common ':binary';
use Log2t::Time;           # to manipulate time

#use Log2t::Win;  # Windows specific information
#use Log2t::Numbers;  # to manipulate numbers
use Log2t::BinRead;    # methods to read binary files (it is preferable to always load this library)

#use Log2t::Network;  # information about network traffic

# define the VERSION variable
use vars qw($VERSION @ISA);

# inherit the base input module, or the super class.
@ISA = ("Log2t::base::input");

# indicate the version number of this input module
$VERSION = '0.1';

my %REACTION_LEVEL = (
    '0' => 'Invalid',
    '1' => 'None',
    '2' => 'Log',
    '3' => 'Deny',
    '4' => 'Kill',
    '5' => 'Kill Terminal',
    '6' => 'Kill User',
    '9' => 'Prevent by kill',
    '10' => 'Create exception'
);

my %SEVERITY_LEVEL = (
    '0' => 'Disabled',
    '1' => 'Info',
    '2' => 'Low',
    '3' => 'Medium',
    '4' => 'High'
);

my %EVENT_LEVEL = (
    '1' => 'Debug',
    '2' => 'PGPError',
    '3' => 'System',
    '4' => 'Service',
    '5' => 'IPSec',
    '6' => 'Intrusion',
    '7' => 'Traffic',
    '8' => 'Process',
    '10' => 'Entercept'
);


# ------------------------------------------------------------------------------------------------
#       Event.log (one line per event)
# ------------------------------------------------------------------------------------------------
# EVENT TYPE  EVENT TIME (epoch UTC)  IP ADDRESS  DATA FILE  (EVENT TYPE DEPENDENT FIELDS)
#
# EVENT TYPE DEFENDENT FIELDS (not always the case)
# 6 - INTRUSION
#  TYPE  SEVERITY  REACTION  PATH  EVENT TIME  DESCRIPTION  IP PROTOCOL  LOCAL IP  LOCAL PORT  REMOTE IP  REMOTE PORT  INBOUND  PROCESS ID
#
# 7 - TRAFFIC
#   RULE ID  IP PROTOCOL  LOCAL IP  LOCAL PORT  REMOTE IP  REMOTE PORT  INBOUND  PERMIT  PROCESS ID  PATH  QUARANTINE
#
# 8 - PROCESS
#  (PROCESS ID)  PATH  HASH  PERMIT  TYPE
#
# 10 - ENTERCEPT
#  CLASS  DIRECTIVES  SEVERITY  SIGNATURE ID  REACTION  WARNING  EXCEPTIONS  EVENT TIME  EVENT CLASS  USER NAME  USER GROUP  PATH
#
# each line is a new event
#
# In addition, each event can also use a standard format (Starts from field 1)
#
# EVENT TYPE  EVENT TIME (epoch UTC)  IP ADDRESS  ?DATA FILE?  EXEC_LOCATION  ?PERMIT?  ?TYPE?
#
# or could use a different format

# the constructor...
sub new() {
    my $class = shift;

    # bless the class ;)
    my $self = $class->SUPER::new();

    # indicate that we would like to parse each line separately
    $self->{'multi_line'} = 1;

    bless($self, $class);

    return $self;
}

#       get_version
# A simple subroutine that returns the version number of the format file
#
# @return A version number
sub get_version() {
    return $VERSION;
}

#       get_description
# A simple subroutine that returns a string containing a description of
# the funcionality of the format file. This string is used when a list of
# all available format files is printed out
#
# @return A string containing a description of the format file's functionality
sub get_description() {
    return "Parse the content of a McAfee HIPS event.log file";
}

# return a readable string for a given integer reaction
sub ReturnReaction {
    my $reactionLevel = shift;

    return $REACTION_LEVEL{$reactionLevel} if exists $REACTION_LEVEL{$reactionLevel};
    return "Unknown [Level $reactionLevel]";
}

# return a readable string for a given integer severity
sub ReturnSeverity {
    my $severityLevel = shift;

    return $SEVERITY_LEVEL{$severityLevel} if exists $SEVERITY_LEVEL{$severityLevel};
    return "Unknown [Level $severityLevel]";
}

# return a readable string for a given integer event
sub ReturnEvent {
    my $eventLevel = shift;

    return $EVENT_LEVEL{$eventLevel} if exists $EVENT_LEVEL{$eventLevel};
    return "Unknown [Level $eventLevel]";
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
sub init {

    # read the paramaters passed to the script
    my $self = shift;

    # initialize variables
    $self->{'old_date'}    = undef;
    $self->{'line_loaded'} = 0;
    $self->{'eof'}         = 0;
    $self->{'first_line'}  = 1;

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

sub get_time {
    my $self = shift;

    # log file variables
    my $eventtype;
    my $eventtime;
    my $ipaddress;
    my $content;
    my $text;
    my $datafile;

    # timestamp object
    my %t_line;

    # get the filehandle and read the next line
    my $fh = $self->{'file'};
    my $line = <$fh>;
    if (not $line) {
        print STDERR "[MCAFEEHEL] Unable to read in line.\n";
        return \%t_line;
    }

    #remove any newlines
    $line =~ s/\r|\n//g;

    # split the string into variables

#( $timestamp, $elapsed, $ip, $action, $size, $method, $uri, $ident, $from, $content ) = split( / /, $line );
# first four (really five) fields are similar most layout types
    ($eventtype, $eventtime, $ipaddress, $datafile, $content) = split(/\t/, $line, 5);

    # try to fix any inconsistencies in the current event log line
    # check $ipaddress and make sure it really is an ip address
    if ($ipaddress !~ /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/) {

        # it might have gotten shifted over to $datafile, check that and fix everything (hopefully)
        if ($datafile =~ /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/) {

            # it did get shifted over, attempt to figure out what shifted it
            if ($eventtime =~ /\d{1,2}\/\d{1,2}\/\d{4} \d{1,2}:\d{2}/ && $ipaddress =~ /\d+/) {

                # appears to be shifted by inserting the m/d/y H:M before the EPOCH time
                # attempt to fix $eventtime, $ipaddress, $datafile, and $content
                if ($ipaddress =~ /\d+/) {
                    $eventtime = $ipaddress;
                }

                $ipaddress = $datafile;
                ($datafile, $content) = split(/\t/, $content, 2);
            }
            elsif ($eventtype !~ /[0-9]|10/ && $eventtime =~ /[0-9]|10/) {

                # appears to be shifted by inserting something before the event type
                # attempt to fix everything
                $eventtype = $eventtime;
                $eventtime = $ipaddress;
                $ipaddress = $datafile;
                ($datafile, $content) = split(/\t/, $content, 2);
            }
        }
    }

    # event time is not necessarily in EPOCH time, so check the format and convert if needed
    if ($eventtime =~ /\d{1,2}\/\d{1,2}\/\d{4} \d{1,2}:\d{2}/) {

        # date/time format = m/d/Y H:M (e.g. 2/5/2011 14:32)
        # convert to epoch time
        my $parser = DateTime::Format::Strptime->new(pattern => '%m/%d/%Y %H:%M');
        my $dt = $parser->parse_datetime($eventtime);
        $eventtime = $dt->epoch();
    }

#  Common format
#       EVENT TYPE  EVENT TIME (epoch UTC)  IP ADDRESS  ?DATA FILE?  EXEC_LOCATION  ?PERMIT?  ?TYPE?
#  ^\[[^\s]+ (\w\w\w) (\d\d) (\d\d):(\d\d):(\d\d) (\d\d\d\d)\] \[([^\]]+)\] (\[([^\]]+)\])? (.*)$
# complete = /^([0-9]|10)\t(\d+)\t(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\t(.*?)\t(-?\d+)\t(.*?)\t(.*?)\t(\d+)\t(\d+)\s*$/
# partial = /(-?\d+)\t(.*?)\t(.*?)\t(\d+)\t(\d+)\s*$/

    #print STDERR "line is ||" . $line . "||\n";

    # only need the partial regex, the previous part was verified previously
    if ($content =~ /^(-?\d+)\t(.*?)\t(.*?)\t(\d+)\t(\d+)\s*$/) {
        $text .=
            ReturnEvent($eventtype)
          . ' event | Event '
          . (($4 != 0) ? 'permitted' : 'blocked')
          . ' | Path: '
          . $2;

        # create the t_line variable
        %t_line = (
            'time' => { 0 => { 'value' => $eventtime, 'type' => 'Entry written', 'legacy' => 15 } },
            'desc' => $text,

            #'extra' => { 'user' => $ip, 'host' => $ip, 'src-ip' => $ip, 'size' => $size }
                  );

        #return \%t_line;
    }

    #  Event Dependent
    else {
        if ($eventtype == 6) {

# Intrusion Event
# 6  1292700167  141.7.51.171    3700  4  3    12/18/2010 13:22    6  161.7.61.15  22528  116.7.111.151  17151  1  0
# complete = /^([0-9]|10)\t(\d+)\t(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\t(.*?)\t(-?\d+)\t(\d+)\t(\d+)\t(\d+)\t(.*?)\t(.*?)\t(.*?)\t(\d+)\t(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\t(\d+)\t(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\t(\d+)\t(\d+)\t(\d+)\s*$/
# partial = /(-?\d+)\t(\d+)\t(\d+)\t(\d+)\t(.*?)\t(.*?)\t(.*?)\t(\d+)\t(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\t(\d+)\t(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\t(\d+)\t(\d+)\t(\d+)\s*$/
            if ($content =~
                /^(-?\d+)\t(\d+)\t(\d+)\t(\.*?)\t(.*?)\t(.*?)\t(\d+)\t(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\t(\d+)\t(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\t(\d+)\t(\d+)\t(\d+)\s*$/
               )
            {
                $text .=
                    'Intrusion event | Severity: '
                  . ReturnSeverity($2)
                  . ' | Reaction: '
                  . ReturnReaction($3)
                  . ' | Local IP: '
                  . $8
                  . ' | Local Port: '
                  . $9
                  . ' | Remote IP: '
                  . $10
                  . ' | Remote Port: '
                  . $11;

                # create the t_line variable
                %t_line = (
                    'time' =>
                      { 0 => { 'value' => $eventtime, 'type' => 'Entry written', 'legacy' => 15 } },
                    'desc' => $text,

                    #'extra' => { 'user' => $ip, 'host' => $ip, 'src-ip' => $ip, 'size' => $size }
                          );
            }
            else {    # create the t_line variable
                %t_line = (
                    'time' =>
                      { 0 => { 'value' => $eventtime, 'type' => 'Entry written', 'legacy' => 15 } },
                    'desc' => ReturnEvent($eventtype) . ' event | Unknown format: ' . $1,

                    #'extra' => { 'user' => $ip, 'host' => $ip, 'src-ip' => $ip, 'size' => $size }
                          );
            }
        }
        elsif ($eventtype == 7) {

# Traffic Event
# 7  1280596789  10.1.20.63    -1  17  10.1.20.64  35072  10.1.20.63  26638  1  0  4  C:\WINDOWS\SYSTEM32\NTOSKRNL.EXE  0
# complete = /^([0-9]|10)\t(\d+)\t(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\t(.*?)\t(-?\d+)\t(\d+)\t(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\t(\d+)\t(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\t(\d+)\t(\d+)\t(\d+)\t(\d+)\t(.*?)\t(\d+)\s*$/
# partial = /(-?\d+)\t(\d+)\t(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\t(\d+)\t(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\t(\d+)\t(\d+)\t(\d+)\t(\d+)\t(.*?)\t(\d+)$/
            if ($content =~
                /^(-?\d+)\t(\d+)\t(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\t(\d+)\t(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\t(\d+)\t(\d+)\t(\d+)\t(\d+)\t(.*?)\t(\d+)\s*$/
               )
            {
                $text .=
                    'Traffic event | Event '
                  . (($8 != 0) ? 'permitted' : 'blocked')
                  . ' | Path: '
                  . $10
                  . ' | Local IP: '
                  . $3
                  . ' | Local Port: '
                  . $4
                  . ' | Remote IP: '
                  . $5
                  . ' Remote Port: '
                  . $6;

                # create the t_line variable
                %t_line = (
                    'time' =>
                      { 0 => { 'value' => $eventtime, 'type' => 'Entry written', 'legacy' => 15 } },
                    'desc' => $text,

                    #'extra' => { 'user' => $ip, 'host' => $ip, 'src-ip' => $ip, 'size' => $size }
                          );
            }

            #7  1295556922  140.111.41.154    87  6  190.112.242.39  48385  160.137.3.154  28534
            elsif ($content =~
                /^(-?\d+)\t(\d+)\t(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\t(\d+)\t(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\t(\d+)\s*$/
              )
            {
                $text .=
                    'Traffic event | Event '
                  . (($8 != 0) ? 'permitted' : 'blocked')
                  . ' | Local IP: '
                  . $3
                  . ' | Local Port: '
                  . $4
                  . ' | Remote IP: '
                  . $5
                  . ' Remote Port: '
                  . $6;

                # create the t_line variable
                %t_line = (
                    'time' =>
                      { 0 => { 'value' => $eventtime, 'type' => 'Entry written', 'legacy' => 15 } },
                    'desc' => $text,

                    #'extra' => { 'user' => $ip, 'host' => $ip, 'src-ip' => $ip, 'size' => $size }
                          );
            }

            #something else
            else {    # create the t_line variable
                %t_line = (
                    'time' =>
                      { 0 => { 'value' => $eventtime, 'type' => 'Entry written', 'legacy' => 15 } },
                    'desc' => ReturnEvent($eventtype) . ' event | Unknown format: ' . $1,

                    #'extra' => { 'user' => $ip, 'host' => $ip, 'src-ip' => $ip, 'size' => $size }
                          );
            }
        }
        elsif ($eventtype == 8) {

# Process Event
# 8  1300881943  0.0.0.0    0  0  2  344  3  0  1  3/23/2011 8:02  Registry  NT Authority\Local System    D:\Documents and Settings\John.Doe\Application Data\McAfee\McAfee DLP Agent\install\vcredist_KeyView_x86.exe
# complete = /^([0-9]|10)\t(\d+)\t(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\t(.*?)\t(-?\d+)\t(\d+)\t(\d+)\t(\d+)\t(\d+)\t(\d+)\t(\d+)\t(.*?)\t(.*?)\t(.*?)\t(.*?)\t(.*?)\s*$/
# partial = /(-?\d+)\t(\d+)\t(\d+)\t(\d+)\t(\d+)\t(\d+)\t(\d+)\t(.*?)\t(.*?)\t(.*?)\t(.*?)\t(.*?)\s*$/
            if ($content =~
                /^(-?\d+)\t(\d+)\t(\d+)\t(\d+)\t(\d+)\t(\d+)\t(\d+)\t(.*?)\t(.*?)\t(.*?)\t(.*?)\t(.*?)\s*$/
               )
            {
                $text .=
                    'Process event | Event '
                  . (($4 != 0) ? 'permitted' : 'blocked')
                  . ' | Path: '
                  . $12;

                # create the t_line variable
                %t_line = (
                    'time' =>
                      { 0 => { 'value' => $eventtime, 'type' => 'Entry written', 'legacy' => 15 } },
                    'desc'  => $text,
                    'extra' => { 'user' => $10 },

                    #'extra' => { 'user' => $ip, 'host' => $ip, 'src-ip' => $ip, 'size' => $size }
                          );
            }
            else {    # create the t_line variable
                %t_line = (
                    'time' =>
                      { 0 => { 'value' => $eventtime, 'type' => 'Entry written', 'legacy' => 15 } },
                    'desc' => ReturnEvent($eventtype) . ' event | Unknown format: ' . $1,

                    #'extra' => { 'user' => $ip, 'host' => $ip, 'src-ip' => $ip, 'size' => $size }
                          );
            }
        }
        elsif ($eventtype == 10) {

# Entercept Event
# 10  1268108843  0.0.0.0    0  0  2  1148  2  0  1  3/8/2010 22:27  Files  NT Authority\Local System    C:\WINDOWS\System32\svchost.exe
# complete = /^([0-9]|10)\t(\d+)\t(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\t(.*?)\t(-?\d+)\t(\d+)\t(\d+)\t(\d+)\t(\d+)\t(\d+)\t(\d+)\t(.*?)\t(.*?)\t(.*?)\t(.*?)\t(.*?)\s*$/)
# partial = /(-?\d+)\t(\d+)\t(\d+)\t(\d+)\t(\d+)\t(\d+)\t(\d+)\t(.*?)\t(.*?)\t(.*?)\t(.*?)\t(.*?)\s*$/)
            if ($content =~
                /^(-?\d+)\t(\d+)\t(\d+)\t(\d+)\t(\d+)\t(\d+)\t(\d+)\t(.*?)\t(.*?)\t(.*?)\t(.*?)\t(.*?)\s*$/
               )
            {
                $text .=
                  'Entercept event | Severity: ' . $3 . ' | Reaction: ' . ReturnReaction($5) . '.';

                # create the t_line variable
                %t_line = (
                    'time' =>
                      { 0 => { 'value' => $eventtime, 'type' => 'Entry written', 'legacy' => 15 } },
                    'desc'  => $text,
                    'extra' => { 'user' => $10 },

                    #'extra' => { 'user' => $ip, 'host' => $ip, 'src-ip' => $ip, 'size' => $size }
                          );
            }
            else {    # create the t_line variable
                %t_line = (
                    'time' =>
                      { 0 => { 'value' => $eventtime, 'type' => 'Entry written', 'legacy' => 15 } },
                    'desc' => ReturnEvent($eventtype) . ' event | Unknown format: ' . $1,

                    #'extra' => { 'user' => $ip, 'host' => $ip, 'src-ip' => $ip, 'size' => $size }
                          );
            }
        }
        else {

# if we get here, it means that none of the regular expressions fit this line.
# this is likely because the event type is one that we don't care about (and that doesn't follow the common template)
# e.g. even types 3 and 4 sometimes use the format:
# 3  1300507451  0.0.0.0    6  974  pgpNetKernelWorker.cpp
# 4  1300507451  0.0.0.0    9  AAAAA...  0.0.0.0  982  pgpNetKernelWorker.cpp

            #print STDERR "Line ||" . $line . "|| did not pass a regex!\n";
            #write it anyway
            %t_line = (
                'time' =>
                  { 0 => { 'value' => $eventtime, 'type' => 'Entry written', 'legacy' => 15 } },
                'desc' => ReturnEvent($eventtype) . ' event | Unknown format: ' . chomp($1),

                #'extra' => { 'user' => $ip, 'host' => $ip, 'src-ip' => $ip, 'size' => $size }
                      );
        }
    }

    $t_line{'short'}      = ReturnEvent($eventtype) . ' event';
    $t_line{'source'}     = 'HIPS Event Log';
    $t_line{'sourcetype'} = 'HIPS';
    $t_line{'version'}    = 2;

    # print STDERR "Found timestamp! (" . $eventtime . ")\n";

    # fix the timestamp variable
    #@date = split( /\./, $timestamp );

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
   #%t_line = (
   #        'time' => { 0 => { 'value' => $eventtime, 'type' => 'Entry written', 'legacy' => 15 } },
   #        'desc' => $text,
   #        'short' => 'Event type ' . $eventtype . 'triggered',
   #        'source' => 'LOG',
   #        'sourcetype' => 'McAfee HIPS event log',
   #        'version' => 2,
   #        #'extra' => { 'user' => $ip, 'host' => $ip, 'src-ip' => $ip, 'size' => $size }
   #);

    return \%t_line;
}

#       get_help
#
# A simple subroutine that returns a string containing the help
# message for this particular format file.
#
# @return A string containing a help file for this format file
sub get_help() {
    return "Usage: $0 -f mcafee_hel event.log

This plugin parses the content of event.log, the McAfee HIPS
event log.  This file is typically in ...";

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
#  file/dir/artifact is supporter by this input module as well as a reason why
#  it failed (if it failed)

# Read a line from the file and ensure that the layout is at least correct.
#   Currently, it checks the line for:
#  starts with a 1-10
#  third field is an ip address
sub verify {

    # define an array to keep
    my %return;
    my $line;
    my @words;

    my $self = shift;

    # default values
    $return{'success'} = 0;
    $return{'msg'}     = 'success';

    # depending on which type you are examining, directory or a file
    return \%return unless -f ${ $self->{'name'} };

    my $ofs = 0;

    # start by setting the endian correctly
    Log2t::BinRead::set_endian(LITTLE_E);

    # open the file (at least try to open it)
    eval {
        unless ($self->{'quick'})
        {

            # a line should start with a number, let's verify
            seek($self->{'file'}, 0, 0);
            read($self->{'file'}, $line, 2);

            if ($line !~ m/[1-9]|10/) {
                $return{'msg'}     = 'Wrong magic value. line was ' . $line;
                $return{'success'} = 0;
                return \%return;
            }
        }
        $line = Log2t::BinRead::read_ascii_until($self->{'file'}, \$ofs, "\n", 500);
    };
    if ($@) {
        $return{'success'} = 0;
        $return{'msg'}     = "Unable to open file ($@)";
    }

    # now we have one line of the file, let's read it and verify
    # remove unneeded spaces
    #$line =~ s/\s+/ /g;
    @words = split(/\t/, $line);

# word count should more than 8 and less than 18 (is this consistent with the other event types and not just 6,7,8,10?)
    if ($#words > 7 && $#words < 18) {

        # verify that the event type is the first field and of the correct format

        if ($words[0] =~ m/^([0-9]|10)$/) {

            # verify the IP address
            if ($words[2] =~ m/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/) {

                #print "CORRECT\n";
                # the IP address is correctly formed, let's assume other fields are too
                $return{'success'} = 1;
            }
            elsif ($words[3] =~ m/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/) {

                # sometimes the ip address gets shifted over
                $return{'success'} = 1;
            }
            else {
                $return{'msg'}     = 'IP address field [' . $words[2] . '] not correctly formatted';
                $return{'success'} = 0;
            }
        }
        else {
            $return{'msg'}     = 'Event type invalid!';
            $return{'success'} = 0;
        }
    }
    else {

        #print "FAILURE! there are $#words\n";
        $return{'msg'} =
          'There should be at least 9 words per line, instead there are ' . "$#words\n";
        $return{'success'} = 0;
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
    md5,    # MD5 sum of the file
    name,    # the main text that appears in the timeline
    title,    # short description used by some output modules
    source,    # the source of the timeline, usually the same name or similar to the name of the package
    user,    # the username that owns the file or produced the artifact
    host,    # the hostname that the file belongs to
    inode,    # the inode number of the file that contains the artifact
    mode,    # the access rights of the file
    uid,    # the UID of the user that owns the file/artifact
    gid,    # the GID of the user that owns the file/artifact
    size,    # the size of the file/artifact
    atime,    # Time in epoch representing the last ACCESS time
    mtime,    # Time in epoch representing the last MODIFICATION time
    ctime,    # Time in epoch representing the CREATION time (or MFT/INODE modification time)
    crtime    # Time in epoch representing the CREATION time
  }

The subroutine return a reference to the hash (t_line) that will be used by the main script (B<log2timeline>) to produce the actual timeline.  The hash is processed by the main script before forwarding it to an output module for the actual printing of a bodyfile.

=item get_help()

A simple subroutine that returns a string containing the help message for this particular input module. This also contains a longer description of the input module describing each parameter that can be passed to the subroutine.  It sometimes contains a list of all dependencies and possibly some instruction on how to install them on the system to make it easier to implement the input module.

=item verify( $log_file )

This subroutine takes as an argument the file name to be parsed (file/dir/artifact) and verifies it's structure to determine if it is really of the correct format.

This is needed since there is no need to try to parse the file/directory/artifact if the input module is unable to parse it (if it is not designed to parse it)

It is also important to validate the file since the scanner function will try to parse every file it finds, and uses this verify function to determine whether or not a particular file/dir/artifact is supported or not. It is therefore very important to implement this function and make it verify the file structure without false positives and without taking too long time

This subroutine returns a reference to a hash that contains two values
  success    An integer indicating whether not the input module is able to parse the file/directory/artifact
  msg    A message indicating the reason why the input module was not able to parse the file/directory/artifact

=back

=head1 AUTHOR

Kristinn Gudjonsson <kristinn (a t) log2timeline ( d o t ) net> is the original author of the program.

=head1 COPYRIGHT

The tool is released under GPL so anyone can contribute to the tool. Copyright 2009.

=head1 SEE ALSO

L<log2timeline>

=cut

