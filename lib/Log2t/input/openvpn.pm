#################################################################################################
#    OPENVPN LOG
#################################################################################################
# this script is a part of the log2timeline program.
#
# This is a format file that implements a parser for openvpn log files.  It parses the file
# and provides the main script with enough information to provide a body file that can be
# used in a timeline analysis
#
# Standard Format:
#
# Date Time Year Message
#
# Author: Kristinn Gudjonsson
# Version : 0.1
# Date : 16/11/11
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

package Log2t::input::openvpn;

use strict;
use DateTime;              # to modify time stamp
use Log2t::base::input;    # the SUPER class or parent
use Log2t::Common ':binary';
use Log2t::BinRead;
use Log2t::Time;
use File::stat;

use vars qw($VERSION @ISA);

# inherit the base input module, or the super class.
@ISA = ("Log2t::base::input");

# version number
$VERSION = '0.1';

#   get_version
# A simple subroutine that returns the version number of the format file
# @return A version number
sub get_version() {
    return $VERSION;
}

#   get_description
# A simple subroutine that returns a string containing a description of
# the funcionality of the format file. This string is used when a list of
# all available format files is printed out
# @return A string containing a description of the format file's functionality
sub get_description() {
    return "Parse the content of an openVPN log file";
}

#  init
# This subroutine prepares the log file.  It opens the log file and gives the
# script a handle to the file for further processing.
# @params One parameter is defined, the name and path of the log file to be
#  parsed.
# @return An integer is returned to indicate whether the file preparation was
#  successful or not.
#sub init
#{
#  my $self = shift;
#
#  # -> perhaps it's also good to introduce a parameter that can define the year
#  #   for instance when examining an older syslog file (and of course in the
#  #   beginning of a new year that might be a problem) -> need to verify
#  #  reliability of this approach
#
#  return 1;
#}

#  get_time
# This is the main "juice" of the format file.  It takes a line from the log file
# and parses it to produce an array containing all the needed values to print a
# body file.
#
# @param LINE a string containing a single line from the syslog file
# @return Returns a array containing the needed values to print a body file
sub get_time {
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
    if ($line =~ m/^$/) {
        return \%t_line;
    }

    # substitute multiple spaces with one for splitting the string into variables
    $line =~ s/\s+/ /g;

    # the log files consists of lines with the following format:
    # Sun May 15 21:53:19 2011 TLS-Auth MTU parms [ L:1574 D:138 EF:38 EB:0 ET:0 EL:0 ]

    if ($line =~ /^[A-Z][a-z][a-z] ([A-Z][a-z][a-z]) (\d{1,2}) (\d{1,2}:\d{2}:\d{2}) (\d{4}) (.+)$/)
    {

        #print "\n" . $line . "\n";
        my ($hh, $mm, $ss) = split(/:/, $3);
        $li{'month'}   = Log2t::Time::month2int($1);
        $li{'day'}     = $2;
        $li{'year'}    = $4;
        $li{'hour'}    = $hh;
        $li{'min'}     = $mm;
        $li{'sec'}     = $ss;
        $li{'message'} = $5;
    }
    else {

        #print "\n$line\n";
        print STDERR "[OPENVPN] Error, not correct structure\n" if $self->{'debug'};
        print STDERR "[OPENVPN] Line: $line\n" if $self->{'debug'} > 1;
        return \%t_line;
    }

    # now to make some checks
    return \%t_line unless ($li{'day'} < 32   && $li{'day'} > 0);
    return \%t_line unless ($li{'hour'} < 25  && $li{'hour'} > -1);
    return \%t_line unless ($li{'min'} < 61   && $li{'min'} > -1);
    return \%t_line unless ($li{'sec'} < 61   && $li{'sec'} > -1);
    return \%t_line unless ($li{'month'} < 13 && $li{'sec'} > 0);

    # construct a hash of the date
    %date = (
             year      => $li{'year'},
             month     => $li{'month'},
             day       => $li{'day'},
             hour      => $li{'hour'},
             minute    => $li{'min'},
             time_zone => $self->{'tz'},    # current time zone as supplied to the tool
             second    => $li{'sec'}
            );

    $date_s = DateTime->new(\%date);
    $date_e = $date_s->epoch;

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
        'desc'       => $li{'message'},
        'short'      => substr($li{'message'}, 0, 15),
        'source'     => 'LOG',
        'sourcetype' => 'OpenVPN',
        'version'    => 2,
        'extra'      => {},
              );

    return \%t_line;
}

#  get_help
# A simple subroutine that returns a string containing the help
# message for this particular format file.
# @return A string containing a help file for this format file
sub get_help() {
    return "This parser parses the openVPN log file. The format of the file is the
following:

DATE TIME YEAR MESSAGE

Where
  DATE is WeekDay M D 
  TIME is HH:MM:SS 
  YEAR is YYYY
\n";

}

#  verify
# A subroutine that reads a single line from the log file and verifies that it is of the
# correct format so it can be further processed.
#
# Ab example log file is:
# Fri May 13 11:29:01 2011 My message comes here
#
# @return An array containing an integer and a string.  The integer indicates a success or failure and the
#  string is the error message (if the file is not correctly formed)
sub verify {
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
    my $i   = 0;

    $return{'success'} = 0;
    $return{'msg'}     = 'success';

    return \%return unless -f ${ $self->{'name'} };

    my $ofs = 0;

    # start by setting the endian correctly
    Log2t::BinRead::set_endian(LITTLE_E);

    # now we need to continue testing our file
    $tag = 1;
    $ofs = 0;

    # begin with finding the line that defines the fields that are contained
    while ($tag) {
        $tag = 0 unless $line = Log2t::BinRead::read_ascii_until($self->{'file'}, \$ofs, "\n", 200);
        next if ($line =~ m/^#/ or $line =~ m/^$/);
        $tag = 0 if $i++ eq $max;    # check if we have reached the end of our attempts
        next unless $tag;

        #
        if ($line =~ /^[A-Z][a-z][a-z] ([A-Z][a-z][a-z]) (\d{1,2}) (\d{1,2}:\d{2}:\d{2} \d{4}) /) {

            # now just to verify the actual date, to see if it is correctly formed
            if (Log2t::Time::month2int($1)) {

                # we have a match
                if ($2 > -1 && $2 < 32) {

                    # the day is correct
                    $return{'success'} = 1;
                }
                else {
                    $return{'msg'} = 'Incorrect day, not between 0 and 31 (' . "$2)\n";
                }
            }
            else {
                $return{'msg'} = "Not the correct format of an abbreviated month ($1)\n";
            }

            return \%return;
        }
    }

    $return{'msg'}     = "None of the first $max lines fit the format of OpenVPN logs.";
    $return{'success'} = 0;

    return \%return;
}

1;
