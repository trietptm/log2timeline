#################################################################################################
#    tln
#################################################################################################
# this script reads a bodyfile in the TLN (timeline) format and produces a bodyfile as defined in
# the output plugin.
#
# This TIMELINE or TLN format was created by H. Carvey is using. The fields are:
# Time|Source|Host|User|Description|TZ|Notes
#
# Where TZ (timezone) and Notes are optional fields.
# IF any of the standard fields are emtpy they are to be populated with - while optional fields
# are empty if not used.
#
# The format was described in this blog post:
# http://windowsir.blogspot.com/2009/02/timeline-analysis-pt-iii.html
#
# And a better and more up-to-date description:
# http://windowsir.blogspot.com/2010/02/timeline-analysisdo-we-need-standard.html
#
# Author: Kristinn Gudjonsson
# Version : 0.5
# Date : 27/04/11
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
package Log2t::input::tln;

use strict;
use Log2t::base::input;    # the SUPER class or parent
use Log2t::Time;
use Log2t::BinRead;
use Log2t::Common ':binary';

use vars qw($VERSION @ISA);

# inherit the base input module, or the super class.
@ISA = ("Log2t::base::input");

# version number
$VERSION = '0.5';

#       get_description
# A simple subroutine that returns a string containing a description of
# the funcionality of the format file. This string is used when a list of
# all available format files is printed out
#
# @return A string containing a description of the format file's functionality
sub get_description() {
    return "Parse the content of a body file in the TLN format";
}

#       init
# This subroutine starts by ..
#
#
sub init {
    my $self = shift;

    # initialize variable simple
    $self->{'simple'} = 0;

    return 1;
}

#       get_version
# A simple subroutine that returns the version number of the format file
# There shouldn't be any need to change this routine, it serves its purpose
# just the way it is defined right now.
#
# @return A version number
sub get_version() {
    return $VERSION;
}

#       get_time
# This is the main "juice" of the format file.  It takes a line from the log file
# and parses it to produce an array containing all the needed values to print a
# body file.
#
# @param LINE a string containing a single line from the access file
# @return Returns a array containing the needed values to print a body file
sub get_time {
    my $self = shift;

    # timestamp object
    my %t_line;
    my ($time, $source, $host, $user, $desc, $notes, $tz);
    my $text;

    # get the filehandle and read the next line
    my $fh = $self->{'file'};
    my $line = <$fh> or return undef;

    if ($line =~ m/^#/) {

        # we have a comment
        return \%t_line;
    }

    # substitute multiple spaces with one for splitting the string into variables
    $line =~ s/\n//g;

    # let's split the line into an array
    ($time, $source, $host, $user, $desc, $tz, $notes) = split(/\|/, $line);

    # the structure of the format (the two last fields are optional)
    # Time|Source|Host|User|Description|TZ|Notes

    if ($self->{'simple'}) {
        $text = $desc;
    }
    else {
        $text = "[$source] User: $user on host: $host - $desc";
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
        'time'   => { 0 => { 'value' => $time, 'type' => 'Entry', 'legacy' => 15 } },
        'desc'   => $desc,
        'short'  => $desc,
        'source' => $source,
        'sourcetype' => $source . ' from TLN',
        'version'    => 2,
        'notes'      => 'Imported from TLN: <' . $notes . '>',
        'extra'      => { 'user' => $user, 'host' => $host, 'tz' => $tz }
              );

    return \%t_line;
}

#       get_help
# A simple subroutine that returns a string containing the help
# message for this particular format file.
# @return A string containing a help file for this format file
sub get_help() {
    return "This format file parses the content of a body file in the TLN
or timeline format, as described by H. Carvey.

The reason for this format file is to provide an easy mechanism to modify timelines
in the TLN format to any other bodyfile format supported by the tool.

The tool accepts one parameter
  -s|--simple  If this parameter is present then the DESCRIPTION field of the TLN
      will be unmodified in the output, instead of incorporating information
      found within other fields\n";
}

#       verify
# A subroutine that verifies if we are examining a prefetch directory so it can be further
# processed.  The correct format is a directory that consists of a folder that contains
# several files that end with a .pf ending.  Then one file in the folder is named Layout.ini
# @return An array containing an integer and a string.  The integer indicates a success or failure and the
#       string is the error message (if the file is not correctly formed)
sub verify {
    my $self = shift;

    # define an array to keep
    my %return;
    my $line;
    my @words;
    my $tag;

    # this variable defines how many lines will be read at a maximum until we find the correct line
    my $max = 10;
    my $i   = 0;

    # default values
    $return{'success'} = 0;
    $return{'msg'}     = 'success';

    return \%return unless -f ${ $self->{'name'} };

    # start by setting the endian correctly
    Log2t::BinRead::set_endian(LITTLE_E);

    my $ofs = 0;

    # open the file (at least try to open it)
    eval {
        unless ($self->{'quick'})
        {

            # the first line should start with an Epoch value (meaning an integer)
            seek($self->{'file'}, 0, 0);
            read($self->{'file'}, $line, 1);
            $return{'msg'} = 'Wrong magic value';

            if ($line !~ m/[0-9]/) {
                return \%return;
            }
        }

        $tag = 1;
        while ($tag) {

            # if we cannot read the line, then we do not have a TLN formatted file
            $tag = 0
              unless $line = Log2t::BinRead::read_ascii_until($self->{'file'}, \$ofs, "\n", 400);
            next unless $tag;

            # check max value
            $tag = 0 if ($i++) eq $max;
            next unless $tag;

            $tag = 0 if $line !~ m/^#/;
        }

        # split the line
        @words = split(/\|/, $line);

        # varying field numbers
        if ($#words ge 4 and $#words le 6) {

            # now we take one examle field to confirm
            if ($words[0] =~ /^\d+$/) {

                # verify epoch format, we want the date to be later than
                # Thu Jan  5 10:40:00 1989 GMT/UTC
                # but before now + 1157 days
                my $test = time;
                $test += 100000000;
                if ($words[0] >= 600000000 && $words[0] < $test) {
                    $return{'success'} = 1;
                }
                else {
                    $return{'success'} = 0;
                    $return{'msg'}     = 'Time value not correctly formed';
                }
            }
            else {
                $return{'success'} = 0;
                $return{'msg'}     = 'Not the correct format (wrong values in fields)';
            }
        }
        else {
            $return{'success'} = 0;
            $return{'msg'} = "The file is not of the correct format ($#words fields instead of 4)";
        }

        # verify that this line is of correct value
    };
    if ($@) {
        $return{'success'} = 0;
        $return{'msg'}     = "Unable to open file";
    }

    return \%return;
}

1;
