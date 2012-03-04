#################################################################################################
#		MACTIME_L
#################################################################################################
# this package provides an output module for the tool log2timeline.
# The package takes as an input a hash that contains all the needed information to print or output
# the timeline that has been produced by a format file. The output format is structured according
# to the mactime format from the TSK (The SleuthKit) for legacy versions, that is version 1.X and
# 2.X, for version 3.0+ use mactime
#
# The specification of the body file can be found here:
#       http://wiki.sleuthkit.org/index.php?title=Body_file
#
# Author: Kristinn Gudjonsson
# Version : 0.7
# Date : 13/04/11
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

package Log2t::output::mactime_l;

use strict;
use Getopt::Long;    # read parameters

my $version = "0.7";

#       get_version
# A simple subroutine that returns the version number of the format file
#
# @return A version number
sub get_version() {
    return $version;
}

#       new
# A simple constructor of the output module. Takes care of parsing
# parameters sent to the output module
sub new($) {
    my $class = shift;

    # bless the class ;)
    my $self = bless {}, $class;

    return $self;

}

#       get_description
# A simple subroutine that returns a string containing a description of
# the funcionality of the format file. This string is used when a list of
# all available format files is printed out
#
# @return A string containing a description of the format file's functionality
sub get_description() {
    return "Output timeline using legacy version of the mactime format (version 1.x and 2.x)";
}

sub print_header() {
    return 1;
}

sub get_footer() {
    return 0;    # no footer
}

sub print_footer() {
    return 1;
}

#      	print_line
# A subroutine that reads a line from the access file and returns it to the
# main script
# @return A string containing one line of the log file (or a -1 if we've reached
#       the end of the log file)
sub print_line() {

    # content of the timestamp object t_line
    # optional fields are marked with []
    #
    # %t_line {
    #       time
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

    my $class  = shift;
    my $t_line = shift;
    my $text;
    my ($atime, $mtime, $ctime, $crtime);
    my $temp;
    my ($md5, $inode, $mode, $uid, $gid, $size, $type);

    if (ref($t_line) eq 'HASH') {

        # default values
        $mtime  = 0;
        $atime  = 0;
        $ctime  = 0;
        $crtime = 0;

        # go through each defined time to find the mactime (and type)
        foreach (keys %{ $t_line->{'time'} }) {
            $mtime = $t_line->{'time'}->{$_}->{'value'}
              if $t_line->{'time'}->{$_}->{'legacy'} & 0b0001;
            $atime = $t_line->{'time'}->{$_}->{'value'}
              if $t_line->{'time'}->{$_}->{'legacy'} & 0b0010;
            $ctime = $t_line->{'time'}->{$_}->{'value'}
              if $t_line->{'time'}->{$_}->{'legacy'} & 0b0100;
            $crtime = $t_line->{'time'}->{$_}->{'value'}
              if $t_line->{'time'}->{$_}->{'legacy'} & 0b1000;

            # construct the type field
            $temp = $t_line->{'time'}->{$_}->{'type'};
            $type .= '/' . $temp if ($type !~ m/$temp/);
        }

        # remove the first occurance of a '/'
        $type = substr $type, 1;

# now to construct the text field (or description), populating it with the missing fields needed to clarify the timeline field
        $text = '[' . $t_line->{'sourcetype'} . '] ';
        $text .= '(' . $type . ') ';
        $text .= 'User: ' . $t_line->{'extra'}->{'user'} . ' '
          if (defined $t_line->{'extra'}->{'user'} && $t_line->{'extra'}->{'user'} ne 'unknown');
        $text .= $t_line->{'desc'};

        # fix a possible pipe symbol inside the name variable
        $text =~
          s/\|/\&#33;/g;    # we don't want to introduce another | symbol where it does not belong
                            #$text =~ s/,/\&#44;/g; # this is for CSV exports of mactime

        # and to define the needed additional fields within the standard
        $md5   = defined $t_line->{'extra'}->{'md5'}   ? $t_line->{'extra'}->{'md5'}   : 0;
        $inode = defined $t_line->{'extra'}->{'inode'} ? $t_line->{'extra'}->{'inode'} : 0;
        $mode  = defined $t_line->{'extra'}->{'mode'}  ? $t_line->{'extra'}->{'mode'}  : 0;
        $uid   = defined $t_line->{'extra'}->{'uid'}   ? $t_line->{'extra'}->{'uid'}   : 0;
        $uid = 0 if $uid eq 'unknown';
        $gid  = defined $t_line->{'extra'}->{'gid'}  ? $t_line->{'extra'}->{'gid'}  : 0;
        $size = defined $t_line->{'extra'}->{'size'} ? $t_line->{'extra'}->{'size'} : 0;

# the format is the following:
#  MD5 | path/name | device | inode | mode_as_value | mode_as_string | num_of_links | UID | GID | rdev | size | atime | mtime | ctime | block_size | num_of_blocks

        # fix a possible pipe symbol inside the name variable
        $text =~ s/\|/-/g;

        # print the timeline in a legacy format
        ::print_line(  $md5 . "|" 
                     . $text . "|0|" 
                     . $inode . "|" 
                     . $mode . "|" 
                     . $mode . "|0|" 
                     . $uid . "|"
                     . $gid . "|0|"
                     . $size . "|"
                     . $atime . "|"
                     . $mtime . "|"
                     . $ctime
                     . "|0|0\n");
    }
    else {
        print STDERR "Error, t_line not scalar\n";
        return 0;
    }
    return 1;

}

#       get_help
# A simple subroutine that returns a string containing the help
# message for this particular format file.
# @return A string containing a help file for this format file
sub get_help() {
    return "This output plugin provides a method to print a body file that can be
imported into the mactime tool (part of TSK).  This provides a method to incorporate timelines
found inside log files or artifacts on system into the more traditional file system timeline (as provided
with tools like fls and ils from the TSK).  The specification of the body file can be found here:
       http://wiki.sleuthkit.org/index.php?title=Body_file
This is the legacy version of the timeline, that is this output is the one used in version 1.X and 2.X of
the mactime tool (for newer versions, please use the output mactime)";

}

1;
