#################################################################################################
#		MACTIME
#################################################################################################
# this package provides an output module for the tool log2timeline.
# The package takes as an input a hash that contains all the needed information to print or output
# the timeline that has been produced by a format file.  The output format is structured according
# to the mactime format from the TSK (The SleuthKit) for version 3.X+
#
# The specification of the body file can be found here:
#       http://wiki.sleuthkit.org/index.php?title=Body_file
#
# Author: Kristinn Gudjonsson
# Version : 0.7
# Date : 13/05/11
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

package Log2t::output::mactime;

use strict;
use Getopt::Long;     # read parameters
use Log2t::Common;    # for path manipulation

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
    return "Output timeline using mactime format";
}

sub print_header() {
    return 1;
}

sub print_footer() {
    return 1;
}

sub get_footer() {
    return 0;    # no footer
}

sub _process_line {
    my $self   = shift;
    my $t_line = shift;
    my $text;
    my ($md5, $inode, $mode, $uid, $gid, $size);
    my $mactime;

    # remove the first occurance of a '/'
    $self->{'type'} = substr $self->{'type'}, 1;

# now to construct the text field (or description), populating it with the missing fields needed to clarify the timeline field
    $text =
      $t_line->{'source'} eq 'FILE'
      ? '[' . $self->{'mactime'} . '] '
      : '[' . $t_line->{'sourcetype'} . '] ';
    $text .= '(' . $self->{'type'} . ') ' unless $self->{'type'} eq '';
    $text .= '<' . $t_line->{'extra'}->{'host'} . '> '
      if (defined $t_line->{'extra'}->{'host'} and $t_line->{'extra'}->{'host'} ne 'unknown');
    $text .= 'User: ' . $t_line->{'extra'}->{'user'} . ' '
      if (defined $t_line->{'extra'}->{'user'} && $t_line->{'extra'}->{'user'} ne 'unknown');
    $text .= $t_line->{'desc'};

    # include the file name
    $text .= ' (file: ';
    $text .= $t_line->{'extra'}->{'path'} if defined $t_line->{'extra'}->{'path'};

    # check if we have the original directory definition
    if (defined $t_line->{'extra'}->{'parse_dir'}) {

        # we need to remove the "path" from the file before proceeding

        # get the file name
        my $fname = $t_line->{'extra'}->{'filename'};
        Log2t::Common::replace_char(\$fname, 0);
        my $orig = $t_line->{'extra'}->{'parse_dir'};
        Log2t::Common::replace_char(\$orig, 0);

        # remove the directory from the path
        $fname =~ s/^$orig//;

        Log2t::Common::replace_char(\$fname, 1);
        $text .= $fname . ')';
    }
    else {

        # we don't have to worry about filename stuff
        $text .= $t_line->{'extra'}->{'filename'} . ')';
    }

    # add the notes field (if it contains some value that is)
    $text .= ' [' . $t_line->{'notes'} . ']' unless $t_line->{'notes'} eq '';

    # fix a possible pipe symbol inside the name variable
    $text =~ s/\|/\&#33;/g;   # we don't want to introduce another | symbol where it does not belong
    $text =~ s/,/-/g
      ; # exchange the commas for -, to make the change of mactime output to csv easier (mactime doesn't like , inside the output)
    $text =~ s/;/_/g
      ; # exchange the ; for _, to make the change of mactime output to csv easier (Excel doesn't like ; inside the output)
        #$text =~ s/,/\&#44;/g;	# this is for CSV exports of mactime

    # and to define the needed additional fields within the standard
    $md5   = defined $t_line->{'extra'}->{'md5'}   ? $t_line->{'extra'}->{'md5'}   : 0;
    $inode = defined $t_line->{'extra'}->{'inode'} ? $t_line->{'extra'}->{'inode'} : 0;
    $mode  = defined $t_line->{'extra'}->{'mode'}  ? $t_line->{'extra'}->{'mode'}  : 0;
    $uid   = defined $t_line->{'extra'}->{'uid'}   ? $t_line->{'extra'}->{'uid'}   : 0;
    $uid = 0 if $uid eq 'unknown';
    $gid  = defined $t_line->{'extra'}->{'gid'}  ? $t_line->{'extra'}->{'gid'}  : 0;
    $size = defined $t_line->{'extra'}->{'size'} ? $t_line->{'extra'}->{'size'} : 0;

    # print using the standard output for timeline analysis
    ::print_line(  $md5 . "|" 
                 . $text . "|" 
                 . $inode . "|" 
                 . $mode . "|" 
                 . $uid . "|" 
                 . $gid . "|" 
                 . $size . "|"
                 . $self->{'atime'} . "|"
                 . $self->{'mtime'} . "|"
                 . $self->{'ctime'} . "|"
                 . $self->{'crtime'}
                 . "\n");
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
    my $self   = shift;
    my $t_line = shift;
    my ($mtime, $atime, $ctime, $crtime);
    my $mactime;
    my $temp;

    # empty the 'type'
    $self->{'type'} = '';

    if (scalar(%{$t_line})) {

        # print the timeline in a TSK 3.x format as defined here:
        # MD5|name|inode|mode_as_string|UID|GID|size|atime|mtime|ctime|crtime

        # default values
        $self->{'mtime'}  = 0;
        $self->{'atime'}  = 0;
        $self->{'ctime'}  = 0;
        $self->{'crtime'} = 0;

# we have to check out first, is this file, and if it is... then we could be getting 8 timestamps (FN and SI)
        if ($t_line->{'source'} eq 'FILE') {

            # this is a file, let's process it accordingly....
            # go through each defined time to find the mactime (and type)
            foreach (keys %{ $t_line->{'time'} }) {
                next unless $t_line->{'time'}->{$_}->{'value'};
                if ($t_line->{'time'}->{$_}->{'type'} =~ m/SI/) {

                    # standard information
                    $self->{'mtime'} = $t_line->{'time'}->{$_}->{'value'}
                      if $t_line->{'time'}->{$_}->{'legacy'} & 0b0001;
                    $self->{'atime'} = $t_line->{'time'}->{$_}->{'value'}
                      if $t_line->{'time'}->{$_}->{'legacy'} & 0b0010;
                    $self->{'ctime'} = $t_line->{'time'}->{$_}->{'value'}
                      if $t_line->{'time'}->{$_}->{'legacy'} & 0b0100;
                    $self->{'crtime'} = $t_line->{'time'}->{$_}->{'value'}
                      if $t_line->{'time'}->{$_}->{'legacy'} & 0b1000;
                }
                else {

                    # filename
                    $mtime = $t_line->{'time'}->{$_}->{'value'}
                      if $t_line->{'time'}->{$_}->{'legacy'} & 0b0001;
                    $atime = $t_line->{'time'}->{$_}->{'value'}
                      if $t_line->{'time'}->{$_}->{'legacy'} & 0b0010;
                    $ctime = $t_line->{'time'}->{$_}->{'value'}
                      if $t_line->{'time'}->{$_}->{'legacy'} & 0b0100;
                    $crtime = $t_line->{'time'}->{$_}->{'value'}
                      if $t_line->{'time'}->{$_}->{'legacy'} & 0b1000;
                }
            }

            # now we need to process two lines
            $self->{'mactime'} = '$SI';
            $self->_process_line($t_line);

            # and process the second line
            $self->{'mactime'} = '$FN';
            $self->{'mtime'}   = $mtime;
            $self->{'atime'}   = $atime;
            $self->{'ctime'}   = $ctime;
            $self->{'crtime'}  = $crtime;

            $self->_process_line($t_line);
        }
        else {

            # go through each defined time to find the mactime (and type)
            foreach (keys %{ $t_line->{'time'} }) {
                $self->{'mtime'} = $t_line->{'time'}->{$_}->{'value'}
                  if $t_line->{'time'}->{$_}->{'legacy'} & 0b0001;
                $self->{'atime'} = $t_line->{'time'}->{$_}->{'value'}
                  if $t_line->{'time'}->{$_}->{'legacy'} & 0b0010;
                $self->{'ctime'} = $t_line->{'time'}->{$_}->{'value'}
                  if $t_line->{'time'}->{$_}->{'legacy'} & 0b0100;
                $self->{'crtime'} = $t_line->{'time'}->{$_}->{'value'}
                  if $t_line->{'time'}->{$_}->{'legacy'} & 0b1000;

                # construct the type field
                $temp = $t_line->{'time'}->{$_}->{'type'};
                $self->{'type'} .= '/' . $temp if ($self->{'type'} !~ m/$temp/);
            }

            # process the line
            $self->_process_line($t_line);
        }
    }
    else {
        print STDERR "Problem printing timeline";
        return 0;
    }

    return 1;

}

#       get_help
# A simple subroutine that returns a string containing the help
# message for this particular format file.
# @return A string containing a help file for this format file
sub get_help() {
    return "This output plugin provides a method to print a body file that can be imported 
into the mactime tool (part of TSK).  This provides a method to incorporate 
timelines found inside log files or artifacts on system into the more traditional 
file system timeline (as provided with tools like fls and ils from the TSK).  
The specification of the body file can be found here:
       http://wiki.sleuthkit.org/index.php?title=Body_file";
}

1;
