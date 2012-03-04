#################################################################################################
#      mactime
#################################################################################################
# this script reads a bodyfile in the mactime (timeline) format and produces a bodyfile as defined in
# the output plugin.
#
# The structure of the body file is defined here:
#   http://wiki.sleuthkit.org/index.php?title=Body_file
#
# Author: Kristinn Gudjonsson
# Version : 0.6
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
package Log2t::input::mactime;

use strict;
use Log2t::base::input;    # the SUPER class or parent
use Log2t::Time;
use Log2t::BinRead;
use Log2t::Common ':binary';

use vars qw($VERSION @ISA);

# inherit the base input module, or the super class.
@ISA = ("Log2t::base::input");

# version number
$VERSION = '0.6';

#       get_description
# A simple subroutine that returns a string containing a description of
# the funcionality of the format file. This string is used when a list of
# all available format files is printed out
#
# @return A string containing a description of the format file's functionality
sub get_description() {
    return "Parse the content of a body file in the mactime format";
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
# The default structure of Squid log file is:
# timestamp elapsed IP/Client Action/Code Size Method URI Ident Hierarchy/From Content
#
# @param LINE a string containing a single line from the access file
# @return Returns a array containing the needed values to print a body file

sub get_time {
    my $self = shift;

    # timestamp object
    my %t_line;
    my ($MD5, $name, $inode, $mode_as_string, $UID, $GID, $size, $atime, $mtime, $ctime, $crtime);

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
    ($MD5, $name, $inode, $mode_as_string, $UID, $GID, $size, $atime, $mtime, $ctime, $crtime) =
      split(/\|/, $line);

    # the structure of the format
    # MD5|name|inode|mode_as_string|UID|GID|size|atime|mtime|ctime|crtime

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

    # check and combine identical time values
    my %time;
    $time{$mtime}  += 1;
    $time{$atime}  += 2;
    $time{$ctime}  += 4;
    $time{$crtime} += 8;

    # create the t_line variable
    %t_line = (
               'desc'       => $name,
               'short'      => $name,
               'source'     => 'MACTIME',
               'sourcetype' => 'MACTIME',
               'version'    => 2,
               'extra'      => {
                            'md5'   => $MD5,
                            'inode' => $inode,
                            'mode'  => $mode_as_string,
                            'uid'   => $UID,
                            'gid'   => $GID,
                            'size'  => $size
                          }
              );

    my $i = 0;

    # and now to include the timestamps
    foreach (keys %time) {
        my $t = '';
        $t .= 'M' if ($time{$_} & 0x01);
        $t .= 'A' if ($time{$_} & 0x02);
        $t .= 'C' if ($time{$_} & 0x04);
        $t .= 'B' if ($time{$_} & 0x08);

        $t_line{'time'}->{ $i++ } = {
                                      'value'  => $_,
                                      'type'   => '[' . $t . '] time',
                                      'legacy' => $time{$_}
                                    };
    }

    return \%t_line;
}

#       get_help
# A simple subroutine that returns a string containing the help
# message for this particular format file.
# @return A string containing a help file for this format file
sub get_help() {
    return "This format file parses the content of a body file in the mactime
format, as defined in the SleuthKit by Brian Carrier 

   http://wiki.sleuthkit.org/index.php?title=Body_file

This format file accepts two parameters:
  -h|--host HOST
    To add a host name to the output (for certain output files)
  -u|--user USER
    To add a user name to the output (for certain output files)\n";
}

#       verify
# A subroutine that verifies if we are examining a prefetch directory so it can be further
# processed.  The correct format is a directory that consists of a folder that contains
# several files that end with a .pf ending.  Then one file in the folder is named Layout.ini
# @return An array containing an integer and a string.  The integer indicates a success or failure and the
#       string is the error message (if the file is not correctly formed)
sub verify {

    # define an array to keep
    my %return;
    my $line;
    my @words;
    my $tag;

    my $self = shift;

    return \%return unless -f ${ $self->{'name'} };

    # this defines the maximum amount of lines that we read in the file before finding a line
    # that does not contain comments
    my $max = 10;
    my $i   = 0;

    # default values
    $return{'success'} = 0;
    $return{'msg'}     = 'success';

    # start by setting the endian correctly
    Log2t::BinRead::set_endian(LITTLE_E);

    my $ofs = 0;

    # open the file (at least try to open it)
    eval {
        unless ($self->{'quick'})
        {

            # the first field is the MD5 sum, so it is a number
            seek($self->{'file'}, 0, 0);
            read($self->{'file'}, $tag, 1);

            # so we have a possible MD5 sum, which is in hex
            if ($tag !~ m/[0-9A-Fa-f]/) {
                $return{'msg'} = 'Wrong magic value, not a MD5 sum';
                return \%return;
            }
        }

        # let's continue
        $tag = 1;
        while ($tag) {
            $tag = 0
              unless $line = Log2t::BinRead::read_ascii_until($self->{'file'}, \$ofs, "\n", 800);
            next unless $tag;

            # check max value
            $tag = 0 if ($i++) eq $max;
            next unless $tag;

            $tag = 0 if $line !~ m/^#/;
        }

        # split the line
        @words = split(/\|/, $line);

        if ($#words eq 10) {

            # now we take one examle field to confirm

            # check the first field (md5 to verify it is a hex number)
            if ($words[0] =~ m/^[0-9A-Fa-f]+$/) {

                # now we have a correctly formed MD5 sum, check another field
                if ($words[6] =~ m/^\d+$/) {

                    # the size is an integer, check next field
                    if ($words[8] =~ /^\d+$/) {

                        # now, to verify it's an epoch format
                        if ($words[8] >= 0 && $words[8] < time) {
                            $return{'success'} = 1;
                        }
                        else {
                            $return{'success'} = 0;
                            $return{'msg'}     = 'Time value not correctly formed';
                        }
                    }
                    else {
                        $return{'success'} = 0;
                        $return{'msg'}     = 'Time value not an integer';
                    }

                }
                else {
                    $return{'success'} = 0;
                    $return{'msg'}     = 'Size value not correctly formed';
                }

            }
            else {
                $return{'success'} = 0;
                $return{'msg'} =
                  'Not the correct format (MD5 sum incorrectly formatted - [' . $words[0] . '])';
            }
        }
        else {
            $return{'success'} = 0;
            $return{'msg'} = "The file is not of the correct format ($#words fields instead of 10)";
        }

        # verify that this line is of correct value
    };
    if ($@) {
        $return{'success'} = 0;
        $return{'msg'}     = "Unable to open file";
    }

    # now we have one line of the file, let's read it and verify
    # and here we have an error checking routine... (witch success = 1 if we are able to verify)

    return \%return;
}

1;
