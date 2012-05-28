#################################################################################################
#    RECYCLER
#################################################################################################
# this script reads the INFO2 (or I$) file/s that contains information about deleted items that
# still reside in the recycle bin of a Windows machine and produces a bodyfile containing the
# timeline information that can be used directly with the script mactime from TSK collection.
# The specification of the body file can be found here:
#  http://wiki.sleuthkit.org/index.php?title=Body_file
#
# Author: Kristinn Gudjonsson
# Version : 0.6
# Date : 04/05/11
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

package Log2t::input::recycler;

use strict;
use Log2t::base::input;    # the SUPER class or parent
use Log2t::Common ':binary';
use Log2t::Time;
use Log2t::Numbers;
use Log2t::BinRead;
use Encode;
use vars qw($VERSION @ISA);

# inherit the base input module, or the super class.
@ISA = ("Log2t::base::input");

$VERSION = "0.6";

# default constructor
sub new() {
    my $class = shift;

    # bless the class ;)
    my $self = $class->SUPER::new();

    # indicate that we return a single object
    $self->{'multi_line'} = 0;
    $self->{'type'}       = 'dir';    # it's a directory, not a file that we are about to parse
    $self->{'file_access'} =
      1;    # do we need to parse the actual file or is it enough to get a file handle

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
    return "Parse the content of the recycle bin directory";
}

sub _parse_i_file() {
    my $self = shift;

    # get the current filename
    my $file = ${ $self->{'name'} } . $self->{'sep'} . $self->{'files'}->{ $self->{'filekey'} };
    my $ofs  = 0;
    my ($a, $b);
    my $f_size;
    my %record;
    my @array;
    my $text;
    my $name;
    my $size;
    my $date;
    my $path;

    print STDERR "[RECYCLER] Parsing the file " . $self->{'files'}->{ $self->{'filekey'} } . "\n"
      if $self->{'debug'};

    # check the file size
    $f_size = (stat($file))[7];

    # and now to point to the file
    @array = split(/\//, $file);
    $name = $array[$#array];
    $name =~ s/^\$I/\$R/;

    # open the file
    open(IF, $file);
    binmode(IF);

    # read the I file
    $ofs = 8;                                      # starting offset of any data
    $a   = Log2t::BinRead::read_32(\*IF, \$ofs);
    $b   = Log2t::BinRead::read_32(\*IF, \$ofs);

    $size = Log2t::Numbers::join_numbers($a, $b);

    # read the next 8 bytes (the date)
    $a = Log2t::BinRead::read_32(\*IF, \$ofs);
    $b = Log2t::BinRead::read_32(\*IF, \$ofs);

    $date = Log2t::Time::Win2Unix($a, $b);

    # the path
    $path = Log2t::BinRead::read_unicode_end(\*IF, \$ofs, $f_size);

    close(IF);

    if ($self->{'path'} ne '') {
        $name=~ s/^$self->{'path_orig'}//;
    }
    $text = $path . ' <-' . $name;

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

    # let's encode this
    #$text = encode( 'utf-8', $text );
    #$text = decode( 'utf-8', $text );

    # create the t_line variable
    $self->{'container'}->{ $self->{'cont_index'}++ } = {
        'time' => { 0 => { 'value' => $date, 'type' => 'File deleted', 'legacy' => 15 } },
        'desc' => $text,
        'short'      => 'DELETED ' . $path,
        'source'     => 'RECBIN',
        'sourcetype' => '$Recycle.bin',
        'version'    => 2,
        'extra'      => { 'size' => $size }
                                                        };

    return 1;
}

#  _parse_info2
#
sub _parse_info2 {
    my $self = shift;

    # define some variables
    my $return = 1;
    my $ofs;
    my $rec_size;
    my $f_size;
    my $temp;
    my @dates;
    my $tag;
    my $off;
    my @chars;
    my $path;
    my ($a, $b);
    my ($index, $drive, $date, $size);

    # populate the possible drives
    my %drive_list = (
                      0x00 => "A",
                      0x01 => "B",
                      0x02 => "C",
                      0x03 => "D",
                      0x04 => "E",
                      0x05 => "F",
                      0x06 => "G",
                      0x07 => "H",
                      0x08 => "I",
                      0x09 => "J",
                      0x0A => "K",
                      0x0B => "L",
                      0x0C => "M",
                      0x0D => "N",
                      0x0E => "O",
                      0x0F => "P",
                      0x10 => "Q",
                      0x11 => "R",
                      0x12 => "S",
                      0x13 => "T",
                      0x14 => "U",
                      0x15 => "V",
                      0x16 => "W",
                      0x17 => "X",
                      0x18 => "Y",
                      0x19 => "Z"
                     );

    # read the record size
    $ofs = 0xC;
    seek($self->{'info_handle'}, $ofs, 0);
    read($self->{'info_handle'}, $temp, 4);
    ($a, $b) = unpack("vv", $temp);
    $rec_size = Log2t::Numbers::join_numbers($a, $b);

    # find the file size
    $f_size = (stat(${ $self->{'name'} } . $self->{'sep'} . 'INFO2'))[7];

    # read the entire file, record by record
    $ofs = 0x10;    # the location of the first record
    while ($ofs < ($f_size - $rec_size))    # read all available records
    {

        # find the index number
        seek($self->{'info_handle'}, $ofs + 0x108, 0);
        read($self->{'info_handle'}, $temp, 4);

        # insert the index number into an array
        ($a, $b) = unpack("vv", $temp);
        $index = Log2t::Numbers::join_numbers($a, $b);

        # now let's find the drive that contains the file
        seek($self->{'info_handle'}, $ofs + 0x10C, 0);
        read($self->{'info_handle'}, $temp, 4);

        # insert the drive letter into an array
        $drive = $drive_list{ unpack("v", $temp) };

        # read the date of deletion
        seek($self->{'info_handle'}, $ofs + 0x110, 0);
        read($self->{'info_handle'}, $temp, 8);

        @dates = unpack("VV", $temp);
        $date = Log2t::Time::Win2Unix($dates[0], $dates[1]);

        # read the file size as found inside the record
        seek($self->{'info_handle'}, $ofs + 0x118, 0);
        read($self->{'info_handle'}, $temp, 4);

        $size = unpack("V", $temp);

        # now let's read the name in unicode
        $tag = 1;
        $off = 0;
        while ($tag) {
            seek($self->{'info_handle'}, $ofs + 0x11C + $off, 0);
            read($self->{'info_handle'}, $temp, 2);

            if (unpack("v", $temp) == 0) {

                # the end of the name (end of line)
                $tag = 0;
            }
            else {

                # we are reading each character at a time
                push(@chars, $temp);
            }
            $off += 2;
        }

        # join the characters into a single line
        $path = join('', @chars);
        if ($self->{'path'} ne '') {
            $path =~ s/^$self->{'path_orig'}//;
        }

        # delete unneccesary characters
        $path =~ s/\00//g;

        # reset the chars array
        @chars = '';

        # increment the offset, that is read the next record
        $ofs += $rec_size;

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

        # let's encode this
        #$text = encode( 'utf-8', $text );
        #$text = decode( 'utf-8', $text );

        # create the t_line variable
        $self->{'container'}->{ $self->{'cont_index'}++ } = {
            'time' => { 0 => { 'value' => $date, 'type' => 'File deleted', 'legacy' => 15 } },
            'desc'       => 'nr: Dc' . $index . ' - ' . $path . ' (drive ' . $drive . ')',
            'short'      => 'DELETED ' . $path,
            'source'     => 'RECBIN',
            'sourcetype' => '$Recycle.bin',
            'version'    => 2,
            'extra'      => { 'size' => $size }
                                                            };

    }

    return $return;
}

#       end
# A subroutine that closes the file, after it has been parsed
# @return An integer indicating that the close operation was successful
sub end {
    my $self = shift;

    close($self->{'info_handle'}) if $self->{'older_version'};

    return 1;
}

#       get_time
# This function simply takes as a argument an index into the arrays that contain the
# parsed information and creates an array that is returned to the main script
#
# @param INDEX an integer into the arrays that contain parsed information
# @return Returns a array containing the needed values to print a body file
sub get_time {
    my $self = shift;

    # the timestamp object
    my $text;
    $self->{'cont_index'} = 0;

    # check the version we are dealing with
    if ($self->{'older_version'}) {

        # parse the info2
        $self->_parse_info2;
    }
    else {

        # go through all the files
        foreach (keys %{ $self->{'files'} }) {
            $self->{'filekey'} = $_;
            $self->_parse_i_file;
        }
    }

    return $self->{'container'};
}

#       get_help
# A simple subroutine that returns a string containing the help
# message for this particular format file.
# @return A string containing a help file for this format file
sub get_help() {
    return "This plugin parses the recycle bin directory that either contains an INFO2 file or
several files containing the names of \$R and \$I (Vista, Win7 and later versions).  The input module examines the
directory and parses the input according to the version of recycle bin that is being used.

The INFO2 or I\$ files contain information about deleted files found in the Recycle Bin of a Windows OS.  
There are no requirements to use this plugin as it uses native Perl libraries.

The INFO2 file is usually found in \"DRIVE:RECYCLER\\{SID}\\INFO2\"

The input module is used agains the directory, or against
  \"DRIVE_LETTER:\\RECYCLER\\{SID}
or
  \"DRIVE_LETTER:\\\$Recycle.Bin\\{SID}

  ";

}

#       verify
# A subroutine that verifies if we are examining a INFO2 document so it can be further
# processed.  The correct format is a file which starts with the magic value of 0x0500
# @return An array containing an integer and a string.  The integer indicates a success or failure and the
#       string is the error message (if the file is not correctly formed)
sub verify {
    my $self = shift;

    # define an array to keep
    my %return;
    my $line;
    my %file_hash;

    # start by setting the endian correctly
    Log2t::BinRead::set_endian(LITTLE_E);

    # default values
    $return{'success'} = 0;
    $return{'msg'}     = 'Not the correct format';

    # first of all we need to be reading a directory content
    return \%return unless -d ${ $self->{'name'} };
    # rewind the directory to the beginning
    seekdir $self->{'file'}, 0;

    # now to verify that we have either INFO2 or $I
    $self->{'older_version'} = -f ${ $self->{'name'} } . $self->{'sep'} . "INFO2" ? 1 : 0;

    # now to verify the structure (finally)
    if ($self->{'older_version'}) {

# verify that we have an INFO2 file (since we are currently examining an older version of the recycle bin)
# open the file (at least try to open it)
        eval {
            open(FILE, ${ $self->{'name'} } . $self->{'sep'} . 'INFO2');
            binmode(FILE);
            $self->{'info_handle'} = \*FILE;

            seek($self->{'info_handle'}, 0, 0);
            read($self->{'info_handle'}, $line, 2);

        };
        if ($@) {
            $return{'success'} = 0;
            $return{'msg'}     = "Unable to open file";
        }

        if (unpack("v", $line) eq 5) {
            $return{'success'} = 1;
        }
        else {
            $return{'success'} = 0;
            $return{'msg'}     = "Not the right magic value";
        }
    }
    else {
        eval {
            $self->{'count'} = 0;

            # now we do not have a INFO2 file, so this is either a Vista/Win7 or later versions of Windows, or not a recycle bin after all
            # rewind the directory to the beginning
            seekdir $self->{'file'}, 0;
            %file_hash = map { $self->{'count'}++ => $_ } grep { /^\$I/ } readdir($self->{'file'});
            $self->{'files'} = \%file_hash;
        };

        if ($@) {
            print STDERR "[Recycler] Error while parsing directory: $@\n";
            $return{'success'} = 0;
            $return{'msg'}     = "Error while reading directory structure ($@)";
            return \%return;
        }

        # check for the existance of an $I.... file
        if (scalar(keys %file_hash) ge 0) {

            # check for a file
            open(RF, ${ $self->{'name'} } . $self->{'sep'} . $self->{'files'}->{0});
            binmode(RF);
            my $ofs = 0;

            # read the header
            $line = Log2t::BinRead::read_32(\*RF, \$ofs);

            if ($line eq 0x01) {

                # the first half of the header is verified, read the second half
                $line = Log2t::BinRead::read_32(\*RF, \$ofs);

                if ($line eq 0x00) {
                    $return{'success'} = 1;
                    $return{'msg'}     = 'Magic file is correct';
                }
                else {
                    $return{'success'} = 0;
                    $return{'msg'} = sprintf "Wrong magic value [0x%x]", $line;
                }
            }
            else {
                $return{'success'} = 0;
                $return{'msg'} = sprintf "Wrong magic value [0x%x]", $line;
            }

            close(RF);
        }
        else {
            $return{'success'} = 0;
            $return{'msg'}     = 'No $I... files found';
        }
    }

    return \%return;
}

1;

