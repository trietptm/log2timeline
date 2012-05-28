#################################################################################################
#    SOL / LSO
#################################################################################################
# This script is a part of the log2timeline framework for timeline creation and analysis.
# This script implements an input module, or a parser capable of parsing a single log file (or
# directory) and creating a hash that is returned to the main script.  That hash is then used
# to create a body file (to create a timeline) or a timeline (directly).
#
# This parser parses Flash Shared Objects (Local Shared Object) files that Flash stores.  These
# files are usually called Flash cookies, as they often contain the same content as regular cookies.
#
# Information about the structure of LSO can be found here:
#   http://sourceforge.net/docman/display_doc.php?docid=27026&group_id=131628
#      (site available through Google Cache)
#
# Information from Adobe about how to create a tracking Flash banner can be found here:
#   http://www.adobe.com/resources/richmedia/tracking/designers_guide/
#
# And information from Adobe can be found here:
#   http://www.adobe.com/products/flashplayer/articles/lso/
#
# Information about version 10.1 of the Flash Player and how it will implement
# privacy browsing,
# http://www.adobe.com/devnet/flashplayer/articles/privacy_mode_fp10.1.html
#
# Information about the format was partially extracted from the source code of the
# tool Solve (http://solve.sourceforge.net by Darron Schall) - no code has been used
# from the project, just the layout and structure of the LSO files.
#
# The files read are:
#  datatypes/Types.java    - for the available data types
#  fileformat/TCSOFileReader.java  - to analyse the structure of each data type
#
# Author: Kristinn Gudjonsson
# Version : 0.5
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
#
# Few lines of code have been borrowed from a CPAN module called Parse::Flash::Cookie
#  Copyright 2007 Andreas Faafeng, all rights reserved.
package Log2t::input::sol;

use strict;
use Log2t::base::input;    # the SUPER class or parent
use Log2t::Common qw/LITTLE_E BIG_E/;
use Log2t::Time;           # to manipulate time

#use Log2t::Numbers;  # to manipulate numbers
use Log2t::BinRead;        # methods to read binary files

# for reading and parsing the XML schema
use XML::LibXML;
use XML::LibXML::Common;

use vars qw($VERSION @ISA);

# inherit the base input module, or the super class.
@ISA = ("Log2t::base::input");

# version number
$VERSION = '0.5';

my %header;
my %data;
my $file;
my $loaded;
my $path;

my %date;       # a hash that stores all available dates
my $d_index;    # an index to that hash

# the constructor
sub new() {
    my $class = shift;

    # inherit from the base class
    my $self = $class->SUPER::new();

    # indicate that we would like to parse this file in one attempt, and return it in a single hash
    $self->{'multi_line'} = 0;

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
    return "Parse the content of a .sol (LSO) or a Flash cookie file";
}

#  get_time
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
sub get_time {

    # read the paramaters passed to the script
    my $self = shift;

    # default values
    my $ofs = 0;
    my $temp;
    my $index;
    $self->{'cont_index'} = 0;    # counter to the container

    $d_index = 0;                 # set the date index to zero

    # default values

    # indication that the line has not been read
    $loaded = 0;

    # read the file's content
    $ofs = 16;                    # skip the header (already verified)

    # read the first part of the file
    $temp = Log2t::BinRead::read_16($self->{'file'}, \$ofs);

    # construct a hash that contains all the needed information about the
    # the LSO file
    %data = (
             'size' => $temp,
             'name' => Log2t::BinRead::read_ascii($self->{'file'}, \$ofs, $temp),
             'nothing' => Log2t::BinRead::read_32($self->{'file'}, \$ofs),
            );

    # initialize the index variable
    $index = 0;

    # now we need to read in the variable part

    # read in the variables
    my $tag = 1;

    # read until we have reached the end of the flash cookie
    while ($tag) {
        $tag = 0 unless $ofs < $self->{'header'}->{'size'};
        $tag = 0 if $ofs eq $self->{'header'}->{'size'};
        next unless $tag;

        printf STDERR "[LSO] Reading the SOL (ofs: 0%x)\n", $ofs if $self->{'debug'};

        # read the length variable as a temporary status
        $temp = Log2t::BinRead::read_16($self->{'file'}, \$ofs);

        # check to see if we have reached the end of file
        $tag = 0 if $temp eq 0;
        next unless $tag;

        # start creating the variable
        $data{'variable'}->{$index} = {
            'name'   => Log2t::BinRead::read_ascii($self->{'file'}, \$ofs, $temp),
            'length' => $temp,
            'type' => Log2t::BinRead::read_8($self->{'file'}, \$ofs)
                                      };

        printf STDERR "[LSO] Reading:\nType:\t%s\nName:\t%s\nLength:\t%s\n",
          $data{'variable'}->{$index}->{'type'}, $data{'variable'}->{$index}->{'name'},
          $data{'variable'}->{$index}->{'length'}
          if $self->{'debug'};

        # read the data type
        $data{'variable'}->{$index}->{'data'} =
          $self->_lso_read_data_type(\$ofs,
                                     $data{'variable'}->{$index}->{'type'},
                                     $data{'variable'}->{$index}->{'name'});

        return undef unless defined $data{'variable'}->{$index}->{'data'};

        # special date handling
        if ($data{'variable'}->{$index}->{'type'} eq 11) {

            # fill in the date hash
            $date{ $d_index++ } = {
                                    'date' => $data{'variable'}->{$index}->{'data'},
                                    'name' => $data{'variable'}->{$index}->{'name'}
                                  };

        }

        # each data blocks ends (or begins with four bytes that are not used)
        $ofs++;
        $index++;
    }

    # special case, now we include the file's creation time
    $self->{'g_date'} = (stat(${ $self->{'name'} }))[10];
    $self->{'g_name'} = 'LSO created';
    $self->_parse_timestamp;

    # we have two varibles
    #  loaded - indicates the number of loaded lines
    #  d_index  - indicates the number of available date objects
    foreach (keys %date) {

        print STDERR "[LSO] LOADING: LOADED $_ INDEX G DATE "
          . $date{$_}->{'data'}
          . " G NAME "
          . $date{$_}->{'name'} . "\n"
          if $self->{'debug'};
        $self->{'g_date'} = $date{$_}->{'date'};
        $self->{'g_name'} = $date{$_}->{'name'};
        $self->_parse_timestamp;
    }

    return $self->{'container'};
}

#       parse_line
#
# This is the main "juice" of the format file.  It depends on the subfunction
# load_line that loads a line of the log file into a global variable and then
# parses that line to produce the hash t_line, which is read and sent to the
# output modules by the main script to produce a timeline or a bodyfile
#
# @return Returns a reference to a hash containing the needed values to print a body file
sub _parse_timestamp {
    my $self = shift;
    my $text;

    # check for inf or nan
    return 0 if $self->{'g_date'} eq 'inf';
    return 0 if $self->{'g_date'} eq 'nan';

    # get information about dates (std. filesystem timestamps)
    #my ($atime,$mtime,$ctime) = (stat( $file ) )[8,9,10];

    # check for global names (should be assigned)
    if ($self->{'g_name'} ne '') {
        $text = $self->{'g_name'} . ' -> ';
    }
    else {
        $text = 'LSO created -> ';
    }

    # construct the text variable
    my $path = ${ $self->{'name'} };

    if ($self->{'path'} ne '') {
        $path =~ s/^$self->{'path_orig'}//;
    }
    $text .= 'File: ' . $path . ' and object name: ' . $data{'name'} . ' variable: {'
      if $self->{'path'} eq '';
    $text .=
        'File: '
      . $self->{'path'}
      . $self->{'sep'}
      . $path
      . ' and object name: '
      . $data{'name'}
      . ' variable: {'
      unless $self->{'path'} eq '';

    # go through each variable found inside the flash cookie
    foreach (keys %{ $data{'variable'} }) {

# check if we have a date object (or any other kind)
# we need to construct the date object in a different manner ("resolve" the date, or write it in a human readable format)
        if ($data{'variable'}->{$_}->{'type'} eq 11) {

            # then we have a date
            if (   ($data{'variable'}->{$_}->{'data'} eq 'inf')
                || ($data{'variable'}->{$_}->{'data'} eq 'nan'))
            {
                $text .= $data{'variable'}->{$_}->{'name'} . ' = (';
                $text .= $data{'variable'}->{$_}->{'data'} eq 'inf' ? 'infinite' : 'not a number';
                $text .= '), ';
            }
            else {
                $text .=
                    $data{'variable'}->{$_}->{'name'} . ' = ('
                  . Log2t::Time::epoch2text($data{'variable'}->{$_}->{'data'}, 1, $self->{'tz'})
                  . ') ';
            }
        }
        else {

            # not a date, so just process it "normally"
            $text .=
              $data{'variable'}->{$_}->{'name'} . ' = ('
              . $self->_dump_value($data{'variable'}->{$_}->{'data'},
                                   $data{'variable'}->{$_}->{'type'})
              . ') ';
        }
    }
    chomp($text);
    $text =~ s/, $//;

    # remove new line characters
    $text =~ s/\n//;
    $text =~ s/\r//;
    $text .= '}';

    # content of the timestamp object, t_line ([optional])
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

    # create the t_line variable
    $self->{'container'}->{ $self->{'cont_index'}++ } = {
           'desc' => $text,
           'time' =>
             { 0 => { 'value' => $self->{'g_date'}, 'type' => $self->{'g_name'}, 'legacy' => 15 } },
           'short'      => 'Flash Cookie: site ' . $data{'name'},
           'source'     => 'LSO',
           'sourcetype' => 'Flash Cookie',
           'version'    => 2,
           'extra'      => {}
    };

    # check for date variable (use filesystem or extracted timestamp)
    #if( $g_date ne '' && $g_date ne 'inf' && $g_date ne 'nan' )
    #{
    #  # use extracted
    #  $t_line{'time'} = { 0 => { 'value' => $g_date, 'type' => $g_name, 'legacy' => 15 } };
    #}
    #else
    #{
    #  # traditional filesystem timestamps
    #  $t_line{'time'} = {
    #    0 => { 'value' => $atime, 'type' => 'atime', 'legacy' => 2 },
    #    1 => { 'value' => $mtime, 'type' => 'mtime', 'legacy' => 1 },
    #    2 => { 'value' => $ctime, 'type' => 'ctime', 'legacy' => 4 },
    #    3 => { 'value' => $ctime, 'type' => 'crtime', 'legacy' => 8 },
    #  };
    #}

    return 1;
}

#  dump_value
#
# This function simply takes as an argument the data part of the variable found
# inside the flash cookie and checks if it is a string or a reference to a hash.
#
# If it is a reference to a hash it then recursively goes through the hash to
# format it properly to print it out.
#
# Otherwise it just prints it out.
#
# @param value The data part (either a reference to a hash or a variable)
# @return Return a string containing the content of the value parameter
sub _dump_value($) {
    my $self  = shift;
    my $value = shift;
    my $type  = shift;
    my $t;

    # check the data type
    if (ref($value) eq 'HASH') {
        foreach (keys %$value) {
            $t .= $_ . ' => ';
            if (scalar($value->{$_}) && (ref($value->{$_}) eq 'HASH')) {
                $t .= $self->_dump_value($value->{$_}->{'data'}, $value->{$_}->{'type'});
            }
            else {
                $t .= sprintf "0x%x ", $type;
                $t .= Log2t::Time::epoch2text($value->{$_}, 1, $self->{'tz'}) if $type eq 0xb;
                $t .= $value->{$_} unless $type eq 0xb;
            }

            $t .= ', ';
        }

        return $t;
    }
    else {
        return $value unless $type eq 0xb;
        return Log2t::Time::epoch2text($value, 1, $self->{'tz'}) unless $value eq ('inf' or 'nan');

        return $value;
    }
}

#       get_help
#
# A simple subroutine that returns a string containing the help
# message for this particular format file.
#
# @return A string containing a help file for this format file
sub get_help() {
    return "This is an input module that parses Local Shared Objects (LSO) or 
a flash cookie.  It parses the cookie and prints the output on the timeline along with
the filesystem timestamps for the file itself.\n";

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
sub verify {
    my $self = shift;

    # define an array to keep
    my %return;

    my $ofs = 0;

    # default values
    $return{'success'} = 0;
    $return{'msg'}     = 'success';

    # reset variables
    %header = undef;
    %data   = undef;

    return \%return unless -f ${ $self->{'name'} };

    # open the file (at least try to open it)
    eval {

        # fix the "endian"
        Log2t::BinRead::set_endian(Log2t::Common::BIG_E);

        # read the header of the SOL
        $self->{'header'}->{'header'} = Log2t::BinRead::read_16($self->{'file'}, \$ofs);

        # check the magic value
        $return{'msg'} = 'Wrong magic value';
        return \%return unless $self->{'header'}->{'header'} == 0xbf;

        $self->{'header'}->{'size'} = Log2t::BinRead::read_32($self->{'file'}, \$ofs);
        $self->{'header'}->{'magic'} = Log2t::BinRead::read_ascii($self->{'file'}, \$ofs, 4);
        $self->{'header'}->{'pad'} =
          Log2t::BinRead::read_32($self->{'file'}, \$ofs);    # the padding is really 6 bytes, not 4
    };
    if ($@) {
        $return{'success'} = 0;
        $return{'msg'}     = "Unable to open file";
    }

    # check the magic value and verify that we have a correct header
    if (    ($self->{'header'}->{'magic'} eq 'TCSO')
        and ($self->{'header'}->{'header'} == 0xbf)
        and ($self->{'header'}->{'pad'} == 0x40000))
    {
        $return{'success'} = 1;
        $self->{'header'}->{'size'} += 6;    # to get the correct size
    }
    else {
        $return{'success'} = 0;
        $return{'msg'}     = 'Wrong magic value (' . $self->{'header'}->{'magic'} . ')';
    }

    return \%return;
}

#  lso_read_double
#
# A function that takes as a parameter the offset to the flash cookie file (the
# current location) as well as the name of the variable and reads a double
# number from the flash cookie.
#
# The function also checks if the double number can be converted to a date object
# since some flash cookies store timestamps in a double number instead of using a
# proper date object.
#
# @param o A reference to an integer that stores the current offset into the LSO file
# @param name The name of the variable (use it in the case the number is a time object)
# @return Returns the date as milliseconds from Epoch, or the string 'inf' (infinitive)
# or 'nan' (not a number)
sub _lso_read_double($$$) {
    my $self = shift;
    my $o    = shift;
    my $name = shift;

    my $num = undef;

    # read the double
    $num = Log2t::BinRead::read_double($self->{'file'}, $o);

    print STDERR "[LSO] Reading a double number ($name) = $num\n" if $self->{'debug'};

    return 'nan' unless defined $num;

    # check if the number is either infinite or not a number
    if ($num ne 'inf' && $num ne 'nan') {

        # check if this is really a date
        my $check = Log2t::Time::sol_date_calc($num, 0);

        # if it looks like a date, then we fill it up
        if ($check ne 'inf' && $check ne 'nan' && $check gt 0) {
            print STDERR "[LSO] The double number is a date $check\n" if $self->{'debug'};

            # fill in the date hash
            $date{ $d_index++ } = {
                                    'date' => $check,
                                    'name' => $name
                                  };

            # return the value in a human readable format
            return Log2t::Time::epoch2text($check, 1, $self->{'tz'});
        }
    }

    return $num;
}

#  lso_read_boolean
#
# A function that takes as an input the current offset into the flash cookie and reads
# a boolean value from it.
#
# @param o A reference to an integer that stores the current offset into the LSO file
# @return A string containing the words 'FALSE' or 'TRUE', depending on the value found inside
sub _lso_read_boolean($) {
    my $self = shift;
    my $o    = shift;
    my $t;

    $t = Log2t::BinRead::read_8($self->{'file'}, $o);

    printf STDERR "[LSO] BOOLEAN 0x%x\n", $t if $self->{'debug'};

    return 'FALSE' if $t eq 00;
    return 'TRUE';
}

#  lso_read_string
#
# A function that takes as an input the current offset into the flash cookie and reads
# a string value from it.
#
# The function also reads the length variable, to know how far into the file the string lies.
#
# @param o A reference to an integer that stores the current offset into the LSO file
# @return The string as it was read
sub _lso_read_string($) {
    my $self = shift;
    my $o    = shift;
    my $t    = Log2t::BinRead::read_16($self->{'file'}, $o);

    return Log2t::BinRead::read_ascii($self->{'file'}, $o, $t);
}

#       _lso_read_data_type
#
# A function that takes as an input the current offset into the flash cookie, the type
# of data object to read and the name of the variable and then calls the appropriate
# read functions based on the type of record.
#
# @param o A reference to an integer that stores the current offset into the LSO file
# @param type An integer indicating which type of record to be read
# @return Returns the data object that the appropriate read function returned, it should
# either be a variable (string/int/..) or a reference to a hash
sub _lso_read_data_type {
    my $self = shift;
    my $o    = shift;
    my $type = shift;
    my $name = shift;

    printf STDERR "[LSO] READING DATA TYPE 0x%x at offset: 0x%x\n", $type, $$o if $self->{'debug'};

    #   --- the available types ---
    #
    #  0x00 - NUMBER
    #  0x01 - BOOLEAN
    #  0x02 - STRING
    #   0x03 - OBJECT
    #  0x05 - NULL
    #  0x06 - UNDEFINED
    #  0x08 - ARRAY
    #  0x0B - DATE
    #  0x0F - XML
    #  0x10 - CLASS
    #
    #
    #  0x0D - NULL REALLY

    # check the type of the variable (data part is of variable length, depending on the type)
    # no switch sentence in Perl... so a long if..elsif..else sentence instead
    # wanted to do code reference instead, but somehow I'm getting it wrong....
    my $typecheck = {
        0x00    => \&_lso_read_double($self,  $o, $name),
        0x01    => \&_lso_read_boolean($self, $o),
        0x02    => \&_lso_read_string($self,  $o),
        0x03    => \&_lso_read_object($self,  $o),
        0x05    => sub                        { return 'type 5 (none)' },
        0x06    => sub                        { return 'type 6 (undefined)' },
        0x08    => \&_lso_read_array($self,   $o),
        0x0D    => sub                        { return 'NULL' },
        0x0B    => \&_lso_read_date($self,    $o),
        0x0F    => \&_lso_read_xml($self,     $o),
        0x10    => \&_lso_read_class($self,   $o),
        DEFAULT => sub {
            printf STDERR
              "[LSO] unknown data type found (0x%x). Unable to process file [$file] further\n",
              $type;
            return undef;
          }
    };

    #my $func = $typecheck->{$type} || $typecheck->{DEFAULT};
    ##return $func->();

    if ($type eq 0x00) {

        # here we get a number (double)
        return $self->_lso_read_double($o, $name);
    }
    elsif ($type eq 0x01) {

        # the data part is either FALSE or TRUE   (BOOLEAN)
        return $self->_lso_read_boolean($o);
    }
    elsif ($type eq 0x02) {

        # we get a string value (so read the lenght in a temporary value)
        return $self->_lso_read_string($o);
    }
    elsif ($type eq 0x03) {

        # this type is an OBJECT, read the object
        return $self->_lso_read_object($o);
    }
    elsif ($type eq 0x05) {

        # nothing
        return 'type 5 (none)';
    }
    elsif ($type eq 0x06) {

        # nothing
        return 'type 6 (undefined)';
    }
    elsif ($type eq 0x08) {

        # array
        return $self->_lso_read_array($o);
    }
    elsif ($type eq 0x0D) {

        # observed type in one instance
        return 'NULL';
    }
    elsif ($type eq 11) {

        # and we've got a DATE
        return $self->_lso_read_date($o);
    }
    elsif ($type eq 0x0F) {

        # a XML document
        return $self->_lso_read_xml($o);
    }
    elsif ($type eq 0x10) {

        # CLASS
        return $self->_lso_read_class($o);
    }
    else {
        printf STDERR "[LSO] unknown data type found (0x%x). Unable to process file ["
          . ${ $self->{'name'} }
          . "] further\n", $type;
        return undef;
    }

    # return the content
    return '';
}

#  lso_read_class
#
# A function that takes as an input the current offset into the flash cookie and reads
# an class object from it.
#
# The function (which is almost the same as lso_read_array) reads all the variables as
# well as their values from the LSO file and stores it as a HASH
#
# The object ends with a magic value of "00 00 09"
#
# The difference between an object and a class is that the class starts with a CLASS
# name, which is then followed with other data types while the object does not contain
# a name part
#
# @param o A reference to an integer that stores the current offset into the LSO file
# @return A reference to a hash that stores all of the values inside the array
sub _lso_read_class($) {
    my $self = shift;
    my $o    = shift;
    my $t;
    my $tag;
    my %content;
    my $name;
    my $oname;

    # read the name of the object
    $oname = $self->_lso_read_string($o);

    # check if we've reached the "magic", meaning we've reached the end
    $tag = $self->_lso_reached_magic($o);

    # read the object until we've reached the end
    while ($tag) {

        # check if we've reached the "magic", meaning we've reached the end
        $tag = $self->_lso_reached_magic($o);
        next unless $tag;

        # read the objects name
        $name = $self->_lso_read_string($o);

        # read the data type
        $t = Log2t::BinRead::read_8($self->{'file'}, $o);

        $content{"$oname/$name"} = {
                                 'data' => $self->_lso_read_data_type($o, $t, $oname . '/' . $name),
                                 'type' => $t
                                   };

        # check if we've read an undefined data type
        return undef unless defined $content{"$oname/$name"};

        if ($t eq 11) {

            # fill in the date hash
            $date{ $d_index++ } = {
                                    'date' => $content{"$oname/$name"}->{'data'},
                                    'name' => $oname . '/' . $name
                                  };
        }
    }

    # we don't want to be sending an object down
    return \%content;
}

#   lso_read_xml
#
# This function reads the LSO file and reads an XML structure from it
sub _lso_read_xml( $ ) {
    my $self = shift;
    my $t;
    my $o = shift;
    my $string;
    my $xml_text;

    printf STDERR "[LSO] Parse XML offset 0x%x\n", $$o if $self->{'debug'};

    # xml variables
    my ($xml, $xml_parsed, $prop);
    my (@prop_array);

    $t = Log2t::BinRead::read_16($self->{'file'}, $o);

    if ($t ne 0x00) {
        printf STDERR "[LSO] Reading XML - value should be zero, 0x%x\n", $t if $self->{'debug'};
    }

    # read the XML structure
    $t = $self->_lso_read_string($o);
    $t =~ s/\n//g;
    $t =~ s/\r//g;

    return $t;

    $xml_text = "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\" ?>\n" . $t . "</xml>";

    # get the XML
    $xml = XML::LibXML->new();

    print STDERR "[LSO] XML [$t]\n" if $self->{'debug'};

    $xml_parsed = $xml->parse_string($xml_text);

    # now we need to parse the XML structure
    $prop       = $xml_parsed->getDocumentElement();
    @prop_array = $prop->childNodes;

    # go through each of the child nodes
    foreach (@prop_array) {
        if ($_->nodeType == ELEMENT_NODE) {
            $string .= $self->_parse_xml($_);
        }
    }

    return $string;
}

sub _parse_xml($) {
    my $self = shift;
    my $node = shift;
    my $string;
    my @attrs;
    my $temp;
    my @children;

    $temp = '';

    # we will go through each of the supplied value
    # check if the node has attributes
    if ($node->hasAttributes()) {
        @attrs = $node->attributes();
        foreach my $attr (@attrs) {
            $temp .= $attr->nodeName . ' = ' . $attr->value . '- ';
        }

        # remove the last '- ' from the temp variable
        $temp =~ s/- $//;
    }

    if ($node->hasChildNodes()) {
        @children = $node->childNodes;

        foreach (@children) {
            $string .= $self->_parse_xml($_);
        }
    }
    else {
        $string =
            $temp eq ''
          ? $node->nodeName . ' = ' . $node->textContent
          : $node->nodeName . ' (' . $temp . ') = ' . $node->textContent;
    }

    $string =~ s/\r//g;
    $string =~ s/\n//g;
    return $string;

}

# lso_read_date
#
# This function takes as an input the current offset into the flash cookie file
# and then reads a date object found inside it.
#
# Some of the methods here are derived from the Parse::Flash::Cookie
# CPAN module.
#
# Copyright 2007 Andreas Faafeng, all rights reserved.
#
# @param o A reference to the integer that stores the current offset into the LSO file
# @return Returns the date as a number (ms since Epoch) or a string (inf - infinite,
# nan - not a number)
sub _lso_read_date($) {
    my $self = shift;
    my $o    = shift;
    my ($time, $utcofs, $time_ofs);

    # read the time or the actual double number representing the date
    $time = Log2t::BinRead::read_double($self->{'file'}, $o);

    # read the current offset from UTC
    #$utcofs = Log2t::BinRead::read_16(\*FILE, $o );
    $utcofs = Log2t::BinRead::read_short($self->{'file'}, $o);

    # calculate the time offset
    $time_ofs = -$utcofs / 60;

    print STDERR "[LSO - DATE] Time: $time - $time_ofs ("
      . Log2t::Time::sol_date_calc($time, $time_ofs) . ")\n"
      if $self->{'debug'};

    return Log2t::Time::sol_date_calc($time, $time_ofs);
}

#       lso_read_array
#
# A function that takes as an input the current offset into the flash cookie and reads
# an array object from it.
#
# The function (which is almost the same as lso_read_object) starts by reading the
# number of items to store inside the array (the only difference between an array and
# an object) and then reads all the variables as well as their values from the LSO file
# and stores it as a HASH
#
# @param o A reference to an integer that stores the current offset into the LSO file
# @return A reference to a hash that stores all of the values inside the array
sub _lso_read_array($) {
    my $self = shift;
    my $o    = shift;
    my $t;
    my $tag;
    my %content;
    my $name;

    # read the number of items to process
    $t = Log2t::BinRead::read_32($self->{'file'}, $o);

    print STDERR '[LSO] Array with ', $t, ' items.', "\n" if $self->{'debug'};

    # check if we've reached the "magic", meaning we've reached the end
    $tag = $self->_lso_reached_magic($o);

    # read the object until we've reached the end
    while ($tag) {

        # check if we've reached the "magic", meaning we've reached the end
        $tag = $self->_lso_reached_magic($o);
        next unless $tag;

        # read the variable's name
        $name = $self->_lso_read_string($o);

        print STDERR "[LSO] READING NAME [$name]\n" if $self->{'debug'};

        # read the data type
        $t = Log2t::BinRead::read_8($self->{'file'}, $o);

        $content{"$name"} = {
                              'data' => $self->_lso_read_data_type($o, $t, $name),
                              'type' => $t
                            };

        # check if we've read an undefined data type
        return undef unless defined $content{"$name"};

        # check if we have reached an undefined type
        return undef unless defined $content{"$name"}->{'data'};

        if ($t eq 11) {
            print STDERR "[LSO] OBJECT IS A TIME OBJECT, AKA A DATE\n" if $self->{'debug'};

            # fill in the date hash
            $date{ $d_index++ } = {
                                    'date' => $content{"$name"}->{'data'},
                                    'name' => $name
                                  };
        }
    }

    return \%content;
}

#  lso_reached_magic
#
# A simple function that takes as an input the current offset into the LSO file
# and reads three bytes to determine whether or not they contain the magic value
# that represents the end of an array or an object data type.
#
# @param o A reference to an integer that contains the current offset into the LSO file
# @return Returns TRUE (1) if the magic value is not found and FALSE (0) if it is found
sub _lso_reached_magic($) {
    my $self = shift;
    my $o    = shift;
    my $t;    # temp

    # check if we find the magic value
    seek($self->{'file'}, $$o, 0);
    read($self->{'file'}, $t, 1) or return 0;

    # check the first value
    if (unpack("s", $t) == 0x0) {

        # check the next two bytes
        seek($self->{'file'}, $$o + 1, 0);
        read($self->{'file'}, $t, 2) or return 0;

        # check the last two bytes
        if (unpack("n", $t) == 0x0009) {
            $$o += 3;
            return 0;
        }
    }

    # did not find the magic value
    return 1;
}

#       lso_read_object
#
# A function that takes as an input the current offset into the flash cookie and reads
# an array object from it.
#
# The function (which is almost the same as lso_read_array) reads all the variables as
# well as their values from the LSO file and stores it as a HASH
#
# The object ends with a magic value of "00 00 09"
#
# @param o A reference to an integer that stores the current offset into the LSO file
# @return A reference to a hash that stores all of the values inside the array
sub _lso_read_object($) {
    my $self = shift;
    my $o    = shift;
    my $t;
    my $tag;
    my %content;
    my $name;

    # check if we've reached the "magic", meaning we've reached the end
    $tag = $self->_lso_reached_magic($o);

    # read the object until we've reached the end
    while ($tag) {

        # check if we've reached the "magic", meaning we've reached the end
        $tag = $self->_lso_reached_magic($o);
        next unless $tag;

        # read the objects name
        $name = $self->_lso_read_string($o);

        # read the data type
        $t = Log2t::BinRead::read_8($self->{'file'}, $o);

        $content{"$name"} = {
                              'data' => $self->_lso_read_data_type($o, $t, $name),
                              'type' => $t
                            };

        # check if we've read an undefined data type
        return undef unless defined $content{"$name"};

        if ($t eq 11) {

            # fill in the date hash
            $date{ $d_index++ } = {
                                    'date' => $content{"$name"}->{'data'},
                                    'name' => $name
                                  };
        }
    }

    # we don't want to be sending an object down
    return \%content;
}

1;

__END__

=pod

=head1 NAME

B<sol> - an input module B<log2timeline> that parses Local Shared Objects (LSO) or Flash cookies as they are often referred to

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

