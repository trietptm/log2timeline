#!/usr/bin/perl
#########################################################################################
#                       WinReg
#########################################################################################
# This is a small library that is a part of the tool log2timeline. It's purpose is to
# assist with various common functions that are used by more than one module.
#
# This library is built upon the script deleted.pl, that is distributed with the SIFT
# forensics workstation (SANS).  The script parses a registry file and extracts
# deleted keys from it.

# The file has been changed so it can be provided as a library instead of a standalone
# script. It can therefore be used by tools such as log2timeline to extract deleted
# registry keys from a registry file.
#
# Original Author: Jolanta Thomassen
# Author: Kristinn Gudjonsson
# Date : 13/10/09
#
# Copyright 2009 Kristinn Gudjonsson (kristinn ( a t ) log2timeline (d o t) net)
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

package Log2t::WinReg;

# unchanged from deleted.pl
use strict;
use warnings;

#	initialize global constants

use constant WORD            => 2;
use constant DWORD           => 4;
use constant FILE_TIME_LOW   => 0xd53e8000;
use constant FILE_TIME_HIGH  => 0x019db1de;
use constant BLOCK_SIZE      => 4096;
use constant BIN_HEADER_SIZE => 32;
use constant MIN_NK_SIZE     => 80;

#	bin header (hbin)

use constant BIN_SIZE_OFFSET => 8;

#	base block (regf)

use constant FILE_TIMESTAMP_OFFSET => 12;
use constant FILE_NAME_OFFSET      => 48;
use constant FILE_NAME_LENGTH      => 64;

#	cells with signature (nk, vk, sk, lf, lh, ri, li)

use constant CELL_SIGNATURE_OFFSET => 4;

# 	key node cell (nk)
use constant KEY_TYPE_OFFSET         => 6;
use constant KEY_TIMESTAMP_OFFSET    => 8;
use constant PARENT_OFFSET           => 20;
use constant NUMBER_OF_VALUES_OFFSET => 40;
use constant VALUE_LIST_OFFSET       => 44;
use constant KEY_NAME_LENGTH_OFFSET  => 76;
use constant KEY_NAME_OFFSET         => 80;

# 	subkey list cell (lf, lh, ri, li)

use constant NUMBER_OF_SUBKEYS_OFFSET => 6;

# 	key value cell (vk)

use constant VALUE_NAME_LENGTH_OFFSET => 6;
use constant VALUE_LENGTH_OFFSET      => 8;
use constant VALUE_CLASS_OFFSET       => 10;
use constant VALUE_OFFSET             => 12;
use constant VALUE_TYPE_OFFSET        => 16;
use constant VALUE_NAME_OFFSET        => 24;

my %regtype = (
               0  => '$fh_NONE',
               1  => '$fh_SZ',
               2  => '$fh_EXPAND_SZ',
               3  => '$fh_BINARY',
               4  => '$fh_DWORD',
               5  => '$fh_DWORD_BIG_ENDIAN',
               6  => '$fh_LINK',
               7  => '$fh_MULTI_SZ',
               8  => '$fh_RESOURCE_LIST',
               9  => '$fh_FULL_RESOURCE_DESCRIPTION',
               10 => '$fh_RESSOURCE_REQUIREMENT_MAP',
               11 => '$fh_QWORD',
              );

# define global variables
my $file_size;
my %free_cells;
my $fh;
my %ret;
my $ret_index;

sub get_deleted_entries($) {
    my $class = shift;
    $fh        = $class->{'file'};
    %ret       = ();
    $ret_index = 0;

    $file_size = -s $fh;

    #	parse registry hive
    parse_base_block();

    %free_cells = locate_hive_slack();

    for my $key (sort { $a <=> $b } keys %free_cells) {
        if ($free_cells{$key} > MIN_NK_SIZE) {
            print STDERR "Locating\n";
            locate_key_nodes($key, $free_cells{$key});
        }
    }
    print STDERR "HERE\n";

    # slack space (we will skip this since it contains no timestamps)
    #	for my $offset ( sort {$a <=> $b } keys %free_cells ) {
    #
    #		# the minimum size of the slack fragment to be diplayed can be changed
    #	        if ($free_cells{$offset} > 0)
    #	        {
    #		        seek($fh, $offset, 0);
    #		        read($fh, my $slack, $free_cells{$offset});
    #		        $slack=~s/[\x00-\x20]/./g;
    #	        	print "\n$offset: $slack\n";
    #	        }
    #
    #	}

    # and now to return the hash
    return \%ret;
}

# Parses the hive file signature (regf) alias base block.
# Extracts the name of the hive file - leading characters are truncated
# by Windows if the file name is longer than 32 characters.
# Extracts hive file timestamp.
sub parse_base_block {

    #       parse hive file name

    die "Corrupted hive." if (-s $fh) % 4096 > 0;
    seek($fh, 0, 0);
    read($fh, my $record, DWORD);
    die "Corrupted hive." if $record ne "regf";
    seek($fh, FILE_NAME_OFFSET, 0);
    read($fh, $record, FILE_NAME_LENGTH);
    $record =~ s/\x00//g;    # translate Unicode to Ascii

    #	print "\"...$record\"\n";

    #       parse hive file timestamp
    my $time = parse_time(FILE_TIMESTAMP_OFFSET);

    # create the t_line variable
    my %t_line = (
        'time' => { 0 => { 'value' => $time, 'type' => 'Last Written', 'legacy' => 15 } },
        'desc'       => '[DELETED] ' . $record,
        'short'      => '[DELETED] ' . $record,
        'source'     => 'REG',
        'sourcetype' => 'Deleted Registry',
        'version'    => 2,
        'extra'      => {},
                 );

    # assign the t_line object to the return value
    $ret{ $ret_index++ } = \%t_line;

}

# Parses hive file in order to locate file slack.
# Skips base block and the first bin header (hbin).
# First four bytes of each hive cell indicate cell's size.
# If the size is negative - the cell is allocated and its size is abs(size).
# If the size is positive - the cell is not allocated (hive slack).
# Returns hash containing offsets to and sizes of unallocated cells.

sub locate_hive_slack {

    my $offset = BLOCK_SIZE;

    # hash to store offsets to and sizes of unallocated cells
    my %free_cells = ();
    my $cell_size  = 0;
    my $cell_offset;

    do {

        seek($fh, $offset, 0);
        read($fh, my $record, DWORD);
        if ($record eq "hbin") {
            $cell_size = BIN_HEADER_SIZE * -1;

        }
        else {
            $cell_size = unpack("l", $record);

        }

        # if size is negative - cell is unallocated
        if ($cell_size > 0) {

            $cell_offset = $offset;
            $free_cells{$cell_offset} = $cell_size;

        }

        # continue to the next cell
        $offset += abs($cell_size);

    } until (($cell_size == 0) || !valid_offset($offset));

    if ($cell_offset + $free_cells{$cell_offset} != $file_size) {
        $free_cells{$cell_offset} = $file_size - $cell_offset;
    }

    return %free_cells;
}

# Reads unallocated cell and looks for "nk" signature
# Calls parse_key_node when signature is found

sub locate_key_nodes {
    my $offset = $_[0];
    my $size   = $_[1];

    my $max_offset = $offset + $size - MIN_NK_SIZE;

    # stop reading when the remaining space is too small to hold a key.
    while ($offset < $max_offset) {
        seek($fh, $offset, 0);
        read($fh, my $record, WORD);
        if ($record eq "nk") {
            parse_key_node($offset - 4, $offset + $size);
        }
        $offset = $offset + 4;
    }
}

sub parse_key_node {
    my $offset     = $_[0];
    my $max_offset = $_[1];

    seek($fh, $offset + CELL_SIGNATURE_OFFSET, 0);
    read($fh, my $record, WORD);
    return if ($record ne "nk");

    # type has to be "20" (for subkey) followed by "00" constant
    seek($fh, $offset + KEY_TYPE_OFFSET, 0);
    read($fh, $record, WORD);
    return if (unpack("H4", $record) ne "2000");

    # read key name length
    seek($fh, $offset + KEY_NAME_LENGTH_OFFSET, 0);
    read($fh, $record, WORD);
    my $key_name_length = unpack("S", $record);
    return if (($key_name_length <= 0) || ($key_name_length > 255));

    # do not read beyond boundaries of the cell
    return if ($offset + MIN_NK_SIZE + $key_name_length) > $max_offset;

    # read key name
    seek($fh, $offset + KEY_NAME_OFFSET, 0);
    read($fh, my $key_name, $key_name_length);

    # data is corrupted if name contains control characters
    return if $key_name =~ m/[\x00-\x19]/;

    # read timestamp
    my $time = parse_time($offset + KEY_TIMESTAMP_OFFSET);

    # data is corrupted if time is invalid
    return if ($time < 0 || $time > time);

    # reconstruct key path

    #print "\n" . parse_key_path($offset) . "\n";
    #print "[" . gmtime($time) . "]\n";
    # create the t_line variable
    my $text = '[DELETED] ' . parse_key_path($offset);
    my %t_line = (
        'time'   => { 0 => { 'value' => $time, 'type' => 'Last Written', 'legacy' => 15 } },
        'desc'   => $text,
        'short'  => $text,
        'source' => 'REG',
        'sourcetype' => 'Deleted Registry',
        'version'    => 2,
        'extra'      => {},
                 );

    # assign the t_line to the ret hash
    $ret{ $ret_index++ } = \%t_line;

    # we are skipping this due to the fact that there are not associated timestamps to this entries
    parse_value_list($offset);
}

# Bactracks to parent keys to recover full path
# Prints name and path of the key

sub parse_key_path {
    my $offset = $_[0];
    return if !valid_offset($offset);

    my $path      = "";
    my $signature = "";
    my $type      = "";
    my $loop_counter = 0;
    my $loop_max = 50;
    do {
        $loop_counter++;

        # parse key type
        seek($fh, $offset + KEY_TYPE_OFFSET, 0);
        read($fh, my $record, WORD);
        $type = unpack("H4", $record);
        return ("???\\" . $path) if ($type ne "2000") && ($type ne "2c00");

        # parse key name
        seek($fh, $offset + KEY_NAME_LENGTH_OFFSET, 0);
        read($fh, $record, WORD);
        my $key_name_length = unpack("S", $record);
        return ("???\\" . $path) if ($key_name_length < 0) || ($key_name_length > 255);

        return $path if !valid_offset($offset + MIN_NK_SIZE + $key_name_length);
        seek($fh, $offset + KEY_NAME_OFFSET, 0);
        read($fh, my $key_name, $key_name_length);

        $path = $key_name . "\\" . $path;

        # go to parent node
        seek($fh, $offset + PARENT_OFFSET, 0);
        read($fh, $record, DWORD);
        $offset = unpack("L", $record) + BLOCK_SIZE;
        return ("???\\" . $path) if !valid_offset($offset);

        # read parent signature
        seek($fh, $offset + CELL_SIGNATURE_OFFSET, 0);
        read($fh, $signature, WORD);

        return $path if $loop_counter ge $loop_max;

    } until (($signature ne "nk"));

    if ($type ne "2c00")    # could not backtrack to root key
    {
        $path = "???\\" . $path;
    }
    return ($path);
}

sub parse_value_list

{
    my $offset = $_[0];
    return if !valid_offset($offset);

    seek($fh, $offset + VALUE_LIST_OFFSET, 0);
    read($fh, my $record, DWORD);
    my $value_list_offset = unpack("L", $record);
    unless ($value_list_offset == 0xffffffff) {
        $value_list_offset += BLOCK_SIZE;

        seek($fh, $offset + NUMBER_OF_VALUES_OFFSET, 0);
        read($fh, $record, DWORD);
        my $number_of_values = unpack("L", $record);

        for (my $value = 1; $value <= $number_of_values; $value++) {
            return if !valid_offset($value_list_offset + $value * 4);
            seek($fh, $value_list_offset + $value * 4, 0);
            read($fh, $record, DWORD);
            my $value_offset = unpack("L", $record) + BLOCK_SIZE;

            parse_key_value($value_offset);
        }
    }
}

sub parse_key_value

{
    my $offset = $_[0];
    return if !valid_offset($offset);
    my $text;

    seek($fh, $offset + CELL_SIGNATURE_OFFSET, 0);
    read($fh, my $record, WORD);
    return if ($record ne "vk");

    seek($fh, $offset + VALUE_CLASS_OFFSET, 0);
    read($fh, $record, WORD);
    my $value_class = unpack("S", $record);

    seek($fh, $offset + VALUE_TYPE_OFFSET, 0);
    read($fh, $record, DWORD);
    my $value_type = unpack("L", $record);

    seek($fh, $offset + VALUE_LENGTH_OFFSET, 0);
    read($fh, $record, WORD);
    my $value_length = unpack("S", $record);

    seek($fh, $offset + VALUE_NAME_LENGTH_OFFSET, 0);
    read($fh, $record, WORD);
    my $value_name_length = unpack("S", $record);

    my $data = "";

    if ($value_type <= 11) {
        $text = "\t-->$regtype{$value_type}; ";
    }
    else {
        $text = "\t-->$value_type; ";
    }

    if ($value_name_length > 0) {
        seek($fh, $offset + VALUE_NAME_OFFSET, 0);
        read($fh, $record, $value_name_length);
        if ($record =~ m/^HRZR/) {
            $record =~ tr/N-ZA-Mn-za-m/A-Za-z/;
        }
        $text .= "$record; ";

    }
    else {
        $text .= "Default; ";
    }

    if ($value_class == 0x8000)

      # value is included in vk record
    {
        seek($fh, $offset + VALUE_OFFSET, 0);
        read($fh, $data, $value_length);

    }
    else

      # linked value
    {
        seek($fh, $offset + VALUE_OFFSET, 0);
        read($fh, $record, 4);
        my $valoffset = unpack("V", $record);
        if ($valoffset != 0xffffffff) {
            $valoffset = $valoffset + BLOCK_SIZE;
            seek($fh, $valoffset, 0);
            read($fh, $record, 4);
            read($fh, $data,   $value_length);
        }
    }

    if ($value_length > 0) {
        if (($value_type == 1) | ($value_type == 2) | ($value_type == 6) | ($value_type == 7))

          # $fh_SZ, $fh_EXPAND_SZ, $fh_LINK, $fh_MULTI_SZ
        {
            chop($data);    # remove last null character

            if ($value_type == 7)

              # $fh_MULTI_SZ - Multiple strings are seperated by null characters
            {
                my @arr = split(/\x00\x00/, $data);
                $data = join("; ", @arr);
            }
            $data =~ s/\x00//g;            # translate Unicode to Ascii
            $data =~ s/[\x00-\x19]/./g;    # replace evt. control characters
            $text .= "$data\n";

        }
        elsif (($value_type == 0) | ($value_type == 3) | ($value_type == 8) | ($value_type == 9) |
               ($value_type == 10))

# $fh_NONE, $fh_BINARY, $fh_RESOURCE_LIST, $fh_FULL_RESOURCE_DESCRIPTION, $fh_RESSOURCE_REQUIREMENT_MAP
        {

            my $str = unpack("H*", $data);
            my $binary_data = "";
            for (my $i = 0; $i < length($str); $i = $i + 2) {
                $binary_data = $binary_data . " " unless $binary_data eq "";
                $binary_data = $binary_data . substr($str, $i, 2);
            }
            $data =~ s/[\x00-\x20]/./g;
            $text .= "$binary_data\n\t   $data\n";

        }

        # $fh_DWORD, $fh_DWORD_BIG_ENDIAN, $fh_QWORD
        else {
            my $str = unpack("H*", $data);
            $data = "";
            for (my $i = 0; $i < length($str); $i = $i + 2) {
                $data = $data . " " . substr($str, $i, 2);
            }
            $text .= "$data\n";
        }
    }

}

sub valid_offset {
    my $offset = $_[0];
    return (($offset > BLOCK_SIZE) && ($offset < $file_size));

}

sub parse_time {
    my $offset = $_[0];
    seek($fh, $offset, 0);
    read($fh, my $record, DWORD);
    my $time_low = unpack("L", $record);
    read($fh, $record, DWORD);
    my $time_high = unpack("L", $record);
    $time_low  -= FILE_TIME_LOW;
    $time_high -= FILE_TIME_HIGH;
    return int($time_high * 429.4967296 + $time_low * 1e-7);

}

1;
