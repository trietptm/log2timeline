#################################################################################################
#    ANALOG CACHE
#################################################################################################
# this script is a part of the log2timeline program.
#
# This is a format file that implements a parser for Analog cache files.  It parses the file
# and provides the main script with enough information to provide a body file that can be
# used in a timeline analysis
#
# Standard Format:
#
# http://www.williballenthin.com/forensics/analog/index.html
#
# Author: Willi Ballenthin
# Version : 0.1
# Date : 17/08/11
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

package Log2t::input::analog_cache;
$VERSION = '0.1';

use strict;
use integer;
use Log2t::base::input;    # the SUPER class or parent
use DateTime;              # to modify time stamp
use Log2t::Common ':binary';
use Log2t::BinRead;

use vars qw($VERSION @ISA);
@ISA = ("Log2t::base::input");

my %struct;

############## ANALOG CACHE TIMESTAMP PARSING #########################
my $FEB = 1;
my $DEC = 11;

my @daysbefore  = (0,  31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334);
my @monthlength = (31, 28, 31, 30, 31,  30,  31,  31,  30,  31,  30,  31);

sub _is_leapyear($) {
    my $y = shift();
    return $y % 4 == 0;
}

sub _min($$) {
    my $a = shift();
    my $b = shift();
    return $a < $b ? $a : $b;
}

sub analog_time($) {
    my $self = shift();
    my $time = shift();

    my $year;
    my $month;
    my $day;
    my $hour;
    my $min;
    my $sec;

    $sec  = 0;
    $min  = $time % 60;
    $hour = ($time % 1440) / 60;
    $time /= 1440;

    $time += 364;
    $year = 1969 + 4 * ($time / 1461);
    $time %= 1461;
    $year += _min($time / 365, 3);

    if ($time == 1460) {
        $month = $DEC;
        $day   = 31;
    }
    else {
        $time %= 365;
        for ($month = $DEC;
             $daysbefore[$month] + (_is_leapyear($year) && $month > $FEB) > $time;
             $month--)
        {
        }

        $day = $time - $daysbefore[$month] + 1 - (_is_leapyear($year) && $month > $FEB);
    }
    $month++;    # make month readable

    # Analog stores timestamps in the web server log format, but with
    # no indication of time zone... :-(
    my %temp = (
                year      => $year,
                month     => $month,
                day       => $day,
                hour      => $hour,
                minute    => $min,
                second    => $sec,
                time_zone => $self->{'tz'},    # use local timezone, see generic_linux.pm
               );

    my $date_s = DateTime->new(\%temp);
    my $date_e = $date_s->epoch;

    my %ret = (
               date_s => $date_s,
               date_e => $date_e
              );

    return %ret;
}

############## PARSING MODULE CLASS #########################
sub new() {
    my $class = shift;
    my $self  = $class->SUPER::new();

    # binary file (only one entry returned)
    $self->{'multi_line'} = 0;

    bless($self, $class);
    return $self;
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

#   get_description
# A simple subroutine that returns a string containing a description of
# the funcionality of the format file. This string is used when a list of
# all available format files is printed out
# @return A string containing a description of the format file's functionality
sub get_description() {
    return "Parse the content of an Analog cache file";
}

#       get_time
# The main "juice", the routine that is called to extract all timestamps
# from the database.  The database returns a reference to a hash that
# contains all the timestamp objects extracted from the database
sub get_time {
    my $self      = shift;
    my %ret_lines = {};
    my $ret_index = 0;

    my $pattern_header =
      "^CACHE type 5 produced by analog 6.0/Unix. Do not modify or delete!\\s*\$";
    my $pattern_req_summary =
      "^T\\s+(\\d+)\\s+(\\d+)\\s+(\\d+)\\s+(\\d+)\\s+(\\d+)\\s+(\\d+)\\s+(\\d+)\\s*\$";  # 7 columns
    my $pattern_date_summary = "^D\\s+(\\d+)\\s+(\\d+)\\s*\$";                           # 2 columns
    my $pattern_activity     = "^(\\d+)\\s+(\\d+)\\s+(\\d+)\\s+(\\d+)\\s*(\\d+)\\s*\$";  # 4 columns
    my $pattern_item =
      "^(\\d+)\\s+(\\d+)\\s+(\\d+)\\s+(\\d+)\\s+(\\d+)\\s+(\\d+)\\s+(\\d+)\\s+(\\d+)\\s+(\\d+)\\s+(\\d+)\\s+(\\d+)\\s+(\\d+)\\s+(.*)\$"
      ;    # 12 columns
    my $pattern_z     = "^z\\s+(\\d+)\\s+(\\d+)\\s+(\\d+)\\s+(\\d+)\\s+(\\d+)\\s*\$";    # 5 columns
    my $pattern_codes = "^c\\s+(\\d+)\\s+(\\d+)\\s+(\\d+)\\s*\$";                        # 3 columns
    my $pattern_p =
      "^p\\s+(\\d+)\\s+(\\d+)\\s+(\\d+)\\s+(\\d+)\\s+(\\d+)\\s+(\\d+)\\s*\$";            # 6 columns

    my $fh = $self->{'file'};
    while (<$fh>) {
        my $line = $_;

        if ($line =~ m/$pattern_header/) {

            # no timestamps here
            print STDERR "[ANALOG CACHE] Processed header line\n" if $self->{'debug'};
            next;
        }
        if ($line =~ m/$pattern_req_summary/) {

            # no timestamps here
            print STDERR "[ANALOG CACHE] Processed requests summary line\n" if $self->{'debug'};
            next;
        }
        elsif ($line =~ m/$pattern_date_summary/) {
            my %first_time = $self->analog_time($1);
            my $first_time = $first_time{'date_e'};
            my %last_time  = $self->analog_time($2);
            my $last_time  = $last_time{'date_e'};

            $ret_lines{ $ret_index++ } = {
                   'time' =>
                     { 0 => { 'value' => $first_time, 'type' => 'Entry written', 'legacy' => 15 } },
                   'desc'       => "Analog cache file records begin",
                   'short'      => "Analog cache file records begin",
                   'source'     => 'Analog',
                   'sourcetype' => 'Analog Cache File',
                   'version'    => 2,
                   'extra'      => {}
            };

            $ret_lines{ $ret_index++ } = {
                    'time' =>
                      { 0 => { 'value' => $last_time, 'type' => 'Entry written', 'legacy' => 15 } },
                    'desc'       => "Analog cache file records end",
                    'short'      => "Analog cache file records end",
                    'source'     => 'Analog',
                    'sourcetype' => 'Analog Cache File',
                    'version'    => 2,
                    'extra'      => {}
            };
            print STDERR "[ANALOG CACHE] Processed date summary line\n" if $self->{'debug'};
        }
        elsif ($line =~ m/$pattern_activity/) {

            # no parsable timestamps here/dont understand this field
            print STDERR "[ANALOG CACHE] Processed activity line\n" if $self->{'debug'};
            next;
        }
        elsif ($line =~ m/$pattern_item/) {
            my $type       = $1;
            my $count      = $2;
            my $succ       = $3;
            my $redir      = $4;
            my $errors     = $5;
            my %first_time = $self->analog_time($6);
            my $first_time = $first_time{'date_e'};
            my %last_time  = $self->analog_time($9);
            my $last_time  = $last_time{'date_e'};
            my $bytes      = $12;
            my $item       = $13;

            if ($type == 1) {
                $type = "URL";
            }
            elsif ($type == 2) {

                # ???
                next;
            }
            elsif ($type == 3) {
                $type = "referer";
            }
            elsif ($type == 4) {
                $type = "user agent";
            }
            elsif ($type == 5) {
                $type = "IP address";
            }
            else {

                # unknown, shouldnt exist
                print STDERR "[ANALOG CACHE] Unknown item type\n" if $self->{'debug'};
                next;
            }

            print STDERR "[ANALOG CACHE] Item type: " . $type . "\n" if $self->{'debug'};

            my $first_msg = "Analog first records " . $type . " " . $item;
            my $last_msg  = "Analog last records " . $type . " " . $item;
            my %extra = (
                         'count'  => $count,
                         'succ'   => $succ,
                         'redir'  => $redir,
                         'errors' => $errors,
                         'bytes'  => $bytes
                        );

            $ret_lines{ $ret_index++ } = {
                   'time' =>
                     { 0 => { 'value' => $first_time, 'type' => 'Entry written', 'legacy' => 15 } },
                   'desc'       => $first_msg,
                   'short'      => $first_msg,
                   'source'     => 'Analog',
                   'sourcetype' => 'Analog Cache File',
                   'version'    => 2,
                   'extra'      => \%extra
            };

            $ret_lines{ $ret_index++ } = {
                    'time' =>
                      { 0 => { 'value' => $last_time, 'type' => 'Entry written', 'legacy' => 15 } },
                    'desc'       => $last_msg,
                    'short'      => $last_msg,
                    'source'     => 'Analog',
                    'sourcetype' => 'Analog Cache File',
                    'version'    => 2,
                    'extra'      => \%extra
            };

            print STDERR "[ANALOG CACHE] Processed " . $type . " item line\n" if $self->{'debug'};
        }
        elsif ($line =~ m/$pattern_z/) {

            # dont understand what z is
            print STDERR "[ANALOG CACHE] Processed z line\n" if $self->{'debug'};
            next;
        }
        elsif ($line =~ m/$pattern_codes/) {
            my $code      = $1;
            my $count     = $2;
            my %last_time = $self->analog_time($3);
            my $last_time = $last_time{'date_e'};

            $ret_lines{ $ret_index++ } = {
                    'time' =>
                      { 0 => { 'value' => $last_time, 'type' => 'Entry written', 'legacy' => 15 } },
                    'desc'       => "Analog last records status code " . $code,
                    'short'      => "Analog last records status code " . $code,
                    'source'     => 'Analog',
                    'sourcetype' => 'Analog Cache File',
                    'version'    => 2,
                    'extra'      => { 'count' => $count }
            };
            print STDERR "[ANALOG CACHE] Processed status codes line\n" if $self->{'debug'};
        }
        elsif ($line =~ m/$pattern_p/) {

            # p is processing, no timestamps
            print STDERR "[ANALOG CACHE] Processed p line\n" if $self->{'debug'};
            next;
        }
        else {

            # unknown, shouldnt exist
            print STDERR "[ANALOG CACHE] Processed unknown line: " . $line . " \n"
              if $self->{'debug'};
            next;
        }
    }

    return \%ret_lines;
}

#  get_help
# A simple subroutine that returns a string containing the help
# message for this particular format file.
# @return A string containing a help file for this format file
sub get_help() {
    return "This parser parses the Analog cache log file. To see the definition of the 
log format, please see:
http://www.williballenthin.com/forensics/analog/index.html

This format file depends upon the library
  DateTime
for converting date variables to epoch time. Possible to install using
perl -MCPAN -e shell
(when loaded)
install DateTime\n";

}

#  verify
# A subroutine that reads a single line from the log file and verifies that it is of the
# correct format so it can be further processed.
# @return An array containing an integer and a string.  The integer indicates a success or failure and the
#  string is the error message (if the file is not correctly formed)
sub verify {
    my $self = shift;

    my %ret;
    my $line;

    $ret{'success'} = 0;
    $ret{'msg'}     = 'success';

    # depending on which type you are examining, directory or a file
    return \%ret unless -f ${ $self->{'name'} };

    my $ofs = 0;

    # start by setting the endian correctly
    Log2t::BinRead::set_endian(LITTLE_E);

    my $needle = "CACHE type 5 produced by analog 6.0/Unix. Do not modify or delete!";
    $line = Log2t::BinRead::read_ascii_until($self->{'file'}, \$ofs, "\n", 400);

    if ($line =~ m/$needle/) {
        $ret{'success'} = 1;
        return \%ret;
    }

    $ret{'msg'}     = "The file does not match the Analog cache file format.";
    $ret{'success'} = 0;

    return \%ret;
}

1;
