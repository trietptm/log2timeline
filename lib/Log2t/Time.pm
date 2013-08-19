#!/usr/bin/perl
#########################################################################################
#                       Time
#########################################################################################
# Author: Kristinn Gudjonsson
# Version : 0.3
# Date : 29/10/09
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

=pod

=head1 NAME

Log2t::Time - A library that provides method to work with different timestamps. 

=head1 DESCRIPTION

This is a small library to assist with time manipulation. It contains multiple methods that
can be used in log2timeline modules when dealing with converting timestamps that are stored in
various formats into Epoch, and also to convert Epoch timestamps to textual representations.

This library should always be used when converting timestamps either to or from an epoch value
since the sub routines defined here can be used by all modules (code reuse, and if a quicker method
is developed it will make maintenance considerably easier).

All methods should be documented here in the code so that it will be easy for anyone to
use them in the code.

=head1 METHODS

=cut

package Log2t::Time;

use strict;
use DateTime;
use Date::Manip;
use Encode;
use DateTime::Format::Strptime;

use vars qw($VERSION);

use constant {
               LITTLE_E => 1,
               BIG_E    => 0
             };

$VERSION = "0.3";

=head2 C<Win2Unix>

A subroutine copied from ptfinder.pl developed by Andreas Schuster and
Csaba Barta.  This sub routine converts windows filetime into a unix 
format

n.b FILETIME is represented in UTC

Windows epoch is 1601-01-01 00:00:00, resolution 100ns

UNIX epoch is 1970-01-01 00:00:00, resolution 1s

Copyright (c) 2009 by Andreas Schuster and Csaba Barta.

=head3 Args:

=head4 Lo: An integer (32 bits) representing the lower 32 bits of the timestamp.

=head4 Hi: An integer (32 bits) representing the higher 32 bits of the timestamp.

=head3 Returns:

=head4 An integer representing the number of seconds since Epoch time.

=cut

sub Win2Unix($$) {

    # Convert windows FILETIME to UNIX format.
    my $Lo = shift;
    my $Hi = shift;
    my $Time;

    if (($Lo == 0) and ($Hi == 0)) {
        $Time = 0;
    }
    else {
        $Lo -= 0xd53e8000;
        $Hi -= 0x019db1de;
        $Time = int($Hi * 429.4967296 + $Lo / 1e7);
    }
    $Time = 0 if ($Time < 0);

    return $Time;
}

=head2 C<getNanoWinFileTime>

A small subroutine that returns the nanoseconds of a Windows FILETIME

=head3 Args:

=head4 l: An integer, 32 bits, representing the lower 32 bits of the timestamp.

=head4 h: An integer, 32 bits, representing the higher 32 bits of the timestamp.

=head3 Returns:

=head4 An integer that represents the nanoseconds of a FILETIME timestamp. 

=cut

sub getNanoWinFileTime($$) {
    my $l = shift;
    my $h = shift;
    my $time;

    return 0 if (($l == 0) and ($h == 0));

    $time = $h * 2**32 + $l;
    return ($time - 11644473600 * 1e7) % 1e7;
}

sub getWebKitTime($) {
    my $webkit_time = shift;

    my $time_offset = 11644473600;
    return $webkit_time - $time_offset;
}

=head2 C<Dos2Unix>

Taken from the dos2unixtime function from the tsk3/fs/fatfs_meta.c file from The Sleuthkit.
The logic and code taken there, and adapted to be a Perl code (the other is a C code)

** Brian Carrier [carrier <at> sleuthkit [dot] org]

** Copyright (c) 2006-2008 Brian Carrier, Basis Technology.  All Rights reserved

** Copyright (c) 2003-2005 Brian Carrier.  All rights reserved

**

** TASK

** Copyright (c) 2002 Brian Carrier, @stake Inc.  All rights reserved

**

**

** This software is distributed under the Common Public License 1.0

**

** Unicode added with support from I.D.E.A.L. Technology Corp (Aug '05)

Convert DOS DATE and TIME format to Unix Epoch.

DOS DATE is a two byte packet data where

0-4 DAY (1-31)

5-8 MONTH (1-12)

9-15 YEAR (from 1980)

DOS TIME is a two byte packet 

0-4 sec (divided by two)

5-10 min

11-15 hour

Links pointing towards further information:

B<http://msdn.microsoft.com/en-us/library/aa371853%28VS.85%29.aspx>

B<http://www.vsft.com/hal/dostime.htm>

=head3 Args:

=head4 date: Packed 16 bit (2 byte) value that represents the date.

=head4 time: Packed 16 bit (2 byte) value that represents the time of day.


=cut

sub Dos2Unix($$) {
    my $date = shift;
    my $time = shift;
    my $d;

    # and now to convert the time
    my $sec = (($time & 0x1f) >> 0) * 2;
    if (($sec < 0) || ($sec > 60)) {
        print STDERR
          "[TIME DOS2UNIX] Seconds not correctly formed ($sec).  Resetting to zero value\n";
        $sec = 0;
    }

    my $min = ($time & 0x7e0) >> 5;
    if (($min < 0) || ($min > 59)) {
        print STDERR
          "[TIME DOS2UNIX] Minutes not correctly formed ($min).  Resetting to zero value\n";
        $min = 0;
    }

    my $hour = ($time & 0xf800) >> 11;
    if (($hour < 0) || ($hour > 23)) {
        print STDERR
          "[TIME DOS2UNIX] Hour not correctly formed ($hour).  Resetting to zero value\n";
        $hour = 0;
    }

    # and to convert the date function
    my $day = ($date & 0x1f) >> 0;
    if (($day < 1) || ($day > 31)) {
        print STDERR "[TIME DOS2UNIX] Day not correctly formed ($day).  Resetting to zero value\n";
        $day = 1;
    }

    my $month = (($date & 0x1e0) >> 5);
    if (($month < 1) || ($month > 12)) {
        print STDERR
          "[TIME DOS2UNIX] Month not correctly formed ($month).  Resetting to zero value\n";
        $month = 1;
    }

    my $year = (($date & 0xfe00) >> 9) + 80;
    if (($year < 0) || ($year > 137)) {
        print STDERR
          "[TIME DOS2UNIX] Year not correctly formed ($year).  Resetting to zero value\n";
        $year = 0;
    }
    else {
        $year += 1900;
    }

    if (($sec == 0) && ($min == 0) && ($hour == 0)) {
        print STDERR
          "[TIME DOS2UNIX] Timestamp is WITHOUT ANY INFORMATION REGARDING TIME, ONLY THE DATE IS ACCURATE\n";
    }

    # construct a hash of the date
    $d = DateTime->new(
                       year      => $year,
                       month     => $month,
                       day       => $day,
                       hour      => $hour,
                       minute    => $min,
                       second    => $sec,
                       time_zone => 'GMT'
                      );

    # return the date in UTC
    return $d->epoch;
}

=head2 C<iso2epoch>

This routine transforms a date formated according to ISO 8601
to an epoch time (see definition on Wikipedia):

B<http://en.wikipedia.org/wiki/ISO_8601>

=head3 Args:

=head4 iso: A string containing the timestamp, in ISO_8601 notation.

=head4 tz: The timezone of the file.

=head3 Returns:

=head4 An integer representing the number of seconds since Epoch.

=cut

sub iso2epoch($$) {
    my ($sa, $sb) = 0, 0;
    my ($year, $month, $day, $hour, $min, $sec) = 0, 0, 0, 0, 0, 0;
    my ($a, $b);
    my @test;
    my $date;
    my $temp = undef;
    my $iso  = shift;
    my $tz   = shift;
    my $op;
    my $add_h = 0;
    my $add_m = 0;

    # modify the date into Epoch, its in ISO 8601 format
    # 2009-08-08T19:07Z
    ($a, $b) = split(/T/, $iso);

    # start by checking the YEAR part
    # can be YYYY YYYY-MM-DD YYYYMMDD  YYYY-MM
    if ($a =~ m/^\d{4}$/) {
        $year  = $a;
        $month = 1;
        $day   = 1;
        $sa    = 1;
    }
    elsif ($a =~ m/^\d{4}-\d{2}-\d{2}$/) {
        ($year, $month, $day) = split(/-/, $a);
        $sa = 1;
    }
    elsif ($a =~ m/^\d{8}$/) {
        $year  = substr $a, 0, 4;
        $month = substr $a, 4, 2;
        $day   = substr $a, 6, 2;
        $sa    = 1;
    }
    elsif ($a =~ m/^\d{4}-\d{2}$/) {
        ($year, $month) = split(/-/, $a);
        $day = 1;
        $sa  = 1;
    }
    else {
        $sa = 0;
    }

    # now to check the time part (b)
    # can be of value hh:mm:ss hhmmss hh:mm hhmm hh
    # and then a timezone can be added after

    # first check for signs of time zone
    @test = split(/-/, $b);

    if ($#test gt 0) {
        $b    = $test[0];
        $tz   = 'UTC';
        $temp = $test[1];
        $op   = 'm';
    }

    @test = split(/\+/, $b);
    if ($#test gt 0) {
        $b    = $test[0];
        $tz   = 'UTC';
        $temp = $test[1];
        $op   = 'p';
    }

    if (defined $temp) {
        $tz = 'UTC';
        if ($temp =~ m/^\d{2}$/) {
            if ($op eq 'p') {
                $add_h = $temp;
            }
            else {
                $add_h = -$temp;
            }
        }
        elsif ($temp =~ m/^\d{2}:\d{2}$/) {
            if ($op eq 'p') {
                $add_h = substr $temp, 0, 2;
                $add_m = substr $temp, 3, 2;
            }
            else {
                $add_h = -substr $temp, 0, 2;
                $add_m = -substr $temp, 3, 2;
            }
        }
        elsif ($temp =~ m/^\d{4}/) {
            if ($op eq 'p') {
                $add_h = substr $temp, 0, 2;
                $add_m = substr $temp, 2, 2;
            }
            else {
                $add_h = -substr $temp, 0, 2;
                $add_m = -substr $temp, 2, 2;
            }
        }
        else {
            print STDERR "Not correctly formatted\n";
        }
    }

    # check if it ends with Z
    if ($b =~ m/Z$/) {
        $tz = 'UTC';
        chop($b);
    }

    if ($b =~ m/G$/) {
        $tz = 'GMT';
        chop($b);
    }

    if ($b =~ m/^\d{2}:\d{2}:\d{2}$/) {
        ($hour, $min, $sec) = split(/:/, $b);
        $sb = 1;
    }
    elsif ($b =~ m/^\d{6}$/) {
        $hour = substr $b, 0, 2;
        $min  = substr $b, 2, 2;
        $sec  = substr $b, 4, 2;
        $sb   = 1;
    }
    elsif ($b =~ m/^\d{2}:\d{2}$/) {
        ($hour, $min) = split(/:/, $b);
        $sb = 1;
    }
    elsif ($b =~ m/^\d{4}$/) {
        $hour = substr $b, 0, 2;
        $min  = substr $b, 2, 2;
        $sec  = 0;
        $sb   = 1;
    }
    elsif ($b =~ m/^\d{2}$/) {
        $sb   = 1;
        $hour = $b;
        $min  = 0;
        $sec  = 0;
    }
    elsif ($b =~ m/^$/) {
        $sb   = 1;
        $hour = 0;
        $min  = 0;
        $sec  = 0;
    }
    else {
        $sb = 0;
    }

    # now to examine the time variable
    # format is:
    # hhmmss - hhmm - hh or hh:mm:ss hh:mm
    # then the time zone might be defined
    if ($sa and $sb) {

        # construct a hash of the date
        $date = DateTime->new(
                              year      => $year,
                              month     => $month,
                              day       => $day,
                              hour      => $hour + $add_h,
                              minute    => $min + $add_m,
                              second    => $sec,
                              time_zone => $tz
                             );

        # return the date in UTC
        return $date->epoch;
    }
    else {
        return -1;
    }
}

=head2 C<epoch2cftl>

A sub routine that converts an Epoch timestamp into a timestamp
that CFTL (Computer Forensics Time Lab accepts in it's XML schema).

=head3 Args:

=head4 epoch: An integer in the epoch format.

=head4 tz: The timezone of the timestamp.

=head3 Returns:

=head4 A string representing the timestamp in a format that CFTL accepts.

=cut

sub epoch2cftl($$) {
    my $epoch = shift;
    my $tz    = shift;

    my $iso = DateTime->from_epoch(epoch => $epoch, 'time_zone' => $tz);

    # set the timezone to UTC
    $iso->set_time_zone('UTC');

    return sprintf "%0.4d-%0.2d-%0.2d %0.2d:%0.2d:%0.2d.0", $iso->year, $iso->month, $iso->day,
      $iso->hour, $iso->minute, $iso->second;
}

=head2 C<epoch2text>

A sub routine that converts an Epoch timestamp into a textual human readable format.

The sub routine returns the text in three different formats depending on the value of the variable use_local.

The formats are:

+ [0] One value: Day Month DD YYYY HH:MM:SS (GMT)

+ [1] One value: Day Month DD YYYY HH:MM:SS (ZONE)

+ [3] Two values: MM/DD/YYYY and HH:MM:SS

=head3 Args:

=head4 epoch: An integer in the Epoch format

=head4 use_local: An integer that determines the format of the output, values can be found above in the description.

=head4 tz: The timezone of the timestamp.

=head3 Returns:

=head4 A string representing the timestamp, depending on the value of use_local.

=cut

sub epoch2text($$$) {
    my $epoch     = shift;
    my $use_local = shift;
    $use_local = int($use_local);

    # get the applied timezone
    my $tz = shift;

    my $iso = DateTime->from_epoch(epoch => $epoch, 'time_zone' => $tz);

    # set the timezone to the applied one
    $iso->set_time_zone($tz) if $use_local;
    $iso->set_time_zone('UTC') unless $use_local;

    return ((sprintf "%0.2d/%0.2d/%0.4d", $iso->month, $iso->day, $iso->year),
            (sprintf "%0.2d:%0.2d:%0.2d", $iso->hour, $iso->minute, $iso->second))
      if $use_local == 3;

    return sprintf "%s %s %0.2d %0.4d %0.2d:%0.2d:%0.2d (%s)", $iso->day_abbr, $iso->month_abbr,
      $iso->day, $iso->year, $iso->hour, $iso->minute, $iso->second, $tz
      if $use_local;
    return sprintf "%s %s %0.2d %0.4d %0.2d:%0.2d:%0.2d GMT", $iso->day_abbr, $iso->month_abbr,
      $iso->day, $iso->year, $iso->hour, $iso->minute, $iso->second
      unless $use_local;
}

=head2 C<month2int>

A small sub routine that takes as an input a string that is an abbreviated textual representation of a month and returns an integer,
that is the month value of that particular month, eg. Jan becomes 1, Nov becomes 11, etc.

=head3 Args:

=head4 Month: A string, abbreviated text of a month (eg Jan, Feb, Mar, ...)

=head3 Returns:

=head4 An integer, from 1-12

=cut

sub month2int($) {
    my $month = shift;

    # if we receive this as an unicode, remove additional 0x00
    $month =~ s/\x00//g;

    # change to lowercase
    $month = lc($month);

    my %mon2num =
      qw( jan 1  feb 2  mar 3  apr 4  may 5  jun 6 jul 7  aug 8  sep 9  oct 10 nov 11 dec 12 );

    return $mon2num{$month};
}

sub ftk2date($) {
    my $d = shift;
    my $stamp;    # the timestamp
    my $date;     # the date object

    # the date has the following format
    # 2008-Feb-23 00:24:38.812500 UTC
    # YYYY-Mon-DD HH:MM:SS.LESS TZ

    # split up the date function and fix it into variables
    #my ($da,$ti,$tz) = split( / /, $$d );
    #my ($year,$month,$day) = split( /-/, $da );
    #my ($hour,$min,$sec) = split( /:/, $ti);
    #my ($s,$t) = split( /\./, $sec );

    # remove the "unicode" stuff from the variables
    #$year =~ s/\x00//g;
    #$day =~ s/\x00//g;
    #$hour =~ s/\x00//g;
    #$min =~ s/\x00//g;
    #$s =~ s/\x00//g;
    #$tz =~ s/\x00//g;

    # make some checking
    #	return 0 unless ( $day < 32 && $day > 0 );
    #	return 0 unless ( $hour < 25 && $hour > -1 );
    #	return 0 unless ( $min < 60 && $min > -1 );
    #	return 0 unless ( $s < 60 && $s > -1 );

    # create the date variable
    #	$date = DateTime->new(
    #		year    =>      int($year),
    #		month   =>      month2int($month),
    #		day     =>      int($day),
    #		hour    =>	int($hour),
    #		minute  =>      int($min),
    #		second  =>      int($s),
    #		time_zone       => $tz
    #	);

    #	return $date->epoch;

    # remove the unicode "stuff" from the date object
    $stamp = $$d;
    $stamp =~ s/\x00//g;

    # check the date, see if it is properly formed
    if ($stamp =~
        /(\d{4})-([a-zA-Z]+)-(\d{1,2})\s(\d{1,2}):(\d{1,2}):(\d{1,2})\s([a-zA-Z\+\-0-9]+)/)
    {

        # make some checking
        return 0 unless ($3 < 32 && $3 > 0);
        return 0 unless ($4 < 25 && $4 > -1);
        return 0 unless ($5 < 60 && $5 > -1);
        return 0 unless ($6 < 60 && $6 > -1);

        # construct a hash of the date
        $date = DateTime->new(
                              year      => $1,
                              month     => month2int($2),
                              day       => $3,
                              hour      => $4,
                              minute    => $5,
                              second    => $6,
                              time_zone => $7
                             );

        #	print STDERR "[TIME] " . $date->epoch . "\n";
        # return the date in UTC
        return $date->epoch;
    }
    elsif ($stamp =~
          /(\d{4})-([a-zA-Z]+)-(\d{1,2})\s(\d{1,2}):(\d{1,2}):(\d{1,2})\.?\d+?\s([a-zA-Z\+\-0-9]+)/)
    {

        # make some checking
        return 0 unless ($3 < 32 && $3 > 0);
        return 0 unless ($4 < 25 && $4 > -1);
        return 0 unless ($5 < 60 && $5 > -1);
        return 0 unless ($6 < 60 && $6 > -1);

        # construct a hash of the date
        $date = DateTime->new(
                              year      => $1,
                              month     => month2int($2),
                              day       => $3,
                              hour      => $4,
                              minute    => $5,
                              second    => $6,
                              time_zone => $7
                             );

        #	print STDERR "[TIME] " . $date->epoch . "\n";
        # return the date in UTC
        return $date->epoch;
    }
    elsif ($stamp == 0) {
        print STDERR "[FTK2DATE] The timestamp was empty\n";
        return 0;
    }
    else {
        print STDERR "[FTK2DATE] The timestamp ($stamp) was not properly coded\n";
        return 0;
    }
}

sub epoch2iso($$) {
    my $epoch = shift;
    my $tz    = shift;

    my $iso = DateTime->from_epoch(epoch => $epoch, 'time_zone' => $tz);

    # set the timezone to UTC
    $iso->set_time_zone('UTC');

    return sprintf "%0.4d-%0.2d-%0.2dT%0.2d:%0.2d%0.2dZ", $iso->year, $iso->month, $iso->day,
      $iso->hour, $iso->minute, $iso->second;
}

sub is_date($) {

    # verify that we have a date value
    my $str = shift;

    # should be on the form YYYY:MM:DD HH:MM:SS
    my $return = $str =~ m/^\d{4}:\d{2}:\d{2} \d{2}:\d{2}:\d{2}/ ? 1 : 0;

    # check if string solely consists of zero's
    $return = 0 if $str =~ m/^0000:00:00 00:00:00/;

    return $return;

}

sub exif_to_epoch_new($$) {
    my $str = shift;
    my $tz  = shift;

    # we get the time in epoch format, yet in the host timezone

    # start by check for timezone settings
    my $time = int($str);

    # if we are only dealing with an integer
    return $time if $time eq $str;

    # otherwise examine a bit further
}

sub exif_to_epoch($$) {

    # know that this is a date formatted with exiftools
    my $str = shift;
    my $tz  = shift;
    my $date;
    my $sign;
    my $ofs_sec;

    # sometimes there is an error in the Image::Exiftool toolkit
    # and times appear three times in a row (fix that)
    my @t = split(/,/, $str);
    $str = $t[0];

    #print STDERR "[TIME] Time ($str) Timezone <$tz>\n";

    my ($y, $d) = split(/\s/, $str);

    my ($year, $month, $day) = split(/:/, $y);
    my ($hour, $min,   $s)   = split(/:/, $d);

    my ($sec, $ofs);

    # we can have the sec variable as SS+HH:MM for timezone
    if ($s =~ m/\+/) {

        #print STDERR "[TIME] WE HAVE A PLUS\n";
        ($sec, $ofs) = split(/\+/, $s);
        $sign = 1;
    }
    elsif ($s =~ m/\-/) {

        #print STDERR "[TIME] WE HAVE A MINUS\n";
        ($sec, $ofs) = split(/\-/, $s);
        $sign = 0;    # indicating a minus
    }
    else {
        $sec  = $s;
        $ofs  = undef;
        $sign = undef;
    }

    #print STDERR "[TIME] SEC $sec AND OFS $ofs\n";

    # check for timezone settings
    if ($sec =~ m/Z$/i or $sec =~ m/GMT$/i) {

        # remove the Z
        $sec =~ s/Z$//i;
        $sec =~ s/GMT$//i;

        # set the timezone
        $tz = 'UTC';
    }

    #print STDERR "[TIME] SEC IS [$sec]\n";
    # test if the seconds operator ends with a Z (indicating GMT)
    if ($sec =~ m/\d{2}\.([0-9]+)$/) {

        #print STDERR "[TIME] We have detected a .\n";
        # the seconds contain ms
        $sec = int($sec);
    }

    # a special check, if either the year or month is of zero value, we skip checking
    if ($year == 0) {
        return -1;
    }

    # check for valid months
    return -1 unless ($month > 0 && $month < 13);

    #print STDERR "[TIME] SEC $sec AND OFS $ofs\n";

    # check the offset
    if (defined $ofs) {

        # then we need to calculate the offset
        if ($ofs =~ m/\d{2}:\d{2}/) {
            my ($ofs_h, $ofs_m) = split(/:/, $ofs);

            # check if we are adding or subtracting time
            $ofs_sec = 60 * $ofs_m + 3600 * $ofs_h;
        }
        else {
            $ofs_sec = 3600 * int($ofs);
        }
    }

    eval {

        #print STDERR "[Time] $year-$month-$day $hour:$min:$sec $tz\n";
        $date = DateTime->new(
                              year      => $year,
                              month     => $month,
                              day       => $day,
                              hour      => $hour,
                              minute    => $min,
                              second    => $sec,
                              time_zone => $tz
                             );
    };
    if ($@) {
        print STDERR "[Time] Error from time routine (time passed $str).  $@\n";

        return -1;
    }
    else {

        # check out if there is an offset
        if (defined $ofs) {
            $date->subtract(seconds => $ofs_sec) if $sign;
            $date->add(seconds => $ofs_sec) unless $sign;
        }

        # return the time in eopch format
        return $date->epoch;
    }
}

# Author: Hal Pomeranz
# hal.pomeranz@mandiant.com
# Convert Mac "absolute time" values to Unix epoch
# These time values are just "number of seconds since Jan 1, 2001", so coversion
# is simple-- just add a constant value for the number of seconds from the start
# of the Unix epoch.

sub mac2epoch {
    my ($macabstime) = @_;
    return (int($macabstime) + 978307200);
}

# Author: Julien Touche
# julien (dot) t43 (at) gmail (dot ) com
# contributed to log2timeline as part of the volatility input module
## convert string to epoch
sub text2epoch($$) {
    my $string = shift;
    my $tz     = shift;    # added by Kristinn
    my $analyzer =
      DateTime::Format::Strptime->new(pattern => '%a %b %d %H:%M:%S %Y', time_zone => $tz)
      ;                    # time zone information added by Kristinn
    my $dt = $analyzer->parse_datetime($string);
    if ($dt) {
        return $dt->epoch;
    }
    else {
        return $string;
    }
}

# simple method (based on text2epoch) to convert the CSV date format back
# into Epoch (to read in the CSV time)
sub csv2epoch($$) {
    my $string = shift;
    my $tz     = shift;    # added by Kristinn

    my $analyzer = DateTime::Format::Strptime->new(pattern => '%m/%d/%Y %H:%M:%S', time_zone => $tz)
      ;                    # time zone information added by Kristinn
    my $dt = $analyzer->parse_datetime($string);
    if ($dt) {
        return $dt->epoch;
    }
    else {
        return $string;
    }
}

#	sol_date_calc
#
# A function that calculates a date object (Epoch time) from an input provided by a Flash cookie
# The date object may be either:
#	Epoch time in ms
#	Epoch time in s
# The function really accepts any value of a double number and then determines if it is truly a date
# object or just a number (compares it to likely date values)
#
sub sol_date_calc($$) {
    my $ms  = shift;    # the double number as it is read from the Flash Cookie
    my $ofs = shift;    # the current offset in hours from UTC
    my $sec;

    my $date;

    #print STDERR "MS EQUALS TO [$ms]\n";

    # check for "illegal" values, or non date values
    if ($ms lt 0 || $ms eq 'nan') {
        return 'nan';
    }

    # check if we have a time in Epoch (that is not ms)
    if (($ms > 793800000) && ($ms < (time() + 631065600))) {
        $sec = $ms;
    }
    else {

        # we have ms, so we need to divid by 1.000
        $sec = int($ms / 1000);
    }

    # check against a predefined date
    # 793800000 - Sun Feb 26 12:00:00 1995 GMT
    return 'nan' if ($sec < 793800000);

    # and now + 20 years ( 631065600 )
    return 'inf' if ($sec) > (time() + 631065600);

    # now we are pretty certain that we've got a date object, let's calculate the date
    $date = DateTime->from_epoch(epoch => $sec);

    #print STDERR "[DATECALC] The sec are: " . $sec . "\n";

    #$date->subtract( hours => $ofs );
    #printf STDERR "[DATECALC] The offset is %d\n",-$ofs;

    $sec = $date->epoch;

    #print STDERR "[DATECALC] EPOCH " . $date->epoch . "\n";

    return 'inf' if $sec eq -1;

    return $date->epoch;
}

#	hash_to_date
#
#
sub hash_to_date($$) {
    my $hash = shift;
    my $epoch;
    my $date;
    my $t;
    my $tz = shift;

    return undef if $hash->{'month'} eq '';
    return undef if $hash->{'time'}  eq '';

    #print STDERR '[HASH2DATE] M-: (' . $hash->{'month'} . ') T-: (' . $hash->{'time'} . ")\n";

    # date is of the form MONTH/DAY/YEAR
    # time is of the FORM HH:MM:SS AM/PM (or 24 hours)
    my ($month, $day, $year) = split(/\//, $hash->{'month'});

    #print STDERR "[HASH2DATE] M $month D $day Y $year\n";
    # check the values
    return undef if $month eq '';
    return undef if $day   eq '';
    return undef if $year  eq '';

    # check if the month day and year is a number
    return undef unless int($month) eq $month;
    return undef unless int($day)   eq $day;
    return undef unless int($year)  eq $year;

    # one more test
    # get the current year
    my @s        = localtime(time);
    my $cur_year = $s[5] + 1900;
    $cur_year = int($cur_year);

    #print STDERR "[HASH2DATE] YEAR <$year> AND NOW <$cur_year>\n";

    # and now to check if the year is within "reasonable" bounds
    return undef unless (($year < ($cur_year + 100)) and ($year > ($cur_year - 100)));

    #print STDERR "[TIME] MONTH IS $month AND DAY $day\n";
    # check day
    if (int($month) > 12) {

        # switch places
        $t     = $month;
        $month = $day;
        $day   = $t;
    }

    #print STDERR "[TIME] AFTER MONTH IS $month AND DAY $day\n";
    # check day

    my ($hour, $min, $sec) = split(/:/, $hash->{'time'});
    $hour = int($hour);
    $min  = int($min);

    # check values
    return undef if $sec  eq '';
    return undef if $min  eq '';
    return undef if $hour eq '';

    # check for AM/PM
    if ($sec =~ m/(\d+) ([A|P]M)/) {
        if ($2 eq 'AM') {
            $sec = int($1);
        }
        elsif ($2 eq 'PM') {
            $sec = int($1);
            $hour += 12 unless $hour == 12;
        }
        else {

            #print STDERR "[TIME] Wrong SECOND field ($sec)";
            return undef;
        }
    }

    # try to
    eval {
        $date = DateTime->new(
                              year      => $year,
                              month     => $month,
                              day       => $day,
                              hour      => $hour,
                              minute    => $min,
                              second    => $sec,
                              time_zone => $tz
                             );
    };
    if ($@) {

#print STDERR "[TIME] Unable to create a proper time from value (" . $hash->{'month'} . ' ' . $hash->{'time'} . ")\n";
#print STDERR "[TIME] Y $year M $month D $day H $hour M $min S $sec TZ $tz\n";
        print STDERR "[TIME] There was an error while trying to convert to Epoch: $@\n";
        return undef;
    }

    return $date->epoch;
}

sub pdf_to_date($) {

# PDF dates are in the form: D:20050718143045-04'00 or D:20091113194615
# the can also be in the form of "D:YYYY:MM:DD HH:M:SS"
# according to the PDF specifications:
#
#	7.9.4       Dates
#	Date values used in a PDF shall conform to a standard date format, which closely follows that of the
#	international standard ASN.1 (Abstract Syntax Notation One), defined in ISO/IEC 8824. A date shall be a text
#	string of the form
#	     ( D : YYYYMMDDHHmmSSOHH ' mm )
#	where:
#	     YYYY shall be the year
#	     MM shall be the month (01-12)
#	     DD shall be the day (01-31)
#	     HH shall be the hour (00-23)
#	     mm shall be the minute (00-59)
#	     SS shall be the second (00-59)
#	     O shall be the relationship of local time to Universal Time (UT), and shall be denoted by one of the
#	     characters PLUS SIGN (U+002B) (+), HYPHEN-MINUS (U+002D) (-), or LATIN CAPITAL LETTER Z
#	     (U+005A) (Z) (see below)
#	     HH followed by APOSTROPHE (U+0027) (') shall be the absolute value of the offset from UT in hours
#		     (00-23)
#	     mm shall be the absolute value of the offset from UT in minutes (00-59)
#	The prefix D: shall be present, the year field (YYYY) shall be present and all other fields may be present but
#	only if all of their preceding fields are also present. The APOSTROPHE following the hour offset field (HH) shall
#	only be present if the HH field is present. The minute offset field (mm) shall only be present if the
#	APOSTROPHE following the hour offset field (HH) is present. The default values for MM and DD shall be both
#	01; all other numerical fields shall default to zero values. A PLUS SIGN as the value of the O field signifies that
#	local time is later than UT, a HYPHEN-MINUS signifies that local time is earlier than UT, and the LATIN
#	CAPITAL LETTER Z signifies that local time is equal to UT. If no UT information is specified, the relationship of
#	the specified time to UT shall be considered to be GMT. Regardless of whether the time zone is specified, the
#	rest of the date shall be specified in local time.
#	EXAMPLE             For example, December 23, 1998, at 7:52 PM, U.S. Pacific Standard Time, is represented by the string
#	                    D : 199812231952

    my $text = shift;
    my ($relat, $year, $month, $day, $hour, $min, $sec);
    my $ofs;
    my ($ohour, $omin);    # offset in hour and minutes
    my $date;

    #print STDERR "[TIME] STRING IS BEFORE [$text]\n";
    # check the start
    return undef if substr $text, 0, 2 eq 'D:';

    #print STDERR "[TIME] STRING IS AFTER [$text]\n";

    # modify the text variable (remove the D: and uneccessary variables)
    $text =~ s/^D://;
    $text =~ s/://g;
    $text =~ s/\s+//g;

    # now we've removed all extra stuff and should be left with YYYYMMDDHHMMSS
    # this is in total 14 characters in length (plus possible time offset)
    # although the standard dictates that it is not necessary to include minutes and seconds
    # I still return with an undef unless they are assigned, since otherwise the timestamp
    # would be too inaccurate to rely upon
    return undef unless length($text) ge 14;

    #print STDERR "[TIME] Not a bad length...so continue\n";

    # get the date part
    $year  = substr $text, 0,  4;
    $month = substr $text, 4,  2;
    $day   = substr $text, 6,  2;
    $hour  = substr $text, 8,  2;
    $min   = substr $text, 10, 2;
    $sec   = substr $text, 12, 2;
    $relat = substr $text, 14, 1;

    # make sure we are dealing with numbers
    $year  = int($year);
    $month = int($month);
    $day   = int($day);
    $hour  = int($hour);
    $min   = int($min);
    $sec   = int($sec);

    #print STDERR "[TIME] Y $year M $month D $day H $hour M $min S $sec\n";
    # now to add some more checks to it (according to standard)
    return undef unless $month > 0 and $month < 13;
    return undef unless $day > 0   and $day < 32;
    return undef unless $hour > -1 and $hour < 24;
    return undef unless $min > -1  and $min < 60;
    return undef unless $sec > -1  and $sec < 60;

    #print STDERR "[TIME] Y $year M $month D $day H $hour M $min S $sec\n";

    # an extra check
    return undef unless $year eq int($year);

    # check offset
    if ($text =~ m/.+\-(.+)/) {

        # need to reduce the date
        $ofs = $1;

        # get the offset
        if ($ofs =~ m/\'/) {
            ($ohour, $omin) = split(/\'/, $ofs);
        }
        else {

            # check if this is longer
            my $length = length $ofs;
            if ($length == 3) {
                $ohour = $ofs;
                $omin  = 0;
            }
            elsif ($length == 5) {
                $ohour = int(substr $ofs, 0, 2);
                $omin  = int(substr $ofs, 2, 2);
            }
            else {
                $ohour = $ofs;
                $omin  = 0;
            }
        }

    }
    elsif ($text =~ m/.+\+(.+)/) {

        # need to increased the date
        $ofs = $1;

        ($ohour, $omin) = split(/\'/, $ofs);

        $ohour = -$ohour;
        $omin  = -$omin;
    }
    else {
        $ofs = 0;
    }

    if (int($sec) > 60) {
        $sec -= 60;
        $min++;

        if (int($min) > 60) {
            $hour++;
            $min -= 60;
        }
        if (int($hour) > 24) {
            $day++;
            $hour -= 24;
        }
    }

    #print STDERR "[TIME] Y $year M $month D $day H $hour M $min S $sec OFS $ofs\n";

    # try to
    eval {
        $date = DateTime->new(
                              year      => $year,
                              month     => $month,
                              day       => $day,
                              hour      => $hour,
                              minute    => $min,
                              second    => $sec,
                              time_zone => 'UTC'
                             );
    };
    if ($@) {

#print STDERR "[TIME] Unable to create a proper time from value (" . $hash->{'month'} . ' ' . $hash->{'time'} . ")\n";
#print STDERR "[TIME] Y $year M $month D $day H $hour M $min S $sec TZ $tz\n";
        print STDERR "[TIME] There was an error while trying to convert to Epoch: $@\n";
        return undef;
    }

    # and test if we need to increase/decrease
    if ($ofs) {
        $date->add(hours => $ohour, minutes => $omin);
    }

    return $date->epoch;
}

#       fix_epoch
#
# A simple routine that takes a time in Epoch, which is represented in a local timezone
# and returns the epoch time in UTC
#
# @parmas Reference to a variable that stores an epoch value
sub fix_epoch($$) {
    my $epoch = shift;
    my $tz    = shift;
    my ($a, $b, $diff);
    my $val;

    # figure out if we are in DST or not
    my $dt = DateTime->from_epoch(epoch => $$epoch, 'time_zone' => $tz);
    $val = 1 unless $dt->is_dst();
    $val = 8 if $dt->is_dst();

    eval {

        # start by constructing a datetime object using the provided timezone
        $a = DateTime->new(
                           year      => 2000,
                           month     => $val,
                           day       => 1,
                           hour      => 12,
                           minute    => 0,
                           second    => 0,
                           time_zone => $tz
                          );

        # then we construct another datetime object, now using UTC as our baseline
        $b = DateTime->new(
                           year      => 2000,
                           month     => $val,
                           day       => 1,
                           hour      => 12,
                           minute    => 0,
                           second    => 0,
                           time_zone => 'UTC'
                          );

  # now we need to calculate the difference between the two
  #$diff = $a->delta_ms( $b )->in_units('minutes');               # always returns a positive number

        $diff = $b->subtract_datetime($a)->in_units('minutes');

        # and finally to fix the data
        $$epoch -= ($diff * 60);
    };
    if ($@) {
        print STDERR "[Time] Unable to fix Epoch time $$epoch: \n $@\n";
        return 0;
    }

    # everything went smoothly
    return 1;
}

sub get_cur_local_time() {

    # get the time
    my ($second, $minute, $hour, $dayOfMonth, $m, $year, $dayOfWeek, $dayOfYear, $daylightSavings) =
      localtime();

    # "fix" it
    $year += 1900;

    # get the textual representation of month and weekday
    my @months   = qw(Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec);
    my @weekDays = qw(Sun Mon Tue Wed Thu Fri Sat Sun);

    # and return it
    return sprintf "%0.2d:%0.2d:%0.2d, %s %s %0.2d %0.4d ", $hour, $minute, $second,
      $weekDays[$dayOfWeek], $months[$m], $dayOfMonth, $year;
}

sub encase2date($$) {
    my $d  = shift;
    my $tz = shift;
    my $stamp;    # the timestamp
    my $date;     # the date object

    # the date has the following format:
    # 07/02/11 11:35:12
    # DD/MM/YY HH:MM:SS

    # remove the unicode "stuff" from the date object
    $stamp = $$d;
    $stamp =~ s/\x00//g;

    # check the date, see if it is properly formed
    if ($stamp =~ /(\d{1,2})\/(\d{1,2})\/(\d{1,2})\s(\d{1,2}):(\d{1,2}):(\d{1,2})/) {

        #       print STDERR "[DATE1] $1 - $2 - $3 - $4 - $5 - $6\n";
        # make some checking
        return 0 unless ($2 < 32 && $2 > 0);
        return 0 unless ($4 < 25 && $4 > -1);
        return 0 unless ($5 < 60 && $5 > -1);
        return 0 unless ($6 < 60 && $6 > -1);

        my $y = $3;
        $y += 1900;
        $y += 100 if $3 < 50;

        #       print STDERR "[DATE2] $1 - $2 - $3 - $4 - $5 - $6\n";
        # construct a hash of the date
        $date = DateTime->new(
                              year      => $y,
                              month     => $2,
                              day       => $1,
                              hour      => $4,
                              minute    => $5,
                              second    => $6,
                              time_zone => $tz
                             );

        return $date->epoch;
    }
    elsif ($stamp == 0) {
        print STDERR "[ENCASE2DATE] The timestamp was empty\n";
        return 0;
    }
    else {
        print STDERR "[ENCASE2DATE] The timestamp ($stamp) was not properly coded\n";
        return 0;
    }

    return 0;
}

=head2 C<exceldate2epoch>

A method that takes a timestamp that is defined in the native Excel format
and transforms that into an Epoch timestamp.

The Excel format is:

DDDD.TTTT

Where DDDD is the number of days elapsed since 01/01/1901 and TTTT is the 
number of seconds since the start of the day.

Further reading:

B<http://office.microsoft.com/en-us/access-help/on-time-and-how-much-has-elapsed-HA001110218.aspx>

B<http://support.microsoft.com/kb/214019>

Since Epoch is measured in seconds since 01/01/1970 there is only 69 year difference between
the two representations, so we can just simply calculate the difference and return that.

=head3 Args:

=head4 d: A string that represents the timestamp in the Excel format.

=head4 tz: The timezone of the file in question.

=head3 Returns:

=head4 An integer, representing the timestamp in Epoch format.

=cut

sub exceldate2epoch($$) {
    my $d  = shift;
    my $tz = shift;

    my ($days, $seconds);

    ($days, $seconds) = split(/\./, $d);
    $seconds = int($seconds / 100000);

    # since we have leap years every four years, let's add them to the picture
    my $year = int($days / 365);
    my $leap = 0;

    for (my $i = 0; $i < $year; $i++) {
        $leap = Log2t::Time::is_leap_year(1901 + int($i)) ? $leap + 1 : $leap;
    }
    print "Year is: " . int($days / 365) . " - Leap is $leap\n";

    return (int($days) * 24 * 60 * 60) + int($leap * 24 * 60 * 60) + int($seconds) -
      (69 * 365 * 24 * 60 * 60);

    #return (int($days) * 24 * 60 * 60) + int($leap * 24 * 60 * 60) - (69 * 365 * 24 * 60 * 60);
}

=head2 C<is_leap_year>

A small method used to determine if a given year is a leap year
or not.

Method derived from this document:

B<http://support.microsoft.com/kb/214019>

Essentially the method is split up in the following steps:

1: Is the year evenly divisible by 4? step 2: step 5

2: Is the year evenly divisible by 100? step 3: step 4

3: Is the year evenly divisible by 400? step 4: step 5

4: Leap year, return 1

5: Not a leap year, return 0

=head3 Args:

=head4 year: a four digit integer (year)

=head3 Returns:

=head4 1 if this is a leap year, 0 otherwise.

=cut

sub is_leap_year($) {
    my $year = int(shift);

    if ($year % 4 == 0) {
        if ($year % 100 == 0) {
            if ($year % 400 == 0) {
                return 1;
            }
            else {
                return 0;
            }
        }
        else {
            return 1;
        }
    }
    else {
        return 0;
    }
}

1;
__END__
