#################################################################################################
#    ALTIRIS LOGS
#################################################################################################
# this script is a part of the log2timeline program.
#
# This file implements a parser for the AeXAMInventory.txt, AeXAMDiscovery.txt (disabled), and AeXProcessList.txt log files
#
# NOTE: It is possible that AeXAMInventory can have a missing start time. In this case, the discovery time (if available) will be used as the time instead of the last start time
#    Due to this, always look at the description field to make sure that the timestamp used as the date + time refers to what you are expecting!
#
# Author: anonymous donator
# Version : 0.1
# Date : 7/22/2011
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

package Log2t::input::altiris;

use strict;
use Log2t::base::input;    # the SUPER class or parent

#use Log2t::Numbers;  # work with numbers, round-up, etc...
#use Log2t::Network;  # some routines that deal with network information
use Log2t::BinRead;  # to work with binary files (during verification all files are treaded as such)
use Log2t::Common ':binary';

#use Log2t::Time;  # for time manipulations
#use Log2t:Win;    # for few Windows related operations, GUID translations, etc..
#use Log2t:WinReg;  # to recover deleted information from registry
use vars qw($VERSION @ISA);

# inherit the base input module, or the super class.
@ISA = ("Log2t::base::input");

# version number
$VERSION = '0.1';

# by default these are the global varibles that get passed to the module
# by the engine.
# These variables can therefore be used in the module without needing to
# do anything to initalize them.
#
#  $self->{'debug'}  - (int) Indicates whether or not debug is turned on or off
#  $self->{'quick'}   - (int) Indicates if we will like to do a quick verification
#  $self->{'tz'}    - (string) The timezone that got passed to the tool
#  $self->{'temp'}    - (string) The name of the temporary directory that can be used
#  $self->{'text'}    - (string) The path that is possible to add to the input (-m parameter)
#  $self->{'sep'}     - (string) The separator used (/ in Linux, \ in Windows for instance)
#

#  new
# this is the constructor for the subroutine.
#
# If this input module uses all of the default values and does not need to define any new value, it is best to
# skip implementing it altogether (just remove it), since we are inheriting this subroutine from the SUPER
# class
sub new() {
    my $class = shift;

    # now we call the SUPER class's new function, since we are inheriting all the
    # functions from the SUPER class (input.pm), we start by inheriting it's calls
    # and if we would like to overwrite some of its subroutines we can do that, otherwise
    # we don't need to include that subroutine
    my $self = $class->SUPER::new();

    # the available log types
    $self->{'types'} = {
        1 => 'XeXAMInventory',

        #2 => 'XeXAMDiscovery',
        3 => 'AeXProcessList'
                       };

    # bless the class ;)
    bless($self, $class);

    return $self;
}

#   init
#
# The init call resets all variables that are global and might mess up with recursive
# scans.
#
# This subroutine is called after the file has been verified, and before it is parsed.
#
# If there is no need for this subroutine to do anything, it is best to skip implementing
# it altogether (just remove it), since we are inheriting this subroutine from the SUPER
# class
sub init() {
    my $self = shift;

    return 1;
}

#   get_version
# A simple subroutine that returns the version number of the format file
# There shouldn't be any need to change this routine, it serves its purpose
# just the way it is defined right now. (so it shouldn't be changed)
#
# @return A version number
sub get_version() {
    return $VERSION;
}

#   get_description
# A simple subroutine that returns a string containing a description of
# the funcionality of the format file. This string is used when a list of
# all available format files is printed out
#
# @return A string containing a description of the input module
sub get_description() {

    # change this value so it reflects the purpose of this module
    return "Parse the content of an XeXAMInventory or AeXProcessList log file";
}

#  end
# A subroutine that closes everything, remove residudes if any are left
#
# If there is no need for this subroutine to do anything, it is best to skip implementing
# it altogether (just remove it), since we are inheriting this subroutine from the SUPER
# class
sub end() {
    my $self = shift;

    return 1;
}

# convert a timestamp in an altiris log (iso8601)
# returned time has local and UTC components!
# the format of the date/time is YYYYMMDDhhmmss.<?fractions of a second?>+240 (pretty much ISO8601)
# 20110118080628.296000+240 = 01/18/2011 08:06:28.296000 +240 = +4 hours to get UTC time.
sub ConvertAltirisTime($) {
    my %evTime;
    my $altTime = shift(@_);
    $altTime =~ /(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})\.(\d+)([\+-])(\d+)/;

    # get the epoch time
    # the timestamp is in local time, but instead of using
    # the supplied timezone, we will get it directly from the altiris
    # timestamp after this
    $altTime = DateTime->new(
                             year      => $1,
                             month     => $2,
                             day       => $3,
                             hour      => $4,
                             minute    => $5,
                             second    => $6,
                             time_zone => 'UTC'
                            );
    $evTime{'local'} = $altTime->epoch();

    # modify the local epoch time into UTC epoch time using the timezone information
    if    ($8 eq '-') { $evTime{'UTC'} = $evTime{'local'} - ($9 * 60); }
    elsif ($8 eq '+') { $evTime{'UTC'} = $evTime{'local'} + ($9 * 60); }
    else              { $evTime{'local'} = -1; $evTime{'UTC'} = -1; }

    #print "local time is:".$evTime{'local'}.", UTC time is:".$evTime{'UTC'}."\n";
    return \%evTime;
}

#  get_time
# This is the main "juice" of the input module. It parses the input file
# and produces a timestamp object that get's returned (or if we said that
# self->{'multi_line'} = 0 it will return a single hash reference that contains
# multiple timestamp objects within it.
#
# This subroutine needs to be implemented at all times
sub get_time() {
    my $self = shift;

    # the timestamp object
    my %t_line;
    my $text;
    my $date = -1;
    my @content;
    my $user;
    my $host;

    # get the filehandle and read the next line
    my $fh = $self->{'file'};
    my $line = <$fh> or return undef;

    my $shrtDesc;

    # check if we read in only a newline
    if ($line eq "\n") {

        # print "found blank line\n";
        # for now, just return a blank hash
        return \%t_line;
    }

    # first remove any newlines
    $line =~ s/\r|\n//g;

    # then split up the data into separate locations
    @content = split('\t', $line);

    # each file type has a different format and different information
    # Types are:
    #  1 => 'XeXAMInventory',
    #  2 => 'XeXAMDiscovery',
    #  3 => 'AeXProcessList'
    if ($self->{'type'} == 1) {

# XeXAMInventory is
# Manufacturer | Internal Name | File Version | File Name | Product Name | Known As | User | Domain | Discovered | Last Start | ?Denial Count? | Run Count | Total Run Time (sec) | Avg CPU Usage | Peak Memory (bytes)
# Discovered is the date the application was discovered by application metering software
# Last Start is the date the application was monitored
# Total run time is described as "Total amount of time during the last application monitoring period
#   that the application was used in seconds. This value is determined by monitoring the application process and is updated every 30 seconds"
# [Altiris, Inc.  AeXNSAgent  6.0.0.2406  aexnsagent.exe  Altiris Agent  6.0.0.2406  SYSTEM  LOCALMACHINE  20110118080628.296000+240  20110318072537.062000+240  0  0  0  0  0]

        #epoch
        my $time1;
        my $time2;

        #datetime
        my $discDT    = 0;
        my $lsStartDT = 0;

        #remove the first and last characters ('[' and ']')
        $content[0] = substr($content[0], 1);
        chop($content[$#content]);

        # print "new content is $content[0] and $content[$#content]\n";

        #print "process is $content[3]\n";
        #print " time1 = $content[8], time 2 = $content[9]\n";

        # get the discovery time (if able) and convert it into epoch time
        if ($content[8] ne '') {

            # get the date/time and convert it into something log2timeline expects
            # ConvertAltirisTime will return the localized time
            $time1 = ConvertAltirisTime($content[8]);

            #print "time1 is %time1\n";
            #print "time is:".$time1->{'local'}."\n";
            #print "time is:".$time1->{'UTC'}."\n";

            if ($time1->{'UTC'} == -1) {
                print STDERR "Could not convert discovery time!\n" if $self->{'debug'};
                return \%t_line;
            }
            else {
                $discDT = DateTime->from_epoch('epoch' => $time1->{'local'});
            }
        }
        else {
            print STDERR "Discovery time missing! Skipping...\n" if $self->{'debug'};
            return \%t_line;
        }

        # get the last start time if able
        if ($content[9] ne '') {

            # get the date/time and convert it into something log2timeline expects
            # ConvertAltirisTime will return the localized time
            $time2 = ConvertAltirisTime($content[9]);

            if ($time2->{'UTC'} == -1) {
                print STDERR "Could not convert start time!\n" if $self->{'debug'};
                return \%t_line;
            }
            else {
                $date = $time2->{'UTC'};
                $lsStartDT = DateTime->from_epoch('epoch' => $time2->{'local'});
            }
        }
        else {
            print STDERR "Last start time missing! Using discovery time instead...\n"
              if $self->{'debug'};
            $time2 = $time1;
            $date  = $time1->{'UTC'};
        }

        #print "time1: $time1, time2: $time2\n";

        # fill out a useful description
        $text =
            'Filename: '
          . $content[3]
          . (($content[0] ne '') ? ' | Manufacturer: ' . $content[0]  : '')
          . (($content[1] ne '') ? ' | Internal Name: ' . $content[1] : '')
          . (($content[2] ne '') ? ' | File Version: ' . $content[2]  : '')
          . (($content[4] ne '') ? ' | Product Name: ' . $content[4]  : '')
          . (($content[5] ne '') ? ' | Known As: ' . $content[5]      : '');
        $text .=
            (($content[7] ne '') ? ' | Domain: ' . $content[7] : '')
          . ' | Discovered: '
          . (($discDT) ? ($discDT->ymd . ' ' . $discDT->hms) : ('Unavailable'))
          . ' | Last Start: '
          . (($lsStartDT) ? ($lsStartDT->ymd . ' ' . $lsStartDT->hms) : ('Unavailable'));
        if ($content[11] != 0) {
            $text .=
                ' | Run Count: '
              . $content[11]
              . '  | Total Run Time: '
              . $content[12]
              . ' | Avg CPU Usage: '
              . $content[13]
              . ' | Peak Memory: '
              . $content[14];

            #print "|$11 | $12 | $13 | $14\n"
        }

        $user = $content[6];

        #$host = $content[7];
        $shrtDesc = $content[3] . ' found in inventory';

        #print $text.' ('.$content[4].')'."\n";
        #print "time1 = $time1, time2 = $time2\n";
    }

#elsif($self->{'type'}==2)
#{
# XeXAMDiscovery is
# Manufacturer | Internal Name | File Version | File Name | Product Name  |  Product Version | [TAB]
# Altiris  AeXCustInv  6.1.1075.0  aexcustinv.exe  Altiris AeXCustInv  6.1.1075.0  [TAB]

    # there are no time stamps in this file, so use the file's time
    #  $date ;

# build a useful description string
#  $text = 'File Name: '.$content[3].(($content[0] ne '')?' | Manufacturer: '.$content[0]:'').(($content[1] ne '')?' | Internal Name: '.$content[1]:'').(($content[2] ne '')?' | File Version: '.$content[2]:'').(($content[4] ne '')?' | Product Name: '.$content[4]:'')
#  $shrtDesc = $content[3].' discovered';
#}
    elsif ($self->{'type'} == 3) {

# AeXProcessList is
# PID || Start Date || File Path || User || Domain || ?Denied? || ?Total Execution Time (sec)? || ?Peak Memory Usage (bytes)? || ?Avg CPU usage?
# [1572  20110419081010.375000+240  \??\C:\WINDOWS\system32\winlogon.exe  SYSTEM  LOCALMACHINE  0  5362.7656  26861568  0.1012]

        #remove the first and last characters ('[' and ']')
        $content[0] = substr($content[0], 1);
        chop($content[$#content]);

        # convert the time
        $date = ConvertAltirisTime($content[1]);

        if ($date->{'UTC'} == -1) {
            print "Could not convert time!\n";
        }

        $date = $date->{'UTC'};

        # build a useful description string
        $text = 'PID: '
          . $content[0]
          . ' | File Path: '
          . $content[2]
          . ' | Domain: '
          . $content[4]
          . ' | Total Execution Time: '
          . $content[6]
          . ' | Peak Memory Usage: '
          . $content[7]
          . ' | Avg CPU Usage: '
          . $content[8];
        $user = $content[3];

        #$host = $content[4];
        $shrtDesc = substr($content[2], rindex($content[2], '\\') + 1) . ' running';

        #print "$shrtDesc\n";
    }
    else {

        # probably shouldn't have gotten here. weird.
    }

# The timestamp object looks something like this:
# The fields denoted by [] are optional and might be used by some modules and not others.
# The extra field gets in part populated by the main engine, however some fields might be created in the module,
# for instance if it is possible to extract the username it gets there, or the hostname. Other values might be
# source ip (src-ip) or some other values that might be of interest yet are not part of the main variables.
# Another interesting field that might be included in the extra field is the URL ('url').  If it is possible to
# show the user where he or she can get additional information regarding the event that is being produced
# this is a good place to put it in, for example Windows events found inside the Windows Event Log contain
# valuable information that can be further read... so in the evt.pm module a reference to the particular event is
# placed inside this variable:
#   $t_line{'extra'}->{'url'} =http://eventid.net/display.asp?eventid=' . $r{evt_id} . '&source=' . $source
#
# %t_line {
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
#

    # create the t_line variable
    %t_line = (
        'time'  => { 0 => { 'value' => $date, 'type' => 'Entry Written', 'legacy' => 15 } },
        'desc'  => $text,
        'short' => $shrtDesc,
        'source'     => 'Altiris Log',
        'sourcetype' => 'HIPS',
        'version'    => 2,
        'extra'      => { 'user' => $user }    #, 'host' => $host }
              );

    return \%t_line;
}

#  get_help
# A simple subroutine that returns a string containing the help
# message for this particular format file.
# @return A string containing a help file for this input module
sub get_help() {

    # this message contains the full message that gest printed
    # when the user calls for a help on a particular module.
    #
    # So this text that needs to be changed contains more information
    # than the description field.  It might contain information about the
    # path names that the file might be found that this module parses, or
    # URLs for additional information regarding the structure or forensic value of it.
    return "This parser parses the log file X and it might be found on location Y.";
}

#  verify
# This subroutine is very important.  Its purpose is to check the file or directory that is passed
# to the tool and verify its structure. If the structure is correct, then this module is suited to
# parse said file or directory.
#
# This is most important when a recursive scan is performed, since then we are comparing all files/dir
# against the module, making it vital for it to be both accurate and optimized.  Slow verification
# subroutine means the tool will take considerably longer time to complete, too vague confirmation
# could also lead to the module trying to parse files that it is not capable of parsing.
#
# The subroutine returns a reference to a hash that contains two keys,
#  success    -> INT, either 0 or 1 (meaning not the correct structure, or the correct one)
#  msg    -> A short description why the verification failed (if the value of success
#      is zero that is).
sub verify() {
    my $self = shift;

    # define an array to keep
    my %return;
    my $line;

    $return{'success'} = 0;
    $return{'msg'}     = 'success';

# to make things faster, start by checking if this is a file or a directory, depending on what this
# module is about to parse (and to eliminate shortcut files, devices or other non-files immediately)
    return \%return unless -f ${ $self->{'name'} };

    # start by setting the endian correctly
    Log2t::BinRead::set_endian(BIG_E);

    my $ofs = 0;

    # now we try to read from the file
    eval {

# now read a line and figure out if we are dealing with XeXAMInventory, XeXAMDiscovery, AeXProcessList, or something else
        $line = Log2t::BinRead::read_ascii_until($self->{'file'}, \$ofs, "\n", 400);

        my @fields = split('\t', $line);

        if ($#fields ne 8 && $#fields ne 14) {

            #print "only $#fields found!\n";
            $return{'success'} = 0;
            $return{'msg'}     = 'Incorrect number of fields';
            return \%return;
        }

# First check for an AeXProcessList log
# [1572  20110419081010.375000+240  \??\C:\WINDOWS\system32\winlogon.exe  SYSTEM  LOCALMACHINE  0  5362.7656  26861568  0.1012]
        if ($line =~
            /^\[(\d+)\t([\d\.\+]+)\t(.*?)\t(.*?)\t(.*?)\t(\d+)\t(\d+\.\d+)\t(\d+)\t(\d+\.\d+)\]\s*$/
           )
        {
            print STDERR "Found AeXProcessList log\n" if $self->{'debug'};
            $self->{'type'} = 3;
            $return{'success'} = 1;
        }

# next check for an XeXAMInventory log
# [Altiris, Inc.  AeXNSAgent  6.0.0.2406  aexnsagent.exe  Altiris Agent  6.0.0.2406  SYSTEM  LOCALMACHINE  20110118080628.296000+240  20110318072537.062000+240  0  0  0  0  0]
        elsif ($line =~
            /^\[(.*?)\t(.*?)\t(.*?)\t(.*?)\t(.*?)\t(.*?)\t(.*?)\t(.*?)\t([\d\.\+]+)\t([\d\.\+]+)\t(\d+)\t(\d+)\t(.*?)\t(.*?)\t(.*?)\]\s*$/
          )
        {
            print STDERR "Found XeXAMInventory log\n" if $self->{'debug'};
            $self->{'type'} = 1;
            $return{'success'} = 1;
        }

# now check for an XeXAMDiscovery log
# Microsoft Corporation  cmd  5.1.2600.2180 (xpsp_sp2_rtm.040803-2158)  cmd.exe  Microsoft® Windows® Operating System  5.1.2600.2180
#elsif($#fields==6 && $line =~ /^(.*?)\t(.*?)\t(.*)\t(.*?)\t(.*?)\t(.*?)\t(.*?)\s*$/)
#{
#  #print "found XeXAMDiscovery log\n";
#  $self->{'type'} = 2;
#  $return{'success'} = 0;
#  $return{'msg'} = 'XeXAMDiscovery log parsing is currently not available';
#}
# not something this module can parse
        else {
            $return{'success'} = 0;
            $return{'msg'}     = 'Wrong magic value or format';
        }
    };
    if ($@) {
        $return{'success'} = 0;
        $return{'msg'}     = "Unable to process file ($@)";
    }

    return \%return;
}

1;

__END__

=pod

=head1 NAME

structure - An example input module for log2timeline

=head1 METHODS

=over 4

=item new

A default constructor for the input module. There are no parameters passed to the constructor, however it defines the behaviour of the module.  That is to say it indicates whether or not this module parses a file or a directory, and it also defines if this is a log file that gets parsed line-by-line or a file that parses all the timestamp objects and returns them all at once.

=item init

A small routine that takes no parameters and is called by the engine before a file is parsed.  This routine takes care of initializing global variables, so that no values are stored from a previous file that got parsed by the module to avoid confusion.

=item end

Similar to the init routine, except this routine is called by the engine when the parsing is completed.  The purpose of this routine is to close all database handles or other handles that got opened by the module itself (excluding the file handle) and to remove any temporary files that might still be present.

=item get_time

This is the main routine of the module.  This is the routine that parses the actual file and produces timestamp objects that get returned to the main engine for further processing.  The routine reads the file or directory and extracts timestamps and other needed information to create a timestamp object that then gets returned to the engine, either line-by-line or all in one (as defined in the constructor of the module).

=item verify

The purpose of this routine is to verify the structure of the file or directory being passed to the module and tell the engine whether not this module is capable of parsing the file in question or not. This routine is therfore very important for the recursive search of the engine, and it is very important to make this routine as compact and optimized as possible to avoid slowing the tool down too much.

=item get_help()

Returns a string that contains a longer version of the description of the output module, as well as possibly providing some assistance in how the module should be used.

=item get_version()

Returns the version number of the module.

=item get_description()

Returns a string that contains a short description of the module. This short description is used when a list of all available modules is printed out.

=back

=cut

