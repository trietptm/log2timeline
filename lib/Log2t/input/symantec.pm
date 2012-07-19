#################################################################################################
#    SYMANTEC LOGS
#################################################################################################
# this script is a part of the log2timeline program.
#
# This file implements a parser for Symantec log files
#
# Author: anonymous donator
# Version : 0.1
# Date : 7/27/2011
#
# The complete structure of a Symantec log file may be found at:
# http://www.symantec.com/business/support/index?page=content&id=TECH100099
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
package Log2t::input::symantec;

use strict;
use Log2t::base::input;    # the SUPER class or parent

use Log2t::BinRead;  # to work with binary files (during verification all files are treaded as such)
use Log2t::Common ':binary';

use vars qw($VERSION @ISA);
use Switch;

# inherit the base input module, or the super class.
@ISA = ("Log2t::base::input");

# version number
$VERSION = '0.1';

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
    return "Parse the content of a Symantec log file";
}

#  end
# A subroutine that closes everything, remove residues if any are left
#
# If there is no need for this subroutine to do anything, it is best to skip implementing
# it altogether (just remove it), since we are inheriting this subroutine from the SUPER
# class
sub end() {
    my $self = shift;

    return 1;
}

sub ReturnCategory {
    my $catlevel = shift(@_);

    switch ($catlevel) {
        case (1) { return "Infection"; }
        case (2) { return "Summary"; }
        case (3) { return "Pattern"; }
        case (4) { return "Security"; }
        default  { return $catlevel; }
    }

    return "Unknown";
}

sub ReturnAction {
    my $catlevel = shift(@_);

    switch ($catlevel) {
        case (1)  { return "Quarantined"; }
        case (2)  { return "Renamed"; }
        case (3)  { return "Deleted"; }
        case (4)  { return "Left alone"; }
        case (5)  { return "Cleaned"; }
        case (6)  { return "Cleaned or macros delted"; }
        case (7)  { return "Saved file"; }
        case (8)  { return "Left alone"; }
        case (9)  { return "Moved to backup location"; }
        case (10) { return "Renamed backup file"; }
        case (11) { return "Undo action in Quarantine View"; }
        case (12) { return "Write protected or lack of permissions - Unable to act on file"; }
        case (13) { return "Backed up file"; }
        case (14) { return "Pending analysis"; }
        case (15) { return "First action was partially successful; second action was Leave Alone"; }
        case (16) { return "A process needs to be terminated to remove a risk"; }
        case (17) {
            return "Prevent a risk from being logged or a user interface from being displayed";
        }
        case (18) { return "Performing a request to restart the computer"; }
        case (19) {
            return
              "Shows as Cleaned by Deletion in the Risk History in the UI and the Logs in the SSC";
        }
        case (20) {
            return "Auto-Protect prevented a file from being created; reported \"Access denied\"";
        }
        default { return $catlevel; }
    }

    return "Unknown";
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
    my $date;
    my @fields;

    # get the filehandle and read the next line
    my $fh = $self->{'file'};
    my $line = <$fh>;
    if (not $line) {
        print STDERR "[SYMANTEC] Unable to read in more lines.\n" if $self->{'debug'};
        return undef;
    }

    # then split up the data
    @fields = split(/,/, $line);

    #print "field = ||$fields[13]||\n";

    # break the date/time into chunks of two characters
    my @time = unpack("(A2)*", $fields[0]);

    # convert from hex to decimal
    $time[0] = hex($time[0]);
    $time[1] = hex($time[1]);
    $time[2] = hex($time[2]);
    $time[3] = hex($time[3]);
    $time[4] = hex($time[4]);
    $time[5] = hex($time[5]);

    # build the date
    # format is: Years since 1970 | Month (Jan = 0) | Day | Hour | Minute | Seconds
    # This is in local time
    $date = DateTime->new(
                          year      => ($time[0] + 1970),
                          month     => ($time[1] + 1),
                          day       => $time[2],
                          hour      => $time[3],
                          minute    => $time[4],
                          second    => $time[5],
                          time_zone => $self->{'tz'}
                         );

    # get it in the format log2timeline expects
    $date = $date->epoch();

    #print "date = $date ($time[0]/$time[1]/$time[2] $time[3]:$time[4]:$time[5])\n";

    # build the description string
    $text =
        'Category: '
      . ReturnCategory($fields[2])
      . (($fields[13]) ? (' | Description: ' . $fields[13])                : (''))
      . (($fields[6])  ? (' | Detected: ' . $fields[6])                    : (''))
      . (($fields[7])  ? (' | Location: ' . $fields[7])                    : (''))
      . (($fields[10]) ? (' | Action taken: ' . ReturnAction($fields[10])) : (''));

    # create the t_line variable
    %t_line = (
        'time' => { 0 => { 'value' => $date, 'type' => 'Entry Written', 'legacy' => 15 } },
        'desc' => $text,
        'short'      => 'Symantec event',
        'source'     => 'Symantec Log',
        'sourcetype' => 'HIPS',
        'version'    => 2,
        'extra'      => { 'user' => $fields[5], 'host' => $fields[4] }
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
    return "This parser parses Symantec log files.";
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
sub verify {
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
    eval { $line = Log2t::BinRead::read_ascii_until($self->{'file'}, \$ofs, "\n", 600); };
    if ($@) {
        $return{'success'} = 0;
        $return{'msg'}     = "Unable to process file ($@)";
    }

# symantec says there are 39 fields in Symantec AV Corporate Edition 8.x, 53 fields in 9.x and later
# however the actual number of fields counted can be different on windows vs linux
    my @fields = split(/,/, $line);

    #
    if ($#fields lt 40)    #$#fields ne 40 && $#fields ne 54 && ($#fields lt 57 && $#fields gt 59) )
    {
        $return{'success'} = 0;
        $return{'msg'}     = "Incorrect number of fields ($#fields)";
    }
    else {

        # do some additional checks and make sure that we do indeed have a symantec log
        # first field should be a time stamp consisting of six hexadecimal octets
        if ($fields[0] =~ /[0-9A-Fa-f]{12}/) {

            # one more check
            if ($fields[1] =~ /\d+/) {
                $return{'success'} = 1;
                print "Found symantec log\n" if ($self->{'debug'});
            }
            else {
                $return{'success'} = 0;
                $return{'msg'}     = 'Incorrect event number';
            }
        }
        else {
            $return{'success'} = 0;
            $return{'msg'}     = 'Incorrect timestamp format';
        }
    }

    #print "fields = $#fields\n";

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

