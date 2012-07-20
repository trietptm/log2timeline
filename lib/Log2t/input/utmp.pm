#################################################################################################
#    UTMP
#################################################################################################
# This script is a part of the log2timeline program.
#
# It implements a parser for Linux wtmp e wtmp files, with respect to the wtmp(5) specification
# (a reference here: http://linux.die.net/man/5/wtmp)
# Applies to btmp files too, in that case entries are related to failed logins.
#
# Author: Francesco Picasso
# Version : 0.1
# Date : 22/06/12
#
# Copyright 2012 Francesco Picasso (francesco.picasso ( a t ) gmail (d o t) com)
# Distributed with and under the same licensing terms as log2timeline
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

=pod

=head1 NAME

utmp - Linux wtmp/wtmpx/btmp files module parser.

=head1 DESCRIPTION

A relevant artifact during Linux exploration are users logins and logouts, both
successful and failed. Those information are kept inside wtmp and btmp file respectively,
normally found inside the /var/log directory.
The module parses the wtmp/wtmpx Linux files with respect to the wtmp(5) specification
(a reference here: http://linux.die.net/man/5/wtmp), extracting users logins and logouts.
The module can parse btmp files too since the internal format it's the same as wtmp.
The check between wtmp and btmp files can be made only on the file name: the output on
btmp files will show that every entry is a failed login.

=head1 METHODS

=cut

package Log2t::input::utmp;

use strict;
use Log2t::base::input;    # the SUPER class or parent
use Log2t::BinRead;  # to work with binary files (during verification all files are treaded as such)
use Log2t::Common ':binary';
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

=head2 C<new>

Module constructor.

=head3 Returns:

=head4 An instance of the class.

=cut

sub new() {
    my $class = shift;

    # now we call the SUPER class's new function, since we are inheriting all the
    # functions from the SUPER class (input.pm), we start by inheriting it's calls
    # and if we would like to overwrite some of its subroutines we can do that, otherwise
    # we don't need to include that subroutine
    my $self = $class->SUPER::new();

    # wtmp are binary files and there is no 'line' concept, even if they are composed
    # by many instances of the same data type (C struct utmp) called entry in this context.
    $self->{'multi_line'} = 0;

    # it's a file
    $self->{'type'} = 'file';

    # a file handle is enough
    $self->{'file_access'} = 0;

    # from utmp.h Linux header file
    #define UT_UNKNOWN            0
    #define RUN_LVL               1
    #define BOOT_TIME             2
    #define NEW_TIME              3
    #define OLD_TIME              4
    #define INIT_PROCESS          5
    #define LOGIN_PROCESS         6
    #define USER_PROCESS          7
    #define DEAD_PROCESS          8
    #define ACCOUNTING            9
    #define UT_LINESIZE           12
    #define UT_NAMESIZE           32
    #define UT_HOSTSIZE           256
    # struct utmp {
    #   short ut_type;              /* type of login */
    #   pid_t ut_pid;               /* pid of login process */
    #   char ut_line[UT_LINESIZE];  /* device name of tty - "/dev/" */
    #   char ut_id[4];              /* init id or abbrev. ttyname */
    #   char ut_user[UT_NAMESIZE];  /* user name */
    #   char ut_host[UT_HOSTSIZE];  /* hostname for remote login */
    #   struct exit_status ut_exit; /* The exit status of a process
    #                                  marked as DEAD_PROCESS. */
    #   long ut_session;            /* session ID, used for windowing*/
    #   struct timeval ut_tv;       /* time entry was made.  */
    #   int32_t ut_addr_v6[4];      /* IP address of remote host.  */
    #   char pad[20];               /* Reserved for future use.  */
    # };

    # utmp entry type
    $self->{'ut_types'} = {
                            0 => "empty",           # No valid user accounting information
                            1 => "Run Level",       # The system's runlevel
                            2 => "Boot Time",       # Time of system boot
                            3 => "New Time",        # Time after system clock changed
                            4 => "Old Time",        # Time when system clock changed
                            5 => "Init",            # Process spawned by the init process
                            6 => "Login",           # Session leader of a logged in user
                            7 => "User Process",    # Normal process
                            8 => "Process End",     # Terminated process
                            9 => "Accounting"       # Accouting
                          };

    # utmp entry size
    # Note that summing each in the struct utmp declaration gives 382 bytes
    # Probably due to alignment, the short ut_type is 4 bytes long (so, no short applies)
    # TBR TODO here: please provide counterchecks regarding previous assertion
    $self->{'ut_size'} = 384;

    # this is the template used to unpack (parse) an utmp entry
    $self->{'unpack_template'} = 'L L A32 A4 A32 A256 S S L L L L4 A20';

    # flag to distinguish between successful logins (wtmp) or failed logins (btmp)
    # the check (and eventually the flag setting) is done in the verify subroutine
    $self->{'is_btmp'} = 0;

    # if set, the module will output some entries normally skipped since not
    # really related to users logins/logouts (es: tty start at boot time)
    # TBR TODO here where to take those input parameter??
    $self->{'detailed'} = 0;

    bless($self, $class);
    return $self;
}

=head2 C<get_version>

A simple subroutine that returns the version number of the input module.

=head3 Returns:

=head4 A string representing the version number.

=cut

sub get_version() {
    return $VERSION;
}

=head2 C<get_description>

A simple subroutine that returns a string containing a description of
the funcionality of the input module. This string is used when a list of
all available input modules is printed out.

=head3 Returns:

=head4 A string containing a description of the input module.

=cut

sub get_description() {
    return "Parse the content of Linux wtmp/wtmpx/btmp files";
}

=head2 C<get_time>

B<UPDATE_ME>

This is the main "juice" of the input module. It parses the input file
and produces a timestamp object that get's returned (or if we said that
self->{'multi_line'} = 0 it will return a single hash reference that contains
multiple timestamp objects within it.

This subroutine needs to be implemented at all times and this comments need
to be updated to reflect the logic of the routine, what it does and how
it does it... are there any risks, might there be loss of data, possibly provide
some tips on analysis, etc...

=cut

sub get_time() {
    my $self = shift;

    # the hash of all timestamp objects and its counter
    my %t_lines;
    my $t_counter = 0;

    # the hash of currently logged users, key is ut_line
    my %TTY = ();

    # an utmp record entry
    my $entry;

    open(UTMPFH, "<", ${ $self->{'name'} });
    binmode(UTMPFH);

    while (read(UTMPFH, $entry, $self->{'ut_size'})) {
        my $short = '';
        my $desc  = '';

        my (
            $utType, $pid,       $utLine, $utId,   $utUser, $utHost, $exTerm,
            $exExit, $utSession, $tvSec,  $tvUsec, $utAddr, $unused
           ) = unpack($self->{'unpack_template'}, $entry);

        if (1 == $utType) {

            # RunLevel
            # conservative check
            if ($utUser ne 'runlevel' and $utUser ne 'shutdown') {
                print STDERR
                  "ERROR (skip entry): RunLevel but user '$utUser' is not [runlevel|shutdown]!\n";
                next;
            }

            # shutdown!
            if ($utLine eq '~' and $utUser eq 'shutdown') {
                $short = 'SHUTDOWN';
                for my $key (keys %TTY) {
                    my $delta    = $tvSec - $TTY{$key}[1];
                    my $deltaMin = int($delta / 60);
                    my $deltaSec = $delta % 60;
                    $desc .= "user=$TTY{$key}[0] line=$key DOWN session=$deltaMin:$deltaSec; ";
                }
                %TTY = ();
            }
            if ($utUser eq 'runlevel') {
                if (not $self->{'detailed'}) {
                    print STDERR
                      "Skip entry (no detailed input) ut_type=$utType ut_user=$utUser ut_line=$utLine\n";
                    next;
                }
            }
        }
        elsif (2 == $utType) {

            # BootTime
            if ($utUser ne 'reboot') {
                print STDERR "ERROR (skip entry): BootTime but user '$utUser' is not [reboot]!\n";
                next;
            }
            if ($utLine eq '~' and $utUser eq 'reboot') {
                $short = 'BOOTING';

                # ideally we should not have users logged in during boot time!
                # It happens (depending on log file) that some users never logged out..
                # To avoid ut_line conflicting errors logged users are PURGED out
                for my $key (keys %TTY) {
                    my $delta    = $tvSec - $TTY{$key}[1];
                    my $deltaMin = int($delta / 60);
                    my $deltaSec = $delta % 60;
                    $desc .= "user=$TTY{$key}[0] line=$key PURGED session=$deltaMin:$deltaSec; ";
                }
                %TTY = ();
            }
        }
        elsif (3 == $utType or 4 == $utType) {

            #NewTime,OldTime
            # TBR TODO missing samples here
        }
        elsif (5 == $utType) {

            #Init
        }
        elsif (6 == $utType) {

            #Login
            if ($utHost eq '' and $utUser eq 'LOGIN') {
                if (not $self->{'detailed'}) {
                    print STDERR
                      "Skip entry (no detailed input) ut_type=$utType ut_user=$utUser ut_line=$utLine\n";
                    next;
                }
            }
        }
        elsif (7 == $utType) {

            #User Process
            $short = 'LOGIN ';
            my $key = $utLine;
            if ($TTY{$key}) {
                print STDERR
                  "ERROR (skip entry): '$utUser' logged on '$utLine' used by $TTY{$key}[0]!\n";
                next;
            }
            $TTY{$key} = [ "$utUser\@$utHost", $tvSec ];
            $desc = "user=$utUser\@$utHost logged in on line=$key; ";
            $desc .= 'now=';
            for $key (keys %TTY) { $desc .= "$TTY{$key}[0]_$key "; }
        }
        elsif (8 == $utType) {

            #Process End
            $short = 'LOGOUT';
            my $key = $utLine;
            if ($TTY{$key}) {
                if ($TTY{$key}[1] == 0) {
                    print STDERR "ERROR '$key' never logged in ???!\n";
                    next;
                }
                my $delta    = $tvSec - $TTY{$key}[1];
                my $deltaMin = int($delta / 60);
                my $deltaSec = $delta % 60;
                $desc =
                  "user=$TTY{$key}[0] logged out from line=$key session=$deltaMin:$deltaSec; ";
                delete $TTY{$key};
                $desc .= 'now=';
                for $key (keys %TTY) { $desc .= "$TTY{$key}[0]_$key "; }
            }
            else {
                if ($utHost eq '' and $utUser eq '') {
                    if (not $self->{'detailed'}) {
                        print STDERR
                          "Skip entry (no detailed input) ut_type=$utType ut_user=$utUser ut_line=$utLine\n";
                        next;
                    }
                }
                else { $desc = "user='$utUser' on line='$utLine' logged out WITHOUT login; "; }
            }
        }
        elsif (9 == $utType) {

            #Accounting
        }
        else {
            print STDERR "ERROR: Unexpected ut_type '$utType'!\n";
        }

        if ($self->{'is_btmp'}) {
            %TTY   = ();
            $short = "FAILED ";
            $desc  = "user=$utUser\@$utHost login failed on line=$utLine; ";
        }

        my $utTypeString = $self->{'ut_types'}->{$utType};
        $utTypeString = "unknown" unless defined $utTypeString;
        my $ipv4String = join ".", map { (($utAddr >> 8 * ($_)) & 0xFF) } 0 .. 3;
        my $srcType = "$short";
        $srcType = "Failed Login" if ($self->{'is_btmp'});

        $t_lines{ $t_counter++ } = {
            'time'   => { 0 => { 'value' => $tvSec, 'type' => 'Time Written', 'legacy' => 15 } },
            'desc'   => $desc,
            'short'  => $short,
            'source' => 'LOG',
            'sourcetype' => "$srcType",
            'version'    => 2,

            # TBR TODO perhaps it's better to remove 'host' since it refers eventually
            # to the remote host connecting (es: ssh, telnet)...
            'extra' => { 'user' => $utUser, 'host' => $utHost, 'terminal' => $utLine }
                                   };

        #$nameString  = "[$desc] $note type=$utTypeString line=$utLine user=$utUser ";
    }
    close(UTMPFH);
    return \%t_lines;
}

=head2 C<get_help>

A simple subroutine that returns a string containing the help 
message for this particular input module.

=head3 Returns:

=head4 A string containing a help description for this input module.

=cut

sub get_help() {
    return "A relevant artifact during Linux exploration are users logins and logouts, both
successful and failed. Those information are kept inside wtmp and btmp file respectively,
normally found inside the /var/log directory.
The module parses the wtmp/wtmpx Linux files with respect to the wtmp(5) specification
(a reference here: http://linux.die.net/man/5/wtmp), extracting users logins and logouts.
The module can parse btmp files too since the internal format it's the same as wtmp.
The check between wtmp and btmp files can be made only on the file name: the output on
btmp files will show that every entry is a failed login.";
}

=head2 C<verify>

The module verify subroutine makes these checks to understand if it's
the right file:
- check if input it's a file (correct) or a directory (wrong)
- check name: if the name includes 'wtmp' or 'btmp' in it
  Note that renamed files will be skipped!
- check if filesize is a multiple of entry size (384 bytes)
  Note that size-corrupted will be skipped!
- check the first 4 bytes if they contain a valid known utmp entry type
  Note that extensions to what is defined in the linux vanilla kernel will
  make files skipped!

=head3 Returns:

=head4 A reference to a hash that contains two keys/values.

success -> INT, either 0 or 1 (meaning not the correct structure, or the correct one)
msg     -> A short description why the verification failed (if the value of success is zero that is).

=cut

sub verify() {
    my $self = shift;

    # define an array to keep
    my %return;
    my $file_size;
    my $tag;
    my $file_name = ${ $self->{'name'} };

    $return{'success'} = 0;
    $return{'msg'}     = 'success';

    # file/directory check
    return \%return unless -f $file_name;

    # name check
    if (not $file_name =~ m/(wtmp|btmp)/) {
        $return{'msg'} = 'Wrong file name';
        return \%return;
    }
    else {
        # set the flag that input could be a btmp (failed logins)
        $self->{'is_btmp'} = 1 if ($file_name =~ m/btmp/);
    }

    # size check
    $file_size = (stat($self->{'name'}))[7];
    if ($file_size % $self->{'ut_size'}) {
        $return{'msg'} = "Wrong file size ($file_size not multiple of $self->{'ut_size'})";
        return \%return;
    }

    # ut_type check
    eval {
        open(IF, $self->{'name'});
        binmode(IF);

        my $ofs = 0;
        Log2t::BinRead::set_endian(LITTLE_E);
        my $ut_type = Log2t::BinRead::read_32($self->{'file'}, \$ofs);

        # solely based on known ut_types! Need to be updated in the case
        if (defined $self->{'ut_types'}->{$ut_type}) {

            # return OK only here!
            $return{'success'} = 1;
        }
        else {
            $return{'msg'} = "Unmanaged utmp type $ut_type in first entry";
        }
        close(IF);

        # this last check is not related to the processed file but
        # it's a defensive check to be sure that what we will unpack
        # it's waht we assume to be
        my $ut_template_size = length(pack($self->{'unpack_template'}, ()));
        if ($ut_template_size != $self->{'ut_size'}) {
            $return{'msg'} =
              "Wrong utmp template size ($ut_template_size, expected $self->{'ut_size'})";
            $return{'success'} = 0;
        }
    };
    if ($@) {
        close(IF);
        $return{'success'} = 0;
        $return{'msg'}     = "Unable to process file ($@)";
        return \%return;
    }
    return \%return;
}

1;

__END__
