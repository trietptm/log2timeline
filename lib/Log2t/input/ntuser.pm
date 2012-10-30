#################################################################################################
#     NTUSER (formerly userassist)
#################################################################################################
# this script reads the user registry file (NTUSER.DAT) and parses it.  It then further extracts
# the user assist part of the registry and produces a bodyfile containing the timeline information
# that can be used directly with the script mactime from TSK collection.
#
# The specification of the body file can be found here:
#  http://wiki.sleuthkit.org/index.php?title=Body_file
#
# This script was originally based on the userassist.pl from the RegRipper (regripper.net),
# written by H. Carvey.  The script consists of most parts of the function pluginmain from
# that file.  Since the structure of log2timeline is different from that of RegRipper, that
# function had to be split up into several functions and some changes made to the function
# (some features taken out while others added in).  But essentially for the Windows XP
# part this is the same code.
# The code was taken from the 20080726 version of userassist.pl.
#
# Support for the Windows 7/Vista UserAssist keys was added by me after reading the
# article "Windows 7 UserAssist Registry keys" by Didier Stevens in the Into The Boxes
# magazine, q1 2009
#
# For ShellBags read: http://www.dfrws.org/2009/proceedings/p69-zhu.pdf
#
# The code was then further expanded to read more keys from the NTUSER.DAT file, so that
# it does not only include entries from the UserAssist key but various keys that are commonly
# found within the NTUSER.DAT file.
#
# Author: Kristinn Gudjonsson
# Version : 1.0
# Date : 11/05/11
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
#-----------------------------------------------------------
# userassist.pl
# Plugin for Registry Ripper, NTUSER.DAT edition - gets the
# UserAssist values
#
# Change history
#  20080726 - added reference to help examiner understand Control
#             Panel entries found in output
#  20080301 - updated to include run count along with date
#
#
#
# copyright 2008 H. Carvey
#-----------------------------------------------------------
package Log2t::input::ntuser;

use strict;
use Log2t::base::input;    # the SUPER class or parent
use Parse::Win32Registry qw(:REG_);
use Log2t::Common ':binary';
use Log2t::BinRead;
use Log2t::WinReg;         # for deleted entries
use Log2t::Time;
use Log2t::Win;
use Encode;

use vars qw($VERSION @ISA);

# inherit the base input module, or the super class.
@ISA = qw( Log2t::base::input );

#@ISA = qw( Log2t::base::input Log2t::WinReg::Ntuser );

# version number
$VERSION = '1.0';

##########################################################################################################################
#    PARSING FUNCTIONS
#------------------------------------------------------------------------------------------------------------------------#
# the default parsing of an object
sub _parse_default {
    my $self = shift;

    my $ts   = $self->{'value'}->get_timestamp();
    my $name = shift;

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
    # we've got all the values
    # create the t_line variable
    $self->{'container'}->{ $self->{'cont_index'}++ } = {
        'time' => { 0 => { 'value' => $ts, 'type' => 'Last Written', 'legacy' => 15 }, },
        'desc'       => "Key name: HKEY_USER/$name",
        'short'      => $name,
        'source'     => 'REG',
        'sourcetype' => 'NTUSER key',
        'version'    => 2,
        'extra'      => { 'user' => $self->{'username'}, }
                                                        };

    return 1;

}

sub _populate_folder {
    my $self = shift;
    my $k    = $self->{'value'};    # the key
    my $fbag = shift;               # the bag from previous path
    my $kp   = shift;               # the KeyPath
    my $id = shift;    # the ID of the bag associated with this particular field (found in parent)

    print STDERR
      "[ShellBag] -----------------------------------------------------------------------\n"
      if $self->{'debug'};
    print STDERR "[ShellBag] Populating folder with parent slot number $id (", $fbag->{'ascii'},
      ") [", $fbag->{'utf'}, "] - $kp\n"
      if $self->{'debug'};

    my $fn;            # the aquired file name/folder
    my $temp;          # a temporary value
    my %bag;           # values extracted from bag

    my $rk = $self->{'reg'}->get_root_key;

    # fix the path variables a bit
    $fbag->{'ascii'} =~ s/\\/\//g;      # change \ to /
    $fbag->{'ascii'} =~ s/\/\//\//g;    # change // to /
    $fbag->{'utf'}   =~ s/\\/\//g;      # change \ to /
    $fbag->{'utf'}   =~ s/\/\//\//g;    # change // to /

    my $nk;                             # new key
    my $v;                              # value

    # get all the values beneath (and thus the filenames/paths)
    my @ar = $k->get_list_of_values();

    # the slot number of the parent
    my $slot;

    # get the NodeSlot value for the key, this is the number that represent
    # the bag name, and it is also the index to the hash $h
    # n.b. this is the id of the PARENT, that is the actual key being read, not the
    # sub values, that get parsed throught the array ar
    $v = $k->get_value('NodeSlot');
    if ($v) {
        $slot = $v->get_data();
    }
    else {
        $slot = -1;
    }

    print STDERR "[ShellBag] Reading slot number for folder: $slot\n" if $self->{'debug'};

    # assign the values of the parsed object
    unless ($id == 0) {
        print STDERR "[ShellBag] Assigning slot $slot to UTF ", $fbag->{'utf'}, "\n"
          if $self->{'debug'};

        # don't assign the Desktop folder a value
        $self->{'f_struct'}->{$slot}->{'ascii'}   = $fbag->{'ascii'};
        $self->{'f_struct'}->{$slot}->{'utf'}     = $fbag->{'utf'};
        $self->{'f_struct'}->{$slot}->{'parent'}  = $id;
        $self->{'f_struct'}->{$slot}->{'key'}     = $kp;
        $self->{'f_struct'}->{$slot}->{'mod'}     = $fbag->{'mod'};
        $self->{'f_struct'}->{$slot}->{'created'} = $fbag->{'created'};
        $self->{'f_struct'}->{$slot}->{'access'}  = $fbag->{'access'};
    }

    # navigate through the subkeys
    foreach (@ar) {

        # check if numeric
        if ($_->get_name() =~ m/[0-9]+/) {

            # we need to decode this value
            $v = $_->get_data();

            #open( NOW, ">Nr_" . $_->get_name() . '_ID_' . $id . '_' .  int(rand(190)+50) );
            #binmode( NOW );
            #print NOW $v;
            #close(NOW);

            print STDERR "[ShellBag] We are parsing the number [", $_->get_name(), "]\n"
              if $self->{'debug'};

            # decode the data variable
            # --------------------------------------------------------------------------------------
            #       Information gathered from here
            #
            # http://www.42llc.net/index.php?option=com_myblog&task=tag&category=Enscript&Itemid=39
            # --------------------------------------------------------------------------------------
            #
            # struct BagFile {
            #   USHORT BagSize; // Length of BAG structure
            #   USHORT flags;
            #   DWORD size;
            #   USHORT ModifiedDOSDATE; //Modified Date GMT
            #   USHORT ModifiedDOSTIME; //Modified Time GMT
            #   USHORT FlagUnknown;
            #   char  name[]; // (DOS short filename)
            #   //extra byte here sometimes to align to even byte boundary
            #   UnicodeBagData UnicodeData;
            # };
            #
            # struct UnicodeBagData {
            #      USHORT LengthOfUnicodeStructure;
            #      USHORT Short1; // 0x0003 for XP, 0x0008 for win7
            #      USHORT Short2; // 0x0004
            #      USHORT Short3; // 0xBEEF
            #      USHORT CreatedDOSDATE; // Created Date GMT
            #      USHORT CreatedDOSTIME; // Created Time GMT
            #      USHORT AccessedDOSDATE; // Accessed Date GMT
            #      USHORT AccessedDOSTIME; // Accessed Time GMT
            #      DWORD Unknown; // usually xp = 0x14, win7 = 0x2A
            #      // Vista and Windows 7 Extra Fields (22 bytes total)
            #      DWORD  MftFileId;
            #      USHORT Unknown1;
            #      USHORT MftSequence;
            #      DWORD  Unknown2;
            #      DWORD  Unknown3;
            #      DWORD  Unknown4;
            #      USHORT Unknown5;
            #      // END Vista extra fields
            #      wchar name; // Unicode Filename
            #      USHORT Unknown6;
            # };
            #
            # --------------------------------------------------------------------------------------
            #
            # this is not really how I've seen the ShellBag format being constructed as.... so
            # the first variable is a USHORT BagSize one.... although it seems that you need to add
            # either one, two or three to get the actual size...
            # The flag is not a USHORT, it's a one byte, and depending on it, we see the beginning
            # of the ASCII code:
            #  Flag  ASCII
            #  0x46   0x05
            #  0x2F  0x03
            #  0x31  0x0E
            #  0x2E  X (UTF 0x0A)
            #  0xC3  0x05
            #  0x41  0x05
            #  0xB1  0x0E
            #  0x2E  x
            #  0x42  0x05
            #   0x71  x

            if ($self->{'debug'}) {
                printf STDERR "[UA SHELL] The content of the cell is 0x";

                # go through the entire content  of the V variable
                my $di = 0;
                while ($di < length($v)) {
                    printf STDERR "%0.4x ", unpack("n", substr($v, $di, 2));
                    $di += 2;
                }
                print STDERR "\t";
                $di = 0;
                while ($di < length($v)) {
                    printf STDERR "%s", substr($v, $di++, 1);
                }

                print STDERR "\n";
            }

            # date is eight bytes, divided in two four byte fields (MS-DOS 32)

            # start from the beginning
            my $ofs = 0;

            # read the length
            $bag{'length'} = unpack("v", substr($v, $ofs, 2)) + 2;
            $ofs += 2;

            print STDERR "[ShellBags] The length of the record is $bag{'length'}\n"
              if $self->{'debug'};

            # check for the flags
            $bag{'flags'} = unpack("c", substr($v, $ofs, 1));
            $bag{'flags'} = $bag{'flags'} & 0xff;

            printf STDERR "[ShellBags] Read the flags {0x%x}\n", $bag{'flags'} if $self->{'debug'};

         # set the default values of the timestamps (as zero) since some of the bags don't update it
            $bag{'access'}  = 0;
            $bag{'created'} = 0;
            $bag{'mod'}     = 0;

            # the structure depends on the previously read flag...
            if ($bag{'flags'} == 0x46) {
                print STDERR "[FLAG - 46] WE START AT 0x05 (pure ASCII)\n" if $self->{'debug'};
                $ofs = 0x5;

                # Set the ASCII bag
                $bag{'ascii'} = $fbag->{'ascii'} . '/' unless $fbag->{'ascii'} eq '';
                $bag{'ascii'} = '' if $fbag->{'ascii'} eq '';

                my $t = $self->_read_shell_ascii(\$v, \$ofs);

                # Set the UTF bag
                $bag{'utf'} = $fbag->{'utf'} . '/' unless $fbag->{'utf'} eq '';
                $bag{'utf'} = '' if $fbag->{'utf'} eq '';

                $bag{'utf'} .= $t;

                $bag{'ascii'} .= $t;

                $t = $self->_read_shell_ascii(\$v, \$ofs);
                $bag{'ascii'} .= ' (' . $t . ')';

            }
            elsif ($bag{'flags'} == 0x2f) {
                print STDERR "[FLAG - 2F] WE START AT 0x03 (pure ASCII)\n" if $self->{'debug'};
                $ofs = 0x3;

                # Set the ASCII bag
                $bag{'ascii'} = $fbag->{'ascii'} . '/' unless $fbag->{'ascii'} eq '';
                $bag{'ascii'} = '' if $fbag->{'ascii'} eq '';

                my $t = $self->_read_shell_ascii(\$v, \$ofs);

                # Set the UTF bag
                $bag{'utf'} = $fbag->{'utf'} . '/' unless $fbag->{'utf'} eq '';
                $bag{'utf'} = '' if $fbag->{'utf'} eq '';

                $bag{'utf'} .= $t;

                $bag{'ascii'} .= $t;

            }
            elsif ($bag{'flags'} == 0x31) {
                print STDERR "[FLAG - 31] WE START AT 0x0E (both)\n" if $self->{'debug'};

                # start by reading date objects
                $ofs = 8;
                $bag{'mod_date'} = unpack("v", substr($v, $ofs, 2));
                $ofs += 2;
                $bag{'mod_time'} = unpack("v", substr($v, $ofs, 2));
                $ofs += 2;
                eval { $bag{'mod'} = Log2t::Time::Dos2Unix($bag{'mod_date'}, $bag{'mod_time'}); };
                if ($@) {
                    print STDERR "[ShellBag] Unable to parse the timestamp for modification date\n";
                    $bag{'mod'} = 0;
                }

                $ofs = 0x0e;

                # Set the ASCII bag
                $bag{'ascii'} = $fbag->{'ascii'} . '/' unless $fbag->{'ascii'} eq '';
                $bag{'ascii'} = '' if $fbag->{'ascii'} eq '';

                $bag{'ascii'} .= $self->_read_shell_ascii(\$v, \$ofs);

                # round the number to an even number
                $ofs = int($ofs / 2 + 0.99) * 2;

                $ofs += 8;

                # find the remaining dates
                $bag{'created_date'} = unpack("v", substr($v, $ofs, 2));
                $ofs += 2;
                $bag{'created_time'} = unpack("v", substr($v, $ofs, 2));
                $ofs += 2;
                $bag{'access_date'} = unpack("v", substr($v, $ofs, 2));
                $ofs += 2;
                $bag{'access_time'} = unpack("v", substr($v, $ofs, 2));
                $ofs += 2;

                eval {
                    $bag{'created'} =
                      Log2t::Time::Dos2Unix($bag{'created_date'}, $bag{'created_time'});
                };
                if ($@) {

                    # THE DEBUG REQUIRMENT SHOULD BE REMOVED WHEN MORE STABLE
                    print STDERR
                      "[ShellBags] Error while trying to convert the date object\n Error: $@\n"
                      if $self->{'debug'};
                    $bag{'created'} = 0;
                }

                eval {
                    $bag{'access'} =
                      Log2t::Time::Dos2Unix($bag{'access_date'}, $bag{'access_time'});
                };
                if ($@) {

                    # THE DEBUG REQUIRMENT SHOULD BE REMOVED WHEN MORE STABLE
                    print STDERR
                      "[ShellBags] Error while trying to convert the date object\n Error: $@\n"
                      if $self->{'debug'};
                    $bag{'access'} = 0;
                }

                $ofs += 4;
                printf STDERR "[SHELL] Starting to read (A %s) at offset 0x%x\n", $bag{'ascii'},
                  $ofs
                  if $self->{'debug'};

                # Set the UTF-8 bag
                $bag{'utf'} = $fbag->{'utf'} . '/' unless $fbag->{'utf'} eq '';
                $bag{'utf'} = '' if $fbag->{'utf'} eq '';

                $bag{'utf'} .= $self->_read_shell_utf(\$v, \$ofs, $bag{'length'});

            }
            elsif ($bag{'flags'} == 0x2e) {
                print STDERR "[FLAG - 2E] WE START AT 0x0A (pure UTF)\n" if $self->{'debug'};

                # Set the ASCII bag
                $bag{'ascii'} = $fbag->{'ascii'} . '/' unless $fbag->{'ascii'} eq '';
                $bag{'ascii'} = '' if $fbag->{'ascii'} eq '';

                $bag{'ascii'} .= '?';

                # Set the UTF bag
                $bag{'utf'} = $fbag->{'utf'} . '/' unless $fbag->{'utf'} eq '';
                $bag{'utf'} = '' if $fbag->{'utf'} eq '';

                $bag{'utf'} .= '?';

                #        $ofs = 0xa;
                #
                #        # Set the UTF bag
                #        $bag{'utf'} = $fbag->{'utf'} . '/' unless $fbag->{'utf'} eq '';
                #        $bag{'utf'} = '' if $fbag->{'utf'} eq '';
                #
                #        my $t = $self->_read_shell_utf( \$v, \$ofs, $bag{'length'} );
                #
                #        # Set the ASCII bag
                #        $bag{'ascii'} = $fbag->{'ascii'} . '/' unless $fbag->{'ascii'} eq '';
                #        $bag{'ascii'} = '' if $fbag->{'ascii'} eq '';
                #
                #        $bag{'ascii'} .= $t;
                #        $bag{'utf'} .= $t;

            }
            elsif ($bag{'flags'} == 0xC3) {
                print STDERR "[FLAG - C3] WE START AT 0x05 (pure ASCII)\n" if $self->{'debug'};
                $ofs = 0x5;

                # Set the ASCII bag
                $bag{'ascii'} = $fbag->{'ascii'} . '/' unless $fbag->{'ascii'} eq '';
                $bag{'ascii'} = '' if $fbag->{'ascii'} eq '';

                my $t = $self->_read_shell_ascii(\$v, \$ofs);

                # Set the UTF bag
                $bag{'utf'} = $fbag->{'utf'} . '/' unless $fbag->{'utf'} eq '';
                $bag{'utf'} = '' if $fbag->{'utf'} eq '';

                $bag{'utf'}   .= $t;
                $bag{'ascii'} .= $t;

            }
            elsif ($bag{'flags'} == 0x41) {
                print STDERR "[FLAG - 41] WE START AT 0x05 (pure ASCII, double)\n"
                  if $self->{'debug'};
                $ofs = 0x5;

                # Set the ASCII bag
                $bag{'ascii'} = $fbag->{'ascii'} . '/' unless $fbag->{'ascii'} eq '';
                $bag{'ascii'} = '' if $fbag->{'ascii'} eq '';

                my $t = $self->_read_shell_ascii(\$v, \$ofs);

                # Set the UTF bag
                $bag{'utf'} = $fbag->{'utf'} . '/' unless $fbag->{'utf'} eq '';
                $bag{'utf'} = '' if $fbag->{'utf'} eq '';

                $bag{'utf'}   .= $t;
                $bag{'ascii'} .= $t;

                $t = $self->_read_shell_ascii(\$v, \$ofs);
                $bag{'ascii'} .= '(' . $t . ')';

            }
            elsif ($bag{'flags'} == 0xb1) {
                print STDERR "[FLAG - B1] WE START AT 0x0E (both)\n" if $self->{'debug'};
                $ofs = 0xe;

                # Set the ASCII bag
                $bag{'ascii'} = $fbag->{'ascii'} . '/' unless $fbag->{'ascii'} eq '';
                $bag{'ascii'} = '' if $fbag->{'ascii'} eq '';

                $bag{'ascii'} .= $self->_read_shell_ascii(\$v, \$ofs);

                # increment the offset
                $ofs = int($ofs / 2 + 0.99) * 2;
                $ofs += 20;

                #$ofs += 22;

                printf STDERR "[SHELL] Starting to read (A %s) at offset 0x%x\n", $bag{'ascii'},
                  $ofs
                  if $self->{'debug'};

                # Set the UTF bag
                $bag{'utf'} = $fbag->{'utf'} . '/' unless $fbag->{'utf'} eq '';
                $bag{'utf'} = '' if $fbag->{'utf'} eq '';

                $bag{'utf'} .= $self->_read_shell_utf(\$v, \$ofs, $bag{'length'});

            }
            elsif ($bag{'flags'} == 0x42) {
                print STDERR "[FLAG - 42] WE START AT 0x05 (pure ASCII, double)\n"
                  if $self->{'debug'};
                $ofs = 0x5;

                # Set the ASCII bag
                $bag{'ascii'} = $fbag->{'ascii'} . '/' unless $fbag->{'ascii'} eq '';
                $bag{'ascii'} = '' if $fbag->{'ascii'} eq '';

                my $t = $self->_read_shell_ascii(\$v, \$ofs);

                # Set the UTF bag
                $bag{'utf'} = $fbag->{'utf'} . '/' unless $fbag->{'utf'} eq '';
                $bag{'utf'} = '' if $fbag->{'utf'} eq '';

                $bag{'utf'}   .= $t;
                $bag{'ascii'} .= $t;

                $t = $self->_read_shell_ascii(\$v, \$ofs);
                $bag{'ascii'} .= '(' . $t . ')';

            }
            elsif ($bag{'flags'} == 0x71) {
                print STDERR "[FLAG  - 71] WE ARE NOT TO READ ANY ...\n" if $self->{'debug'};

                # Set the ASCII bag
                $bag{'ascii'} = $fbag->{'ascii'} . '/' unless $fbag->{'ascii'} eq '';
                $bag{'ascii'} = '' if $fbag->{'ascii'} eq '';

                $bag{'ascii'} .= '?';

                # Set the UTF bag
                $bag{'utf'} = $fbag->{'utf'} . '/' unless $fbag->{'utf'} eq '';
                $bag{'utf'} = '' if $fbag->{'utf'} eq '';

                $bag{'utf'} .= '?';

            }
            else {
                printf STDERR "[FLAG] WE DONT KNOW WHERE TO START (0x%0.2x)\n", $bag{'flags'};
            }

            print STDERR "\n" if $self->{'debug'};

#      {
#        # full fledged reading
#        $bag{'flags'} = unpack( "v", substr( $v, $ofs, 2 ) ) ;
#        $ofs+=2;
#        $bag{'size'} = unpack( "v", substr( $v, $ofs, 4 ) ) ;
#        $ofs+=4;
#
#        $bag{'mod_date'} = unpack( "v", substr( $v, $ofs, 2 ) ) ;
#        $ofs+=2;
#        $bag{'mod_time'} = unpack( "v", substr( $v, $ofs, 2 ) ) ;
#        $ofs+=2;
#        eval
#        {
#          $bag{'mod'} = Log2t::Time::Dos2Unix( $bag{'mod_date'}, $bag{'mod_time'} );
#        };
#        if( $@ )
#        {
#          print STDERR "[ShellBag] Unable to parse the timestamp for modification date\n";
#          $bag{'mod'} = 0;
#        }
#
#        #print STDERR "[ShellBag] Modified time: ", $bag{'mod'} , " [", $bag{'mod_date'}, "] (", $bag{'mod_time'}, ") \n" if $self->{'debug'};
#
#        $bag{'unk_flags'} = unpack( "v", substr( $v, $ofs, 2 ) ) ;
#        $ofs+=2;
#      }
#
#      my $s = 1;
#      my $c;
#
#      print STDERR "[ShellBag] Ascii is before parsing ", $bag{'ascii'}, " (", $fbag->{'ascii'}, ")\n" if $self->{'debug'};
#      $bag{'ascii'} = $fbag->{'ascii'} . '/' unless $fbag->{'ascii'} eq '';
#      $bag{'ascii'} = '' if $fbag->{'ascii'} eq '';
#
#      printf STDERR "[ShellBag] Offset now 0x%x :", $ofs if $self->{'debug'};
#      while ( $s )
#      {
#        printf STDERR ".0x%x.", $ofs if $self->{'debug'};
#        # read a single character
#        $c = substr( $v, $ofs++,1 );
#        printf STDERR "(%s)",$c if $self->{'debug'};
#
#        # check if we have reached the end of filename
#        $s = 0 if $c eq "\0";
#
#        next unless $s;
#
#        # add to the ASCII string
#        $bag{'ascii'} .= sprintf "%s", $c;
#      }
#      printf STDERR "\n" if $self->{'debug'};

            # struct UnicodeBagData {
            #       USHORT LengthOfUnicodeStructure;
            #       USHORT Short1; // 0x0003 for XP, 0x0008 for win7
            #       USHORT Short2; // 0x0004
            #       USHORT Short3; // 0xBEEF
            #       USHORT CreatedDOSDATE; // Created Date GMT
            #       USHORT CreatedDOSTIME; // Created Time GMT
            #       USHORT AccessedDOSDATE; // Accessed Date GMT
            #       USHORT AccessedDOSTIME; // Accessed Time GMT
            #       DWORD Unknown; // usually xp = 0x14, win7 = 0x2A
            #       // Vista and Windows 7 Extra Fields (22 bytes total)
            #       DWORD  MftFileId;
            #       USHORT Unknown1;
            #       USHORT MftSequence;
            #       DWORD  Unknown2;
            #       DWORD  Unknown3;
            #       DWORD  Unknown4;
            #       USHORT Unknown5;
            #       // END Vista extra fields
            #       wchar name; // Unicode Filename
            #       USHORT Unknown6;
            # };

  # round the offset to a even number (basically "ceil")
  #      printf STDERR "[ShellBag] Modifying the offset, it's now 0x%x\n", $ofs if $self->{'debug'};
  #      $ofs = int( $ofs/2 + 0.99 ) * 2;

#      printf STDERR "[ShellBag] Offset is now %d (0x%x) and ASCII output is %s\n", $ofs, $ofs, $bag{'ascii'} if $self->{'debug'};
#      printf STDERR "[ShellDebug] Hex kodi 0x%x\n", substr( $v, $ofs, $ofs+20 ) if $self->{'debug'};
#
#      # grab the rest of the values
#      $bag{'length_utf'} = unpack( "v", substr($v, $ofs, 2 ) );
#      $ofs+=2;
#      printf STDERR "[ShellDebug] The length of the UTF portion is 0x%x (%d)\n", $bag{'length_utf'}, $bag{'length_utf'} if $self->{'debug'};

            # now we have reached the end of the ASCII output, let's go to the UTF one
            #      $bag{'utf'} = $fbag->{'utf'} . '/' unless $fbag->{'utf'} eq '';
            #      $bag{'utf'} = '' if $fbag->{'ascii'} eq '';

            # check the length
            #      if( $bag{'length_utf'} > 0 )
            #      {
            #        if( unpack( "v", substr($v, $ofs,2 ) ) == 3 )
            #        {
            #          $bag{'os'} = 'XP';
            #        }
            #        else
            #        {
            #          $bag{'os'} = 'Win7';
            #        }

            #        $ofs+=2;
            #        printf STDERR "[ShellBags] The OS IS %s\n", $bag{'os'} if $self->{'debug'};

#        $ofs+=4; # irrelevant data, skip it, 0x0004 and 0xBEEF
#        $bag{'created_date'} = unpack( "v", substr($v, $ofs, 2 ) );
#        $ofs+=2;
#        $bag{'created_time'} = unpack( "v", substr($v, $ofs, 2 ) );
#        $ofs+=2;
#        $bag{'access_date'} = unpack( "v", substr($v, $ofs, 2 ) );
#        $ofs+=2;
#        $bag{'access_time'} = unpack( "v", substr($v, $ofs, 2 ) );
#        $ofs+=2;
#
#        eval
#        {
#          $bag{'created'} = Log2t::Time::Dos2Unix( $bag{'created_date'}, $bag{'created_time'} );
#        };
#        if( $@ )
#        {
#          # THE DEBUG REQUIRMENT SHOULD BE REMOVED WHEN MORE STABLE
#          print STDERR "[ShellBags] Error while trying to convert the date object\n Error: $@\n" if $self->{'debug'};
#          $bag{'created'} = 0;
#        }
#
#        eval
#        {
#          $bag{'access'} = Log2t::Time::Dos2Unix( $bag{'access_date'}, $bag{'access_time'} );
#        };
#        if( $@ )
#        {
#          # THE DEBUG REQUIRMENT SHOULD BE REMOVED WHEN MORE STABLE
#          print STDERR "[ShellBags] Error while trying to convert the date object\n Error: $@\n" if $self->{'debug'};
#          $bag{'access'} = 0;
#        }
#
#        print STDERR "[ShellBags] Dates: access ", $bag{'access'}, " and created ", $bag{'created'}, " \n" if $self->{'debug'};

            #        $ofs+=4;   # irrelevant (different value between XP and Vista)

            # if we are dealing with a Vista/Win7 system, we need to add some more values
            #        $ofs += 22 if( $bag{'os'} eq 'Win7' );

  #$ofs += 20;
  #        $s = 1;
  #        print STDERR "[ShellBag] UTF is before parsing: ", $bag{'utf'}, "\n" if $self->{'debug'};
  #        while( $s )
  #        {
  #          # read a single character
  #          $c = substr( $v, $ofs, 2 );
  #          $ofs += 2;

     #          printf STDERR "[ShellBag] 0x%x - UTF 0x%x [%s]\n", $ofs, $c, $c if $self->{'debug'};

            # check the length
            #          $s = 0 if sprintf "%s", $c eq "\0";
            #          $s = 0 if $bag{'length'} lt $ofs;

            #          next unless $s;

   #          # add to the UTF-8 string
   #          $bag{'utf'} .= decode( 'utf-8', $c );
   #        }
   #        print STDERR "[ShellBag] UTF is after parsing: ", $bag{'utf'}, "\n" if $self->{'debug'};
   #      }
   #
   #      if( $bag{'utf'} eq '' )
   #      {
   #        $bag{'utf'} = $bag{'ascii'};
   #      }

            print STDERR "[ShellBag] We've got the ASCII output {", $bag{'ascii'},
              "} and the UTF {", $bag{'utf'}, "}\n"
              if $self->{'debug'};

            $nk = $rk->get_subkey($kp . "\\" . $_->get_name());

            $bag{'parent'} = $id;

            # and we go recursively thorough the folder structure
            $self->{'value'} = $nk;
            $self->_populate_folder(\%bag, "$kp\\" . $_->get_name(), $slot);
        }
    }
}

# read ASCII string from a binary variable
sub _read_shell_ascii($$) {
    my $self = shift;
    my $v    = shift;
    my $ofs  = shift;

    my $c;
    my $string;

    my $s = 1;

    # read the ASCII string until we reach the \0 marker
    while ($s) {

        # debug information
        printf STDERR ".0x%x.", $$ofs if $self->{'debug'};

        # read a single character
        $c = substr($$v, $$ofs++, 1);
        printf STDERR "(%s)", $c if $self->{'debug'};

        # check if we have reached the end of filename
        $s = 0 if $c eq "\0";
        $s = 0 if $$ofs > length($v);    # extra check for some bags

        next unless $s;

        # add to the ASCII string
        $string .= sprintf "%s", $c;
    }

    return $string;
}

# read UTF string from a binary variable
sub _read_shell_utf($$$) {
    my $self = shift;
    my $v    = shift;
    my $ofs  = shift;
    my $l    = shift;

    my $string;
    my $c;
    my $s = 1;

    while ($s) {

        # read a single character
        $c = substr($$v, $$ofs, 2);
        $$ofs += 2;

        printf STDERR "[ShellBag] 0x%x - UTF 0x%x [%s]\n", $$ofs, unpack("U", $c),
          encode('utf-8', $c)
          if $self->{'debug'};

        # check the length
        $s = 0 if sprintf "%s", $c eq "\0";
        $s = 0 if $l lt $$ofs;

        next unless $s;

        # add to the UTF-8 string
        $string .= encode('utf-8', $c);
    }

    return $string;

}

# search for every itempos entry
sub _preprocess_shell($$) {
    my $self = shift;
    my @ar;
    my $k        = $self->{'value'};
    my $key_type = $self->{'key_type'};
    my $rk       = $self->{'key'};
    my %text;

    print STDERR "------------------------\n" if $self->{'debug'};

    # get a list of all values available for the key
    @ar = $k->get_list_of_values();

    foreach (@ar) {
        if ($_->get_name() eq 'NodeSlot') {
            print STDERR "[ShellBags] Bag key: ", $_->get_data(), "\n" if $self->{'debug'};
            my $num = $_->get_data();
            my $new_key;

            if ($key_type eq 'ShellNoRoam') {

                # check if the folder is empty
                if ($self->{'debug'}) {
                    print STDERR "[ShellBags] [$num] Skipping bag nr. ", $_->get_data(),
                      " since there is no associated folder to it\n"
                      unless defined $self->{'f_struct'}->{$num}->{'ascii'};
                }
                next unless defined $self->{'f_struct'}->{$num}->{'ascii'};
                $text{'a'} = $self->{'f_struct'}->{$num}->{'ascii'};
                $text{'u'} = $self->{'f_struct'}->{$num}->{'utf'};

                # print the extracted folder
                print STDERR "[ShellBags] [$num] associated to FOLDER ",
                  $self->{'f_struct'}->{$num}->{'ascii'}, " - ",
                  $self->{'f_struct'}->{$num}->{'utf'},   "\n"
                  if $self->{'debug'};

                # add to the timestamp value
                $self->{'vals'}->{ $self->{'vals_count'}++ } =
                  { 'value' => $num, 'type' => $key_type };

                # get that number (fetch the Shell Key underneath the number)
                if ($self->{'debug'}) {
                    print STDERR
                      "[ShellBags] Fetching key: Software\\Microsoft\\Windows\\$key_type\\Bags\\$num\n"
                      ;    #if $self->{'f_struct'}->{$num}->{'os'} eq 'XP';
                     #print STDERR "[ShellBags] Fetching Software\\Classes\\Wow6432Node\\Local Settings\\Software\\Microsoft\\Windows\\$key_type\\Bags\\$num\n" unless $self->{'f_struct'}->{$num}->{'os'} eq 'XP';
                }

       # Software\\Classes\\Wow6432Node\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU

                $new_key =
                  $rk->get_subkey("Software\\Microsoft\\Windows\\$key_type\\Bags\\$num\\Shell")
                  ;    #if $self->{'f_struct'}->{$num}->{'os'} eq 'XP';
                 #$new_key = $rk->get_subkey( "Software\\Classes\\Wow6432Node\\Local Settings\\Software\\Microsoft\\Windows\\$key_type\\Bags\\$num\\Shell") unless $self->{'f_struct'}->{$num}->{'os'} eq 'XP';
            }
            else {

                # check if the folder is empty
                if ($self->{'debug'}) {
                    print STDERR "[ShellBags] [$num] Skipping bag nr. ", $_->get_data(),
                      " since there is no associated folder to it\n"
                      unless defined $self->{'f_struct'}->{$num}->{'ascii'};
                }
                next unless defined $self->{'f_struct'}->{$num}->{'ascii'};
                $text{'a'} = $self->{'f_struct'}->{$num}->{'ascii'};
                $text{'u'} = $self->{'f_struct'}->{$num}->{'utf'};

                # print the extracted folder
                print STDERR "[ShellBags] [$num] associated to FOLDER ",
                  $self->{'f_struct'}->{$num}->{'ascii'}, " - ",
                  $self->{'f_struct'}->{$num}->{'utf'},   "\n"
                  if $self->{'debug'};

                # add to the timestamp value
                $self->{'vals'}->{ $self->{'vals_count'}++ } =
                  { 'value' => $num, 'type' => $key_type };

                # get that number (fetch the Shell Key underneath the number)
                if ($self->{'debug'}) {
                    print STDERR
                      "[ShellBags] Fetching key: Software\\Microsoft\\Windows\\$key_type\\Bags\\$num\n"
                      ;    # if $self->{'f_struct'}->{$num}->{'os'} eq 'XP';
                     #print STDERR "[ShellBags] Fetching Software\\Classes\\Wow6432Node\\Local Settings\\Software\\Microsoft\\Windows\\$key_type\\Bags\\$num\n" unless $self->{'f_struct'}->{$num}->{'os'} eq 'XP';
                }

       # Software\\Classes\\Wow6432Node\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU

                $new_key =
                  $rk->get_subkey("Software\\Microsoft\\Windows\\$key_type\\Bags\\$num\\Shell")
                  ;    #if $self->{'f_struct'}->{$num}->{'os'} eq 'XP';
                 #$new_key = $rk->get_subkey( "Software\\Classes\\Wow6432Node\\Local Settings\\Software\\Microsoft\\Windows\\$key_type\\Bags\\$num\\Shell") unless $self->{'f_struct'}->{$num}->{'os'} eq 'XP';

            }

            # get a list all the values of the key
            my @a = $new_key->get_list_of_values();

            foreach my $ak (@a) {
                if ($ak->get_name =~ m/^ItemPos/) {

                    # we need to parse this object a bit more
                    my $v = $ak->get_data();

                    my $ofs = 0x1E;
                    my %name;
                    $name{'mod_time'} = unpack("v", substr($v, $ofs, 2));
                    $ofs += 2;
                    $name{'mod_date'} = unpack("v", substr($v, $ofs, 2));
                    $ofs += 2;

                    eval {
                        $name{'mod'} = Log2t::Time::Dos2Unix($name{'mod_date'}, $name{'mod_time'});
                    };
                    if ($@) {

                        # THE DEBUG REQUIREMENT SHOULD BE REMOVED WHEN MORE STABLE
                        print STDERR
                          "[ShellBags] Unable to calculate modified time for Shell key. Error $@\n"
                          if $self->{'debug'};
                        $name{'mod'} = 0;
                    }

                    $ofs += 4;    # skip
                                  # read ascii
                    my $s = 1;
                    my $c;
                    while ($s) {

                        # read a single character
                        $c = substr($v, $ofs++, 1);

                        # check if we have reached the end of filename
                        $s = 0 if $c eq "\0";

                        next unless $s;

                        # add to the ASCII string
                        $name{'ascii'} .= sprintf "%s", $c;
                    }
                    $ofs += 8;
                    $name{'access_date'} = unpack("v", substr($v, $ofs, 2));
                    $ofs += 2;
                    $name{'access_time'} = unpack("v", substr($v, $ofs, 2));
                    $ofs += 2;
                    $name{'create_date'} = unpack("v", substr($v, $ofs, 2));
                    $ofs += 2;
                    $name{'create_time'} = unpack("v", substr($v, $ofs, 2));
                    $ofs += 6;

                    eval {
                        $name{'created'} =
                          Log2t::Time::Dos2Unix($name{'create_date'}, $name{'create_time'});
                    };
                    if ($@) {

                        # THE DEBUG REQUIREMENT SHOULD BE REMOVED WHEN MORE STABLE
                        print STDERR
                          "[ShellBags] Unable to calculate create time for Shell key. Error $@\n"
                          if $self->{'debug'};
                        $name{'created'} = 0;
                    }

                    eval {

                        # THE DEBUG REQUIREMENT SHOULD BE REMOVED WHEN MORE STABLE
                        $name{'access'} =
                          Log2t::Time::Dos2Unix($name{'access_date'}, $name{'access_time'});
                    };
                    if ($@) {
                        print STDERR
                          "[ShellBags] Unable to calculate access time for Shell key. Error $@\n"
                          if $self->{'debug'};
                        $name{'access'} = 0;
                    }

                    $name{'type'} = $key_type;
                    $name{'key'}  = "Software\\Microsoft\\Windows\\$key_type\\Bags\\$num\\Shell";

                    printf STDERR "[ShellBag] Shell OFFSET Before UTF 0x%x\n", $ofs
                      if $self->{'debug'};

                    # now read the utf
                    $s = 1;
                    while ($s) {

                        # read a single character
                        $c = substr($v, $ofs, 2);
                        $ofs += 2;

                        printf STDERR "[ShellBag] 0x%x - UTF 0x%x [%s]\n", $ofs,
                          decode('utf-8', $c), $c
                          if $self->{'debug'};

                        # check the length
                        $s = 0 if (sprintf "%s", $c) eq "\0";
                        $s = 0 if (sprintf "%s", $c) eq "\00";
                        $s = 0 if (length $v) < $ofs;

                        next unless $s;

                        # add to the UTF-8 string
                        $name{'utf'} .= decode('utf-8', $c);
                    }

                    $name{'folder_a'} = $text{'a'};
                    $name{'folder_u'} = $text{'u'};

                    # add to the timestamp value
                    $self->{'vals'}->{ $self->{'vals_count'}++ } =
                      { 'value' => \%name, 'type' => 'Shell_' . $key_type };

# check if mod timestamp is empty and print out a warning message
#print STDERR "[ShellBag] WARNING. There is no MODIFICATION TIMESTAMP, ONLY DATE for the file " . encode('utf-8',$name{'folder_u'}) . '/' . encode('utf-8',$name{'utf'}) . " \n" if( $name{'mod_time'} == 0 );

                    printf STDERR "[ShellBags] Shell key value [%s] is \t\t%s (%s)\n",
                      $ak->get_name(), $name{'ascii'}, $name{'utf'}
                      if $self->{'debug'};
                }
            }
        }
    }

    # now to get all subkeys
    @ar = $k->get_list_of_subkeys();

    # to recursively go through the keys, call this function again for each subkey found
    foreach (@ar) {
        $self->{'value'}    = $_;
        $self->{'key_type'} = $key_type;
        $self->_preprocess_shell;
    }

    return 1;
}

sub _parse_shell_key() {
    my $self = shift;
    my $text;
    my $title;

    # we've got two subkeys
    #  BagMRU
    #  Bags
    #
    # key_type is Shell_KEYTYPE
    # value is hash reference

    my $ktype = $self->{'key_type'};
    $ktype =~ s/^Shell_//;

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
    # we've got all the values
    $text =
        $self->{'value'}->{'folder_u'} . '/'
      . $self->{'value'}->{'utf'} . ' ('
      . $self->{'value'}->{'folder_a'} . '/'
      . $self->{'value'}->{'ascii'} . ')';
    $title = $text;

    # create the t_line variable
    $self->{'container'}->{ $self->{'cont_index'}++ } = {
        'time' => {
            0 => { 'value' => $self->{'value'}->{'mod'},     'type' => 'Modified', 'legacy' => 1 },
            1 => { 'value' => $self->{'value'}->{'access'},  'type' => 'Accessed', 'legacy' => 2 },
            2 => { 'value' => $self->{'value'}->{'created'}, 'type' => 'Created',  'legacy' => 12 },
                  },
        'desc'       => "File/Path: " . $text . " (MAC when first closed)",
        'short'      => "File path:" . $title,
        'source'     => 'REG',
        'sourcetype' => $ktype . ' key',
        'version'    => 2,
        'extra'      => {
            'user' => $self->{'username'},
            'notes' =>
              'Dates correspond to the filesystem MAC timestamps from when the file was first closed, and the entry written to the registry'
        }
    };

    return 1;
}

#  parse_shell
#
# This is a simple sub routine designed to parse the ShellBags found inside the NTUSER
# registry file.  The ShellBags represent information about files and folders, both on
# a local volume and on a remote one.
#
# The structure is mostly parsed from the article "Using shellbag information to
# reconstruct user actvities", published in the Digital Investigation magasine,
# Digital Investigation 6 (2009) S69-S77
sub _parse_shell_ts() {
    my $self = shift;
    my $text;
    my $ref;
    my $type;

    # we've got two subkeys
    #  BagMRU
    #  Bags
    #
    # The BagMRU key represents the Desktop folder, and it contains a folder
    # structure underneath, representing each folder underneath the Desktop
    # So we begin with parsing the BagMRU key.... and work our way from there

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
    # we've got all the values
    if ($self->{'vals'}->{ $self->{'val_num'} }->{'type'} eq 'ShellNoRoam') {
        $ref = $self->{'f_struct'}->{ $self->{'val_num'} };
        $text =
            $self->{'f_struct'}->{ $self->{'val_num'} }->{'utf'} . ' ('
          . $self->{'f_struct'}->{ $self->{'val_num'} }->{'ascii'} . ')';
        $type = 'ShellNoRoam';
    }
    elsif ($self->{'vals'}->{ $self->{'val_num'} }->{'type'} eq 'Shell') {
        $ref = $self->{'f_struct'}->{ $self->{'val_num'} };
        $text =
            $self->{'f_struct'}->{ $self->{'val_num'} }->{'utf'} . ' ('
          . $self->{'f_struct'}->{ $self->{'val_num'} }->{'ascii'} . ')';
        $type = 'Shell';
    }
    else {

        # we got a ItemPos, so the type is Shell_type (Shell_Shell or Shell_ShellNoRoam)
        $type = substr $self->{'vals'}->{ $self->{'val_num'} }->{'type'}, 6;
        $type .= ' ItemPos';

        $ref = $self->{'vals'}->{ $self->{'val_num'} }->{'value'};

        $text =
            $ref->{'folder_a'} . '/'
          . $ref - {'ascii'} . ' ('
          . $ref->{'folder_u'} . '/'
          . $ref->{'utf'} . ') - '
          . $ref->{'type'};
    }

    # "fix" the text a bit
    $text =~ s/[[:cntrl:]]//g;
    $text =~ s/\x00//g;

    #$text = encode( 'utf-8', $text );
    $text = _clean_text($text);

    # create the t_line variable
    $self->{'container'}->{ $self->{'cont_index'} } = {
        'desc'       => "Path: " . $text . " (MAC when first closed)",
        'short'      => 'Folder: ' . $text,
        'source'     => 'REG',
        'sourcetype' => $type . ' key',
        'version'    => 2,
        'notes' =>
          'Dates correspond to the filesystem MAC timestamps from when the file was first closed, and the entry written to the registry',
        'extra' => { 'user' => $self->{'username'}, }
    };

    $self->{'container'}->{ $self->{'cont_index'}++ }->{'time'} = {
                         0 => { 'value' => $ref->{'mod'},     'type' => 'Modified', 'legacy' => 5 },
                         1 => { 'value' => $ref->{'access'},  'type' => 'Accessed', 'legacy' => 2 },
                         2 => { 'value' => $ref->{'created'}, 'type' => 'Created',  'legacy' => 8 }
                                                                  };

    return 1;
}

#  parse_fe
#
# This is a simple sub routine that parses the FileExts key of the NTUSER.DAT file,
# a registry key that contains the last application that opened a file with a given
# file extension.
#
# The code is mostly taken from the fileexts.pl from RegRipper, written by H. Carvey
sub _parse_fe() {
    my $self = shift;
    my $time_value;
    my $text;
    my $title;
    my $list;
    my $data;

    my @t_array = $self->{'value'}->get_list_of_subkeys();

    # go through all of the keys
    foreach my $subkey (@t_array) {
        my $name = $subkey->get_name();
        next unless ($name =~ m/^\.\w+/);

        # next to check if the subkey exists
        my %hv = map { $_->get_name() => 1 } $subkey->get_list_of_subkeys();
        next unless defined $hv{'OpenWithList'};

        # code taken from fileexts.pl (slightly changed to fit the code)
        eval {
            $data = $subkey->get_subkey("OpenWithList")->get_value("MRUList")->get_data();
            if ($data =~ m/^\w/) {

                # get the time value
                $time_value = $subkey->get_subkey("OpenWithList")->get_timestamp();

                # and construct the text
                $text = 'File extension [' . $name . '] opened with {';

                # find out the latest entry
                $list = substr $data, 0, 1;    # get the latest key

                # fetch that entry
                my $software = $subkey->get_subkey("OpenWithList")->get_value($list)->get_data();
                $text .= $software . '}';

                $title = 'File extension ' . $name . ' opened by ' . $software;
            }
        };
        if ($@) {
            print STDERR "Error while processing FileExt key ($@)\n" if $self->{'debug'};
            next;
        }

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

        # create the t_line variable
        $self->{'container'}->{ $self->{'cont_index'}++ } = {
               'time' =>
                 { 0 => { 'value' => $time_value, 'type' => 'Extension Changed', 'legacy' => 15 } },
               'desc'       => $text,
               'short'      => $title,
               'source'     => 'REG',
               'sourcetype' => 'FileExts key',
               'version'    => 2,
               'extra'      => { 'user' => $self->{'username'}, }
        };
    }

    return 1;
}

#  parse_lvm
# A simple routine that parses the "last visited MRU" of the NTUSER.DAT registry file.
#
# Code mostly borrowed from the comdlg32.pl, a plugin file from the RegRipper tool
# written by H. Carvey
sub _parse_lvm() {
    my $self = shift;
    my $time_value;
    my $text;
    my $title;
    my %mru;

    my @att;

    # get all the sub keys of the last visited MRU
    @att = $self->{'value'}->get_list_of_values();
    return 0 unless scalar(@att) > 0;

    # enter all of the keys into a hash
    map { $mru{ $_->get_name() } = $_->get_data() } (@att);

    # get the time
    $time_value = $self->{'value'}->get_timestamp();

    # get the value
    my $first = substr $mru{'MRUList'}, 0, 1;
    my ($file, $dir) = split(/\00\00/, $mru{$first}, 2);
    $file =~ s/\00//g;
    $dir  =~ s/\00//g;

    $text  = 'Most recently opened file in Windows (in an "Open" dialog): ' . $dir . ' -> ' . $file;
    $title = 'File opened: ' . $dir . ' -> ' . $file;

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

    # create the t_line variable
    $self->{'container'}->{ $self->{'cont_index'}++ } = {
             'time' => { 0 => { 'value' => $time_value, 'type' => 'File Opened', 'legacy' => 15 } },
             'desc'       => $text,
             'short'      => $text,
             'source'     => 'REG',
             'sourcetype' => 'NTUSER key',
             'version'    => 2,
             'extra'      => {
                          'user' => $self->{'username'},
                          'url'  => 'http://support.microsoft.com/kb/322948/EN-US/'
                        }
    };

    return 1;
}

# OpenSaveMRU
sub _parse_osm() {
    my $self = shift;
    my $time_value;
    my $text;
    my $title;
    my %mru;

    my @att;

    # get all the sub keys of the last visited MRU
    @att = $self->{'value'}->get_list_of_values();
    return 0 unless scalar(@att) > 0;

    # enter all of the keys into a hash
    map { $mru{ $_->get_name() } = $_->get_data() } (@att);

    # check if we have a MRUList variable defined
    return 0 unless exists $mru{'MRUList'};

    # get the time
    $time_value = $self->{'value'}->get_timestamp();

    # get the value
    my $first = substr $mru{'MRUList'}, 0, 1;

    $text =
      'Most recent file saved or copied to a specific location in Windows (in an "Open" or "Save As" dialog): '
      . $mru{$first};
    $title = 'File saved or copied: ' . $mru{$first};

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

    # create the t_line variable
    $self->{'container'}->{ $self->{'cont_index'}++ } = {

        'time' =>
          { 0 => { 'value' => $time_value, 'type' => 'File saved or copied', 'legacy' => 15 } },
        'desc'       => $text,
        'short'      => $title,
        'source'     => 'REG',
        'sourcetype' => 'OpenSaveMRU key',
        'version'    => 2,
        'extra'      => {
                     'user' => $self->{'username'},
                     'url'  => 'http://support.microsoft.com/kb/322948/EN-US/'
                   }
    };

    return 1;
}

# Map Network Drive MRU
sub _parse_mndm() {
    my $self = shift;
    my $time_value;
    my $text;
    my $title;
    my %mru;

    my @att;

    # get all the sub keys of the last visited MRU
    @att = $self->{'value'}->get_list_of_values();
    return 0 unless scalar(@att) > 0;

    # enter all of the keys into a hash
    map { $mru{ $_->get_name() } = $_->get_data() } (@att);

    # check if we have a MRUList variable defined
    return 0 unless exists $mru{'MRUList'};

    # get the time
    $time_value = $self->{'value'}->get_timestamp();

    # get the value
    my $first = substr $mru{'MRUList'}, 0, 1;

    $text  = $mru{$first} . ' - Recently mounted network drive';
    $title = $mru{$first} . ' mounted';

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

    # create the t_line variable
    $self->{'container'}->{ $self->{'cont_index'}++ } = {
        'time' => { 0 => { 'value' => $time_value, 'type' => 'Drive Mounted', 'legacy' => 15 } },
        'desc' => $text,
        'short'      => $title,
        'source'     => 'REG',
        'sourcetype' => 'Map Network Drive MRU key',
        'version'    => 2,
        'extra'      => { 'user' => $self->{'username'}, }
                                                        };

    return 0;
}

# MountPoints2
# taken mostly from mp2.pl from RegRipper
sub _parse_mp2() {
    my $self = shift;
    my $time_value;
    my $text;
    my $title;

    my @t_array = $self->{'value'}->get_list_of_subkeys();

    foreach my $s (@t_array) {

        # code gotten from mp2.pl, originally written by H. Carvey
        my $name = $s->get_name();

        if ($name =~ m/^{/) {
            $text = $name . ' volume mounted';
        }
        elsif ($name =~ m/^[A-Z]/) {
            $text = $name . ' drive mounted';
        }
        elsif ($name =~ m/^#/) {
            $text = $name . ' (remote) Drive mounted';
        }
        else {
            $text = 'Key name = ' . $name;
        }

        # get the timestamp
        $time_value = $s->get_timestamp();

        $title = $text;

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

        # create the t_line variable
        $self->{'container'}->{ $self->{'cont_index'}++ } = {
              'time' =>
                { 0 => { 'value' => $time_value, 'type' => 'Drive last mounted', 'legacy' => 15 } },
              'desc'       => $text,
              'short'      => $title,
              'source'     => 'REG',
              'sourcetype' => 'MountPoints2 key',
              'version'    => 2,
              'extra'      => { 'user' => $self->{'username'}, }
        };
    }

    return 1;
}

# a sub routine borrowed from the recentdocs.pl, written by H. Carvey
sub _getRDValues {
    my $self = shift;
    my $key  = shift;

    my $mru = "MRUList";
    my %rdvals;

    my @vals = $key->get_list_of_values();
    if (scalar @vals > 0) {
        foreach my $v (@vals) {
            my $name = $v->get_name();
            my $data = $v->get_data();
            if ($name =~ m/^$mru/) {
                my @mru;
                if ($name eq "MRUList") {
                    @mru = split(//, $data);
                }
                elsif ($name eq "MRUListEx") {
                    @mru = unpack("V*", $data);
                }
                $rdvals{$name} = join(',', @mru);
            }
            else {
                my $file = (split(/\00\00/, $data))[0];
                $file =~ s/\00//g;
                $rdvals{$name} = $file;
            }
        }
        return %rdvals;
    }
    else {
        return undef;
    }
}

# RecentDocs, mostly borrowed from recentdocs.pl, written by H. Carvey for the RegRipper tool
sub _parse_rd() {
    my $self = shift;
    my $time_value;
    my $text;
    my $title;
    my $t = 'File';    # default behaviour of the type of file in question

    my @t_array = $self->{'value'}->get_list_of_subkeys();

    foreach my $key (@t_array) {
        my $name = $key->get_name();
        $t = $name eq 'Folder' ? 'Folder' : 'File';

        $time_value = $key->get_timestamp();

        # code from recentdocs.pl, slightly changed to fit this tool
        my %rdvals = $self->_getRDValues($key);

        # check to see if we've got a proper value
        if (%rdvals) {
            my $tag;
            if (exists $rdvals{"MRUListEx"}) {
                $tag = "MRUListEx";
            }
            elsif (exists $rdvals{"MRUList"}) {
                $tag = "MRUList";
            }
            else {
            }

            my @list = split(/,/, $rdvals{$tag});

            # get the first tag in the MRU list (the one that the timestamp corresponds to)
            my $first = $list[0];

            $text =
                'Recently opened file of extension: ' 
              . $name
              . ' - value: '
              . encode('utf-8', $rdvals{$first});
        }
        else {
            print STDERR
              "[UA] Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs\\", $name,
              " has no values.\n"
              if $self->{'debug'};
            next;
        }

        # end of recentdocs.pl code
        $title = $text;

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

        # create the t_line variable
        $self->{'container'}->{ $self->{'cont_index'}++ } = {
            'time' => { 0 => { 'value' => $time_value, 'type' => $t . ' opened', 'legacy' => 15 } },
            'desc'       => $text,
            'short'      => $title,
            'source'     => 'REG',
            'sourcetype' => 'RecentDocs key',
            'version'    => 2,
            'extra'      => { 'user' => $self->{'username'}, }
                                                            };
    }
    return 1;
}

sub _parse_shell {
    my $self = shift;

    $self->{'key_type'} = 'Shell';

    # so we start by populating the folder structure
    $self->{'f_struct'}  = undef;
    $self->{'vals'}      = {};
    $self->{'val_count'} = 0;

    my $key = $self->{'value'};    # save the key
    $self->_populate_folder(undef, "Software\\Microsoft\\Windows\\Shell\\BagMRU\\0", 0);

    # no we've populated the folder structure, let's process the bag files
    $self->{'key'}   = $self->{'reg'}->get_root_key;
    $self->{'value'} = $key;
    $self->_preprocess_shell;

    foreach (keys %{ $self->{'vals'} }) {
        $self->{'val_num'} = $_;
        $self->_parse_shell_ts;
    }

    return 1;
}

sub _parse_shell_no {
    my $self = shift;

    $self->{'key_type'} = 'ShellNoRoam';

    # so we start by populating the folder structure
    $self->{'f_struct'}  = undef;
    $self->{'vals'}      = {};
    $self->{'val_count'} = 0;
    my $key = $self->{'value'};    # save the key

    $self->_populate_folder(undef, "Software\\Microsoft\\Windows\\ShellNoRoam\\BagMRU\\0", 0);

    # no we've populated the folder structure, let's process the bag files
    $self->{'key'}   = $self->{'reg'}->get_root_key;
    $self->{'value'} = $key;
    $self->_preprocess_shell;

    foreach (keys %{ $self->{'vals'} }) {
        $self->{'val_num'} = $_;
        $self->_parse_shell_ts;
    }

    return 1;
}

sub _clean_text {
    my $text = shift;
    my $t    = '';
    my $c;

    for (my $a = 0; $a < length($text); $a++) {
        eval {
            $c = substr $text, $a, 1;
            if ($c =~ m/[a-zA-Z_\-\/\\\.\?\@0-9\~]/) {
                $t .= substr $text, $a, 1;
            }
            else {
                $t .= '.';
            }
        };
        if ($@) {
            $t .= '.';
        }
    }

    return $t;
}

# RunMRU
sub _parse_rm() {
    my $self = shift;
    my %t_line;
    my $time_value;
    my $text;
    my $title;
    my %mru;

    my @att;

    # get all the sub keys of the last visited MRU
    @att = $self->{'value'}->get_list_of_values();
    return \%t_line unless scalar(@att) > 0;

    # enter all of the keys into a hash
    map { $mru{ $_->get_name() } = $_->get_data() } (@att);

    # check if we have a MRUList variable defined
    return \%t_line unless exists $mru{'MRUList'};

    # get the time
    $time_value = $self->{'value'}->get_timestamp();

    # get the value
    my $first = substr $mru{'MRUList'}, 0, 1;

    $text  = 'typed the following cmd in the RUN dialog {' . $mru{$first} . '}';
    $title = 'RunMRU value [' . $mru{$first} . ']';

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

    # create the t_line variable
    $self->{'container'}->{ $self->{'cont_index'}++ } = {
        'time'   => { 0 => { 'value' => $time_value, 'type' => 'CMD typed', 'legacy' => 15 } },
        'desc'   => $text,
        'short'  => $title,
        'source' => 'REG',
        'sourcetype' => 'RunMRU key',
        'version'    => 2,
        'extra'      => { 'user' => $self->{'username'}, }
                                                        };

    return \%t_line;
}

# Regedit, taken from the applets.pl (part of RegRipper), written by H. Carvey
sub _parse_re() {
    my $self = shift;
    my %t_line;
    my $time_value;
    my $text;
    my $title;
    my $lastkey = undef;

    # get the time
    $time_value = $self->{'value'}->get_timestamp();

    # part from applets.pl
    eval { $lastkey = $self->{'value'}->get_value("LastKey")->get_data(); };
    if ($@) {
        print STDERR "[NTUSER ERROR] Error while getting the RegEdit key\n";
        return \%t_line;
    }

    $text = 'RegEdit LastKey value (last key edited by user)-> ' . $lastkey;

    # end of code from applets.pl

    $title = $text;

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

    # create the t_line variable
    $self->{'container'}->{ $self->{'cont_index'}++ } = {
        'time'   => { 0 => { 'value' => $time_value, 'type' => 'Key Edited', 'legacy' => 15 } },
        'desc'   => $text,
        'short'  => $title,
        'source' => 'REG',
        'sourcetype' => 'RegEdit key',
        'version'    => 2,
        'extra'      => { 'user' => $self->{'username'}, }
                                                        };

    return \%t_line;
}

#   parse_ua
#
# This is a sub routine that parses the UserAssist key of the registry
#
# This mainly consists of code taken from the userassist.pl of the RegRipper, written
# by H. Carvey
sub _parse_ua() {
    my $self = shift;

    # the timestamp object
    my $v;
    my %ua;
    my $hrzr = "HRZR";
    my $text;
    my $time_value;
    my $title;
    my $detail;

    # when we get here, we get the top key, we need to proceed first by parsing all subkeys
    my @t_array = $self->{'value'}->get_list_of_values();

    foreach my $v (@t_array) {
        my $value_name = $v->get_name();
        print STDERR "[UA] Parsing (as read) $value_name\n" if $self->{'debug'};

        my $data = $v->get_data();

        if ($self->{'type'} eq 'xp') {
            print STDERR "[UA] We are parsing the UserAssist key according to XP rules\n"
              if $self->{'debug'};

            if (length($data) == 16) {
                my ($session, $count, $val1, $val2) = unpack("V*", $data);
                if ($val2 != 0) {
                    $time_value = Log2t::Time::Win2Unix($val1, $val2);
                    if ($value_name =~ m/^$hrzr/) {
                        $value_name =~ tr/N-ZA-Mn-za-m/A-Za-z/;
                    }
                    $count -= 5 if ($count > 5);

                    # check if a GUID has been used
                    if ($value_name =~ m/(\{.+\})/) {
                        print STDERR "[UA] A GUID IS IN THE PATH ($value_name)\n"
                          if $self->{'debug'};

                        # we have a GUID that needs to be replaced
                        print STDERR "[UA] The guid is $1\n" if $self->{'debug'};

                        # check if GUID exists in a "known" GUID table
                        if (Log2t::Win::guid_exists($1)) {

                            # then we need to remove the GUID and replace it with the path name
                            my $val = Log2t::Win::get_guid_path("$1");

                            print STDERR "[UA] And the text version is '$val'\n"
                              if $self->{'debug'};

                            $value_name =~ s/$1/$val/;
                        }
                    }

                    $text  = $value_name . ' [Count: ' . $count . ']';
                    $title = $value_name;
                    print STDERR "THE TEXT [$text]\n" if $self->{'debug'};

                }
                else    # added by kristinn
                {
                    print STDERR "Val2 is equal to zero ($val2) and therfore an invalid record\n"
                      if $self->{'debug'};
                    next;
                }

                # check the text for common beginning (added by Kristinn)
                if ($text =~ m/RUNPATH/) {
                    $detail =
                      'Absolute path, occured either via double clicking an icon in Explorer or typing in the name of the application in Start/Run dialog';
                }
                elsif ($text =~ m/RUNCPL/) {
                    $detail = 'Control Panel Applet being launched';
                }
                elsif ($text =~ m/RUNPIDL/) {
                    $detail =
                      'A PIDL (reference to an object), most likely caused by running a shortcut (LNK file)';
                }
                else {
                    $detail = 'no additional information provided.';
                }
            }
            else {

                # we have a bad length for the record and therefore it is invalid
                # supress the error message
                print STDERR "Error message: Key $value_name has no values (the length is invalid "
                  . length($data) . ").\n"
                  if $self->{'debug'};
                next;
            }
        }
        elsif ($self->{'type'} eq 'new') {

            # we are dealing with a Windows Vista or newer
            if (length($data) == 72) {

                # we have a valid data length
                print STDERR "[UA] Valid data length\n" if $self->{'debug'};
                $value_name =~ tr/N-ZA-Mn-za-m/A-Za-z/;
                print STDERR "[UA] Decoded key name: $value_name\n" if $self->{'debug'};

                # unpack the entire string into 32 bit integers
                my (@values) = unpack("V*", $data);

                # check if a GUID has been used
                if ($value_name =~ m/(\{.+\})/) {
                    print STDERR "[UA] A GUID IS IN THE PATH ($value_name)\n" if $self->{'debug'};

                    # we have a GUID that needs to be replaced
                    print STDERR "[UA] The guid is $1\n" if $self->{'debug'};

                    # check if GUID exists in a "known" GUID table
                    if (Log2t::Win::guid_exists($1)) {

                        # then we need to remove the GUID and replace it with the path name
                        my $val = Log2t::Win::get_guid_path("$1");

                        print STDERR "[UA] And the text version is '$val'\n" if $self->{'debug'};

                        $value_name =~ s/$1/$val/;
                    }
                }

                $time_value = Log2t::Time::Win2Unix($values[15], $values[16]);
                $text =
                    $value_name
                  . ' [Count: '
                  . $values[1]
                  . ']  nr. of times app had focus: '
                  . $values[2]
                  . ' and duration of focus: '
                  . $values[3] . 'ms';
                $title = $value_name;
            }
            else {

                # invalid data length
                print STDERR "[UA] Invalid data length " . length($data) . " - length not 72\n"
                  if $self->{'debug'};
                next;
            }
        }
        else {
            $text  = '';
            $title = '';
        }

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

        # create the t_line variable
        $self->{'container'}->{ $self->{'cont_index'}++ } = {
                  'time' =>
                    { 0 => { 'value' => $time_value, 'type' => 'Time of Launch', 'legacy' => 15 } },
                  'desc'       => $text,
                  'short'      => $title,
                  'source'     => 'REG',
                  'sourcetype' => 'UserAssist key',
                  'version'    => 2,
                  'notes'      => $detail,
                  'extra'      => { 'user' => $self->{'username'}, }
        };
    }

    return 1;
}

#logonusername.pl
sub _get_username {
    my $self = shift;
    my $logon_name;
    my $key;
    my $name_key_path;

    print STDERR "[UA] Reading username\n" if $self->{'debug'};

    my $root_key = $self->{'reg'}->get_root_key;

    if ($self->{'type'} eq 'xp') {
        $logon_name    = "Logon User Name";
        $name_key_path = 'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer';
    }
    elsif ($self->{'type'} eq 'new') {
        $name_key_path =
          'Software\\Microsoft\\Active Setup\\Installed Components\\{44BBA840-CC51-11CF-AAFA-00AA00B6015C}';
        $logon_name = 'Username';
    }
    else {
        print STDERR
          "[UA] Username not found since we are dealing with an unknown NTUSER.DAT file\n"
          if $self->{'debug'};
        return 'unknown';
    }

    if ($key = $root_key->get_subkey($name_key_path)) {
        my @n_vals = $key->get_list_of_values();
        if (scalar(@n_vals) > 0) {
            foreach my $v (@n_vals) {
                if ($v->get_name() eq $logon_name) {
                    print STDERR "[UA] Username found " . $v->get_data() . "\n" if $self->{'debug'};
                    return $v->get_data();
                }
                else {
                    print STDERR "[UA] Username keys extracted, examining: " . $v->get_name() . "\n"
                      if $self->{'debug'};
                }
            }
        }
        else {
            print STDERR "[UA] Username failed: Now values found\n" if $self->{'debug'};
            return 'unknown';
        }
    }
    else {
        print STDERR "[UA] Username not found: Key does not exist\n" if $self->{'debug'};
        return 'unknown';
    }

    print STDERR "[UA] Key found yet no username returned: logon name perhaps changed?\n"
      if $self->{'debug'};

    return 'unknown';
}

##########################################################################################################################

# the constructor
sub new() {
    my $class = shift;

    # inherit from the base class
    my $self = $class->SUPER::new();

    # indicate that we would like to parse this file in one attempt, and return it in a single hash
    $self->{'multi_line'} = 0;

    # TEMPORARY - remove when FH is accepted through Parse::Win32Registry
    $self->{'file_access'} =
      1;    # do we need to parse the actual file or is it enough to get a file handle

    # set some default variables
    $self->{'ua_key_base'} = 'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist';
    $self->{'ua_xp_key_path'}    = '{75048700-EF1F-11D0-9888-006097DEACF9}\\Count';
    $self->{'ua_new_key_path_1'} = '{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\\Count';
    $self->{'ua_new_key_path_2'} = '{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}\\Count';

    bless($self, $class);

    return $self;
}

sub init() {

    # initialize all variables
    my $self = shift;

    $self->{'vista'}      = 0;
    $self->{'vals_count'} = 0;       # reset the counter of the hash vals
    $self->{'vals'}       = undef;

    return 1;
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
    return "Parses the NTUSER.DAT registry file";
}

sub _regscan {
    my $self = shift;
    my $key  = shift;

    my $name = $key->as_string();
    $name =~ s/\$\$\$PROTO\.HIV//;
    $name = (split(/\[/, $name))[0];
    $name =~ s/^CMI-CreateHive{[A-F0-9_\-]+}//;
    $name =~ s/^\\//;
    $name =~ s/\s//g;

    $self->{'key_name'} = $name;

#print STDERR "\n\n";
#print STDERR "[NTUSER] We are about to load record nr. " . $self->{'counter'}++ . "\n" ;#if $self->{'debug'};

    #print STDERR "TESTING AGAINST [$name]\n";
    #foreach( keys %{$self->{'key_parse'}} )
    #{
    #  print STDERR "\t($_)\n";
    #}

    # check the key
    if (defined $self->{'key_parse'}->{$name}) {

        #print STDERR "[NTUSER] <$name> IS DEFINED\n";
        # key defined, we are about to do some parsing here
        $self->{'value'} = $key;
        eval { $self->{'key_parse'}->{$name}->($self); };
        if ($@) {
            print STDERR "[NTUSER] Unable to parse the registry key $name. Error $@\n";
            return 1;
        }
    }
    else {

#print STDERR "[NTUSER] <$name> NOT DEFINED\n";
# not defined, we need the default behaviour (print this particular key and then find all the sub keys
        $self->{'value'} = $key;
        eval { $self->{'key_parse'}->{'DEFAULT'}->($self, $name); };
        if ($@) {
            print STDERR "[NTUSER] Unable to parse the registry key $name. Error $@\n";
            return 1;
        }

        # and now to find the subkeys
        foreach my $subkey ($key->get_list_of_subkeys()) {
            $self->_regscan($subkey);
        }
    }

    return 1;
}

#  get_time
# This subroutine starts by reading the NTUSER.DAT registry file and parse it
# using the Win32Registry library.  It then retrives the UserAssist part of the
# registry and stores it's values in the array @vals (which is global)
#
# It then returns a reference to a hash that stores all the timestamp
# objects to the main engine for further processing
sub get_time() {
    my $self = shift;
    my $key;
    my $root_key;
    my @extra;
    my $path;
    my @t_array;
    my %t_hash;

    # set the default values
    $self->{'no_go'} = 0;

    # initialize
    $self->{'container'}  = undef;
    $self->{'cont_index'} = 0;
    $self->{'counter'}    = 1;

    # get the root key
    $root_key = $self->{'reg'}->get_root_key;

    # define a dispatch table, or a code reference table
    $self->{'key_parse'} = {
        'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\{75048700-EF1F-11D0-9888-006097DEACF9}\\Count'
          => \&_parse_ua,    # UserAssist (XP)
        'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\\Count'
          => \&_parse_ua,    # UserAssist (Win 7-1)
        'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}\\Count'
          => \&_parse_ua,    # UserAssist (Win 7-2)
        'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FileExts' =>
          \&_parse_fe,                                                          # FileExts
        'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\LastVisitedMRU' =>
          \&_parse_lvm,                                                         # LastVisitedMRU
        'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\OpenSaveMRU' =>
          \&_parse_osm,                                                         # OpenSaveMRU
        'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MapNetworkDriveMRU' =>
          \&_parse_mndm,    # Map Network Drive MRU
        'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2' =>
          \&_parse_mp2,                                                             # MountPoints2
        'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs' =>
          \&_parse_rd,                                                              # RecentDocs
        'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU' => \&_parse_rm,   # RunMRU
        'Software\\Microsoft\\Windows\\CurrentVersion\\Applets\\Regedit' => \&_parse_re,   # RegEdit
             #'Software\\Microsoft\\Windows\\Shell\\BagMRU' => \&_parse_shell,  # Shell
          #'Software\\Microsoft\\Windows\\ShellNoRoam\\BagMRU\\0' => \&_parse_shell_no,  # ShellNoRoam,
          #'' => \&_parse_shell_key,  # ^Shell_
        'DEFAULT' => \&_parse_default    # default parsing (not a known key)
                           };

    eval {

        # now we need to traverse through all of the registry keys, check if we

        # now we need to test for the existance of the keys in question
        # get the userassist key
        # test if this is an XP or Vista (that is new or old format)
        $key = $root_key->get_subkey($self->{'ua_key_base'} . '\\' . $self->{'ua_xp_key_path'});
        if (defined $key) {
            $self->{'type'} = 'xp';
            print STDERR "[UA] We have detected the XP UserAssist key\n" if $self->{'debug'};
        }
        else {
            $key =
              $root_key->get_subkey($self->{'ua_key_base'} . '\\' . $self->{'ua_new_key_path_1'});
            $self->{'type'} = 'new' if defined $key;
            $self->{'type'} = 'none' unless defined $key;
        }

        # override settings
        $self->{'type'} = 'new' if $self->{'vista'};
        print STDERR "[NTUSER] Overriding settings: VISTA\n" if $self->{'vista'};

        unless ($self->{'type'} eq 'xp' or $self->{'type'} eq 'new') {
            print STDERR
              "[NTUSER] We have an unknown an unidentified UserAssist key and no processing will be done\n"
              if $self->{'debug'};
            $self->{'no_go'} = 1;
            return $self->{'container'};
        }

        # get the username (if possible)
        $self->{'username'} = $self->_get_username() unless $self->{'no_go'};

        if ($self->{'username'} eq '0' || $self->{'username'} eq 'unknown') {
            $self->{'username'} = Log2t::Common::get_username_from_path(${ $self->{'name'} });
            print STDERR "[NTUSER] Guessed username '" . $self->{'username'} . "'\n"
              if $self->{'debug'};
        }

# now we need to process other keys that belong to the NTUSER.DAT file and include those into the line

        # HERE
        # Go to the LastVisitedMRU key
        # Key: Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedMRU not found.
        # URL: http://support.microsoft.com/kb/322948/EN-US/

        # Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSaveMRU not found.
        # Software\Microsoft\Windows\CurrentVersion\Explorer\Map Network Drive MRU

        # Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2
        # Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\...
        # Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
        # Software\Microsoft\Windows\CurrentVersion\Applets\Regedit

        # --- ShellBags ---
        # Two keys: identical structure

#   VISTA/Win 7 keys
#* HKEY_CURRENT_USER\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags
#* HKEY_CURRENT_USER\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU
#* HKEY_CURRENT_USER\Software\Classes\Wow6432Node\Local Settings\Software\Microsoft\Windows\Shell\Bags
#* HKEY_CURRENT_USER\Software\Classes\Wow6432Node\Local Settings\Software\Microsoft\Windows\Shell\BagMRU

# Shell key is used to store information related to remote folders
#    if( $key = $root_key->get_subkey( "Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU" ) )
#    {
#      print STDERR "[NTUSER] We've got a Shell (shellbag) for remote folders\n" if $self->{'debug'};
#
#      # start by the Desktop folder, or the initial key
#      # then we need to recursively go through the key... and employ the same
#      # processing to each key (so a new function)
#
#      # so we start by populating the folder structure
#      $self->_populate_folder( \$key, $self->{'shell_folder'}, undef, "Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU\\0", 0 );
#
#      # no we've populated the folder structure, let's process the bag files
#      $self->_preprocess_shell( \$key, 'Shell' );
#    }

#    if( $key = $root_key->get_subkey( "Software\\Classes\\Wow6432Node\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU\\0" ) )
#    {
#      print STDERR "[NTUSER] We've got a ShellNoRoam (shellbag) for local folders\n" if $self->{'debug'};
#
#      # start by the Desktop folder, or the initial key
#      # then we need to recursively go through the key... and employ the same
#      # processing to each key (so a new function)
#
#      # so we start by populating the folder structure
#      $self->_populate_folder( \$key, $self->{'shell_noroam_folder'}, undef, "Software\\Classes\\Wow6432Node\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU\\0", 0 );
#
#      # no we've populated the folder structure, let's process the bag files
#      $self->_preprocess_shell( \$key, 'ShellNoRoam' );
#    }
    };
    if ($@) {
        $self->{'no_go'} =
          1;    # indicate that an error occured and we do not have a valid registry file
                # supress error message
        print STDERR "[NTUSER - ERROR] There was an error reading the registry file: $@\n"
          if $self->{'debug'};
    }

    # if no_go is set, then we just return with no line
    return undef if $self->{'no_go'};

# now we've confirmed everything, set up all the needed functions, no we just need to do some recursive scan through the registry
# parsing the keys we can, and make a simple gesture for the rest
    $self->_regscan($root_key);

    # now we've done the recursive scan, let's try to recover deleted information
    my $deleted_entries = Log2t::WinReg::get_deleted_entries($self);

    # add the deleted entries into the pile...
    foreach my $h (keys %{$deleted_entries}) {
        $self->{'container'}->{ $self->{'cont_index'}++ } = $deleted_entries->{$h};
    }

    return $self->{'container'};
}

#       get_help
# A simple subroutine that returns a string containing the help
# message for this particular format file.
# @return A string containing a help file for this format file
sub get_help() {
    return "This format file reads and parses the user registry file NTUSER.DAT,
extracts from it the UserAssist key, decodes it and produces a body file.  The body
file can than be used in a timeline analysis (using tools like mactime from TSK).

The script depends upon the Perl library:
  Parse::Win32Registry

The parameter to this format file is the NTUSER.DAT file that can be found for instance
at the following location (win xp):
  C:\\Documents and Settings\\ MYUSERNAME\\NTUSER.DAT

Description of Control Panel Files in XP - http://support.microsoft.com/kb/313808

This format file accepts the following option
  --host   HOST\n";

}

#       verify
# A subroutine that verifies if we are examining a ntuser file, so it can be further
# processed.
# @return An array containing an integer and a string.  The integer indicates a success or failure and the
#       string is the error message (if the file is not correctly formed)
sub verify {
    my $self = shift;

    # define an array to keep
    my %return;
    my $line;
    my @words;
    my $root_key;
    my $key;

    # start by setting the endian correctly
    #Log2t::BinRead::set_endian( Log2t::Common::LITTLE_E );
    #Log2t::BinRead::set_endian( LITTLE_E );

    # default values
    $return{'success'} = 0;
    $return{'msg'}     = 'not a file';

    return \%return unless -f ${ $self->{'name'} };

    my $ofs = 0;

    # start by checking if this is a file or not
    if (-f ${ $self->{'name'} }) {

        # this is a file, check further
        eval { $line = Log2t::BinRead::read_ascii($self->{'file'}, \$ofs, 4); };
        if ($@) {
            $return{'success'} = 0;
            $return{'msg'}     = "Unable to open the file ($@)";
            return \%return;
        }

        # the content of these bytes should be
        # regf = 7265 6766
        if ($line eq 'regf') {

            # load the array ( or try to at least )
            eval { $self->{'reg'} = Parse::Win32Registry->new(${ $self->{'name'} }); };
            if ($@) {

                # an error occured, return from this mess ;)
                $return{'msg'}     = "[UserAssist] Unable to load registry file";
                $return{'success'} = 0;

                return \%return;
            }

            # sometimes there might be false positives here, so let's try to get the root key
            eval {

                # the registry is now loaded, check the existance of a UserAssist key
                $root_key = $self->{'reg'}->get_root_key;
            };
            if ($@) {
                $return{'msg'} =
                  'Unable to retrieve the root key, this might not be a registry file ('
                  . ${ $self->{'name'} } . ')';
                $return{'success'} = 0;
                return \%return;
            }

            eval {

                # now we need to test for the existance of the keys in question
                # one test
                # get the userassist key

                $key = $root_key->get_subkey($self->{'ua_key_base'});
                if (defined $key) {
                    $return{'success'} = 1;
                }
                else {
                    $return{'success'} = 0;
                    $return{'msg'}     = 'The UserAssist key does not exist';
                }
            };
            if ($@) {
                $return{'msg'}     = 'Unable to load UserAssist key, not a NTUSER.DAT file';
                $return{'success'} = 0;
            }
        }
        else {
            $return{'success'} = 0;
            $return{'msg'}     = 'File not a registry file.';
        }
    }
    else {

        # not a file, so back out
        $return{'success'} = 0;
        $return{'msg'}     = ${ $self->{'name'} } . ' is not a file. ';
    }

    return \%return;
}

1;

