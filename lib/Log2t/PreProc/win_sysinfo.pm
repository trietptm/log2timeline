#################################################################################################
#               win_sysinfo
#################################################################################################
# This script is a part of the log2timeline framework for timeline creation and analysis.
#
# This script implements a preprocessing module.  A preprocessing module is a module that
# is started before log2timeline parses the image (mounted image) to gather information
# from the system, that is then used in the rest of the processing.
#
# This module reads the registry of a Windows machine to determine the timezone settings
# and the hostname
#
# Author: Kristinn Gudjonsson
# Version : 0.1
# Date : 12/04/11
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

package Log2t::PreProc::win_sysinfo;

use strict;
use Parse::Win32Registry qw(:REG_);    # to be able to read the registry
use Log2t::Win;

sub get_info($) {
    my $self = shift;
    my $l2t  = shift;
    my $path = undef;
    my $go   = 0;                      # set this if we find the full path (windows system32 config)

    # check if the object is valid
    return 0 unless $l2t->is_valid;

    # this needs to be a directory, otherwise this will not work
    return 0 unless -d $l2t->{'file'};

    # read the directory
    opendir(PD, $l2t->{'file'});
    my @dir = readdir(PD);
    closedir(PD);

    # go through the directory and find the system config directory
    foreach my $root (@dir) {
        if (($root =~ m/^windows$/i or $root =~ m/^winnt$/i)
            and -d $l2t->{'file'} . $l2t->{'sep'} . $root)
        {
            $path = $root . $l2t->{'sep'};
            opendir(PD, $l2t->{'file'} . $l2t->{'sep'} . $path);
            my @windir = readdir(PD);
            closedir(PD);

            foreach my $win (@windir) {
                if (-d $l2t->{'file'} . $l2t->{'sep'} . $path . $l2t->{'sep'} . $win
                    and $win =~ m/^system32$/i)
                {
                    $path .= $l2t->{'sep'} . $win;

                    opendir(PD, $l2t->{'file'} . $l2t->{'sep'} . $path);
                    my @sysdir = readdir(PD);
                    closedir(PD);

                    foreach my $sys (@sysdir) {
                        if (-d $l2t->{'file'} . $l2t->{'sep'} . $path . $l2t->{'sep'} . $sys
                            and $sys =~ m/^config$/i)
                        {
                            $path .= $l2t->{'sep'} . $sys;
                            $go = 1;
                        }
                    }
                }
            }
        }
    }

    # check if we've found the directory
    return 0 unless $go;

    # open the config directory (where the system registry lies)
    opendir(PD, $l2t->{'file'} . $l2t->{'sep'} . $path);
    @dir = readdir(PD);
    closedir(PD);

    # define the registry file
    my $reg_file  = undef;
    my $reg_file2 = undef;

    # go through the registry folder/directory
    foreach (@dir) {
        if (/^system$/i) {

            # now we've got a registry file
            $reg_file = $l2t->{'file'} . $l2t->{'sep'} . $path . $l2t->{'sep'} . $_;
        }
        elsif (/^software$/i) {

            # now we've got a registry file
            $reg_file2 = $l2t->{'file'} . $l2t->{'sep'} . $path . $l2t->{'sep'} . $_;
        }
    }

    return 0 unless $reg_file;

    # start reading the registry
    my $reg      = Parse::Win32Registry->new($reg_file);
    my $root_key = $reg->get_root_key;

    # code from cmpnaname, part of regripper, written by H. Carvey
    my $key;
    my $current;
    if ($key = $root_key->get_subkey('Select')) {

        # get the current control set
        $current = $key->get_value("Current")->get_data();
        my $ccs = "ControlSet00" . $current;

        # get the computer name
        my $cn_path = $ccs . "\\Control\\ComputerName\\ComputerName";
        my $cn;
        if ($cn = $root_key->get_subkey($cn_path)) {
            my $name = $cn->get_value("ComputerName")->get_data();
            $l2t->set('hostname' => $name);
            print STDERR "[PreProcessing] Hostname is set to $name\n";
        }

        # and now to get the timezone information (code from timezone.pl, written by H. Carvey)
        my $tz_path = $ccs . "\\Control\\TimeZoneInformation";
        my $tz;
        if ($tz = $root_key->get_subkey($tz_path)) {
            my %tz_vals;
            my @vals = $tz->get_list_of_values();
            if (scalar(@vals) > 0) {
                map { $tz_vals{ $_->get_name() } = $_->get_data() } (@vals);
                my $tz = $tz_vals{'StandardName'};
                $tz =~ s/[a-z]//g;
                $tz =~ s/\s//g;

                # we do not set the time zone right now
                my $trans_tz = Log2t::Win::get_win_tz($tz_vals{'StandardName'});

                # check if the transform exists
                # then check if it's the same as the one chosen
                if ($trans_tz) {
                    if ("$trans_tz" eq "$l2t->{'time_zone'}") {
                        print STDERR
                          "[PreProcessing] The timezone according to the registry is the same as the one chosen ($trans_tz)\n";
                    }
                    else {
                        print STDERR "[PreProcessing] The timezone according to registry is: ($tz) "
                          . $tz_vals{'StandardName'} . "\n";
                        print STDERR
                          "[PreProcessing] The chosen timezone does NOT match the one in the registry, changing values.\n";
                        $l2t->set('time_zone' => $trans_tz);
                        print STDERR "[PreProcessing] Time zone changed to: $trans_tz.\n";
                    }
                }
                else {
                    print STDERR "[PreProcessing] The timezone according to registry is: ($tz) "
                      . $tz_vals{'StandardName'} . "\n";
                    print STDERR
                      "[PreProcessing] The timezone settings are NOT overwritten so the settings might have to be adjusted.\n";
                }
            }
        }

    }

    # get the default system browser
    if (-f $reg_file2) {
        $reg                         = Parse::Win32Registry->new($reg_file2);
        $root_key                    = $reg->get_root_key;
        $l2t->{'defbrowser'}->{'os'} = '';

        eval {
            if ($key = $root_key->get_subkey("Clients\\StartMenuInternet"))
            {
                $l2t->{'defbrowser'}->{'os'} .= $key->get_value("")->get_data();
            }

            if ($key = $root_key->get_subkey("Classes\\HTTP\\shell\\open\\command")) {
                my $add = $l2t->{'defbrowser'}->{'os'} eq '' ? 0 : 1;

                $l2t->{'defbrowser'}->{'os'} .= ' (' if $add;
                $l2t->{'defbrowser'}->{'os'} .= $key->get_value("")->get_data();
                $l2t->{'defbrowser'}->{'os'} .= ')'  if $add;
            }

            print STDERR "[PreProcessing] The default system browser is: : "
              . $l2t->{'defbrowser'}->{'os'} . "\n";
        };
        if ($@) {
            print STDERR "[PreProcessing] Unable to determine the system wide default browser\n";
        }
    }

    return 1;
}

1;
