#################################################################################################
#               user_browser
#################################################################################################
# This script is a part of the log2timeline framework for timeline creation and analysis.
#
# This script implements a preprocessing module.  A preprocessing module is a module that
# is started before log2timeline parses the image (mounted image) to gather information
# from the system, that is then used in the rest of the processing.
#
# This module reads the registry of a Windows machine to determine the default browser of
# each of the users in the system.
#
#
# Author: Kristinn Gudjonsson
# Version : 0.1
# Date : 14/05/11
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

package Log2t::PreProc::user_browser;

use strict;
use Parse::Win32Registry qw(:REG_);    # to be able to read the registry

sub get_info($) {
    my $self = shift;
    my $l2t  = shift;
    my $go   = 0;                      # set this if we find the full path (windows system32 config)
    my %user_files;                    # a hash with the path to all NTUSER.DAT files to parse

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

        # remove spaces and make lower case
        my $croot = lc($root);
        $croot =~ s/\s//g;

        if (($croot =~ m/^users$/i or $croot =~ m/^documentsandsettings$/i)
            and -d $l2t->{'file'} . $l2t->{'sep'} . "$root")
        {
            opendir(PD, $l2t->{'file'} . $l2t->{'sep'} . $root);
            my @userdir = readdir(PD);
            closedir(PD);

            foreach my $user (@userdir) {
                if (-d $l2t->{'file'} . $l2t->{'sep'} . $root . $l2t->{'sep'} . $user) {
                    opendir(UD, $l2t->{'file'} . $l2t->{'sep'} . $root . $l2t->{'sep'} . $user);
                    my @userdirs = grep { /ntuser.dat$/i } readdir(UD);
                    closedir(UD);

                    # check each file
                    foreach my $nt (@userdirs) {
                        if (  -f $l2t->{'file'}
                            . $l2t->{'sep'}
                            . $root
                            . $l2t->{'sep'}
                            . $user
                            . $l2t->{'sep'}
                            . $nt and $nt =~ m/ntuser.dat/i)
                        {
                            $go = 1;
                            $user_files{ lc($user) } =
                                $l2t->{'file'}
                              . $l2t->{'sep'}
                              . $root
                              . $l2t->{'sep'}
                              . $user
                              . $l2t->{'sep'}
                              . $nt;
                        }
                    }
                }
            }
        }
    }

    # check if we've found the directory
    return 0 unless $go;

    # now to go over each one of those ntuser registry files and print out information
    foreach my $user (keys %user_files) {

        # start reading the registry
        my $reg      = Parse::Win32Registry->new($user_files{$user});
        my $root_key = $reg->get_root_key;

# we are getting the default browser for each user.... , code gotten from defbrowser.pl written by H. Carvey

        #-----------------------------------------------------------
        # defbrowser.pl
        # Get default browser information - check #1 can apply to HKLM
        # as well as to HKCU
        #
        # Change History:
        #   20091116 - Added Check #1
        #   20081105 - created
        #
        # copyright 2009 H. Carvey, keydet89@yahoo.com
        #-----------------------------------------------------------
        my $key_path = "Software\\Clients\\StartMenuInternet";
        eval {
            if (my $key = $root_key->get_subkey($key_path))
            {
                $l2t->{'defbrowser'}->{$user} = $key->get_value("")->get_data()
                  unless $key->get_value("")->get_data() eq '';
                print STDERR
                  "[PreProcessing] The default browser of user $user according to registry is: ("
                  . $l2t->{'defbrowser'}->{$user} . ")\n";
            }

            # check second check
            $key_path = "Software\\Classes\\HTTP\\shell\\open\\command";
            if (my $key = $root_key->get_subkey($key_path)) {
                $l2t->{'defbrowser'}->{$user} = $key->get_value("")->get_data()
                  unless $key->get_value("")->get_data() eq '';
                print STDERR
                  "[PreProcessing] The default browser of user $user according to registry is: ("
                  . $l2t->{'defbrowser'}->{$user} . ")\n";
            }

            print STDERR "[PreProcessing] Unable to determine the default browser for user $user\n"
              if $l2t->{'defbrowser'}->{$user} eq '';
        };
        if ($@) {
            print STDERR "[PreProcessing] Unable to determine the default browser for user $user\n";
        }
    }

    return 1;
}

1;
