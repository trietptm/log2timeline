#!/usr/bin/perl
#########################################################################################
#                       Common
#########################################################################################
# This is a small library that is a part of the tool log2timeline. It's purpose is to
# assist with various common functions that are used by more than one module.
# One function of this library is to list the input and output modules, a function that
# is typically used by different front-ends of the tool to know which modules are available
#
# Author: Kristinn Gudjonsson
# Date : 01/02/10
#
# Copyright 2009-2012 Kristinn Gudjonsson (kristinn ( a t ) log2timeline (d o t) net)
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

package Log2t::Common;

use strict;
use Exporter qw(import);
use Cwd;

use vars qw($VERSION);

# define some constants
use constant {
               LITTLE_E => 1,
               BIG_E    => 0
             };

# and export them
our @EXPORT_OK = ('LITTLE_E', 'BIG_E');
our %EXPORT_TAGS = (binary => [ 'LITTLE_E', 'BIG_E' ]);

$VERSION = "0.65";

# create a variable for nightly builds
my $n_date    = '20120724';
my $n_release = 1;            # this is 0 for a released version and 1 for a nightly build

sub get_directory() {
    my $folder = undef;

    # go through the INC array and find the Log2t folder
    foreach (@INC) {
        next if defined $folder;
        $folder = $_ if -d $_ . '/Log2t' and -d $_ . '/Log2t/input' and -f $_ . '/Log2t/Common.pm';

    }

    return $folder;
}

sub list_lists() {
    my $folder = undef;
    my @dir;
    my $content;
    my $ret;

    $folder = get_directory();
    return "Unable to find Log2t" unless defined $folder;

    # open up the input module directory and read all the list files
    opendir(PD, $folder . '/Log2t/input') || return "Unable to open the input module directory\n";

    @dir = grep { /\.lst$/ } readdir(PD);
    closedir(PD);
    @dir = sort(@dir);

    # and go through the list
    $ret = "\n-------------------------------------------------------------------------\n";
    $ret .= "\t\t\tAvailable lists of modules\n";
    $ret .= "-------------------------------------------------------------------------\n";
    $ret .= "Use the -f LISTNAME to use only the modules included in the list\n";

    foreach my $d (@dir) {

        # print the name of the directory
        $ret .= sprintf "%s\n", substr $d, 0, -4;

        # this needs to be a real file
        next unless -f $folder . '/Log2t/input/' . $d;

        # open the file
        open(SKRA, $folder . '/Log2t/input/' . $d);

        $ret .= "\t";

        # go through the content
        while (<SKRA>) {
            s/\n//;
            $ret .= $_ . ', ';
        }
        $ret .= "\n\n";

        # close the file
        close(SKRA);
    }

    return $ret;
}

sub list_input() {
    my @dir;
    my $folder = undef;
    my $module;
    my $name;
    my $ret;

    $folder = get_directory();
    return "Unable to find Log2t" unless defined $folder;

    # open up the input module folder to find all the available input modules
    opendir(PD, $folder . '/Log2t/input')
      || die("Could not open the directory '$folder/Log2t/input/'\n");
    @dir = grep { /\.pm$/ } readdir(PD);
    @dir = sort(@dir);
    closedir(PD);

    # print the header
    $ret = "-------------------------------------------------------------------------\n";
    $ret .= sprintf "%20s\tVer.\tDescription\n", "Name";
    $ret .= "-------------------------------------------------------------------------\n";

    foreach (@dir) {

        # we are not interested unless the file ends in .pl
        next unless (/\.pm$/);

        # print out information about all available format files
        eval    # try/catch around the loading of format files
        {

            # load the input module to get information
            require 'Log2t/input/' . $_;

            $module = 'Log2t::input::' . $_;
            $module =~ s/\.pm//g;
            $name = $_;
            $name =~ s/\.pm//g;

            # print a description of the format file
            $ret .= sprintf "%20s\t%4s\t%s\n", $name, $module->get_version(),
              $module->get_description();
        };

        # check to see if there was an error loading up the format file
        return $@ if $@;
    }

    return $ret;
}

sub list_output() {
    my @dir;
    my $folder = undef;
    my $module;
    my $name;
    my $ret;

    $folder = get_directory();
    return "Unable to find Log2t" unless defined $folder;

    # open up the input module folder to find all the available input modules
    opendir(PD, $folder . '/Log2t/output')
      || die("Could not open the directory '$folder/Log2t/output/'\n");
    @dir = readdir(PD);
    @dir = sort(@dir);
    closedir(PD);

    # print the header
    $ret = "-------------------------------------------------------------------------\n";
    $ret .= sprintf "%20s\tVersion\t\tDescription\n", "Name";
    $ret .= "-------------------------------------------------------------------------\n";

    foreach (@dir) {

        # we are not interested unless the file ends in .pl
        next unless (/\.pm$/);

        # print out information about all available format files
        eval    # try/catch around the loading of format files
        {

            # load the input module to get information
            require 'Log2t/output/' . $_;

            $module = 'Log2t::output::' . $_;
            $module =~ s/\.pm//g;
            $name = $_;
            $name =~ s/\.pm//g;

            # print a description of the format file
            $ret .= sprintf "%20s\t%4s\t%s\n", $name, $module->get_version(),
              $module->get_description();
        };

        # check to see if there was an error loading up the format file
        return $@ if $@;
    }

    return $ret;
}

sub get_version() {

    # check if this is a nightly build or not
    return $VERSION . ' nightly build (' . $n_date . ')' if $n_release;

    return $VERSION;
}

sub get_username_from_path($) {
    my $file = shift;
    my $cwd;
    my $username = 'unknown';
    my $t;

    # check the current working directory and try to guess the username
    # from the path name (assuming we have the username in the path
    $cwd = getcwd;

    # username is stored in the following location
    # C:\Documents and Settings\USERNAME\.... [win xp]
    # C:\Users\USERNAME\.... [vista/win7]
    # /Users/USERNAME [Mac OS X]
    # /Users/local/DOMAIN/USERNAME [Mac OS X with Likewise AD authentication]

    # this script can additionally be called from what ever path there is
    # usually the drive is mounted (either in Win/Mac/Linux and then from
    # what ever the mount point is will we see the directory structure)

    #print STDERR "CWD IS [$cwd] AND FILE IS [$file]\n";

    # check if the file name itself contains the directory
    if ($file =~ m/documents/i || $file =~ m/users/i) {

        #print STDERR "CHECK OUT THE FILE [$file]\n";
        # now we are propably using timescanner to recursively search through a directory
        $cwd = $file;

        #print STDERR "CWD IS NOW $cwd\n";
    }

    # win, prior to vista/win 7
    if ($cwd =~ m/[\/]?Documents and Settings\/(.+)\/.+/) {
        $username = $1;
    }

    # applies to win 7/vista/... and Mac OS X
    if ($cwd =~ m/[\/]?Users\/([a-zA-Z ]+)\/.+/) {
        $username = $1;

        #($username,$t) = split( /\//, $1 );
        #print STDERR "USERNAME: $username\n";

        # some implmentations of Mac OS X use different path
        if (lc($username) eq 'local') {

            #print STDERR "USERNAME IS local\n";
            # have an AD connection using tool such as Likewise
            if ($cwd =~ m/\/Users\/local\/[a-zA-Z]+\/([a-zA-Z]+)\//) {

                #print STDERR "USERNAME: $1\n";
                $username = $1;
            }
        }
    }

    # linux
    if ($cwd =~ m/\/home\/([a-zA-Z]+)\/.+/) {
        $username = $1;
    }

    # fix username
    ($username, $t) = split(/\//, $username);

    return $username;
}

# 	replace_char
# A simlpe function that takes as an input the reference to a string
# and then either replaces certain characters with a pattern or
# changes the pattern again to those characters
sub replace_char($$) {
    my $str = shift;
    my $op  = shift;

    if ($op == 0) {

        # we need to change characters into "pseudo" chars
        $$str =~ s/\./::dot::/g;
        $$str =~ s/\\/::bslash::/g;
        $$str =~ s/\//::slash::/g;
        $$str =~ s/\?/::quest::/g;
        $$str =~ s/\*/::ast::/g;
    }
    else {

        # we are changing back
        $$str =~ s/::dot::/\./g;
        $$str =~ s/::bslash::/\\/g;
        $$str =~ s/::slash::/\//g;
        $$str =~ s/::quest::/\?/g;
        $$str =~ s/::ast::/\*/g;
    }
}

1;
