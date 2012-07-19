#################################################################################################
#    LSQuarantine
#################################################################################################
# This is a simple module to parse the LSQurantineEvent database found on Mac OS X systems.
# This SQLite database contains a list of all downloaded files on Mac OS X.
#
# Mac OS X:
#  /Users/<username>/Library/Preferences/com.apple.LaunchServices.QuarantineEvents
#
# Author: Kristinn Gudjonsson
# Version : 0.1
# Date : 18/05/12
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
#
# This script uses part of the code ff3histview, previously published
# by the same author
package Log2t::input::ls_quarantine;

use strict;
use Log2t::base::input;    # the SUPER class or parent
use DBI;
use File::Copy;
use Log2t::Numbers;
use Log2t::Time;
use Log2t::Common;
use Encode;

use vars qw($VERSION @ISA);

# inherit the base input module, or the super class.
@ISA = ("Log2t::base::input");

$VERSION = '0.1';

sub new() {
    my $class = shift;

    # bless the class ;)
    my $self = $class->SUPER::new();

    # indicate that we are dealing with a binary file (only one entry returned)
    $self->{'multi_line'} = 0;

    bless($self, $class);

    return $self;
}

sub init() {
    my $self = shift;

    # initialize variables
    $self->{'db_lock'} = 0;

    return 1;
}

#       get_description
# A simple subroutine that returns a string containing a description of
# the funcionality of the format file. This string is used when a list of
# all available format files is printed out
#
# @return A string containing a description of the format file's functionality
sub get_description() {
    return "Parse the content of a LSQuarantineEvents database";
}

#       get_time
# The main "juice", the routine that is called to extract all timestamps
# from the database.  The database returns a reference to a hash that
# contains all the timestamp objects extracted from the database
sub get_time {
    my $self = shift;

    # define needed variables
    my $return = 1;
    my $temp;
    my ($sth, $sql);
    my $result;
    my $dump;

    # the container for the timestamps
    my %ret_lines = undef;

    # the index to the container
    my $ret_index = 0;

    # The schema of the LSQuarantineEvent table is:
    #   LSQuarantineEventIdentifier TEXT PRIMARY KEY NOT NULL
    #   LSQuarantineTimeStamp REAL
    #   LSQuarantineAgentBundleIdentifier TEXT
    #   LSQuarantineAgentName TEXT
    #   LSQuarantineDataURLString TEXT
    #   LSQuarantineSenderName TEXT
    #   LSQuarantineSenderAddress TEXT
    #   LSQuarantineTypeNumber INTEGER
    #   LSQuarantineOriginTitle TEXT
    #   LSQuarantineOriginURLString TEXT
    #   LSQuarantineOriginAlias BLOB

    # Construct the SQL statement to extract the needed data
    $sql =
      "SELECT LSQuarantineTimestamp+978328800 AS Epoch, LSQuarantineAgentName AS Agent, LSQuarantineOriginURLString AS URL, LSQuarantineDataURLString AS Data
FROM LSQuarantineEvent
ORDER BY Epoch";

    eval {
        $sth    = $self->{'vdb'}->prepare($sql);
        $result = $sth->execute();
    };
    if ($@) {
        print STDERR "[LS_QUARANTINE] Database error ocurred, making parsing of lines not possible. Error msg: $@\n";
        return \%ret_lines;
    }

    # load the result into an array
    while ($dump = $sth->fetchrow_hashref) {
        # content of $dump
        #   Epoch
        #   Agent
        #   URL
        #   Data
        $ret_lines{ $ret_index++ } = {
            'time'       => { 0 => { 'value' => $dump->{'Epoch'}, 'type' => 'File Downloaded', 'legacy' => 15 } },
            'desc'       => '[' . $dump->{'Agent'} . '] Downloaded: ' . $dump->{'URL'} . ' <' . $dump->{'Data'} . '>',
            'short'      => $dump->{'URL'},
            'source'     => 'HIST',
            'sourcetype' => 'LSQuaranine Download Event',
            'version'    => 2,
        };
    }

    # return the container
    return \%ret_lines;
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

#       end
# A subroutine that closes the file, after it has been parsed
# @return An integer indicating that the close operation was successful
sub end() {
    my $self = shift;

    # disconnect the database
    $self->{'vdb'}->disconnect if defined $self->{'vdb'};

    # check to see if database is locked, then delete temp file
    if ($self->{'db_lock'}) {

        #print STDERR "Deleting temporary history file, $db_file \n";
        unlink(${ $self->{'name'} });
        unlink(${ $self->{'name'} } . '-journal') if -e ${ $self->{'name'} } . '-journal';
    }
}

#       get_help
# A simple subroutine that returns a string containing the help
# message for this particular format file.
# @return A string containing a help file for this format file
sub get_help() {
    return "
This module parses the downloaded items database on Mac OS X, stored in the SQLite db
com.apple.LaunchServices.QuarantineEvents

Described here: http://www.tuaw.com/2012/02/14/mac-os-xs-quarantineevents-keeps-a-log-of-all-your-downloads/\n";
}

#       verify
# A subroutine that verifies if we are examining a prefetch directory so it can be further
# processed.  The correct format is a directory that consists of a folder that contains
# several files that end with a .pf ending.  Then one file in the folder is named Layout.ini
# @return An array containing an integer and a string.  The integer indicates a success or failure and the
#       string is the error message (if the file is not correctly formed)
sub verify {
    # define an array to keep
    my %return;
    my $line;
    my @words;
    my $temp;
    my $magic = 'SQLite format 3';
    my $self  = shift;
    my $vsth;

    # we assume that the file is not a SQLite database.
    $return{'success'} = 0;
    $return{'msg'}     = 'unknown';

    return \%return unless -f ${ $self->{'name'} };

    # read the first few bits, see if it matches signature
    for (my $i = 0; $i < 15; $i++) {
        seek($self->{'file'}, $i, 0);
        read($self->{'file'}, $temp, 1);
        $line .= $temp;
    }

    # check if the line indicates a real sqlite database (version 3)
    if ($line ne $magic) {
        $return{'success'} = 0;
        $return{'msg'}     = "Wrong magic value.  Is this really a sqlite database?\n";

        return \%return;
    }

    # we know that this is a SQLite database, but is it a Skype one?
    # start by checking if we have a database journal as well
    my $tmp_path = '';
    if (-f ${ $self->{'name'} } . "-journal") {
        eval {
            # create a new variable to store the temp location
            my $rand_int = int(rand(100));
            $tmp_path = '/tmp/tmp_ch.' . $rand_int . 'v.db';

            # we need to copy the file to a temp location and start again
            copy(${ $self->{'name'} }, $tmp_path) || ($return{'success'} = 0);
            copy(${ $self->{'name'} } . "-journal", $tmp_path . "-journal")
              || ($return{'success'} = 0);

            ${ $self->{'name'} } = $tmp_path;
            $self->{'db_lock'} = 1;    # indicate that we need to delete the lock file
        };
        if ($@) {
            $return{'success'} = 0;
            $return{'msg'} =
              'Database is locked and unable to copy to a temporary location (' . $tmp_path . ')';
        }
    }

    # assume we have the correct DB structure
    my $ls_db= 1;

    eval {
        # connect to the database
        $self->{'vdb'} = DBI->connect("dbi:SQLite:dbname=" . ${ $self->{'name'} }, "", "")
          or ($ls_db= 0);
        $self->{'vdb'}->{'PrintError'} = 0;

        unless ($ls_db) {
            $return{'success'} = 0;
            $return{'msg'}     = 'Unable to connect to the database';
            return \%return;
        }

        # get a list of all available tables
        $vsth = $self->{'vdb'}->prepare("SELECT name FROM sqlite_master WHERE type='table'")
          or die('Not able to query the database.');

        # execute the query
        my $res = $vsth->execute();

        while (@words = $vsth->fetchrow_array()) {
            if ($words[0] eq 'LSQuarantineEvent') {
                my $account_sth =
                  $self->{'vdb'}->prepare(
                    "SELECT LSQuarantineOriginURLString, LSQuarantineDataURLString FROM LSQuarantineEvent"
                    ) or die('Not the correct DB structure.');
            }
        }

        # check if temp is set
        if ($ls_db) {
            # now we have a Skype history SQLite database
            $return{'success'} = 1;
            $return{'msg'}     = 'Success';
        }
        else {
            $return{'success'} = 0;
            $return{'msg'}     = 'This is not a LSQuarantine SQLite database';
        }

        # disconnect from the database
        $vsth->finish;
        undef $vsth;
    };
    if ($@) {
        $return{'success'} = 0;
        $return{'msg'} =
          'Database error ocurred, making verification not possible.  The error message is: '
          . $@;
    }

    return \%return;
}

1;
