#################################################################################################
#		OUTPUT
#################################################################################################
# this package provides an output module for the tool log2timeline.
# The package takes as an input a hash that contains all the needed information to print or output
# the timeline that has been produced by a format file
#
# Author: Kristinn Gudjonsson
# Version : 0.8
# Date : 18/07/11
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

package Log2t::output::sqlite;

use strict;
use DBI;
use vars qw($VERSION);
use Getopt::Long;    # read parameters
use Log2t::Common;

# version number
$VERSION = '0.8';

#       get_version
# A simple subroutine that returns the version number of the format file
#
# @return A version number
sub get_version() {
    return $VERSION;
}

#       new
# A simple constructor of the output module. Takes care of parsing
# parameters sent to the output module
sub new($) {
    my $class = shift;

    # bless the class ;)
    my $self = bless {}, $class;

    return $self;

}

#       get_description
# A simple subroutine that returns a string containing a description of
# the funcionality of the format file. This string is used when a list of
# all available format files is printed out
#
# @return A string containing a description of the format file's functionality
sub get_description() {
    return "Output timeline into a SQLite database";
}

#	print_header
#
sub print_header() {
    my $self = shift;
    my $db_file;
    my $return = 1;
    my $sql;

    # get the file name
    $db_file = $self->{'log_file'};

    # check db_file (must provide a file name)
    if ($db_file eq 'STDOUT') {
        print STDERR
          "Unable to create database, please provide a file name to write database to (use log2timeline with the -w FILE parameter)\n";
        return 0;
    }

    # connect to a database
    $self->{'db'} =
      DBI->connect("dbi:SQLite:dbname=$db_file", "", "", { RaiseError => 1, AutoCommit => 1 })
      or $return = 0;

    # %t_line {
    #       time
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

    $sql = "
CREATE TABLE IF NOT EXISTS records (
	rid INTEGER PRIMARY KEY AUTOINCREMENT,
	short TEXT,
	detailed TEXT,
	srcid INTEGER,
	legacy INT,
	inode INTEGER,
	description TEXT,
	time INTEGER,
	user TEXT,
	fid INTEGER,
	sid INTEGER,
	hid INTEGER,
	hidden INT DEFAULT 0 )";

    $self->{'db'}->do($sql) or $return = 0;

    $sql = "CREATE INDEX record_time ON records(time)";
    $self->{'db'}->do($sql) or $return = 0;
    $sql = "CREATE INDEX user_name ON records(user)";
    $self->{'db'}->do($sql) or $return = 0;

    # create the filename table
    $sql = "
CREATE TABLE IF NOT EXISTS filename (
	fid INTEGER PRIMARY KEY AUTOINCREMENT,
	filename TEXT
	)";
    $self->{'db'}->do($sql) or $return = 0;

    # create the host table
    $sql = "
CREATE TABLE IF NOT EXISTS host (
	hid INTEGER PRIMARY KEY AUTOINCREMENT,
	hostname TEXT,
	description TEXT,
	operating_system TEXT,
	time_zone TEXT,
	other_information TEXT
	)";
    $self->{'db'}->do($sql) or $return = 0;

    # create the "extra" table
    $sql = "
CREATE TABLE IF NOT EXISTS extra (
	eid INTEGER PRIMARY KEY AUTOINCREMENT,
	rid INTEGER,
	variable TEXT,
	value TEXT 
	)";

    $self->{'db'}->do($sql) or $return = 0;

    #	$sql ="CREATE INDEX record_atime ON records(atime)";
    #	$self->{'db'}->do( $sql ) or $return = 0;

    #	$sql ="CREATE INDEX record_mtime ON records(mtime)";
    #	$self->{'db'}->do( $sql ) or $return = 0;

    #	$sql ="CREATE INDEX record_ctime ON records(ctime)";
    #	$self->{'db'}->do( $sql ) or $return = 0;

    #	$sql ="CREATE INDEX record_crtime ON records(crtime)";
    #	$self->{'db'}->do( $sql ) or $return = 0;

    $sql = "
CREATE TABLE IF NOT EXISTS source (
srcid INTEGER PRIMARY KEY AUTOINCREMENT,
name TEXT,
detail TEXT,
description TEXT 
)";
    $self->{'db'}->do($sql) or $return = 0;

    $sql = "
CREATE TABLE IF NOT EXISTS tag (
tid INTEGER PRIMARY KEY AUTOINCREMENT,
name TEXT,
description TEXT 
)";
    $self->{'db'}->do($sql) or $return = 0;

    $sql = "
CREATE TABLE IF NOT EXISTS tagged (
rid INTEGER,
tid INTEGER
)";

    $self->{'db'}->do($sql) or $return = 0;

    $sql = "
	CREATE TABLE IF NOT EXISTS super (
	sid INTEGER PRIMARY KEY AUTOINCREMENT,
	name TEXT,
	description TEXT
	)";
    $self->{'db'}->do($sql) or $return = 0;

    $sql = "
	CREATE TABLE IF NOT EXISTS info (
	version TEXT,
	tool TEXT,
	ver_tool TEXT
	)";
    $self->{'db'}->do($sql) or $return = 0;

    # include information about the tool
    $sql = "INSERT INTO info (version,tool,ver_tool) VALUES( '$VERSION' , 'log2timeline', '"
      . Log2t::Common::get_version . '\')';
    $self->{'db'}->do($sql) or $return = 0;

    return $return;
}

sub get_footer() {
    return 0;    # no footer
}

sub print_footer() {
    my $self = shift;

    $self->{'db'}->disconnect;
    return 1;
}

#      	print_line
# A subroutine that reads a line from the access file and returns it to the
# main script
# @return A string containing one line of the log file (or a -1 if we've reached
#       the end of the log file)
sub print_line() {

    # content of the timestamp object t_line
    # optional fields are marked with []
    #
    # %t_line {
    #       time
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

    my $self   = shift;
    my $t_line = shift;
    my $sql;
    my $sth;
    my $mactime;
    my $sth;
    my $p2;

    #my %t_line = %{$ref};
    if (scalar(%{$t_line})) {

        # get the host ID
        $self->_get_hid($t_line->{'extra'}->{'host'})
          if $t_line->{'extra'}->{'host'} ne $self->{'host'}->{'name'};

        # get the source ID
        $self->_get_sid($t_line->{'source'}, $t_line->{'sourcetype'})
          if $t_line->{'sourcetype'} ne $self->{'source'}->{'detail'};

        # get the filename ID
        $self->_get_fid($t_line->{'extra'}->{'filename'})
          if $t_line->{'extra'}->{'filename'} ne $self->{'file'}->{'name'};

        # go through each defined timestamp
        foreach (keys %{ $t_line->{'time'} }) {

            # don't care about null values
            next unless $t_line->{'time'}->{$_}->{'value'} > 0;

            # check if we have a file (need to include MACB)
            if (lc($t_line->{'source'}) eq 'file') {
                $mactime = $t_line->{'time'}->{$_}->{'legacy'} & 0b0001 ? 'M' : '.';
                $mactime .= $t_line->{'time'}->{$_}->{'legacy'} & 0b0010 ? 'A' : '.';
                $mactime .= $t_line->{'time'}->{$_}->{'legacy'} & 0b0100 ? 'C' : '.';
                $mactime .= $t_line->{'time'}->{$_}->{'legacy'} & 0b1000 ? 'B' : '.';

                if ($t_line->{'time'}->{$_}->{'type'} =~ m/SI/) {

                    $p2 = '[$SI ';
                }
                else {
                    $p2 = '[$FN ';
                }

                $p2 .= $mactime . '] ';
            }
            else {
                $p2 = '';
            }

            # insert the record into the database
            $sql =
              q{INSERT INTO records (short,detailed,srcid,legacy,description,inode,time,user,fid,sid,hid,hidden) VALUES( ?,?,?,?,?,?,?,?,?,?,?,0)};
            $sth = $self->{'db'}->prepare($sql);

            # execute the query
            my @iarray = split(/-/, $t_line->{'inode'});

            $sth->execute(
                $t_line->{'short'},

                #$self->{'db'}->quote( $t_line->{'short'} ),
                $p2 . $t_line->{'desc'},

                #$self->{'db'}->quote( $p2 . $t_line->{'desc'} ),
                int($self->{'source'}->{'srcid'}),
                int($t_line->{'time'}->{$_}->{'legacy'}),
                $t_line->{'time'}->{$_}->{'type'},

                #$self->{'db'}->quote( $t_line->{'time'}->{$_}->{'type'} ),
                int($iarray[0]),

                #$self->{'db'}->quote( $t_line->{'time'}->{$_}->{'value'} ),
                #$self->{'db'}->quote( $t_line->{'extra'}->{'user'} ),
                $t_line->{'time'}->{$_}->{'value'},
                $t_line->{'extra'}->{'user'},
                int($self->{'file'}->{'fid'}),
                0,
                int($self->{'host'}->{'hid'}),
                         );

        }

        $sql = q{SELECT rid FROM records ORDER BY rid DESC LIMIT 1};
        $sth = $self->{'db'}->prepare($sql);
        $sth->execute();

        my @temp = $sth->fetchrow_array;
        my $sid  = $temp[0];

        # go through the extra field (need that last sid value)
        foreach my $i (keys %{ $t_line->{'extra'} }) {

            # things we are about to skip including
            next if $i eq 'host';
            next if $i eq 'user';
            next if $i eq 'inode';
            next if $i eq 'filename';
            next if $i eq 'path';
            next if $i eq 'parse_dir';
            next if $i eq 'format';

            $sql = q{INSERT INTO extra (rid,variable,value) VALUES( ?,?,? )};
            $sth = $self->{'db'}->prepare($sql);

            # execute it
            $sth->execute(
                $sid,

                #$self->{'db'}->quote( $i ),
                #$self->{'db'}->quote( $t_line->{'extra'}->{$i} )
                $i,
                $t_line->{'extra'}->{$i}
                         );
        }
    }
    else {
        print STDERR "Error. t_line not scalar\n";
        return 0;
    }

    return 1;

}

#       get_help
# A simple subroutine that returns a string containing the help
# message for this particular format file.
# @return A string containing a help file for this format file
sub get_help() {
    return "A output plugin that dumps all the records into a single SQLite database table,
with one extra column, hidden, indicating whether the record should be visible or not.

This database can then be read by any tool capable of reading SQLite databases.\n";

}

sub _get_fid {
    my $self    = shift;
    my $file_in = shift;
    my ($sth, $sql);
    my @store;

    # query the db
    $sql = q{SELECT fid FROM filename WHERE filename = ?};
    $sth = $self->{'db'}->prepare($sql);
    $sth->execute($file_in);

    $self->{'file'}->{'name'} = $file_in;

    # check if we get any answer
    if ($sth->rows eq 1) {
        @store = $sth->fetchrow_array;
        $self->{'file'}->{'fid'} = $store[0];
    }
    else {

        # no file, create one
        $sql = q{INSERT INTO filename (filename) VALUES( ? )};
        $sth = $self->{'db'}->prepare($sql);
        $sth->execute($file_in);

        # get the ID
        $sql = q{SELECT fid FROM filename WHERE filename = ?};
        $sth = $self->{'db'}->prepare($sql);
        $sth->execute($file_in);

        @store = $sth->fetchrow_array;
        $self->{'file'}->{'fid'} = $store[0];
    }

    return 1;
}

sub _get_hid {
    my $self      = shift;
    my $host_name = shift;
    my ($sth, $sql);
    my @store;

    # get the time zone value
    my $tz = $self->{'tz'};

    # query the db
    $sql = q{SELECT hid FROM host WHERE hostname = ?};
    $sth = $self->{'db'}->prepare($sql);
    $sth->execute($host_name);

    $self->{'host'}->{'name'} = $host_name;

    # check if we get any answer
    if ($sth->rows eq 1) {
        @store = $sth->fetchrow_array;
        $self->{'host'}->{'hid'} = $store[0];
    }
    else {

        # no host, create one
        $sql = q{INSERT INTO host (hostname,time_zone,description) VALUES( ?,?,'no description' )};
        $sth = $self->{'db'}->prepare($sql);
        $sth->execute($host_name, $tz);

        # get the ID
        $sql = q{SELECT hid FROM host WHERE hostname = ?};
        $sth = $self->{'db'}->prepare($sql);
        $sth->execute($host_name);

        @store = $sth->fetchrow_array;
        $self->{'host'}->{'hid'} = $store[0];
    }

    return 1;
}

sub _get_sid {
    my $self        = shift;
    my $source_name = shift;
    my $source_type = shift;
    my ($sth, $sql);
    my @store;

    # query the db
    $sql = q{SELECT srcid FROM source WHERE name = ? AND detail = ?};
    $sth = $self->{'db'}->prepare($sql);
    $sth->execute($source_name, $source_type);

    $self->{'source'}->{'name'}   = $source_name;
    $self->{'source'}->{'detail'} = $source_type;

    # check if we get any answer
    if ($sth->rows eq 1) {
        @store = $sth->fetchrow_array;
        $self->{'source'}->{'srcid'} = $store[0];
    }
    else {

        # no host, create one
        $sql = q{INSERT INTO source (name,detail,description) VALUES( ?, ?, 'no description' )};
        $sth = $self->{'db'}->prepare($sql);
        $sth->execute($source_name, $source_type);

        # get the ID
        $sql = q{SELECT srcid FROM source WHERE name = ? AND detail = ?};
        $sth = $self->{'db'}->prepare($sql);
        $sth->execute($source_name, $source_type);

        @store = $sth->fetchrow_array;
        $self->{'source'}->{'srcid'} = $store[0];
    }

    return 1;
}

1;
