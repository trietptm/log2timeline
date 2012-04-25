#################################################################################################
#    CHROME
#################################################################################################
# this script reads the browser history file of Google's Chrome.  The history file is a SQLITE
# database that contains the browsing history
#
# The location of the file is usually here:
# Linux:
#   /home/$USER/.config/google-chrome/Default/History
# or
#   /home/$USER/.config/chrome/Default/History
#
# Windows Vista (7):
#  C:\Users\[USERNAME]\AppData\Local\Google\Chrome\
#
# Windows XP:
#  C:\Documents and Settings\[USERNAME]\Local Settings\Application Data\Google\Chrome\
#
# This version only parses the History sqlite database, however, future version should take
# other databases into account:
#  + Top Sites
#  + Login Data
#  + Web Data
#  + History Index ....
#  + Archived History
#
# All of these databases contain information that could be of value, since they contain
# timestamped data.
#
# Login Data:
#  logins
#    origin_url VARCHAR NOT NULL,
#    action_url VARCHAR,
#    username_element VARCHAR,
#    username_value VARCHAR,
#    password_element VARCHAR,
#    password_value BLOB,
#    submit_element VARCHAR,
#    signon_realm VARCHAR NOT NULL,
#    ssl_valid INTEGER NOT NULL,
#    preferred INTEGER NOT NULL,
#    date_created INTEGER NOT NULL,
#    blacklisted_by_user INTEGER NOT NULL,
#    scheme INTEGER NOT NULL,
#
# Change theme, so that during the verification the type of database is detected, and the
# get_time function simply checks the self->{'database_type'} variable and determines which
# get_XXX subroutine needs to be called to parse that particular database.
#
# Author: Kristinn Gudjonsson
# Version : 0.3
# Date : 16/04/11
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
# This script uses part of the code ff3histview, previously published
# by the same author
package Log2t::input::chrome;

use strict;
use DBI;
use File::Copy;
use Log2t::Numbers;
use Log2t::Time;
use Log2t::Common;
use Log2t::base::input;    # the SUPER class or parent

use vars qw($VERSION @ISA);

# inherit the base input module, or the super class.
@ISA = ("Log2t::base::input");

$VERSION = '0.3';

# http://src.chromium.org/viewvc/chrome/trunk/src/chrome/common/page_transition_types.h
# the source can be found here (above URL is the former URL)
# http://src.chromium.org/svn/trunk/src/content/public/common/page_transition_types.h

my %translate = (
      '0' => 'User clicked a link',
      '1' => 'User typed the URL in the URL bar',
      '2' => 'Got through a suggestion in the UI',
      '3' => 'Content automatically loaded in a non-toplevel frame - user may not realize',
      '4' => 'Subframe explicitly requested by the user',
      '5' => 'User typed in the URL bar and selected an entry from the list - such as a search bar',
      '6' => 'The start page of the browser',
      '7' => 'A form the user has submitted values to',
      '8' => 'The user reloaded the page, eg by hitting the reload button or restored a session',
      '9' =>
        'URL what was generated from a replacable keyword other than the default search provider',
      '10' => 'Corresponds to a visit generated from a KEYWORD'
);

my %transition = (

    # User got to this page by clicking a link on another page.
    '0' => 'LINK',

    # User got this page by typing the URL in the URL bar.
    '1' => 'TYPED',

  # User got to this page through a suggestion in the UI, for example,through the destinations page.
    '2' => 'AUTO_BOOKMARK',

# any content that is automatically loaded in a non-toplevel frame. For example, if a page consists of
# several frames containing ads, those ad URLs will have this transition type
# The user may not even realize the content in these pages is a separate frame, so may not care about the URL (see MANUAL below).
    '3' => 'AUTO_SUBFRAME',

# For subframe navigations that are explicitly requested by the user and generate new navigation entries in the back/forward list
# These are probably more important than frames that were automatically loaded in the background because the user probably cares
# about the fact that this link was loaded.
    '4' => 'MANUAL_SUBFRAME',

# User got to this page by typing in the URL bar and selecting an entry that did not look like a URL.  For example, a match might have the URL
# of a Google search result page, but appear like "Search Google for ...".
# These are not quite the same as TYPED navigations because the user didn't type or see the destination URL.
    '5' => 'GENERATED',

    # The page was specified in the command line or is the start page.
    '6' => 'START_PAGE',

# The user filled out values in a form and submitted it. NOTE that in some situations submitting a form does not result in this transition
# type. This can happen if the form uses script to submit the contents.
    '7' => 'FORM_SUBMIT',

# The user "reloaded" the page, either by hitting the reload button or by hitting enter in the address bar.  NOTE: This is distinct from the
# concept of whether a particular load uses "reload semantics" (i.e. bypasses cached data).  For this reason, lots of code needs to pass
# around the concept of whether a load should be treated as a "reload" separately from their tracking of this transition type, which is mainly
# used for proper scoring for consumers who care about how frequently a user typed/visited a particular URL.
#
# SessionRestore and undo tab close use this transition type too.
    '8' => 'RELOAD',

# The url was generated from a replaceable keyword other than the default search provider. If the user types a keyword (which also applies to
# tab-to-search) in the omnibox this qualifier is applied to the transition type of the generated url. TemplateURLModel then may generate an
# additional visit with a transition type of KEYWORD_GENERATED against the url 'http://' + keyword. For example, if you do a tab-to-search against
# wikipedia the generated url has a transition qualifer of KEYWORD, and TemplateURLModel generates a visit for 'wikipedia.org' with a transition
# type of KEYWORD_GENERATED.
    '9' => 'KEYWORD',

    # Corresponds to a visit generated for a keyword. See description of KEYWORD for more details.
    '10' => 'KEYWORD_GENERATED '
);

# the default constructor
sub new() {
    my $class = shift;

    # bless the class ;)
    my $self = $class->SUPER::new();

    # indicate that we are dealing with a binary file (only one entry returned)
    $self->{'multi_line'} = 0;

    # define some variables that are static and used in the code
    $self->{'chrome_date_ofs'} = 11644473600000000
      ;    # the offset of Chrome's date function to the std. Epoch (stored in WEBKIT format)
           # as defined by the current Chrome source as the mask to get core parameters
    $self->{'CORE_MASK'} = 0xff;

    bless($self, $class);

    return $self;
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

sub init() {
    my $self = shift;

    # initialize variables
    $self->{'db_lock'} = 0;
    $self->{'index'}   = 0;

    # boolean values that are used to determine the existance of tables
    #  $self->{'table_downloads'} = 0;
    #  $self->{'table_visits'} = 0;
    #  $self->{'table_urls'} = 0;

    # check if we need to "guess" the username of the user
    $self->{'username'} = Log2t::Common::get_username_from_path($self->{'filename'});

    print STDERR "[Chrome] Username found: " . $self->{'username'} . "\n" if $self->{'debug'};

    return 1;
}

#       get_description
# A simple subroutine that returns a string containing a description of
# the funcionality of the format file. This string is used when a list of
# all available format files is printed out
#
# @return A string containing a description of the format file's functionality
sub get_description() {
    return "Parse the content of a Chrome history file";
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
    my @dump;

    # the container for the timestamps
    my %ret_lines = undef;

    # the index to the container
    my $ret_index = 0;

    # check if this is real Chrome database
    $self->{'vdb'}->prepare('SELECT transition FROM visits LIMIT 1') || ($return = 0);

    if (!$return) {
        print STDERR "[Chrome] The database is not a correct Chrome database";
        return $return;
    }

    # we now know that we have a Chrome SQLITE database, let's continue

    ##################################################################
    # the structure/schema of the visits table
    ##################################################################
    # id INTEGER PRIMARY KEY
    # url INTEGER
    # title LONGVARCHAR
    # visit_time INTEGER
    # from_visit INTEGER
    # transition INTEGER
    # segment_id INTEGER
    # is_indexed INTEGER,
    #-----------------------------------------------------------------
    #
    ##################################################################
    # the structure/schema of the urls table
    # http://src.chromium.org/svn/trunk/src/chrome/browser/history/url_database.h
    # http://src.chromium.org/svn/trunk/src/chrome/browser/history/url_database.cc
    ##################################################################
    # id INTEGER PRIMARY KEY
    # url LONGVARCHAR
    # title LONGVARCHAR
    # visit_count INTEGER DEFAULT 0
    # typed_count INTEGER DEFAULT 0
    # last_visit_time INTEGER
    # hidden INTEGER DEFAULT 0 NOT NULL,
    # favicon_id INTEGER DEFAULT 0 NOT NULL,
    #-----------------------------------------------------------------
    #
    ##################################################################
    # the structure/schema of the downloads table
    ##################################################################
    # id INTEGER
    # full_path LONGVARCHAR
    # url LONGVARCHAR
    # start_time INTEGER
    # received_bytes INTEGER
    # total_bytes INTEGER
    # state INTEGER
    #-----------------------------------------------------------------
    #

    # check for constructs
    if ($self->{'debug'}) {
        print STDERR "[Chrome] Table visits exists\n" if $self->{'table_visits'};
        print STDERR "[Chrome] Table visits does not exist\n" unless $self->{'table_visits'};
        print STDERR "[Chrome] Table urls exists\n" if $self->{'table_urls'};
        print STDERR "[Chrome] Table urls does NOT exist\n" unless $self->{'table_urls'};
        print STDERR "[Chrome] Table downloads exists\n" if $self->{'table_downloads'};
        print STDERR "[Chrome] Table downloads does NOT exist\n" unless $self->{'table_downloads'};
    }

    # Construct the SQL statement to extract the needed data
    if ($self->{'table_visits'} && $self->{'table_urls'}) {
        $sql = "
SELECT urls.url, urls.title, urls.visit_count, urls.typed_count, urls.last_visit_time, urls.hidden, visits.visit_time, visits.from_visit, visits.transition
FROM urls, visits
WHERE
  urls.id = visits.url 
ORDER BY visits.visit_time
    ";

        $sth    = $self->{'vdb'}->prepare($sql);
        $result = $sth->execute();

        # load the result into an array
        while (@dump = $sth->fetchrow_array()) {
            $self->{'r_type'} = 'url';
            $self->{'r_line'} = [@dump];

            $ret_lines{ $ret_index++ } = $self->_parse_timestamp;
        }
    }

    if ($self->{'table_downloads'}) {
        $sql = "
SELECT full_path, url, start_time, received_bytes, total_bytes,state FROM downloads
    ";

        $sth    = $self->{'vdb'}->prepare($sql);
        $result = $sth->execute();

        # load the result into an array
        while (@dump = $sth->fetchrow_array()) {
            $self->{'r_type'} = 'download';
            $self->{'r_line'} = [@dump];

            $ret_lines{ $ret_index++ } = $self->_parse_timestamp;
        }
    }

    # return the container
    return \%ret_lines;
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

#       parse_line
# This is the main "juice" of the format file.  It takes a line from the log file
# and parses it to produce an array containing all the needed values to print a
# body file.
#
# The default structure of Squid log file is:
# timestamp elapsed IP/Client Action/Code Size Method URI Ident Hierarchy/From Content
#
# @param LINE a string containing a single line from the access file
# @return Returns a array containing the needed values to print a body file

sub _parse_timestamp {
    my $self = shift;

    # create the timestamp object
    my %t_line = '';

    my @r_line = @{ $self->{'r_line'} };

    # fields of interest
    my $date;
    my $time_offset = 0;
    my $hostname;
    my $from;
    my $text;
    my $size   = 0;
    my $r_true = 0;
    my $type;

    # start by initializing the text
    $text = '';

    #print STDERR "PARSING A LINE OF TYPE $r_type\n";

    # now we need to check the "type" of record
    if ($self->{'r_type'} eq 'download') {
        $type = 'File downloaded';

        $text .=
            $r_line[1] . ' ('
          . $r_line[0]
          . ').  Total bytes received : '
          . $r_line[3]
          . ' (total: '
          . $r_line[4] . ')';
        $date = $r_line[2];
        $size = $r_line[4];

        # indicate that we have a valid type
        $r_true = 1;
    }
    elsif ($self->{'r_type'} eq 'url') {
        $type = 'URL visited';

        # we need to fix the date, so we can represent it correctly (it is stored in UTC)
        $date = Log2t::Numbers::roundup(($r_line[6] - $self->{'chrome_date_ofs'}) / 1000000);

        # get the hostname
        $hostname = $self->_fix_hostname($r_line[0]);

        # check to see if we came to the web site from another one
        if ($r_line[7] ne 0) {

            # FROM -> URL HOST DATE
            $from = $self->_get_url($r_line[7]);
        }

        if ($from->{'s_url'} ne '') {
            $text .=
                $r_line[0] . ' ('
              . $r_line[1]
              . ') [count: '
              . $r_line[2]
              . '] Host: '
              . $hostname
              . ' visited from: '
              . $from->{'s_url'};
        }
        else {
            $text .=
              $r_line[0] . ' (' . $r_line[1] . ') [count: ' . $r_line[2] . '] Host: ' . $hostname;
        }

        # and include the visit transition
        $text .=
            ' type: ['
          . $transition{ $r_line[8] & $self->{'CORE_MASK'} } . ' - '
          . $translate{ $r_line[8] & $self->{'CORE_MASK'} } . ']';

        if ($r_line[5] eq 1) {
            $text .= ' (url hidden)';
        }
        if ($r_line[3] ge 1) {
            $text .= ' (typed count: ';
            $text .= $r_line[3] . ' time';
            $text .= 's ' if $r_line[3] gt 1;
            $text .= ' - does not indicate directly typed though)';
        }
        else {
            $text .= ' (URL not typed directly - no typed count)';
        }

        # indicate that we have a valid type
        $r_true = 1;

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
    %t_line = (
        'time'       => { 0 => { 'value' => $date, 'type' => $type, 'legacy' => 15 } },
        'desc'       => $text,
        'short'      => 'URL: ' . $r_line[0],
        'source'     => 'WEBHIST',
        'sourcetype' => 'Chrome History',
        'version'    => 2,
        'extra' => { 'user' => $self->{'username'}, 'size' => $size }
              ) if $r_true;

    # check the existence of a default browser for this particular user
    if (defined $self->{'defbrowser'}->{ lc($self->{'username'}) }) {
        $t_line{'notes'} =
          $self->{'defbrowser'}->{ $self->{'username'} } =~ m/chrome/i
          ? 'Default browser for user'
          : 'Not the default browser (' . $self->{'defbrowser'}->{ $self->{'username'} } . ')';
    }
    elsif ($self->{'defbrowser'}->{'os'} ne '') {

        # check the default one (the OS)
        $t_line{'notes'} =
          $self->{'defbrowser'}->{'os'} =~ m/chrome/
          ? 'Default browser for system'
          : 'Not the default system browser (' . $self->{'defbrowser'}->{'os'} . ')';
    }

    %t_line = '' unless $r_true;

    return \%t_line;
}

#       get_help
# A simple subroutine that returns a string containing the help
# message for this particular format file.
# @return A string containing a help file for this format file
sub get_help() {
    return "This plugin parses the content of the History SQL Lite database file that contains
all the information about browser history in Google's Chrome browser.

The History file is usually found at the following location:
  [linux] /home/USER/.config/google-chrome/Default/History
  [linux] /home/USER/.config/chrome/Default/History
  [win 7/vista] C:\\Users\\\[USERNAME\]\\AppData\\Local\\Google\\Chrome\\
  [win xp] C:\\Documents and Settings\\\[USERNAME\]\\Local Settings\\Application Data\\Google\\Chrome\\

There are two options to this script
  -u USERNAME
  -h HOSTNAME
Which is used to define the username of the user that ownes the history file or the host name of the machine in question\n";

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

    # we assume that the file is not FF3
    $return{'success'} = 0;
    $return{'msg'}     = 'unknown';

    # we assume we don't have the tables needed
    $self->{'table_urls'}      = 0;
    $self->{'table_visits'}    = 0;
    $self->{'table_downloads'} = 0;

    return \%return unless -f ${ $self->{'name'} };

    # open the file (at least try to open it)

    # save the original file name
    $self->{'filename'} = ${ $self->{'name'} };

    #unless( $self->{'quick'} )
    #{
    #  # read the first character to see if it matches the first part of the signature
    #  seek($self->{'file'},0,0);
    #  read($self->{'file'},$temp,1);
    #
    #    return \%return unless $temp eq 'S';
    #  }

  # now that we've got a match for the first character, let's move one and test the entire signature
  # read the first few bits, see if it matches signature
    for (my $i = 0; $i < 15; $i++) {
        seek($self->{'file'}, $i, 0);
        read($self->{'file'}, $temp, 1);
        $line .= $temp;
    }

    # check if the line indicates a real sqlite database (version 3)
    if ($line eq $magic) {

        # we know that this is a SQLite database, but is it a Firefox3 database?

        # start by checking if we have a database journal as well
        if (-f ${ $self->{'name'} } . "-journal") {
            eval {

                # create a new variable to store the temp location
                $temp = int(rand(100));
                $temp = $self->{'temp'} . $self->{'sep'} . 'tmp_ch.' . $temp . 'v.db';

                # we need to copy the file to a temp location and start again
                copy(${ $self->{'name'} }, $temp) || ($return{'success'} = 0);
                copy(${ $self->{'name'} } . "-journal", $temp . "-journal")
                  || ($return{'success'} = 0);

                #print STDERR "[CHROME] Created a temp file $temp from $db \n";

                ${ $self->{'name'} } = $temp;
                $self->{'db_lock'} = 1;    # indicate that we need to delete the lock file
            };
            if ($@) {
                $return{'success'} = 0;
                $return{'msg'} =
                  'Database is locked and unable to copy to a temporary location (' . $temp . ')';
            }
        }

        # set a temp variable to 0 (assume we don't have a FF3.5 database)
        $temp = 0;

        eval {

            # connect to the database
            $self->{'vdb'} = DBI->connect("dbi:SQLite:dbname=" . ${ $self->{'name'} }, "", "")
              or ($temp = 1);

            if ($temp) {
                $return{'success'} = 0;
                $return{'msg'}     = 'Unable to connect to the database';
                return \%return;
            }

            # get a list of all available talbes
            $vsth = $self->{'vdb'}->prepare("SELECT name FROM sqlite_master WHERE type='table'")
              or ($temp = 0);

            # execute the query
            $temp = 0;
            my $res = $vsth->execute();

            # check if we have a moz_places table
            while (@words = $vsth->fetchrow_array()) {

                # check for moz_places
                #print STDERR "RESULT IS " . $words[0] . "\n";
                $temp = 1 if $words[0] eq 'visits';

                # check for existance of all tables
                $self->{'table_visits'}    = 1 if $words[0] eq 'visits';
                $self->{'table_urls'}      = 1 if $words[0] eq 'urls';
                $self->{'table_downloads'} = 1 if $words[0] eq 'downloads';
            }

            # check if temp is set
            if ($temp) {

                # now we have a Chrome history SQLite database
                $return{'success'} = 1;
                $return{'msg'}     = 'Success';
            }
            else {
                $return{'success'} = 0;
                $return{'msg'}     = 'This is not a Chrome history SQLite database';
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
    }
    else {
        $return{'success'} = 0;
        $return{'msg'}     = "Wrong magic value.  Is this really a sqlite database?\n";
    }

    return \%return;
}

# functions

#  get_url
# This function takes as an input a ID (from_visit) from the table visits and
# returns a simple array containing few of relevant information from that URL
#
# @param id  The identification number for the URL in the visits table
# @return  An array containing the hostname, URL and date of visit
sub _get_url {
    my $statement;
    my %return;
    my $sql;
    my $result;
    my $self = shift;
    my $url  = shift;

    # construct the SQL statement
    $sql = "
SELECT urls.url,urls.title,visits.visit_time 
FROM urls, visits 
WHERE
  urls.id = visits.url
  AND urls.id = ?
  ";

    $statement = $self->{'vdb'}->prepare($sql);
    $result    = $statement->execute($url);

    # retrieve the results
    ($return{'s_url'}, $return{'s_title'}, $return{'s_date'}) = $statement->fetchrow_array();

    # fix variables
    $return{'s_host'} = $self->_fix_hostname($return{'s_url'});
    $return{'s_date'} =
      Log2t::Numbers::roundup(($return{'s_date'} - $self->{'chrome_date_ofs'}) / 1000000);

    # return the array
    return \%return;
}

#  fix_hostname
# This function takes the full URL as an input and returns just the hostname
#
# @params hostname A string that contains the full URL
# @return Returns a string containing the more readable version of the hostname
sub _fix_hostname {
    my $self = shift;
    my $host = 'unknown';
    my $url  = shift;

    if ($url =~ m/^http?:\/\/(.+)/i) {
        ($host) = split(/\//, $1);
    }

    return $host;
}

1;
