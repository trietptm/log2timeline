#################################################################################################
#    FIREFOX3  
#################################################################################################
# this script reads the places.sqlite SQLITE database that contains information about Firefox
# history files (3.0+) and produces a bodyfile containing the timeline information
# according to the output file used by log2timeline
#
# Database information was both found using sqlite directly as well from the web
# site : http://www.firefoxforensics.com/
#
# For ubuntu, please install
#  apt-get install libdbi-perl
# 
# Author: Kristinn Gudjonsson
# Version : 0.9
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
package Log2t::input::firefox3;

use strict;
use Log2t::base::input; # the SUPER class or parent
use DBI;
use File::Copy;
use Getopt::Long; # read parameters
use Log2t::Numbers;
use Log2t::Time;
use Log2t::Common;

use vars qw($VERSION @ISA);

# inherit the base input module, or the super class.
@ISA = ( "Log2t::base::input" );


$VERSION = '0.8';

my %type = (
  '1' => 'LINK',
  '2' => 'TYPED',
  '3' => 'BOOKMARK',
  '4' => 'EMBED',
  '5' => 'REDIRECT_PERMANENT',
  '6' => 'REDIRECT_TEMPORARY',
  '7' => 'DOWNLOAD'
);

sub new()
{
        my $class = shift;

        # bless the class ;)
        my $self = $class->SUPER::new();

        # indicate that we are dealing with a binary file (only one entry returned)
        $self->{'multi_line'} = 0;

  bless($self,$class);

        return $self;
}


sub init()
{
        my $self = shift;

        # initialize variables  
        $self->{'db_lock'} = 0;

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
sub get_description()
{
  return "Parse the content of a Firefox 3 history file"; 
}

#       get_time
# This subroutine starts by .. 
# 
#
# @params One parameter is defined, the path to the Prefetch directory 
# @return An integer is returned to indicate whether the file preparation was 
#       successful or not.
sub get_time()
{
  my $self = shift;

  # define needed variables
  my $temp;
  my $return = 1;
  my ($sth, $sql);
  my $result;
  my @dump;
  my $i = 0;
  my $path;

  my %ret_lines = undef;
  my $ret_index = 0;

  
  # check if this is real Firefox database
  $self->{'vdb'}->prepare( 'SELECT id FROM moz_places LIMIT 1' ) || ($return = 0);

  if( !$return )
  {
    print STDERR "[Firefox 3] The database is not a correct Firefox database\n";
    return $return;
  }

  # we now know that we have a FireFox SQLITE database, let's continue

  ##################################################################
  # the structure/schema of the moz_places table
  ##################################################################
  # id INTEGER PRIMARY KEY
  # url LONGVARCHAR
  # title LONGVARCHAR
  # rev_host LONGVARCHAR
  # visit_count INTEGER DEFAULT 0
  # hidden INTEGER DEFAULT 0 NOT NULL, 
  # typed INTEGER DEFAULT 0 NOT NULL, 
  # favicon_id INTEGER, 
  # frecency INTEGER DEFAULT -1 NOT NULL
  # structure of moz_historyvisits
  # id INTEGER PRIMARY KEY
  # from_visit INTEGER
  # place_id INTEGER
  # visit_date INTEGER
  # visit_type INTEGER
  # session INTEGER
  #-----------------------------------------------------------------

  # Construct the SQL statement to extract the needed data
  $sql = "
SELECT moz_historyvisits.id, moz_places.url,moz_places.title,moz_places.visit_count,moz_historyvisits.visit_date,moz_historyvisits.from_visit,moz_places.rev_host,moz_places.hidden,moz_places.typed,moz_historyvisits.visit_type
FROM moz_places, moz_historyvisits
WHERE
  moz_places.id = moz_historyvisits.place_id
  ";

  $sth = $self->{'vdb'}->prepare( $sql );
  $result = $sth->execute( );

  # load the result into an array
  while( @dump = $sth->fetchrow_array() )
  {
    $self->{'r_type'} = 'url';
    $self->{'r_line'} = [@dump];

    $ret_lines{$ret_index++} = $self->_parse_timestamp;
  }

  # extract bookmark information 
  $sql = "
SELECT moz_bookmarks.type,moz_bookmarks.title,moz_bookmarks.dateAdded,moz_bookmarks.lastModified,moz_places.url,moz_places.title,moz_places.rev_host,moz_places.visit_count
FROM moz_places, moz_bookmarks
WHERE
  moz_bookmarks.fk = moz_places.id
  AND moz_bookmarks.type <> 3
  ";

  $sth = $self->{'vdb'}->prepare( $sql );
  $result = $sth->execute( );

  # load the result into an array
  while( @dump = $sth->fetchrow_array() )
  {
    $self->{'r_type'} = 'bookmark';
    $self->{'r_line'} = [@dump];

    $ret_lines{$ret_index++} = $self->_parse_timestamp;
  }

  $sql = "
SELECT moz_items_annos.content, moz_items_annos.dateAdded,moz_items_annos.lastModified,moz_bookmarks.title, moz_places.url,moz_places.rev_host
FROM moz_items_annos,moz_bookmarks,moz_places
WHERE
  moz_items_annos.item_id = moz_bookmarks.id
  AND moz_bookmarks.fk = moz_places.id
  ";

  $sth = $self->{'vdb'}->prepare( $sql );
  $result = $sth->execute( );

  # load the result into an array
  while( @dump = $sth->fetchrow_array() )
  {
    $self->{'r_type'} = 'annos';
    $self->{'r_line'} = [@dump];

    $ret_lines{$ret_index++} = $self->_parse_timestamp;
  }

  $sql = "
SELECT moz_bookmarks.title,moz_bookmarks.dateAdded,moz_bookmarks.lastModified
FROM moz_bookmarks
WHERE
  moz_bookmarks.type = 2
  ";

  $sth = $self->{'vdb'}->prepare( $sql );
  $result = $sth->execute( );

  # load the result into an array
  while( @dump = $sth->fetchrow_array() )
  {
    $self->{'r_type'} = 'bookmark_folder';
    $self->{'r_line'} = [@dump];

    $ret_lines{$ret_index++} = $self->_parse_timestamp;
  }

  return \%ret_lines;
}

#       get_version
# A simple subroutine that returns the version number of the format file
# There shouldn't be any need to change this routine, it serves its purpose 
# just the way it is defined right now.
#
# @return A version number
sub get_version()
{
        return $VERSION;
}



#       end
# A subroutine that closes the file, after it has been parsed
# @return An integer indicating that the close operation was successful
sub end()
{
  my $self = shift;

  # disconnect the database
  $self->{'vdb'}->disconnect if defined $self->{'vdb'};

  # check to see if database is locked, then delete temp file
  if( $self->{'db_lock'} )
  {
    #print STDERR "Deleting temporary history file, $db_file \n";
    unlink( ${$self->{'name'}});
    unlink( ${$self->{'name'}}. '-journal' ) if -e ${$self->{'name'}}. '-journal';
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

sub _parse_timestamp
{
  my $self = shift;
  # the timestamp object
  my %t_line;

  # fields of interest
  my ($adate,$cdate);
  my $time_offset = 0;
  my $hostname;
  my $from;
  my $text;
  my $title;
  my $type;

  my @r_line = @{$self->{'r_line'}};


  # start by check which table we are examining
  if( $self->{'r_type'} eq 'url' )
  {
    $type = 'URL visited';

    # insert each item in line into the array 
    # inside: 
    #  moz_historyvisits.id
    #  url,
    #  title,
    #  visit_count,
    #  visit_date,
    #  from_visit,
    #  rev_host,
    #  hidden
    #  moz_places.typed,
    #  moz_historyvisits.visit_type
  
    # we need to fix the date, so we can represent it correctly (it is stored in UTC)
    $adate = Log2t::Numbers::roundup( $r_line[4] / 1000000 );
    # only one timestamp here
    $cdate = $adate;

    # get the hostname  
    $hostname = $self->_fix_hostname( $r_line[6] );

    # check to see if we came to the web site from another one
    if( $r_line[5] ne 0 )
    {
      # FROM -> URL HOST DATE
      $from = $self->_get_url( $r_line[5] );
    }

    if( $from->{'s_url'} ne '' )
    {
      $text .=  $r_line[1] . ' (' . $r_line[2] . ') [count: ' . $r_line[3] . '] Host: ' . $hostname . ' visited from: ' . $from->{'s_url'};
    }
    else
    {
      $text .= $r_line[1] . ' (' . $r_line[2] . ') [count: ' . $r_line[3] . '] Host: ' . $hostname;
    }

    if( $r_line[7] eq 1 )
    {
      $text .= ' (url hidden)';
    }
    if( $r_line[8] eq 1 )
    {
      $text .= ' (directly typed)';
    }
    else
    {
      $text .= ' (URL not typed directly)';
    }

    # and include the visit type
    $text .= ' type: ' . $type{$r_line[9]};

    $title = 'URL: ' . $r_line[1];
  }
  elsif( $self->{'r_type'} eq 'bookmark' )
  {
    $type = 'bookmark';
    # The array r_line now contains:
    #  0 moz_bookmarks.type
    #  1 moz_bookmarks.title
    #  2 moz_bookmarks.dateAdded
    #  3 moz_bookmarks.lastModified
    #  4 moz_places.url
    #  5 moz_places.title
    #  6 moz_places.rev_host
    #  7 moz_places.visit_count
  
    # start by extrating data
    $hostname = $self->_fix_hostname( $r_line[6] );

    # extract the dateAdded
    $cdate = Log2t::Numbers::roundup( $r_line[2] / 1000000 );

    # extract the lastModified 
    $adate = Log2t::Numbers::roundup( $r_line[3] / 1000000 );

    # now to check if one is zero
    if( ( $adate == 0 ) && ( $cdate == 0 ) )
    {
      # both dates are 0
      %t_line = '' ;
      return \%t_line;
    }
    else
    {
      if( $adate == 0 )
      {
        # then cdate isn't
        $adate = $cdate;
      }
      if( $cdate == 0 )
      {
        # then adate isn't
        $cdate = $adate;
      }
    }

    # now we need to construct the text variable
    # moz_bookmarks.type can be one of three things
    #  1 => Bookmark (aka URL)
    #  2 => Folder
    #  3 => Separator
    # we should only be getting type one since we constructed the SQL statement to get the URL as well
    if( $r_line[0] eq 1 )
    {
      $text .= ' Bookmark URL ' . $r_line[1] . ' (' . $r_line[4] . ') [' . $r_line[5] .'] count ' . $r_line[7];
      $title = ' Bookmarked ' . $r_line[1] . ' (' . $r_line[4] . ')';
    }
    else
    {
      # we don't want that
      $text = '';
      $title = '';
    }

  }
  elsif ( $self->{'r_type'} eq 'bookmark_folder' )
  {
    $type = 'bookmark folder';
    # The array r_line now contains:
    #  0 title
    #  1 dateAdded
    #  2 lastModified

    # extract the dateAdded
    $cdate = Log2t::Numbers::roundup( $r_line[1] / 1000000 );

    # extract the lastModified 
    $adate = Log2t::Numbers::roundup( $r_line[2] / 1000000 );

    # now to check if one is zero
    if( ( $adate == 0 ) && ( $cdate == 0 ) )
    {
      # both dates are 0
      %t_line = '' ;
      return \%t_line;
    }
    else
    {
      if( $adate == 0 )
      {
        # then cdate isn't
        $adate = $cdate;
      }
      if( $cdate == 0 )
      {
        # then adate isn't
        $cdate = $adate;
      }
    }

    $text .= 'Bookmark Folder [' . $r_line[0] . ']';
    $title = 'Bookmark folder ' . $r_line[0];
  }
  elsif( $self->{'r_type'} eq 'annos' )
  {
    $type = 'annotations';

    # The array r_line now contains:
    #  0 moz_items_annos.content
    #  1 moz_items_annos.dateAdded
    #  2 moz_items_annos.lastModified
    #  3 moz_bookmarks.title
    #  4 moz_places.url
    #  5 moz_places.rev_host

    # extract the dateAdded
    $cdate = Log2t::Numbers::roundup( $r_line[1] / 1000000 );

    # extract the lastModified 
    $adate = Log2t::Numbers::roundup( $r_line[2] / 1000000 );

    # now to check if one is zero
    if( ( $adate == 0 ) && ( $cdate == 0 ) )
    {
      # both dates are 0
      %t_line = '' ;
      return \%t_line;
    }
    else
    {
      if( $adate == 0 )
      {
        # then cdate isn't
        $adate = $cdate;
      }
      if( $cdate == 0 )
      {
        # then adate isn't
        $cdate = $adate;
      }
    }

    $text .= 'Bookmark Annotation: [' . $r_line[0] . '] to bookmark [' . $r_line[3] . '] (' . $r_line[4] . ')';
    $text =~ s/\n//g;
    $text =~ s/\r//g;
    $title = 'Bookmark Annotation to bookmark ' . $r_line[3] . ' (' . $r_line[4] .')';
  }
  else
  {
    # unknown type
    $text = '';
    $adate = 0;
    $cdate = 0;
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
        %t_line = (
                'desc' => $text,
                'short' => $title,
                'source' => 'WEBHIST',
                'sourcetype' => 'Firefox 3 history',
                'version' => 2,
                'extra' => { 'user' => $self->{'username'}  }
        );

        # check the existence of a default browser for this particular user
        if( defined $self->{'defbrowser'}->{lc($self->{'username'})} )
        {   
                $t_line{'notes'} = $self->{'defbrowser'}->{$self->{'username'}} =~ m/firefox/i ? 'Default browser for user' : 'Not the default browser (' . $self->{'defbrowser'}->{$self->{'username'}} . ')';
        }   
        elsif ( $self->{'defbrowser'}->{'os'} ne '' )
        {   
                # check the default one (the OS)
                $t_line{'notes'} = $self->{'defbrowser'}->{'os'} =~ m/firefox/ ? 'Default browser for system' : 'Not the default system browser (' . $self->{'defbrowser'}->{'os'} . ')';
        } 


  # now we need to add the timestamp (check which type this is first)
  if( $self->{'r_type'} eq 'url' )
  {
    # url, one date
    $t_line{'time'}->{0} = { 'value' => $adate, 'type' => 'URL visited', 'legacy' => 15 };
  }
  else
  {
    # add the dates
    $t_line{'time'}->{0} = { 'value' => $adate, 'type' => 'LastModified', 'legacy' => 12 };
    $t_line{'time'}->{1} = { 'value' => $cdate, 'type' => 'dateAdded', 'legacy' => 3 };
  }

  return \%t_line;
}

#       get_help
# A simple subroutine that returns a string containing the help 
# message for this particular format file.
# @return A string containing a help file for this format file
sub get_help()
{
  return "This plugin parses the content of the places.sqlite file, which is a SQLITE 
database that contains all the information about history visits in Firefox, version 3 and newer.
places.sqlite file is usually found at the following location:
        [win xp] c:\\Documents and Settings\\USER\\Application Data\\Mozilla\\Firefox\\Profiles\\PROFILE\\places.sqlite
        [linux] /home/USER/.mozilla/firefox/PROFILE/places.sqlite
        [mac os x] /Users/USER/Library/Application Support/Firefox/Profiles/PROFILE/places.sqlite\n

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
sub verify
{
  my $self = shift;
  # define an array to keep
  my %return;
  my $line;
  my @words;
  my $temp;
   my $magic = 'SQLite format 3';
  my ($vsth);
  my $file_lock = 0;
  
  # we assume that the file is not FF3
  $return{'success'} = 0;
  $return{'msg'} = 'unknown';

        return \%return unless -f ${$self->{'name'}};

  # save the original file name
  $self->{'filename'} = ${$self->{'name'}};

  # check if this is a quick test (default) or a detailed one
  #unless( $self->{'quick'} )
  #{  
  #  # check the first bit, it has to match the magic value before proceeding
  #  seek($self->{'file'},0,0);
  #  read($self->{'file'},$temp,1);
  #
  #  $return{'msg'} = 'Wrong magic value';
  #  return \%return unless $temp eq 'S';
  #}

  # read the first few bits, see if it matches signature
  for( my $i=0 ; $i < 15; $i++ )
  {
    seek($self->{'file'},$i,0);
    read($self->{'file'},$temp,1);
    push( @words, $temp );
  }

  # create a string from the read characters
  $line = join('',@words);

  # check if the line indicates a real sqlite database (version 3)
  if( $line eq $magic )
  {
    # we know that this is a SQLite database, but is it a Firefox3 database?
  
    # start by checking if we have a database journal as well (or other read-only attributes)
    if ( -f ${$self->{'name'}} . "-journal" or -f ${$self->{'name'}} . "-shm" or -f ${$self->{'name'}} . "-wal" )
    {
      eval
      {
        my $msg = undef;

        # create a new variable to store the temp location
        $temp = int(rand(100));
        $temp = $self->{'temp'} . $self->{'sep'} . 'tmp_ff.' . $temp . 'v.db';
      
        $return{'msg'} = 'Unable to copy the file to a temporary folder';
        $return{'success'} = 0;

        # we need to copy the file to a temp location and start again
        copy( ${$self->{'name'}}, $temp ) or $msg = 'unable to copy database file. ';
        #copy( ${$self->{'name'}} . "-journal", $temp . "-journal" ) or $msg .=  'unable to copy journal file to temporary directory'; 

        # we are trying to copy temporary data, and if the msg variable is defined, then we have a problem
        if( defined $msg )
        {
          $return{'msg'} = 'Error while trying to verify, unable to verify.  The error is: ' . $msg;
          $return{'success'} = 0;
          return \%return;
        }
        #print STDERR "[Firefox] Created a temp file $temp from $db\n";
    
        ${$self->{'name'}} = $temp;
        $self->{'db_lock'} = 1;  # indicate that we need to delete the lock file
      };
      if( $@ )
      {
        $return{'success'} = 0;
        $return{'msg'} = 'Database is locked and unable to copy to a temporary location (' . $temp . '). Error given: ' . $@;


        return \%return;
      }
    }  

    # set a temp variable to 0 (assume we don't have a FF3.5 database)
    $temp = 0;
  
    eval
    {
      # connect to the database
      $self->{'vdb'} = DBI->connect("dbi:SQLite:dbname=" . ${$self->{'name'}},"","") or ( $temp = 1);

      if( $temp )
      {
        $return{'success'} = 0;
        $return{'msg'} = 'Unable to connect to the database';
        return \%return;
      }
  
      # check if this is real Firefox database
      #$vsth = $vdb->prepare( 'SELECT id FROM moz_places LIMIT 1' ) or ($temp = 0);

      # get a list of all available talbes
      $vsth = $self->{'vdb'}->prepare( "SELECT name FROM sqlite_master WHERE type='table'" ) or ($temp = 0);

      #execute the query
      $temp = 0;
      my $res = $vsth->execute();

      # check if we have a moz_places table
            while( @words = $vsth->fetchrow_array() )
            {
        # check for moz_places
        #print STDERR "RESULT IS " . $words[0] . "\n";
        $temp = 1 if $words[0] eq 'moz_places';
            }

      if( $temp )
      {
        # now we have a FF3+ history SQLite database
        $return{'success'} = 1;
        $return{'msg'} = 'Success';
      }
      else
      {
        $return{'success'} = 0;
        $return{'msg'} = 'This is not a Firefox 3 history SQLite database';
      }
    
      # disconnect from the database
      $vsth->finish;
      undef $vsth;
    };
    if( $@ )
    {
      $return{'success'} = 0;
      $return{'msg'} = 'Database error ocurred, making verification not possible.  The error message is: ' . $@;
    }
  }
  else
  {
    $return{'success'} = 0;
    $return{'msg'}  = "Wrong magic value.  Is this really a sqlite database?\n";
  }
  
  return \%return;
}


# functions

#  get_url
# This function takes as an input a ID from the table moz_historyvisists and
# returns a simple array containing few of relevant information from that URL
#
# @param id  The identification number for the URL in the moz_historyvisists table
# @return  An array containing the hostname, URL and date of visit
sub _get_url
{
  my $self = shift;
  my $url = shift;
  my $statement;
  my %return;
  my $sql;
  my $result;
  
  # construct the SQL statement
  $sql = "
SELECT url,rev_host,visit_date 
FROM moz_places, moz_historyvisits
WHERE
  moz_places.id = moz_historyvisits.place_id
  AND moz_historyvisits.id = ?
  ";

  $statement = $self->{'vdb'}->prepare( $sql );
  $result  = $statement->execute( $url );
  
  # retrieve the results
  ($return{'s_url'}, $return{'s_host'}, $return{'s_date'} ) = $statement->fetchrow_array();

  # fix variables
  $return{'s_host'} = $self->_fix_hostname( $return{'s_host'} );  
  $return{'s_date'} = Log2t::Numbers::roundup( $return{'s_date'} / 1000000 );
  
  # return the array
  return \%return;
}

#  fix_hostname
# This function takes the hostname variable, as represented in the 
# moz_places table which is in a reverse format, prepended with a dot
# and reverses it and removes the front dot (.)
#
# @params hostname A string that is of the Mozilla format for rev_host
# @return Returns a string containing the more readable version of the hostname
sub _fix_hostname
{
  my $self = shift;
  my $host = shift;

  $host = reverse $host;
  if( $host =~ m/^\./ )
  {
    $host = substr( $host, 1, length( $host) - 1 );
  }

  return $host;
}


1;
