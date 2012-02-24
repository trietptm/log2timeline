#!/usr/bin/perl 
#################################################################################################
#                        Generic_linux 
#################################################################################################
# This script reads Linux log files that start with Mmm DD HH:MM:SS
#
# Author: Tom Webb
# Version : 0.3
# Date : 26-Sept-2010
#
# Changed on 30/04/2011 by Kristinn to make the module conform to the 0.6x engine
#
# Copyright 2010 Tom Webb
# Copyright 2009-2011 Kristinn Gudjonsson (kristinn ( a t ) log2timeline (d o t) net)
#
#  This file is part of log2timeline.
#
#              log2timeline is free software: you can redistribute it and/or modify
#              it under the terms of the GNU General Public License as published by
#              the Free Software Foundation, either version 3 of the License, or
#              (at your option) any later version.
#
#              log2timeline is distributed in the hope that it will be useful,
#              but WITHOUT ANY WARRANTY; without even the implied warranty of
#              MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#              GNU General Public License for more details.
#
#              You should have received a copy of the GNU General Public License
#              along with log2timeline.  If not, see <http://www.gnu.org/licenses/>.
package Log2t::input::generic_linux;

use DateTime;
use Log2t::base::input; # the SUPER class or parent
use Log2t::Common ':binary';
use Log2t::BinRead;
use Log2t::Time;
use HTTP::Date;
use strict;

use vars qw($VERSION @ISA);

# inherit the base input module, or the super class.
@ISA = ( "Log2t::base::input" );
 
$VERSION = '0.3';
 
#                 get_description
# A simple subroutine that returns a string containing a description of
# the funcionality of the format file. This string is used when a list of
# all available format files is printed out
#
# @return A string containing a description of the format file's functionality
sub get_description()
{
  return "Parse content of Generic Linux logs that start with MMM DD HH:MM:SS";
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


 
#   init
# A routine to initalize the parsing of the module
sub init
{
  my $self = shift;
  my $filetime;
  my @filetimesplit;

        #THIS IS USED TO DETERMINE THE YEAR FOR WHICH THE FILE TIMES ARE LISTED. THIS IS THE YEAR THE FILE WAS LAST MODIFIED.
  use File::stat; 
  use Time::localtime;

        $filetime = ctime(stat(${$self->{'name'}})->mtime);

        @filetimesplit = split( /\s+/, $filetime ); #var time by space
        $self->{'year'}=$filetimesplit[4]; #the 5th field is the year

  return 1;
}
 
#                 get_time
# This is the main "juice" of the format file.  It takes a line from the log file
# and parses it to produce an array containing all the needed values to print a
# body file.
#
# Log format Mmm D or DD HH:MM:SS hostname service:
#
# Aug  9 20:20:26 ubuntu gdm-session-worker[11549]: pam_succeed_if(gdm:auth): requirement "user ingroup nopasswdlogin" not met by user "twebb"
# Aug  9 20:20:32 ubuntu polkitd(authority=local): Registered Authentication Agent for session /org/freedesktop/ConsoleKit/Session2 (system bus name :1.44 [/usr/lib/policykit-1-gnome/polkit-gnome-authentication-agent-1], object path /org/gnome/PolicyKit1/AuthenticationAgent, locale en_US.utf8)
# Aug  9 20:23:08 ubuntu sudo:    twebb : TTY=unknown ; PWD=/home/twebb ; USER=root ; COMMAND=/usr/sbin/synaptic --hide-main-window --non-interactive --parent-window-id 67108903 -o Synaptic::closeZvt=true --pr 
sub get_time
{
  my $self = shift;
  my @words; 
  my @everything_else;
  my %t_line;
  my $text;
  my @timesplit;
  my %date;
  my $date_e;
  my $date_s; 
  my $ee;

        # get the filehandle and read the next line
        my $fh = $self->{'file'};
        my $line = <$fh> or return undef;

  # substitute multiple spaces with one for splitting the string into variables
  $line =~ s/\s+/ /g;

  @words = split( /\s/, $line ); #Splits the line into array using a space as delimiter
  my $count=scalar(@words); #count the number of fields that were split for @everything_else

  my $monthInt=$words[0];
  my $day=$words[1];
  my $time=$words[2];

  @timesplit = split( /:/, $time ); #splits the time based on : 
  
  my $hour=$timesplit[0];
  my $min=$timesplit[1];
  my $sec_total=$timesplit[2];

  # just to be sure
  my ($sec,$left) = split( /\./, $sec_total );
  
  @everything_else=@words[3..$count]; #creates a "Sub-Array of the words array"  with data that is different per service.
  $ee = join (' ', @everything_else ); 

  #From Apache_access.pm

  my $month = Log2t::Time::month2int($monthInt);

    # construct a hash of the date
    %date = (
      year  =>  $self->{'year'},
      month  =>  $month,
      day  =>  $day,
      hour  =>  $hour,
      minute  =>  $min,
      time_zone =>   $self->{'tz'},  # use local timezone
      second   =>   $sec
    );

#print %date;
#print "\n";
    $date_s = DateTime->new( \%date );
    $date_e = $date_s->epoch;

 
                  %t_line = (
                          'time' => { 0 => { 'value' => $date_e, 'type' => 'Entry written', 'legacy' => 15 } },
                          'desc' =>  "$ee",
                          'short' => "$ee",
                          'source' => 'Generic Linux Log',
                          'sourcetype' => 'Generic Linux Log',
                    'version' => 2,
                        'extra' => {  }
                  );
 
                  return \%t_line;
}
                 
#                 get_help
# A simple subroutine that returns a string containing the help
# message for this particular format file.
# @return A string containing a help file for this format file
sub get_help()
{
                  return "This parser parses the Linux log files that start with  MMM DD HH:MM:SS. To see the definition of the
log format, please see:
Use with the FILE option as the Auth log file\n
\t$0 -f generic_linux auth.log
 
This format file depends upon the library
                  HTTP::Date
for converting date variables to epoch time. Possible to install using
perl -MCPAN -e shell
(when loaded)
install HTTP::Date\n";
 
}
 
#    verify
# A subroutine that reads a single line from the log file and verifies that it is of the
# correct format so it can be further processed.
# The correct format of a Apache access file is:
# IP - Username date time Method  URI Status size Referer Useragent
# @return An array containing an integer and a string.  The integer indicates a success or failure and the
#    string is the error message (if the file is not correctly formed)
sub verify
{
  my $self = shift;
                  # define an array to keep
                  my %return;
                  my $line;
                  my @words;
                 my $temp;
 
                  # default values
                  $return{'success'} = 0;
                  $return{'msg'} = 'Unknown Fail';
 
        return \%return unless -f ${$self->{'name'}};

 
                  my $ofs = 0;
                  # start by setting the endian correctly
                  Log2t::BinRead::set_endian( LITTLE_E );
 

      # now that we've got a match for the first character, let's move one and test the entire signature
          # read the first few bits, see if it matches signature
            for( my $i=0 ; $i < 15; $i++ )
            {
                   seek($self->{'file'},$i,0);
                  read($self->{'file'},$temp,1);
                  $line .= $temp;
            }

                  # now we have one line of the file, let's read it and verify
                  # remove unneeded spaces
  
                  $line =~ s/\s+/ /g;
            @words = split( /\s/, $line ); 
  

      if( $words[0] =~ m/[A-Z][a-z][a-z]/ )
                 {

                        # verify one variable in the log file, Time
                          if( $words[2] =~ m/\d\d:\d\d:\d\d/ )
                          {

                       
                               #verify that word one has one or two number fields
                               if( $words[1] =~ m/\d+/ )
                               {
                                             $return{'success'} = 1;    
                               }    
                               else
                               {
                                      $return{'error'} = 'Date Filed [' .$words[1] . "] not correctly formatted\n";
                                      $return{'success'} = 0;
                               }
       }
                          else
                          {
                                  $return{'error'} = 'Time field [' .$words[2] . "] not correctly formatted\n";
                                  $return{'success'} = 0;
                          }
      }  
                  else
                  {
                          $return{'error'} = "There should be Cap letter followed by two lower case latters to start off\n";
                          $return{'success'} = 0;
                  }
  

 return \%return;   

}
1;
