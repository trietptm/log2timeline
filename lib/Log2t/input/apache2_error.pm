#################################################################################################
#    APACHE2 ERROR
#################################################################################################
# this script is a part of the log2timeline program.
# 
# This is a format file that implements a parser for Apache2 error log files.  It parses the file
# and provides the main script with enough information to provide a body file that can be
# used in a timeline analysis
#
# Standard Format:
#
# http://httpd.apache.org/docs/2.2/logs.html#errorlog
#
# In Debian install:
#   apt-get install libdatetime-perl
# 
# Author: Willi Ballenthin
# Version : 0.1
# Date : 14/7/10
#
# Copyright 2009-2010 Kristinn Gudjonsson (kristinn ( a t ) log2timeline (d o t) net)
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

package Log2t::input::apache2_error;

use strict;
use DateTime;    # to modify time stamp
use Log2t::Common ':binary';
use Log2t::BinRead;
use Log2t::base::input; # the SUPER class or parent

use vars qw($VERSION @ISA);

# inherit the base input module, or the super class.
@ISA = ( "Log2t::base::input" );

# version number
$VERSION = '0.2';

my %struct;

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



#   get_description
# A simple subroutine that returns a string containing a description of 
# the funcionality of the format file. This string is used when a list of
# all available format files is printed out
# @return A string containing a description of the format file's functionality
sub get_description()
{
  return "Parse the content of a Apache2 error log file";
}

#  get_time  
# This is the main "juice" of the format file.  It takes a line from the log file
# and parses it to produce an array containing all the needed values to print a 
# body file.
#
# @param LINE a string containing a single line from the error file
# @return Returns a array containing the needed values to print a body file
sub get_time()
{
  my $self = shift;

  # log file variables
  my @date_t; 
  my @date_m; 
  my %li;
  my %date;
  my $date_e;
  my $date_s;

  # the timestamp object
  my %t_line;
  my $text;
  my $uri;

        # get the filehandle and read the next line
        my $fh = $self->{'file'};
        my $line = <$fh> or return undef;
        $line =~ s/\s+/ /g;

        # empty lines, skip them
        if( $line =~ m/^$/ or $line =~ m/^\s+$/ )
        {
                return \%t_line;
        }

  #
  # the log file consists of the following fields:
  #
  # Date  date  The date on which the activity occurred.  Y
  # Time  time  The time, in coordinated universal time (UTC), at which the activity occurred.  Y
  # Severity severity The severity of the error being reported. Y
  # Client IP Address  c-ip  The IP address of the client that made the request.  Y
  # Message message The message itself, which in this case indicates that the server has been configured to deny the client access. Y
  #

  # The default variables are therefore:
  #
  #   date
  #  time
  #  severity
  #  c-ip
  #  message
  
  #    
  #       DOW    month    day    hour   min    sec    year           level       ip           message 
  #  ^\[[^\s]+ (\w\w\w) (\d\d) (\d\d):(\d\d):(\d\d) (\d\d\d\d)\] \[([^\]]+)\] (\[([^\]]+)\])? (.*)$

  #print "parsing line\n";
  if ($line =~ /^\[[^\s]+ (\w\w\w) (\d\d) (\d\d):(\d\d):(\d\d) (\d\d\d\d)\] \[([^\]]+)\] (\[([^\]]+)\]) (.*)$/ )
  {
    $li{'month'} = lc($1);
    $li{'day'} = $2;
    $li{'hour'} = $3;
    $li{'min'} = $4;
    $li{'sec'} = $5;
    $li{'year'} = $6;
    $li{'severity'} = $7;
    $li{'client'} = $8;
    $li{'message'} = $10;

    if ($li{'client'} =~ /client ([0-9\.]+)/) 
    {
      $li{'c-ip'} = $1;
    }
  }
  elsif ($line =~ /^\[[^\s]+ (\w\w\w) (\d\d) (\d\d):(\d\d):(\d\d) (\d\d\d\d)\] \[([^\]]+)\] (.*)$/ ) 
  {
    $li{'month'} = lc($1);
    $li{'day'} = $2;
    $li{'hour'} = $3;
    $li{'min'} = $4;
    $li{'sec'} = $5;
    $li{'year'} = $6;
    $li{'severity'} = $7;
    $li{'message'} = $8;
  }
  else 
  {
    print STDERR "Error, not correct structure ($line)\n";
    return;
  }



  # TODO
  #$li{'sec'} = Log2t::roundup( $li{'sec'} );\

  if ($li{'month'} eq "jan") {
    $li{'month'} = 1;
  }
  elsif ($li{'month'} eq "feb") {
    $li{'month'} = 2;
  }
  elsif ($li{'month'} eq "mar") {
    $li{'month'} = 3;
  }
  elsif ($li{'month'} eq "apr") {
    $li{'month'} = 4;
  }
  elsif ($li{'month'} eq "may") {
    $li{'month'} = 5;
  }
  elsif ($li{'month'} eq "jun") {
    $li{'month'} = 6;
  }
  elsif ($li{'month'} eq "jul") {
    $li{'month'} = 7;
  }
  elsif ($li{'month'} eq "aug") {
    $li{'month'} = 8;
  }
  elsif ($li{'month'} eq "sep") {
    $li{'month'} = 9;
  }
  elsif ($li{'month'} eq "oct") {
    $li{'month'} = 10;
  }
  elsif ($li{'month'} eq "nov") {
    $li{'month'} = 11;
  }
  elsif ($li{'month'} eq "dec") {
    $li{'month'} = 12;
  }
  else
  {
    print STDERR "[APACHE ERROR] Not a correctly formed month ($li{'month'})\n" if $self->{'debug'};
    return \%t_line;
  }


  # construct a hash of the date
  %date = (
    year  =>  $li{'year'}, 
    month  =>  $li{'month'},
    day  =>  $li{'day'},
    hour  =>  $li{'hour'},
    minute  =>  $li{'min'},
    time_zone  => $self->{'tz'}, # current time zone
    second => $li{'sec'}
  );

  $date_s = DateTime->new( \%date );
  $date_e = $date_s->epoch;

  $text = "Apache " . $li{'severity'} . " ";

  if( exists $li{'c-ip'} )
  {
    $text .= "related to client at " . $li{'c-ip'} . " ";
  }

  $text .= ": \"" . $li{'message'} ."\"";

    # content of array t_line ([optional])
    # %t_line {
    #       time
    #       index
    #       value
    #       type
    #       legacy
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
            'time' => { 0 => { 'value' => $date_e, 'type' => 'Entry written', 'legacy' => 15 } },
            'desc' => $text,
            'short' => 'Severity: ' . $li{'severity'},
            'source' => 'apache2_error',
            'sourcetype' => 'Apache2 Error Log File',
            'version' => 2,
            'extra' => { 'user' => $li{'c-ip'}, 'severity' => $li{'severity'}, 'message' => $li{'message'}}
    );

  return \%t_line;
}

#  get_help
# A simple subroutine that returns a string containing the help 
# message for this particular format file.
# @return A string containing a help file for this format file
sub get_help()
{
  return "This parser parses the Apache2 error log file. To see the definition of the 
log format, please see:
http://httpd.apache.org/docs/2.2/logs.html#errorlog
Use with the FILE option as the Apache2 Error log file\n
\t$0 -f apache2_error ex...log

This format file depends upon the library
  DateTime
for converting date variables to epoch time. Possible to install using
perl -MCPAN -e shell
(when loaded)
install DateTime\n";

}

#  verify
# A subroutine that reads a single line from the log file and verifies that it is of the
# correct format so it can be further processed.
# The correct format of an Apache2 error file can be found at:
# http://httpd.apache.org/docs/2.2/logs.html#errorlog
# which  is
# ip/userid/authorized-user/date/request/code/size/referer/useragent
# @return An array containing an integer and a string.  The integer indicates a success or failure and the
#  string is the error message (if the file is not correctly formed)
sub verify
{
  my $self = shift;

  # define an array to keep
  my %return;
  my $line;
  my @words;
  my $tag;
  my $c_ip = 2;
  my $temp;
  my @fields;

  # defines the maximum amount of lines that we read until we determine that we do not have a Apache2 error file
  my $max = 15;
  my $i = 0;
  
  $return{'success'} = 0;
  $return{'msg'} = 'success';

        return \%return unless -f ${$self->{'name'}};

  my $ofs = 0;
        # start by setting the endian correctly
        Log2t::BinRead::set_endian( LITTLE_E );

  # now we need to continue testing our file
  $tag = 1;
  $ofs = 0;
  # begin with finding the line that defines the fields that are contained
  while( $tag )
  {
    $tag = 0 unless $line = Log2t::BinRead::read_ascii_until( $self->{'file'}, \$ofs, "\n", 200 );
    next if ( $line =~ m/^#/ or $line =~ m/^$/ );
    $tag = 0 if $i++ eq $max;  # check if we have reached the end of our attempts
    next unless $tag;

    # HACK. There was maybe some problem with my binary read and missing the 'r]' at the end
    # of [error] on my Ubuntu 10.04, Perl v5.10.1 box, so this match is loosened slightly
    #                                                                    |
    #                                                                    V    
    if ($line =~ /^\[[^\s]+ \w\w\w \d\d \d\d:\d\d:\d\d \d\d\d\d\] \[[^\]]+ \[[^\]]+\] .*$/ )
    {
      $return{'success'} = 1;
      return \%return;
    }
    elsif ($line =~ /^\[[^\s]+ (\w\w\w) (\d\d) (\d\d):(\d\d):(\d\d) (\d\d\d\d)\] \[([^\]]+)\]  (.*)$/ )
    {
      $return{'success'} = 1;
      return \%return;
    }
  }

  $return{'msg'} = "None of the first $max lines fit the format of Apache2 error logs.";
  $return{'success'} = 0;

  return \%return;
}

1;
