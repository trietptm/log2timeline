#################################################################################################
#    IIS
#################################################################################################
# this script is a part of the log2timeline program.
# 
# This is a format file that implements a parser for IIS log files.  It parses the file
# and provides the main script with enough information to provide a body file that can be
# used in a timeline analysis
#
# http://www.microsoft.com/technet/prodtechnol/WindowsServer2003/Library/IIS/be22e074-72f8-46da-bb7e-e27877c85bca.mspx
#
# W3C Extended Log File Fields
# http://www.microsoft.com/technet/prodtechnol/WindowsServer2003/Library/IIS/676400bc-8969-4aa7-851a-9319490a9bbb.mspx
# 
# Format:
# http://www.loganalyzer.net/log-analyzer/w3c-extended.html
# http://www.w3.org/TR/WD-logfile.html
#
# In Debian install:
#   apt-get install libdatetime-perl
# 
# Author: Kristinn Gudjonsson
# Version : 0.5
# Date : 30/04/11
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
package Log2t::input::iis;

use strict;
use Log2t::base::input; # the SUPER class or parent
use DateTime;    # to modify time stamp
use Log2t::Common ':binary';
use Log2t::BinRead;

use vars qw($VERSION @ISA);

# inherit the base input module, or the super class.
@ISA = ( "Log2t::base::input" );

# version number
$VERSION = '0.5';

my %struct;

#   get_description
# A simple subroutine that returns a string containing a description of 
# the funcionality of the format file. This string is used when a list of
# all available format files is printed out
# @return A string containing a description of the format file's functionality
sub get_description()
{
  return "Parse the content of a IIS W3C log file";
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



#  parse_line
# This is the main "juice" of the format file.  It takes a line from the log file
# and parses it to produce an array containing all the needed values to print a 
# body file.
#
# @param LINE a string containing a single line from the access file
# @return Returns a array containing the needed values to print a body file
sub get_time
{
  my $self = shift;
  # log file variables
  my @date_t; 
  my @date_m; 
  my @fields;
  my @words;
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

  # check line
  if( $line =~ m/^#/ )
  {
    # comment, let's skip that one
    return \%t_line;
  }
  elsif( $line =~ m/^$/ )
  {
    # empty line, skip that one as well
    return \%t_line;
  }

  # substitute multiple spaces with one for splitting the string into variables
  $line =~ s/\s+/ /g;

  @fields = @{$struct{fields}};

  #
  # the log file consists of the following fields 
  #
  # Date  date  The date on which the activity occurred.  Y
  # Time  time  The time, in coordinated universal time (UTC), at which the activity occurred.  Y
  # Client IP Address  c-ip  The IP address of the client that made the request.  Y
  # User Name  cs-username  The name of the authenticated user who accessed your server. Anonymous users are indicated by a hyphen.  Y
  # Service Name and Instance Number  s-sitename  The Internet service name and instance number that was running on the client.  N
  # Server Name  s-computername  The name of the server on which the log file entry was generated.  N
  # Server IP Address  s-ip  The IP address of the server on which the log file entry was generated.  Y
  # Server Port  s-port  The server port number that is configured for the service.  Y
  # Method  cs-method  The requested action, for example, a GET method.  Y
  # URI Stem  cs-uri-stem  The target of the action, for example, Default.htm.  Y
  # URI Query  cs-uri-query  The query, if any, that the client was trying to perform. A Universal Resource Identifier (URI) query is necessary only for dynamic pages.  Y
  # HTTP Status  sc-status  The HTTP status code.  Y
  # Win32 Status  sc-win32-status  The Windows status code.  N
  # Bytes Sent  sc-bytes  The number of bytes that the server sent.  N
  # Bytes Received  cs-bytes  The number of bytes that the server received.  N
  # Time Taken  time-taken  The length of time that the action took, in milliseconds.  N
  # Protocol Version  cs-version  The protocol version -HTTP or FTP- that the client used.  N
  # Host  cs-host  The host header name, if any.  N
  # User Agent  cs(User-Agent)  The browser type that the client used.  Y
  # Cookie  cs(Cookie)  The content of the cookie sent or received, if any.  N
  # Referrer  cs(Referrer)  The site that the user last visited. This site provided a link to the current site.  N
  # Protocol Substatus  sc-substatus  The substatus error code.  Y 
  # 
  # The default variables are therefore:
  #  date
  #  time
  #  c-ip
  #   cs-username
  #   s-ip
  #  s-port
  #  cs-method
  #  cs-uri-stem
  #  cs-uri-query
  #  sc-status
  #  cs(User-Agent)
  #  sc-substatus
  
  # split the string into variables
  @words = split( /\s/, $line );

  if( $#fields ne $#words )
  {
    print STDERR "Error, not correct structure\n";
  }

  # build the text output
  for( my $i=0; $i < $#words; $i++ )
  {
    $li{$fields[$i]} = $words[$i];
  }

  # fix the timestamp variable
  # date is of the form YYYY-MM-DD
  # time is of the form HH:MM, HH:MM:SS or HH:MM:SS.S (times provided in GMT)

  if( defined $li{'time'} )
  {
    @date_t = split( /:/, $li{'time'} );
  }
  else
  {
    return \%t_line;
  }

  # check for the date field
  if( defined $li{'date'} )
  {
    @date_m = split( /-/, $li{'date'} );
  }
  else
  {
    # check for the global definition
    if( defined $struct{'date'} )
    {  
      @date_m = split( /-/, $struct{'date'} );
    }
    else
    {
      return \%t_line;
    }

  }


  # construct a hash of the date
  %date = (
    year  =>  $date_m[0], 
    month  =>  $date_m[1],
    day  =>  $date_m[2],
    hour  =>  $date_t[0],
    minute  =>  $date_t[1],
    second =>  $date_t[2],
    time_zone  => 'UTC'  # W3c is always recorded in UTC
  );

  # check the format of the date_t (time) variable, for additional information
  if( $#date_t eq 3 )
  {
    $date{second} = Log2t::roundup( $date_t[2] ) ;
  }

  $date_s = DateTime->new( \%date );
  $date_e = $date_s->epoch;


  # construct the full URL
  $uri = $li{'cs-uri-stem'};
  if( exists $li{'cs-uri-query'} )
  {
    if( $li{'cs-uri-query'} ne '-' )
    {  
      $uri .= '?' . $li{'cs-uri-query'};
    }
  }

  # start constructing the text
  if( exists $li{'s-computername'} )
  {
    $text .= '<' . $li{'s-computername'}. '> ';
  }

  $text .=  $li{'c-ip'} . " connect to '" . $li{'s-ip'} . ":" . $li{'s-port'} . "'";

  if( exists $li{'cs-host'} )
  {
    $text .=  " [host " . $li{'cs-host'} . "]";
  }
  
  $text .= " URI: " . $li{'cs-method'} . ' ' . $uri . " using " . $li{'cs(User-Agent)'} . ', status code ' . $li{'sc-status'};

  if( exists $li{'cs-username'} )
  {
    if( $li{'cs-username'} ne '-' )
    {
      $text .= ' Authentiacted user: ' . $li{'cs-username'};
    }
  }

  if( exists $li{'cs(Referer)'} )
  {
    $text .= ' Came from site: ' . $li{'cs(Referer)'};
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
                'time' => { 0 => { 'value' => $date_e, 'type' => 'Entry written', 'legacy' => 15 } },
                'desc' => $text,
                'short' => 'URL: ' . $uri,
                'source' => 'IIS',
                'sourcetype' => 'IIS Log File',
                'version' => 2,
                'extra' => { 'user' => $li{'c-ip'}, 'host' => $li{'s-ip'}, 'src-ip' => $li{'s-ip'}, 'dst-ip' => $li{'c-ip'}, 'size' => $li{'cs-bytes'} }
        );

  return \%t_line;
}

#  get_help
# A simple subroutine that returns a string containing the help 
# message for this particular format file.
# @return A string containing a help file for this format file
sub get_help()
{
  return "This parser parses the IIS W3C log file. To see the definition of the 
log format, please see:
http://www.w3.org/TR/WD-logfile.html
Use with the FILE option as the W3C log file\n
\t$0 -f iis ex...log

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
# The correct format of a Squid access file (with httpd_emulate equal to off) is:
# timestamp elapsed IP/Client Action/Code Size Method URI Ident Hierarchy/From Content
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

  # defines the maximum amount of lines that we read until we determine that we do not have a IIS file
  my $max = 15;
  my $i = 0;
  %struct = undef;  # initialize the struct hash
  
  $return{'success'} = 0;
  $return{'msg'} = 'success';

        return \%return unless -f ${$self->{'name'}};

  my $ofs = 0;
        # start by setting the endian correctly
        Log2t::BinRead::set_endian( LITTLE_E );

  unless( $self->{'quick'} )
  {
    # we know that an IIS file starts with #, so let's start with that
    seek($self->{'file'},0,0);
    read($self->{'file'},$temp,1);
    $return{'msg'} = 'Not the correct magic value';
    return \%return unless $temp eq '#';
  }

  # now we need to continue testing our file
  $tag = 1;
  $ofs = 0;

  # begin with finding the line that defines the fields that are contained
  while( $tag )
  {
    $tag = 0 unless $line = Log2t::BinRead::read_ascii_until( $self->{'file'}, \$ofs, "\n", 200 );
    $tag = 0 if $i++ eq $max;  # check if we have reached the end of our attempts
    next unless $tag;
      
    # check for existance of the Date field
    if( $line =~ m/^#Date/ )
    {
      if( $line =~ m/Date: (\d{4}-\d{2}-\d{2}).+/ )
      {
        $struct{'date'} = $1;
      }
    }  
    elsif( $line =~ m/^#Fields/ )
    {
      $tag = 0;
      # read the line to get the number of fields
      $line =~ s/\s+/ /g;

      @fields = split( /\s/, $line );

      # first word is the #Fields: line, let's skip that
      $temp = shift(@fields);

      # define the number of fields
      $struct{count} = $#fields;

      # find the c-ip field
      for ( my $i=0; $i < $#fields ; $i++ )
      {
        $c_ip = $i if( $fields[$i] =~ m/^c-ip$/ );
      }
    }
  }

  # the structure is here, let's include it
  $struct{fields} = \@fields;

  # reset tag
  $tag = 1;

  # find a line that is not a comment or an empty line 
  while( $tag )
  {
    $tag = 0 unless $line = Log2t::BinRead::read_ascii_until( $self->{'file'}, \$ofs, "\n", 400 );
    next if ( $line =~ m/^#/ or $line =~ m/^$/ );
    $tag = 0;
  }

  # now we have one line of the file, let's read it and verify
  # remove unneeded spaces
  $line =~ s/\s+/ /g;
  @words = '';
  @words = split(/\s/, $line );
  
  # word count should be equal to the number of fields
  if( $#words eq $struct{count} )
  {
    # verify one variable in the log file, the IP address
    if( $words[$c_ip] =~ m/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/ )
    {
      # the IP address is correctly formed, let's assume other fields are too
      $return{'success'} = 1;
    }
    else
    {
      $return{'msg'} = "IP address field [" .$words[$c_ip] . "] not correctly formatted\n";
      $return{'success'} = 0;
    }
  }
  else
  {
    $return{'msg'} = "There should be $struct{count} words per line, instead there are $#words\n";
    $return{'success'} = 0;
  }


  return \%return;
}

1;
