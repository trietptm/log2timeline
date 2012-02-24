#################################################################################################
#    MCAFEE HIPSHIELD LOG
#################################################################################################
# this script is a part of the log2timeline program.
# 
# This file implements a parser for the McAfee HIPShield log file
#
# Author: anonymous donator
# Version : 0.1
# Date : 7/20/2011
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

package Log2t::input::mcafeehs;

use strict;
use Log2t::base::input; # the SUPER class or parent
#use Log2t::Numbers;  # work with numbers, round-up, etc...
#use Log2t::Network;  # some routines that deal with network information
use Log2t::BinRead;  # to work with binary files (during verification all files are treaded as such)
use Log2t::Common ':binary';
use Log2t::Time;  # for time manipulations
#use Log2t:Win;    # for few Windows related operations, GUID translations, etc..
#use Log2t:WinReg;  # to recover deleted information from registry
use Switch;
use vars qw($VERSION @ISA);

# inherit the base input module, or the super class.
@ISA = ( "Log2t::base::input" );

# version number
$VERSION = '0.1';

# by default these are the global varibles that get passed to the module
# by the engine.
# These variables can therefore be used in the module without needing to 
# do anything to initalize them.
#
#  $self->{'debug'}  - (int) Indicates whether or not debug is turned on or off
#  $self->{'quick'}   - (int) Indicates if we will like to do a quick verification
#  $self->{'tz'}    - (string) The timezone that got passed to the tool
#  $self->{'temp'}    - (string) The name of the temporary directory that can be used
#  $self->{'text'}    - (string) The path that is possible to add to the input (-m parameter) 
#  $self->{'sep'}     - (string) The separator used (/ in Linux, \ in Windows for instance)
#

#  new
# this is the constructor for the subroutine.  
#
# If this input module uses all of the default values and does not need to define any new value, it is best to 
# skip implementing it altogether (just remove it), since we are inheriting this subroutine from the SUPER
# class
sub new()
{
  my $class = shift;

  # now we call the SUPER class's new function, since we are inheriting all the 
  # functions from the SUPER class (input.pm), we start by inheriting its calls
  # and if we would like to overwrite some of its subroutines we can do that, otherwise
  # we don't need to include that subroutine
  my $self = $class->SUPER::new();

  # indicate that we would like to parse this file in one attempt, and return it in a single hash
  $self->{'multi_line'} = 0;
  $self->{'type'} = 'file';       # it's a file type, not a directory

  # $self->{'file_access'} = 1;     # do we need to parse the actual file or is it enough to get a file handle

  # bless the class ;)
  bless($self,$class);

  return $self;
}

#   init
#
# The init call resets all variables that are global and might mess up with recursive
# scans.  
#
# This subroutine is called after the file has been verified, and before it is parsed.
#
# If there is no need for this subroutine to do anything, it is best to skip implementing
# it altogether (just remove it), since we are inheriting this subroutine from the SUPER
# class
sub init()
{
  my $self = shift;
  # there shouldn't be any need to create any global variables.  It might be best to
  # save all such variables inside the $self object
  # Creating such a variable is very simple:
  #  $self->{'new_variable'} = 'value'
  #
  # sometimes it might be good to initialize these global variables, to make sure they 
  # are not used again when parsing a new file.
  #
  # This method, init, is called by the engine before parsing any new file.  That makes
  # this method ideal to initialize or null the values of global variables if they are used.
  # This is especially cruical when recursive parsing is used, to make sure that when the next file 
  # is being parsed by the module there isn't any mix-up between files.

  return 1;
}


#   get_version
# A simple subroutine that returns the version number of the format file
# There shouldn't be any need to change this routine, it serves its purpose 
# just the way it is defined right now. (so it shouldn't be changed)
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
#
# @return A string containing a description of the input module
sub get_description()
{
  # change this value so it reflects the purpose of this module
  return "Parse the content of a McAfee HIPShield log file";
}

#  end
# A subroutine that closes everything, remove residudes if any are left
#
# If there is no need for this subroutine to do anything, it is best to skip implementing
# it altogether (just remove it), since we are inheriting this subroutine from the SUPER
# class
sub end()
{
  my $self = shift;
  
  # there might be some resources that need to be closed, for instance
  # some temporary files created by the module that need to be deleted,
  # or database connections closed or any other possible operations that
  # need to be performed to successfully close the file before it is possible
  # to start parsing the next one.
  # 
  # This method is used for that, so if there is a need to close some 
  # connections, do it here.
  #
  # It is not necessary to close the file handle though, that is done in
  # the main engine, not unless the module has created its own using the 
  # file name that got passed to it, then it might be necessary to close it 
  # here
  return 1;
}

# return a readable string for a given integer reaction
sub ReturnReaction
{
  my $reactionLevel = shift(@_);
  
  switch($reactionLevel)
  {
    case(0){return "Invalid";}
    case(1){return "None";}
    case(2){return "Log";}
    case(3){return "Deny";}
    case(4){return "Kill";}
    case(5){return "Kill Terminal";}
    case(6){return "Kill User";}
    case(9){return "Prevent by kill";}
    case(10){return "Create exception";}
    default{return $reactionLevel;}
  }
  
  return "Unknown";
}

# return a readable string for a given integer severity
sub ReturnSeverity
{
  my $severityLevel = shift(@_);
  
  switch($severityLevel)
  {
    case(0){return "Disabled";}
    case(1){return "Info";}
    case(2){return "Low";}
    case(3){return "Medium";}
    case(4){return "High";}
    default{return $severityLevel;}
  }
  
  return "Unknown";
}

#  get_time
# This is the main "juice" of the input module. It parses the input file
# and produces a timestamp object that get's returned (or if we said that
# self->{'multi_line'} = 0 it will return a single hash reference that contains
# multiple timestamp objects within it.
# 
# This subroutine needs to be implemented at all times
sub get_time()
{
  my $self = shift;

  # reset variables
  my %container;
  my $count_index = 0;
  
  my $text = "text";
  my $type = "shortdesc";

  # get the filehandle 
  my $fh = $self->{'file'};
  
  my $line;
  my $date;
  
  #print STDERR "looking for violations.\n";
  
  # there are basically two ways we can parse the violations in a HIPShield log:
  # 1. use an XML library (such as XML:LibXML) and parse the XML, then get the elements/content/attributes (harder, dynamic)
  # 2. don't use an XML library and just get the data out using a regex (easy, fairly static--probably won't work well (or at all) if data layout isn't the same)
  
  # for now, just do #2, because that's much easier (one line compared to ??)

  # get the process started by reading a line
  $line = <$fh>;
  
  # read all lines
  while( $line )
  {
    # look for the VIOLATION keyword
    if($line =~ /VIOLATION/)
    {
      # get the next line of the file. this should start with <Event> if we can log this
      my $xmlVio = <$fh>;
      
      if($xmlVio =~ /\<Event\>/)
      {
        #print "Found violation!\n";
        
        # get the data
        while( ($line !~ /\<\/Event\>/) && ($line = <$fh>) )
        {
          $xmlVio .= $line;
        }
        
        #print "violation is as follows:\n".$xmlVio;
        
        # extract data from entry
        my $match = $xmlVio =~ /SignatureID="(\d+)"\s+SignatureName="(.*?)"\s+SeverityLevel="([0-4])"\s+Reaction="([0-9]|10)"\s+ProcessUserName="(.*?)"\s+Process="(.*?)"\s+IncidentTime="(.*?)"\s+AllowEx="(True|False)"\s+SigRuleClass="(.*?)"\s+ProcessId="(\d+)"\s+Session="(\d+)"\s+SigRuleDirective="(.*?)"\/\>/;
        my $user;
        
        if($match)
        {        
          $text = 'Event: '.$2. ' | Severity: '.ReturnSeverity($3).' | Reaction: '.ReturnReaction($4).' | Process: '.$6.' | Process ID: '.$10.' | SigRuleClass: '.$9.' | SigRuleDirective: '.$12;
          
          $user = $5;
          
          # date/time format = YYYY-mm-dd HH:MM:SS (e.g. 2010-11-29 07:08:29)
          # convert to epoch time
          my $parser = DateTime::Format::Strptime->new(pattern => '%Y-%m-%d %H:%M:%S', time_zone => $self->{'tz'});
          my $dt = $parser->parse_datetime($7);

          $date = $dt->epoch();
          #print "epoch is ".$date."\n";
          
          #extract Params
          #my $params = $13;
          
          #print "SRD = $12\n";
          
          #$self->{'container'}->{$self->{'cont_index'}++}->{'extra'}->{'host'}=$1;
        }
        else
        {
          # Couldn't parse the file using the specified regex, try a more generic one with only a few fields
          $xmlVio =~ /SignatureName="(.*?)".*?SeverityLevel="([0-4])".*?Reaction="([0-9]|10)".*?ProcessUserName="(.*?)".*?Process="(.*?)".*?IncidentTime="(.*?)".*?ProcessId="(.*?)"/;
          #print "Could not grab entry! XML is:\n$xmlVio\n";
          
          # build description
          $text = 'Event: '.$1. ' | Severity: '.ReturnSeverity($2).' | Reaction: '.ReturnReaction($3).' | Process: '.$5.' | Process ID: '.$7;
          $user = $4;
          
          # get the time
          my $parser = DateTime::Format::Strptime->new(pattern => '%Y-%m-%d %H:%M:%S', time_zone => $self->{'tz'});
          my $dt = $parser->parse_datetime($6);
          $date = $dt->epoch();
        }
        
        if($xmlVio =~ /SigRuleClass="Registry"/)
        {
          # registry modification, so get the registry key
          # <Param name="Registry Value(s)">\REGISTRY\MACHINE\SYSTEM\ControlSet\ENUM\ROOT\LEGACY_MFEAPFK\0000\LOGCONF\BASICCONFIG</Param>
          if($xmlVio =~ /\<Param name="Registry Value\(s\)"\>(.*?)\<\/Param\>/)
          {
            $text .= ' | Registry key: '.$1;
          }
        }
        
        #TODO: add more param parsing and add extra information to $text
        
        # get the computer name if possible
          $xmlVio =~ /"Workstation Name">(.*?)<\/Param>/;
        
        # create the t_line variable
        $container{$count_index} = {
            'time' => { 0 => { 'value' => $date, 'type' => 'Entry written', 'legacy' => 15 } },
            'desc' => $text,
            'short' => 'HIPS Violation',
            'source' => 'HIPShield Log',
            'sourcetype' => 'HIPS',
            'version' => 2,
            'extra' => { 'user' => $user, 'host' => $1,  }
        };
        
        $count_index++;
        
        $line = <$fh>;
      }
      else
      {
        #print "Skipping violation without XML\n";
        # found VIOLATION, but no following event. check to see if $xmlVio contains a violation
        if($xmlVio =~ /VIOLATION/)
        {
          $line = $xmlVio;
          #print "Next line contains a violation!\n"
        }
        else
        {
          # process next line
          $line = <$fh>;
          #print "Next line does not contain a violation!\n"
        }
        # don't read in another line, because the one we currently have might be a violation
      }
    }
    else
    {
      # current line doesn't contain a violation. process next line
      $line = <$fh>;
    }
  }
  
  #foreach my $cHash (keys %container)
  #{
  #  print "Stored epoch time for container ".$cHash." is: ".$container{$cHash}->{'time'}->{0}->{'value'}."\n";
  #}

  return \%container;
}

#  get_help
# A simple subroutine that returns a string containing the help 
# message for this particular format file.
# @return A string containing a help file for this input module
sub get_help()
{
  # this message contains the full message that gest printed 
  # when the user calls for a help on a particular module.
  # 
  # So this text that needs to be changed contains more information
  # than the description field.  It might contain information about the
  # path names that the file might be found that this module parses, or
  # URLs for additional information regarding the structure or forensic value of it.
  return "This parser parses HIPShield log files.";
}

#  verify
# This subroutine is very important.  Its purpose is to check the file or directory that is passed 
# to the tool and verify its structure. If the structure is correct, then this module is suited to 
# parse said file or directory.
#
# This is most important when a recursive scan is performed, since then we are comparing all files/dir
# against the module, making it vital for it to be both accurate and optimized.  Slow verification 
# subroutine means the tool will take considerably longer time to complete, too vague confirmation
# could also lead to the module trying to parse files that it is not capable of parsing.
#
# The subroutine returns a reference to a hash that contains two keys, 
#  success    -> INT, either 0 or 1 (meaning not the correct structure, or the correct one)
#  msg    -> A short description why the verification failed (if the value of success
#      is zero that is).
sub verify
{
  my $self = shift;

  # define an array to keep
  my %return;
  my $temp;
  my $vline;  
  my $ofs = 4;
  
  $return{'success'} = 0;
  $return{'msg'} = 'success';

  # to make things faster, start by checking if this is a file or a directory, depending on what this
  # module is about to parse (and to eliminate shortcut files, devices or other non-files immediately)
  return \%return unless -f ${$self->{'name'}};

    # start by setting the endian correctly
    Log2t::BinRead::set_endian( BIG_E );

  # open the file (at least try to open it)
  eval
  {
    #skip four bytes (these should be 0d 0a 0d 0a)
    $vline = Log2t::BinRead::read_ascii_until( $self->{'file'}, \$ofs, "\n", 400 );
  };
  if ( $@ )
  {
    $return{'success'} = 0;
    $return{'msg'} = "Unable to read from file ($@)";
  }
  
  #print "vline = $vline\n";
  
  if($vline =~ /#{11} HipShield Build:/)
  {
    #print "magic value is okay\n";
    # correct value, let's continue and read a line to find out if this truly is a HIPShield log

    $return{'success'} = 1;
  }
  else
  {
    $return{'success'} = 0;
    $return{'msg'} = 'Wrong format';
  }

  return \%return;
}

1;

__END__

=pod

=head1 NAME

structure - An example input module for log2timeline

=head1 METHODS

=over 4

=item new

A default constructor for the input module. There are no parameters passed to the constructor, however it defines the behaviour of the module.  That is to say it indicates whether or not this module parses a file or a directory, and it also defines if this is a log file that gets parsed line-by-line or a file that parses all the timestamp objects and returns them all at once.

=item init

A small routine that takes no parameters and is called by the engine before a file is parsed.  This routine takes care of initializing global variables, so that no values are stored from a previous file that got parsed by the module to avoid confusion.

=item end

Similar to the init routine, except this routine is called by the engine when the parsing is completed.  The purpose of this routine is to close all database handles or other handles that got opened by the module itself (excluding the file handle) and to remove any temporary files that might still be present.

=item get_time

This is the main routine of the module.  This is the routine that parses the actual file and produces timestamp objects that get returned to the main engine for further processing.  The routine reads the file or directory and extracts timestamps and other needed information to create a timestamp object that then gets returned to the engine, either line-by-line or all in one (as defined in the constructor of the module).

=item verify

The purpose of this routine is to verify the structure of the file or directory being passed to the module and tell the engine whether not this module is capable of parsing the file in question or not. This routine is therfore very important for the recursive search of the engine, and it is very important to make this routine as compact and optimized as possible to avoid slowing the tool down too much.

=item get_help()

Returns a string that contains a longer version of the description of the output module, as well as possibly providing some assistance in how the module should be used.

=item get_version()

Returns the version number of the module.

=item get_description()

Returns a string that contains a short description of the module. This short description is used when a list of all available modules is printed out.

=back

=cut

