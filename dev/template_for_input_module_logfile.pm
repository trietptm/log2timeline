#################################################################################################
#    INPUT MODULE
#################################################################################################
# this script is a part of the log2timeline program.
# 
# It implements a parser for X log file
#
# Author: Kristinn Gudjonsson
# Version : 0.1
# Date : 03/03/10
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

=pod

=head1 NAME

INPUT_MODULE - A small one-line description of the module. 

=head1 DESCRIPTION

Small description of the module, what it's purpose is, how it does stuff, etc.... links to relevant 
information, such as links that describe the structure, or it's evidentiary values, blog posts
discussing how to interpret the results, etc....

=head1 METHODS

=cut

package Log2t::input::logfile;

use strict;
use Log2t::base::input; # the SUPER class or parent
#use Log2t::Numbers;  # work with numbers, round-up, etc...
#use Log2t::Network;  # some routines that deal with network information
use Log2t::BinRead;  # to work with binary files (during verification all files are treaded as such)
use Log2t::Common ':binary';
#use Log2t::Time;  # for time manipulations
#use Log2t:Win;    # for few Windows related operations, GUID translations, etc..
#use Log2t:WinReg;  # to recover deleted information from registry
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


=head2 C<new>

This is the constructor for the subroutine.  

If this input module uses all of the default values and does not need to define any new value, it is best to 
skip implementing it altogether (just remove it), since we are inheriting this subroutine from the SUPER class

There are some variables that can be set here that affect the flow of information for the module.

An examples of such variables are: $self->{'multi_line'} = defines how the get_time method is called and what
it should return. The default value is 1, which makes the tool read the file line-by-line, so the method
get_time is called for each line of the file that is being parsed (and it returns a single object). Otherwise
it is read as a single call to get_time, which then returns a hash or collection of timestamp objects.

Another variable that can be set, $self->{'type'}, which should be set as file, unless we are dealing with
a directory.

Since we might be dealing with files that are not readily accessible, such as files within an image file
(might come in the future), we need to define a tag if we really need to have access to the file (for instance
in the case of a SQLIite database that might have to be copied so it can be read). This is controlled in the
variable $self->{'file_access'}, which defaults to 0, or not allow access to the file.

=head3 Returns:

=head4 An instance of the class.

=cut
sub new() {
  my $class = shift;

  # now we call the SUPER class's new function, since we are inheriting all the 
  # functions from the SUPER class (input.pm), we start by inheriting it's calls
  # and if we would like to overwrite some of its subroutines we can do that, otherwise
  # we don't need to include that subroutine
	my $self = $class->SUPER::new();

  # indicate that this is a text based file, with one line per call to get_time
  #  This option determines the behaviour of the engine. If this variable is set
  #   to 0 it means that we return a single hash that contains multiple timstamp objects
  #  Setting it to 1 means that we return a single timesetamp object for each line that
  #   contains a timestamp in the file.
  #   
  #   So if this is a traditional log file, it is usually better to leave this as 1 and 
  #   process one line at a time.  Otherwise the tool might use too much memory and become
  #  slow (storing all the lines in a large log file in memory might not be such a good idea).
  #
  #  However if you are parsing a binary file, or a file that you know contains few timestamps
  #   in it, it might make more sense to just parse the entire file and return a single value
  #  instead of making the engine call the module in a loop. 

	# do not use these lines in a script, remove them if not needed
	# that is if this uses the default behavior remove these commented lines out of the code  
  #$self->{'multi_line'} = 1;  # default value is 1 - only need to change from the default value

  #$self->{'type'} = 'file';  # it's a file type, not a directory (default file)
	#$self->{'file_access'} = 0;    # do we need to parse the actual file or is it enough to get a file handle

	# defaults to 0

	# bless the class ;)
	bless($self,$class);

  return $self;
}

=head2 C<init>

The init call resets all variables that are global and might mess up with recursive
scans.  

This subroutine is called after the file has been verified, and before it is parsed.

If there is no need for this subroutine to do anything, it is best to skip implementing
it altogether (just remove it), since we are inheriting this subroutine from the SUPER
class.

The method can be used to create any global variables, or to initialize them.

=head3 Returns:

=head4 An integer indicating whether or not this was successfully initalized.

=cut
sub init() {
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


=head2 C<get_version>

A simple subroutine that returns the version number of the input module.
There shouldn't be any need to change this routine, it serves its purpose just the way it is defined right now. (so it shouldn't be changed)

=head3 Returns:

=head4 A string representing the version number.

=cut
sub get_version() {
  return $VERSION;
}

=head2 C<get_description>

A simple subroutine that returns a string containing a description of
the funcionality of the input module. This string is used when a list of
all available input modules is printed out.

=head3 Returns:

=head4 A string containing a description of the input module.

=cut
sub get_description() {
  # change this value so it reflects the purpose of this module
  return "Parse the content of a X log file";
}

=head2 C<end>

Sometimes there might be some resources that need to be closed, for instance
some temporary files created by the module that need to be deleted, or 
database connections closed or any other possible operations that
need to be performed to successfully close the file before it is possible
to start parsing the next one.

This method is used for that, so if there is a need to close some 
connections, do it here.

It is not necessary to close the file handle though, that is done in
the main engine, not unless the module has created its own using the 
file name that got passed to it, then it might be necessary to close it 
here.

=head3 Returns:

=head4 An integer indicating whether or not it was successful.

=cut
sub end() {
  my $self = shift; 
  return 1;
}

=head2 C<get_time>

B<UPDATE_ME>

This is the main "juice" of the input module. It parses the input file
and produces a timestamp object that get's returned (or if we said that
self->{'multi_line'} = 0 it will return a single hash reference that contains
multiple timestamp objects within it.

This subroutine needs to be implemented at all times and this comments need
to be updated to reflect the logic of the routine, what it does and how
it does it... are there any risks, might there be loss of data, possibly provide
some tips on analysis, etc...

=cut
sub get_time()
{
  my $self = shift;

  # the timestamp object
  my %t_line;
  my $text;
  my $date;

  # get the filehandle and read the next line
  my $fh = $self->{'file'};
  my $line = <$fh> or return undef; 

  # check line, to see if there are any comments or other such non-related stuff
  if($line =~ m/^#/) {
    # comment, let's skip that one
    return \%t_line; 
  }
  elsif($line =~ m/^$/ or $line =~ m/^\s+$/) {
    # empty line
    return \%t_line;
  }

  # substitute multiple spaces with one for splitting the string into variables
  $line =~ s/\s+/ /g;

  # some parsing done here ....
  $text = substr $line,10,10;

  # The timestamp object looks something like this:
  # The fields denoted by [] are optional and might be used by some modules and not others.
  # The extra field gets in part populated by the main engine, however some fields might be created in the module,
  # for instance if it is possible to extract the username it gets there, or the hostname. Other values might be
  # source ip (src-ip) or some other values that might be of interest yet are not part of the main variables.
  # Another interesting field that might be included in the extra field is the URL ('url').  If it is possible to 
  # show the user where he or she can get additional information regarding the event that is being produced 
  # this is a good place to put it in, for example Windows events found inside the Windows Event Log contain 
  # valuable information that can be further read... so in the evt.pm module a reference to the particular event is 
  # placed inside this variable:
  #   $t_line{'extra'}->{'url'} =http://eventid.net/display.asp?eventid=' . $r{evt_id} . '&source=' . $source
  # 
        # %t_line {      
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
  #

        # create the t_line variable
        %t_line = (
                'time' => { 0 => { 'value' => $date, 'type' => 'Time Written', 'legacy' => 15 } },
                'desc' => $text,
                'short' => $text,
                'source' => 'LOG',
                'sourcetype' => 'This log file',
                'version' => 2,
                'extra' => { 'user' => 'username extracted from line' } 
        );

  return \%t_line;
}

=head2 C<get_help>

A simple subroutine that returns a string containing the help 
message for this particular input module. This message gets printed 
when the user calls for a help on a particular module.

This text therefore needs to be defined and changed for each input module
so that it accurately describes the module in question. 

It might contain information about the path names that the file might be found that this module parses, or
URLs for additional information regarding the structure or forensic value of it.

=head3 Returns:

=head4 A string containing a help description for this input module.

=cut
sub get_help() {
  return "This parser parses the log file X and it might be found on location Y.";
}

=head2 C<verify>

This subroutine is very important.  Its purpose is to check the file or directory that is passed 
to the tool and verify its structure. If the structure is correct, then this module is suited to 
parse said file or directory.

This is most important when a recursive scan is performed, since then we are comparing all files/dir
against the module, making it vital for it to be both accurate and optimized.  Slow verification 
subroutine means the tool will take considerably longer time to complete, too vague confirmation
could also lead to the module trying to parse files that it is not capable of parsing.

=head3 Returns:

=head4 A reference to a hash that contains two keys/values.

success -> INT, either 0 or 1 (meaning not the correct structure, or the correct one)
msg     -> A short description why the verification failed (if the value of success is zero that is).

=cut
sub verify() {
  my $self = shift;

  # define an array to keep
  my %return;
  my $line;
  my $temp;
  my $tag;

  # defines the maximum amount of lines that we read until we determine that this is not the log file of question
  my $max = 15;
  my $i = 0;
  
  $return{'success'} = 0;
  $return{'msg'} = 'success';

  # to make things faster, start by checking if this is a file or a directory, depending on what this
  # modules is about to parse (and to eliminate shortcut files, devices or other non-files immediately)
  return \%return unless -f ${$self->{'name'}};
  return \%return unless -d ${$self->{'name'}};

	# start by setting the endian correctly
	Log2t::BinRead::set_endian( LITTLE_E );

  my $ofs = 0;
  
  # now we try to read from the file
  eval {
    unless($self->{'quick'}) {
      # a firewall log file should start with a comment, or #, let's verify that
      seek($self->{'file'},0,0);
      read($self->{'file'},$temp,1);
      $return{'msg'} = 'Wrong magic value';
      return \%return unless $temp eq '#';
    }
  
    $tag = 1;

    # begin with finding the line that defines the fields that are contained
    while( $tag ) {
      $tag = 0 unless $line = Log2t::BinRead::read_ascii_until( $self->{'file'}, \$ofs, "\n", 400 );
      $tag = 0 if $i++ eq $max;  # check if we have reached the end of our attempts
      next unless $tag;
      
      $line =~ s/\n//;
      $line =~ s/\r//;

      if( $line =~ m/^magic_quote/ )
      {
        $tag = 0;
        # read the line to get the number of fields
        $line =~ s/\s+/ /g;
    
        $return{'success'} = 1;
      }
    }
  };
  if ( $@ ) {
    $return{'success'} = 0;
    $return{'msg'} = "Unable to process file ($@)";

    return \%return;
  }

  return \%return;
}

1;

__END__
