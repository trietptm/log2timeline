#################################################################################################
#    SYSTEM
#################################################################################################
# This script parses the SYSTEM registry file
#
# Author: Kristinn Gudjonsson
# Version : 0.1
# Date : 11/05/11
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
package Log2t::input::system;

use strict;
use Log2t::base::input;   # the SUPER class or parent
use Parse::Win32Registry qw(:REG_);
use Log2t::Common ':binary';
use Log2t::BinRead;
use Log2t::WinReg;  # for deleted entries
use Log2t::Time;
use Log2t::Win;
use Encode;

use vars qw($VERSION @ISA);

# inherit the base input module, or the super class.
@ISA = qw( Log2t::base::input );
#@ISA = qw( Log2t::base::input Log2t::WinReg::Ntuser );

# version number
$VERSION = '0.1';

##########################################################################################################################
#    PARSING FUNCTIONS
#------------------------------------------------------------------------------------------------------------------------#
# the default parsing of an object
sub _parse_default
{
  my $self = shift;

    my $ts = $self->{'value'}->get_timestamp();
    my $name = shift; 
    #my $name = $self-{'key_name'};

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
  # we've got all the values
        # create the t_line variable
  $self->{'container'}->{$self->{'cont_index'}++} = {
                'time' => { 
      0 => { 'value' => $ts, 'type' => 'Last Written', 'legacy' => 15 },
    },
                'desc' => "Key name: HKLM/System$name" ,
                'short' => $name,
                'source' => 'REG',
                'sourcetype' => 'SYSTEM key',
                'version' => 2,
                'extra' => {  }
        };

  return 1;

}

##########################################################################################################################


# the constructor
sub new()
{
        my $class = shift;

        # inherit from the base class
        my $self = $class->SUPER::new();

        # indicate that we would like to parse this file in one attempt, and return it in a single hash
        $self->{'multi_line'} = 0;

        # TEMPORARY - remove when FH is accepted through Parse::Win32Registry
        $self->{'file_access'} = 1;     # do we need to parse the actual file or is it enough to get a file handle
  
  # set some default variables
  $self->{'verify_key'} = 'Select';

        bless($self,$class);

        return $self;
}

#       get_version
# A simple subroutine that returns the version number of the format file
#
# @return A version number
sub get_version()
{
  return $VERSION;
}

#       get_description
# A simple subroutine that returns a string containing a description of 
# the funcionality of the format file. This string is used when a list of
# all available format files is printed out
#
# @return A string containing a description of the format file's functionality
sub get_description()
{
  return "Parses the SYSTEM registry file";  
}

sub _regscan
{
  my $self = shift;
  my $key = shift;

    my $name = $key->as_string();
    $name =~ s/\$\$\$PROTO\.HIV//;
    $name = (split(/\[/,$name))[0];
  #$name =~ s/^CMI-CreateHive{[A-F0-9_\-]+}//;
  #$name =~ s/^\\//;
  #$name =~ s/\s//g;
  
  $self->{'key_name'} = $name;

  #print STDERR "\n\n";
  #print STDERR "[SYSTEM] We are about to load record nr. " . $self->{'counter'}++ . "\n" ;#if $self->{'debug'};

  #print STDERR "TESTING AGAINST [$name]\n";
  #foreach( keys %{$self->{'key_parse'}} )
  #{
  #  print STDERR "\t($_)\n";
  #}

  # check the key
  if( defined $self->{'key_parse'}->{$name} )
  {
    # key defined, we are about to do some parsing here
    $self->{'value'} = $key;
    eval 
    {
      $self->{'key_parse'}->{$name}->( $self );
    };
    if( $@ )
    {
      print STDERR "[SYSTEM] Unable to parse the registry key $name. Error $@\n";
      return 1;
    }
  }
  else
  {
    #print STDERR "[NTUSER] <$name> NOT DEFINED\n";
    # not defined, we need the default behaviour (print this particular key and then find all the sub keys
    $self->{'value'} = $key;
    eval
    {
      $self->{'key_parse'}->{'DEFAULT'}->($self, $name);
    };
    if( $@ )
    {
      print STDERR "[SYSTEM] Unable to parse the registry key $name. Error $@\n";
      return 1;
    }

    # and now to find the subkeys
    foreach my $subkey ( $key->get_list_of_subkeys() ) 
    {
      $self->_regscan( $subkey );
    }
  }

  return 1;
}

#  get_time
# This subroutine starts by reading the NTUSER.DAT registry file and parse it
# using the Win32Registry library.  It then retrives the UserAssist part of the
# registry and stores it's values in the array @vals (which is global)
# 
# It then returns a reference to a hash that stores all the timestamp
# objects to the main engine for further processing
sub get_time()
{
  my $self = shift;
  my $key;
  my $root_key;
  my @extra;
  my $path;
  my @t_array;
  my %t_hash;

  # set the default values
  $self->{'no_go'} = 0;

  # initialize
  $self->{'container'} = undef;
  $self->{'cont_index'} = 0;
  $self->{'counter'} = 1;

  # get the root key
  $root_key = $self->{'reg'}->get_root_key;

  # define a dispatch table, or a code reference table
  $self->{'key_parse'} = {
    'DEFAULT' => \&_parse_default   # default parsing (not a known key)
  };
  
  # if no_go is set, then we just return with no line
  return undef if $self->{'no_go'};

  # now we've confirmed everything, set up all the needed functions, no we just need to do some recursive scan through the registry
  # parsing the keys we can, and make a simple gesture for the rest
  $self->_regscan( $root_key );

  # now we've done the recursive scan, let's try to recover deleted information
  my $deleted_entries = Log2t::WinReg::get_deleted_entries( $self );

  # add the deleted entries into the pile...
  foreach my $h ( keys %{$deleted_entries} )
  {
    $self->{'container'}->{$self->{'cont_index'}++} = $deleted_entries->{$h};
  }

  return $self->{'container'};
}


#       get_help
# A simple subroutine that returns a string containing the help 
# message for this particular format file.
# @return A string containing a help file for this format file
sub get_help()
{
  return "This input module parses the SYSTEM registry file.
It extracts data from 'known' keys and then displays the last written time and 
name of the rest of the keys.
  ";
}

#       verify
# A subroutine that verifies if we are examining a ntuser file, so it can be further 
# processed.  
# @return An array containing an integer and a string.  The integer indicates a success or failure and the
#       string is the error message (if the file is not correctly formed)
sub verify
{
  my $self = shift;
  # define an array to keep
  my %return;
  my $line;
  my @words;
  my $root_key;
  my $key;

  # start by setting the endian correctly
  #Log2t::BinRead::set_endian( Log2t::Common::LITTLE_E );
  #Log2t::BinRead::set_endian( LITTLE_E );

  # default values
  $return{'success'} = 0;
  $return{'msg'} = 'not a file';
  
  return \%return unless -f ${$self->{'name'}};

  my $ofs = 0;

  # start by checking if this is a file or not
  if( -f ${$self->{'name'}} )
  {
    # this is a file, check further
    eval
    {
      $line = Log2t::BinRead::read_ascii( $self->{'file'},\$ofs,4 );
    };
    if ( $@ )
    {
      $return{'success'} = 0;
      $return{'msg'} = "Unable to open the file ($@)";
      return \%return;
    }

    # the content of these bytes should be
    # regf = 7265 6766
    if( $line eq 'regf' )
    {
      # load the array ( or try to at least )
      eval 
      {
        $self->{'reg'} = Parse::Win32Registry->new(${$self->{'name'}});
      };
      if( $@ )
      {
        # an error occured, return from this mess ;)
        $return{'msg'} = "[UserAssist] Unable to load registry file";
        $return{'success'} = 0;

        return \%return;
      }

                        # sometimes there might be false positives here, so let's try to get the root key
                        eval
                        {
                                # the registry is now loaded, check the existance of a UserAssist key
                                $root_key = $self->{'reg'}->get_root_key;
      };
      if( $@ )
      {
                                $return{'msg'} = 'Unable to retrieve the root key, this might not be a registry file (' . ${$self->{'name'}} .')';
                                $return{'success'} = 0;
                                return \%return;
                        }

      eval 
      {
        # now we need to test for the existance of the keys in question
        # one test
        # get the userassist key

        $key = $root_key->get_subkey($self->{'verify_key'});

        # get the current control set
        my $current = $key->get_value("Current")->get_data();

        if( defined $key && defined $current  )
        {
          $return{'success'} = 1;
        }
        else
        {
          $return{'success'} = 0;
          $return{'msg'} = 'The verification key does not exist';
        }
      };
      if( $@ )
      {
        $return{'msg'} = 'Unable to load the verification key, not a SYSTEM file';
        $return{'success'} = 0;
      }
    }
    else
    {
      $return{'success'} = 0;
      $return{'msg'} = 'File not a registry file.';
    }
  }
  else
  {
    # not a file, so back out
    $return{'success'} = 0;
    $return{'msg'} = ${$self->{'name'}} . ' is not a file. ';
  }

  return \%return;
}


1;

