#################################################################################################
#		IEHISTORY	
#################################################################################################
# This script reads the index.dat file that contain Internet Explorer history files
#
# Based partly on the information found in the document: "Forensic Analysis of Internet Explorer 
# Activity Files" written by Keith J Jones (3/19/03 revised 5/6/03)
# 
# Author: Kristinn Gudjonsson
# Version : 0.8
# Date : 24/08/11
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

package Log2t::input::iehistory;

use strict;
use Log2t::base::input; # the SUPER class or parent
use Log2t::Common ':binary';
use Log2t::Time;      # to manipulate time
#use Log2t::Numbers;   # to manipulate numbers
use Log2t::BinRead;   # methods to read binary files
use Encode;

use vars qw($VERSION @ISA);

# inherit the base input module, or the super class.
@ISA = ( "Log2t::base::input" );

$VERSION = '0.8';

# default constructor
sub new()
{
        my $class = shift;

        # bless the class ;)
        my $self = $class->SUPER::new();

	# indicate that this is a binary file that we would like to return a single hash containing all the timestamp objects
        $self->{'multi_line'} = 0;
	bless($self, $class);

        return $self;
}


#       get_description
# A simple subroutine that returns a string containing a description of 
# the funcionality of the format file. This string is used when a list of
# all available format files is printed out
#
# @return A string containing a description of the format file's functionality
sub get_description()
{
	return "Parse the content of an index.dat file containg IE history"; 
}

#       init
# This subroutine starts by reading the parameters passed to the function
# then it opens the index.dat file and starts reading the header information
# found inside the file.
#
# The function prints out minimum information about the index file to STDERR
# for informational value.
#
# It then parses all the HASH tables found inside the index.dat file and constructs
# an hash containing pointers to URL activities
# 
# @params One parameter is defined, the path to the file name 
# @return An integer is returned to indicate whether the file preparation was 
#       successful or not.
sub init
{
	my $self = shift;

	print STDERR "[IE] Debug info turned on.\n" if $self->{'debug'};

	# initialize the current count variable
	$self->{'cur_count'} = 0;
	$self->{'null_file'} = 0;

	return 1;
}

sub get_time
{
	my $self = shift;
	my %hash_table;
	my $ofs;
	my $path;
	my $return_value;

	$self->{'container'} = undef;	# the container for all the timestamp objects
	$self->{'cont_index'} = 0;	# index into the container

	# we start by reading the header
	#return undef unless _read_header( $self );
	return undef unless $self->_read_header;

	# print information from file
	print STDERR "Index.dat version: " . $self->{'struct'}->{'version'} . "\n" if $self->{'debug'};
	print STDERR "Index.dat file length: " . $self->{'struct'}->{'file_length'} . "\n" if $self->{'debug'};

	print STDERR "Index.dat data directories: \n" if $self->{'debug'};

	# read through all directories
	#foreach( @{$self->{'struct'}->{'directories'}} )
	foreach( sort keys %{$self->{'struct'}->{'directories'}} )
	{
		print STDERR "\t" . $self->{'struct'}->{'directories'}->{$_} . "\n" if $self->{'debug'};
	}

	# we need to read the hash table, increase the offset to the hash offset

	# we set the offset to equal the first hash table
	$ofs = $self->{'struct'}->{'hash_offset'};

	$self->{'null_file'} = 1 if $self->{'struct'}->{'hash_offset'} eq 0x00;

	# if there are now records, we return a true here and then return no line in load_line
	return undef if $self->{'null_file'};
	
	# now we read the first hash table
	return undef unless $self->_read_hash_table( $ofs, \%hash_table );

	# and then we read the hash tables until we reach the end
	while( $hash_table{'next'} ne 0 )
	{
		# we continue to build the records hash
		$ofs = $hash_table{'next'};
		printf STDERR "[IEHISTORY] Reading HASH TABLE - Currently at offset 0x%x\n",$ofs if $self->{'debug'} > 1;
		$return_value = $self->_read_hash_table( $ofs, \%hash_table );

		$hash_table{'next'} = 0 unless $return_value;
	}

	return $self->{'container'};
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



#       _parse_timestamp
# This is the main "juice" of the format file.  It reads the index variable that 
# contains an index into the records hash.  It then reads the corresponding hash
# value inside the records hash, pointing to a valid record inside the index.dat file.
# 
# It then parses the URL activity field and produces a line that can be printed out
#
# @return returns a reference to a hash that contains all the needed fields to produce
# a timeline 
sub _parse_timestamp
{
	my $self = shift;
	# the timestamp object
	my %t_line;
	my $text;
	my %r;
	my $time1 = 'time1';
	my $time2 = 'time2';
	my $first;
	# the fix variable is a "binary" one, 00 each representing a timestamp that needs to be fixed
	# b01 time2 - b10 time1 - b11 both
	my $fix = undef;

	# check if there are no records
	print STDERR "No records inside history file\n" if $self->{'null_file'};
	return undef if $self->{'null_file'};

	# check the first value
	$first = $self->{'record'}->{'pointer'} >> 56;

	# check the value of the first byte
	if( $first eq 0x01 )
	{
		# not pointing to an activity record
		return \%t_line;
	}

	# this value is not valid
	if( $self->{'record'}->{'pointer'} eq 0x0badf00d )
	{
		# not a valid record
		return \%t_line;
	}

	# now we need to verify that we have a real record
	my $ofs = $self->{'record'}->{'pointer'} & 0x00ffffff;
	my $str = Log2t::BinRead::read_ascii($self->{'file'},\$ofs,4);
	
	# verify that the record is valid
	return \%t_line unless ( $str eq 'URL ' or $str eq 'REDR' or $str eq 'LEAK' );

	# first we need to figure out which type of index.dat file this is, that is
	# to know if we are dealing with a Cookie index.dat, IE history file or IE Cache
	# So the types are:
	#	history
	#	cache
	# 	cookie
	# the meaning of the timestamps differ between all these types, which makes if
	# vital to confirm this
	if( ${$self->{'name'}} =~ m/History.IE5/i )
	{
		# this is a History file, so we need further checking, since history
		# files are split up in:
		#	master file
		# 	weekly file
		#	daily file
		# the meaning of each timestamps differ between these files
		# check the filename
		# we are dealing with a file inside the history.ie5 path

		# now to check if this is a daily, master or weekly file
		if( ${$self->{'name'}} =~ m/MSHist01\d{6}(\d{2})\d{6}(\d{2})/i )
		{
			# we need to make one more check to determine if this is a daily file or a weekly one
			if( ( $2-$1 eq 1 ) or ( $1 eq ( 28 or 30 or 31 ) and $2 eq 01 ) )
			{	
				# daily one	
				$time1 = 'Last Access';
				$time2 = 'Last Access';
				$fix = 2;
			}
			else
			{
				# weekly
				$fix = 2;
				$time1 = 'Last Access';
				$time2 = 'index.dat creation time';
			}
		}
		else
		{
			# a master
			$time1 = 'Last Access';
			$time2 = 'Last Access'
		}
	}
	elsif( ${$self->{'name'}} =~ m/Cookies/ )
	{
		# we have a cookie file
		$time1= 'Website modified cookie';
		$time2 = 'Last time cookie passed to website';
	}
	elsif( ${$self->{'name'}} =~ m/Temporary/ )
	{
		# we have a cache
		$time1 = 'Content saved to drive';
		$time2 = 'Content viewed';
	}
	else
	{
		# use the default layout
		$time1 = 'time1';
		$time2 = 'time2';
	}

	# get the pointer part of the pointer
	my $ofs = $self->{'record'}->{'pointer'} & 0x00ffffff;

	$r{start} = $ofs; 	# save the starting point

	# read the activity type
	$r{type} = Log2t::BinRead::read_ascii($self->{'file'},\$ofs,4);

	# find the length of the record
	$r{'length'} = Log2t::BinRead::read_32($self->{'file'},\$ofs);
	$r{'length'} = $r{'length'} * 0x80;

	# now we process the records differently depending on the type
	if( $r{'type'} eq 'URL ' or $r{'type'} eq 'LEAK' )
	{
		$text = 'LEAK record ' if $r{'type'} eq 'LEAK';

		# read the time
		$r{'mod_1'} = Log2t::BinRead::read_32($self->{'file'},\$ofs);
		$r{'mod_2'} = Log2t::BinRead::read_32($self->{'file'},\$ofs);
		$r{'acc_1'} = Log2t::BinRead::read_32($self->{'file'},\$ofs);
		$r{'acc_2'} = Log2t::BinRead::read_32($self->{'file'},\$ofs);

		$r{time2} = Log2t::Time::Win2Unix( $r{'mod_1'}, $r{'mod_2'} ); 
		$r{time1} = Log2t::Time::Win2Unix( $r{'acc_1'}, $r{'acc_2'} ); 

		# the rest of the values depends upon the version 
		$ofs = $self->{'struct'}->{'version'} gt 5 ? $r{'start'} + 0x34: $r{'start'} + 0x38;
		$r{'url_ofs'} = Log2t::BinRead::read_32( $self->{'file'},\$ofs );
	
		# read file name offset
		$ofs = $self->{'struct'}->{'version'} gt 5 ? $r{'start'} + 0x3c: $r{'start'} + 0x40;
		$r{'fn_ofs'} = Log2t::BinRead::read_32( $self->{'file'},\$ofs );

		# read directory index
		$ofs = $self->{'struct'}->{'version'} gt 5 ? $r{'start'} + 0x38: $r{'start'} + 0x3C;
		#$r{'dir_in'} = Log2t::BinRead::read_32( $self->{'file'},\$ofs );
		$r{'dir_in'} = Log2t::BinRead::read_8( $self->{'file'},\$ofs );
		$ofs += 3;
		printf STDERR "[IE] Directory reading [0x%x]: 0b%b ", $ofs-4, $r{'dir_in'} if $self->{'debug'} > 1;
		$r{'dir_in'} = $r{'dir_in'} & 0x000000ff;  
		printf STDERR "and after change: 0x%x\n ", $r{'dir_in'} if $self->{'debug'} > 1;
		$r{'dir'} = $self->{'struct'}->{'directories'}->{int($r{'dir_in'})};
		$r{'dir'} =~ s/[[:cntrl:]]//g;

		$ofs = $self->{'struct'}->{'version'} gt 5 ? $r{'start'} + 0x44: $r{'start'} + 0x48;
		$r{'header_ofs'} = Log2t::BinRead::read_32( $self->{'file'},\$ofs );

		$ofs = $r{'url_ofs'} + $r{'start'};
		$r{'url'} = Log2t::BinRead::read_ascii_end($self->{'file'},\$ofs,$r{'length'});
		
		$ofs = $r{'header_ofs'} + $r{'start'};
		#$r{'header'} = Log2t::BinRead::read_ascii_end($self->{'file'},\$ofs,$r{'length'}-$r{'header_ofs'});
		$r{'header'} = Log2t::BinRead::read_ascii_magic($self->{'file'},\$ofs,$r{'length'}-$r{'header_ofs'},"\r\n\r\n");
		#$r{'header'} = Log2t::BinRead::read_ascii_until($self->{'file'},\$ofs,\@ar,$r{'length'}-$r{'header_ofs'});

		# "fix" the header and extract user info
		( $r{'header'}, $r{'user'} ) = split( /\r\n~U:/, $r{'header'} );

		# and fix again (if empty we are propably using @
		( $r{'user'}, $r{'url'} ) = split( /@/, $r{'url'} ) if $r{'user'} eq '' and $r{'url'} =~ m/@/;

		if( $r{'user'} =~ m/: (.+)/ )
		{
			$r{'user'} = $1;
		}
		
		$r{'user'} =~ s/\n//g;
		$r{'user'} =~ s/\r//g;
		
		$r{'header'} =~ s/\r//g;
		$r{'header'} =~ s/\n/ - /g;
		$r{'header'} =~ s/ - $//g;
		$r{'header'} =~ s/[[:cntrl:]]//g;

		$ofs = $r{'fn_ofs'} + $r{'start'};
		$r{'filename'} = Log2t::BinRead::read_ascii_end($self->{'file'},\$ofs,$r{'length'});

		# construct the text field
		#$text .= 'User ' . $r{'user'} . ' connected to ' if $r{'user'} ne '';

		$text .= 'URL:' . $r{'url'};

		# fix the printable character range
		$r{'header'} =~ s/(.)/(ord($1) > 127) ? "" : $1/egs;

		$text .= ' cache stored in: ' . $r{'dir'} . '/' . $r{'filename'} unless $r{'dir'} eq '';
		$text .= ' - ' . $r{'header'} . '' if ( $r{'header'} ne '' and length( $r{'header'}) > 4 );

		#$text .= 'URL:' . $r{'url'} . ' cache stored in: ' . $r{'dir'} . '/' . $r{'filename'} . ' - ' . $r{'header'} .'';

		# construct the title
		$r{'title'} = 'visited ' . $r{'url'};

	}
	elsif( $r{'type'} eq 'REDR' )
	{
		$text = 'REDR: ';
		$ofs = $r{'start'} + 0x10;
		$r{'url'} = Log2t::BinRead::read_ascii_end( $self->{'file'},\$ofs,$r{'length'} );
		$r{'time1'} = $r{'time2'} = 0;

		$text .= 'User was redirected to: ' . $r{'url'};
		$r{'title'} = 'Redirect to ' . $r{'url'};

	}
	else
	{
		$text = 'unknown type';
	}

	# remove control characters
	$text =~ s/[[:cntrl:]]//g;
	$text = encode( 'utf-8', $text );

	# and now to "fix" timestamps that might have been in local timezone
	if( $fix & 0b01 )
	{
		# we need to fix time2
		#print STDERR "FIXING EPOCH2: ", $r{'time2'};
		Log2t::Time::fix_epoch( \$r{'time2'}, $self->{'tz'} );
		#print STDERR " - now ", $r{'time2'}, "\n";
	}
	if( $fix & 0b10 )
	{
		# we need to fix time1
		#print STDERR "FIXING EPOCH1: ", $r{'time1'};
		Log2t::Time::fix_epoch( \$r{'time1'}, $self->{'tz'} );
		#print STDERR " - now ", $r{'time1'}, "\n";
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
                'short' => $r{'title'},
                'source' => 'WEBHIST',
                'sourcetype' => 'Internet Explorer',
                'version' => 2,
                'extra' => { 'user' => $r{'user'}, }
        );

	if ( $r{'time1'} == $r{'time2'} )
	{
		# same time
		$t_line{'time'} = { 0 => { 'value' => $r{'time1'}, 'type' => $time1 . '/' . $time2, 'legacy' => 15 }, };
	}
	else
	{
		# time is different
		$t_line{'time'} = { 0 => { 'value' => $r{'time1'}, 'type' => $time1, 'legacy' => 14 }, 1 => { 'value' => $r{'time2'}, 'type' => $time2, 'legacy' => 1 } };
	}

        # check the existence of a default browser for this particular user
        if( defined $self->{'defbrowser'}->{lc($r{'user'})} )
        {   
                $t_line{'notes'} = $self->{'defbrowser'}->{$r{'user'}} =~ m/iexplore/ ? 'Default browser for user' : 'Not the default browser (' . $self->{'defbrowser'}->{$r{'user'}} . ')';
        }   
	elsif ( $self->{'defbrowser'}->{'os'} ne '' )
	{
		# check the default one (the OS)
                $t_line{'notes'} = $self->{'defbrowser'}->{'os'} =~ m/iexplore/ ? 'Default browser for system' : 'Not the default system browser (' . $self->{'defbrowser'}->{'os'} . ')';
	}


	# finished processing this line, increase the index
	$self->{'index'}++;

	return \%t_line;
}

#       get_help
# A simple subroutine that returns a string containing the help 
# message for this particular format file.
# @return A string containing a help file for this format file
sub get_help()
{
	return "This plugin parses the index.dat file that contains Internet activities as recorder by Internet Explorer.";

}

#       verify
# A subroutine that verifies if we are examining a prefetch directory so it can be further 
# processed.  The correct format is a directory that consists of a folder that contains
# several files that end with a .pf ending.  Then one file in the folder is named Layout.ini
# @return An array containing an integer and a string.  The integer indicates a success or failure and the
#       string is the error message (if the file is not correctly formed)
sub verify
{
	# define an array to keep
	my %return;
	my $self = shift;
	my $string;
	
	# start by setting the endian correctly
	#Log2t::BinRead::set_endian( Log2t::Common::LITTLE_E );
	Log2t::BinRead::set_endian( LITTLE_E );

	# default value of validation is that the file is of the wrong format
	$return{'success'} = 0;
	$return{'msg'} = 'unknown error';

        return \%return unless -f ${$self->{'name'}};

	my $ofs = 0;

	#unless( $self->{'quick'} )
	#{	
	#	# just read the first letter (shortening the verification phase)
	#	seek($self->{'file'},0,0);
	#	read($self->{'file'},$string,1);
	#	$return{'msg'} = 'Not the correct magic value';
	#	return \%return unless $string eq 'C';
	#}
	
	# now we need to continue reading the file
	$string = Log2t::BinRead::read_ascii( $self->{'file'}, \$ofs, 15 );

	# check if string matches 
	if( $string eq 'Client UrlCache' )
	{
		$return{'success'} = 1;
	}
	else
	{
		$return{'success'} = 0;
		$return{'msg'} = 'Not the correct magic value';
	}

	# return the validation hash
	return \%return;
}

sub _read_header
{
	my $self = shift;
	# since we are reading the header, we need to start on the first byte
	my $ofs = 0;
	my $i = 0; # index into the directory structure

	# read information from the file's header
	$self->{'struct'}->{'version_string'} = Log2t::BinRead::read_ascii_end( $self->{'file'}, \$ofs, 40 );
	my @words = split( /\s/, $self->{'struct'}->{'version_string'} );
	$self->{'struct'}->{'version'} = $words[$#words];

	print STDERR "[IE] Info: Version string is '" . $self->{'struct'}->{'version_string'} . "'\n" if $self->{'debug'};

	$self->{'struct'}->{'file_length'} = Log2t::BinRead::read_32( $self->{'file'},\$ofs );

	print STDERR "[IE] Info: File is " . $self->{'struct'}->{'file_length'} . "\n" if $self->{'debug'};

	$self->{'struct'}->{'hash_offset'} = Log2t::BinRead::read_32($self->{'file'},\$ofs);

	# directory names start in offset 0x50
	$ofs = 0x50;

	# read directory names
	my $tag = 1;
	my @dirs;
	my $dir;
	while( $tag )
	{
		printf STDERR "[IE] Header offset 0x%x\n",$ofs if $self->{'debug'};

		# read 12 bytes (the length of a directory name)
		$dir = Log2t::BinRead::read_ascii( $self->{'file'},\$ofs,8 );
		$ofs+=4;

		printf STDERR "[IE] Header directory %s (0x%x)\n",$dir,$ofs if $self->{'debug'};
	
		# check if we've actually read a directory
		$tag = 0 unless $dir;
		$tag = 0 if $dir eq "\0";
	
		# if we did not read directory name, then we lower the offset
		$ofs -= 12 unless $tag;

		$dir =~ s/[[:cntrl:]]//g;

		next unless $tag;
		$self->{'struct'}->{'directories'}->{$i++} = $dir;
		#push( @dirs, $dir );
	}

	#$self->{'struct'}->{'directories'} = \@dirs;
	
	return 1;
}

sub _read_hash_table($)
{
	my $self = shift;
	my $offset = shift;
	my $table = shift;
	
	# save the first value
	$table->{'start'} = $offset;

	# each table starts with a magic value
	$table->{'magic'} = Log2t::BinRead::read_ascii($self->{'file'},\$offset,4);

	return 0 if $table->{'magic'} ne 'HASH';

	# find out the length of the hash table
	$table->{'units'} = Log2t::BinRead::read_32( $self->{'file'}, \$offset );
	$table->{'length'} = $table->{'units'} * 128;
	$table->{'end'} = $table->{'length'} + $offset - 8;

	# read the next pointer to a hash table
	$table->{'next'} = Log2t::BinRead::read_32( $self->{'file'},\$offset );

	# read the activity record flags
	my $tag;
	
	# read all the activity fields and associated pointers
	for (my $i=0 ; (16 + $i * 8 ) < $table->{'length'} ; $i++ )
	{
		$offset = $table->{'start'} + 16 + 8 * $i;
		$self->{'record'} = {
			'offset' => $offset,
			'flag'	=>  Log2t::BinRead::read_32( $self->{'file'}, \$offset ),
			'pointer' =>  Log2t::BinRead::read_32( $self->{'file'}, \$offset )
		};
		$self->{'container'}->{$self->{'cont_index'}++} = $self->_parse_timestamp;
	}

	return 1;
}

1;
