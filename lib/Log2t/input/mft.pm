#################################################################################################
#		MFT
#################################################################################################
# This input module provides a parser for the NTFS $MFT file (the one that contains all the 
# information about filesystem timestamps). 
#
# So if you are analyzing a NTFS filesystem this module can be used instead of using something
# like TSK to gather the filesystem timestamps.
#
# What this module offers that TSK doesn't is the following:
#	+ Both $SI and $FN timestamps are printed (instead of only $SI)
#	+ Small text is added to the output if there is only a second precision, that is
#	if the timestamp is only precise to the minute instead of nanosecond.
#	Timestomping tools are only able to modify 32-bits of the 64-bit timestamp, or the 
#	second and above, so timestamps that have only second precision might be an indication
#	of timestomping, or alterations of timestamps (although not for certain, there are other
#	legitimate reasons why some timestamps might be with only second precision).
#	+ You can output directly into any of the output modules of log2timeline, instead of needing
#	to convert mactime output using log2timeline
#
# This module is largely built upon the tool analyzeMFT, written by David Kovar.  That tool is
# written in Python, so a Perl convertion was made.  
#
# Some features have been added that weren't in analyzeMFT (such as folder construction) and
# other changes were made to make the code fit into the log2timeline framework, other than
# that, the tool is pretty much the same.
#
# Author: Kristinn Gudjonsson
# Version : 0.1
# Date : 10/05/11
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
#
# This modules is largely built upon the tool analyzeMFT by David Kovar
# porting done by Kristinn Gudjonsson, with permissions from David.
#
# David has provided explicit rights to release this port under the
# GPL license, so his code is now dual-licensed.
# 
# The original license of analyzeMFT:
# 	Copyright (c) 2010 David Kovar. All rights reserved.
# 	This software is distributed under the Common Public License 1.0


package Log2t::input::mft;

use strict;
use Log2t::base::input; # the SUPER class or parent
#use Log2t::Numbers;	# work with numbers, round-up, etc...
#use Log2t::Network;	# some routines that deal with network information
use Log2t::BinRead;	# to work with binary files (during verification all files are treaded as such)
use Log2t::Common ':binary';
use Log2t::Time;	# for time manipulations
#use Log2t:Win;		# for few Windows related operations, GUID translations, etc..
#use Log2t:WinReg;	# to recover deleted information from registry
use Encode;
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
#	$self->{'debug'}	- (int) Indicates whether or not debug is turned on or off
#	$self->{'quick'} 	- (int) Indicates if we will like to do a quick verification
#	$self->{'tz'}		- (string) The timezone that got passed to the tool
#	$self->{'temp'}		- (string) The name of the temporary directory that can be used
#	$self->{'text'}		- (string) The path that is possible to add to the input (-m parameter) 
#	$self->{'sep'} 		- (string) The separator used (/ in Linux, \ in Windows for instance)
#


# 	init
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
	#	$self->{'new_variable'} = 'value'
	#
	# sometimes it might be good to initialize these global variables, to make sure they 
	# are not used again when parsing a new file.
	#
	# This method, init, is called by the engine before parsing any new file.  That makes
	# this method ideal to initialize or null the values of global variables if they are used.
	# This is especially cruical when recursive parsing is used, to make sure that when the next file 
	# is being parsed by the module there isn't any mix-up between files.
	$self->{'ofs'} = 0;
	$self->{'record_length'} = 1024;
	$self->{'record_number'} = 0;

	$self->{'folders'} = {};

	# build the folder structure
	$self->_build_folder_structure;

	return 1;
}


# 	get_version
# A simple subroutine that returns the version number of the format file
# There shouldn't be any need to change this routine, it serves its purpose 
# just the way it is defined right now. (so it shouldn't be changed)
#
# @return A version number
sub get_version()
{
	return $VERSION;
}

# 	get_description
# A simple subroutine that returns a string containing a description of 
# the funcionality of the format file. This string is used when a list of
# all available format files is printed out
#
# @return A string containing a description of the input module
sub get_description()
{
	# change this value so it reflects the purpose of this module
	return "Parse the content of a NTFS MFT file";
}

#	get_time
# This is the main "juice" of the input module. It parses the input file
# and produces a timestamp object that get's returned (or if we said that
# self->{'multi_line'} = 0 it will return a single hash reference that contains
# multiple timestamp objects within it.
# 
# This subroutine needs to be implemented at all times
sub get_time()
{
	my $self = shift;

	# the timestamp object
	my %t_line;
	my $text;
	my %date;
        my %si_time;
        my %fn_time;
	my ($read_ptr, $atr_record, $si_record, $fn_record, $volume_info_record, $object_id_record, $al_record );
	my $mftr;
	my ($si_text,$fn_text );
	my %info = undef;

	# get the filehandle, read the next MFT entry
	my $fh = $self->{'file'};
	seek( $fh, $self->{'ofs'},0 );
	read( $fh, $self->{'record'}, $self->{'record_length'} );

	# want to stop sometime
	return undef unless $self->{'record'};

	# increment the offset
	$self->{'ofs'} += $self->{'record_length'};
	$self->{'record_number'}++;

	$mftr = $self->_decodeMFTHeader;

	printf STDERR "[MFT] Error, bad MFT Header (0x%x)\n", $mftr->{'magic'} if ( ( $mftr->{'magic'} == 0x44414142 ) && ( $self->{'debug'} ) );
	return \%t_line if $mftr->{'magic'} == 0x44414142;
	
	printf STDERR "[MFT] Error, bad MFT Header (0x%x)\n", $mftr->{'magic'}  if ( ( $mftr->{'magic'} != 0x454C4946 ) && ( $self->{'debug'} ) );
	return \%t_line unless $mftr->{'magic'} == 0x454C4946;

	# we got a valid MFT let's continue
	$text = '';
	
	# go through the pointer
	$read_ptr = $mftr->{'attr_off'};
	while( $read_ptr < $self->{'record_length'} )
	{
		$atr_record = $self->_decodeATRHeader( substr $self->{'record'}, $read_ptr );

		# check if we need to break out (end of attributes)
		if( $atr_record->{'type'} == 0xffffffff )
		{
			$read_ptr = $self->{'record_length'} * 2;
			next;
		}

		printf STDERR "Attribute type: 0x%x Length: %d Res: 0x%x\n", $atr_record->{'type'}, $atr_record->{'len'}, $atr_record->{'res'} if $self->{'debug'};

		if ( $atr_record->{'type'} == 0x10 )                   # Standard Information
		{
			printf STDERR "Stardard Information:\n++Type: 0x%x Length: %d Resident: %s Name Len:%d Name Offset: %d\n",$atr_record->{'type'},$atr_record->{'len'},$atr_record->{'res'},$atr_record->{'nlen'},$atr_record->{'name_off'} if $self->{'debug'};


			$si_record = $self->_decodeSIAttribute( substr $self->{'record'}, $read_ptr+$atr_record->{'soff'} );
			$mftr->{'si'} = $si_record;
			printf STDERR  "++CRTime: %d\n++MTime: %d\n++ATime: %d\n++EntryTime: %d\n",$si_record->{'crtime'}, $si_record->{'mtime'}, $si_record->{'atime'},$si_record->{'ctime'} if $self->{'debug'};
		}
		elsif( $atr_record->{'type'} == 0x20 )                 # Attribute list
		{
			print STDER "Attribute list" if $self->{'debug'};

			if ( $atr_record->{'res'} == 0 )
			{
				$al_record = $self->_decodeAttributeList( substr $self->{'record'}, $read_ptr+$atr_record->{'soff'} );
				$mftr->{'al'} = $al_record;
				printf STDERR "Name: %s\n", $al_record->{'name'} if $self->{'debug'};
			}
			else
			{
				print STDERR "Non-resident Attribute List?" if $self->{'debug'};
				$mftr->{'al'} = 'None';
			}
		}
		elsif ( $atr_record->{'type'} == 0x30 )                 # File name
		{
			print STDERR "File name record\n" if $self->{'debug'};
			$fn_record = $self->_decodeFNAttribute( substr $self->{'record'}, $read_ptr+$atr_record->{'soff'} );
			$mftr->{'fn'} = $fn_record;
			$mftr->{'fncnt'} = $fn_record;
			$mftr->{'fncnt'}++;

			printf STDERR "Name: %s",$fn_record->{'name'} if $self->{'debug'};
			if ( $fn_record->{'crtime'} != 0 )
			{
				printf STDERR "\tCRTime: %s MTime: %s ATime: %s EntryTime: %s", $fn_record->{'crtime'}, $fn_record->{'mtime'}, $fn_record->{'atime'}, $fn_record->{'ctime'} if $self->{'debug'};
			}
		}
		elsif ( $atr_record->{'type'} == 0x40 )                 #  Object ID
		{
			$object_id_record = $self->_decodeObjectID( substr $self->{'record'}, $read_ptr + $atr_record->{'soff'} );
			$mftr->{'objid'} = $object_id_record;
			print STDERR "Object ID" if $self->{'debug'};
		}
		elsif ( $atr_record->{'type'} == 0x50 )                 # Security descriptor
		{
			$mftr->{'sd'} = 1;
			print STDERR "Security descriptor" if $self->{'debug'};
		}
		elsif( $atr_record->{'type'} == 0x60 )                 # Volume name
		{
			$mftr->{'volname'} = 1;
			print STDERR "Volume name" if $self->{'debug'};
		}
		elsif ($atr_record->{'type'} == 0x70 )                 # Volume information
		{
			print STDERR "Volume info attribute" if $self->{'debug'};
			$volume_info_record = $self->_decodeVolumeInfo( substr $self->{'record'}, $read_ptr + $atr_record->{'soff'} );
			$mftr->{'volinfo'} = $volume_info_record;
		}
		elsif( $atr_record->{'type'} == 0x80 )                 # Data
		{
			$mftr->{'data'} = 1;
			print STDERR "Data attribute" if $self->{'debug'};
		}
		elsif( $atr_record->{'type'} == 0x90 )                 # Index root
		{
			$mftr->{'indexroot'} = 1; 
			print STDERR "Index root" if $self->{'debug'};
		}
		elsif( $atr_record->{'type'} == 0xA0 )                 # Index allocation
		{
			$mftr->{'indexallocation'} = 1;
			print STDERR "Index allocation" if $self->{'debug'};
		}
		elsif ( $atr_record->{'type'} == 0xB0 )                 # Bitmap
		{
			$mftr->{'bitmap'} = 1;
			print STDERR "Bitmap" if $self->{'debug'};
		}
		elsif ( $atr_record->{'type'} == 0xC0 )                 # Reparse point
		{
			$mftr->{'reparsepoint'} = 1;
			print STDERR "Reparse point" if $self->{'debug'};
		}
		elsif ( $atr_record->{'type'} == 0xD0 )                 # EA Information
		{
			$mftr->{'eainfo'} = 1;
			print STDERR "EA Information" if $self->{'debug'};
		}
		elsif( $atr_record->{'type'} == 0xE0 )                 # EA
		{
			$mftr->{'ea'} = 1;
			print STDERR  "EA" if $self->{'debug'};
		}
		elsif ( $atr_record->{'type'} == 0xF0 )                 # Property set
		{
			$mftr->{'propertyset'} = 1; 
			print STDERR "Property set" if $self->{'debug'};
		}
		elsif ( $atr_record->{'type'} == 0x100 )                 # Logged utility stream
		{
			$mftr->{'loggedutility'} = 1;
			print STDERR "Logged utility stream" if $self->{'debug'};
		}
		else
		{
			print STDERR  "Found an unknown attribute" if $self->{'debug'};
		}

		print STDERR "\n" if $self->{'debug'};
	
		if ( $atr_record->{'len'} > 0 )
		{
			$read_ptr += $atr_record->{'len'};
		}
		else
		{
			print STDERR "ATRrecord->len < 0, exiting loop" if $self->{'debug'};
			$read_ptr = $self->{'record_length'} * 2;
			next;
		}
	}

	# now we complete the processing
	$info{'magic'} = $self->_decodeMFTmagic($mftr->{'magic'});
	$info{'is_active'} = $self->_decodeMFTisactive( $mftr->{'flags'} );
	$info{'rec_type'} = $self->_decodeMFTrecordtype( int( $mftr->{'flags'} ) );

	printf STDERR "[RECORD] nr: %d name: %s type: %d\n",$self->{'record_number'}-1,$fn_record->{'name'}, $info{'rec_type'} if $self->{'debug'};

#	if( $info{'rec_type'} eq 'Folder' )
#	{
#		printf STDERR "FOLDER (inode %d): %s [parent %d]\n", $self->{'record_number'}-1,$mftr->{'fn'}->{'name'},$mftr->{'fn'}->{'par_ref'} if $self->{'debug'};
#
#		# we need to populate the folder structure
#		$self->{'folders'}->{$self->{'record_number'}-1} = {
#			'parent' 	=> $mftr->{'fn'}->{'par_ref'},
#			'name'		=> $fn_record->{'name'}
#		};
#	}

	# get the filename
	$self->{'filename'} = undef;
	# traverse down the folder structure to get the path
	$self->_get_full_path( $mftr->{'fn'}->{'par_ref'} );
	# add the filename
	$self->{'filename'} .= '/' . $fn_record->{'name'};
	# remove additional slashes if there are one....
	$self->{'filename'} =~ s/\/+/\//g;

	# and add information about status of file (is deleted?)
	$self->{'filename'} .= ' (deleted)' unless $info{'is_active'};


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

	# now we need to check if some time was empty (and the second one not empty)
	my $t = '';
	$t .= ($si_record->{'mtime_empty'} and $si_record->{'mtime'}) ? 'M' : '.'; 
        $t .= ($si_record->{'atime_empty'} and $si_record->{'atime'}) ? 'A' : '.';
        $t .= ($si_record->{'ctime_empty'} and $si_record->{'ctime'}) ? 'C' : '.';
	$t .= ($si_record->{'crtime_empty'} and $si_record->{'crtime'}) ? 'B' : '.';

	$si_text = $t eq '....' ? '' : '[' . $t . ']';

	# now check the FN record
	$t = '';
	$t .= ($fn_record->{'mtime_empty'} and $fn_record->{'mtime'}) ? 'M' : '.'; 
        $t .= ($fn_record->{'atime_empty'} and $fn_record->{'atime'}) ? 'A' : '.';
        $t .= ($fn_record->{'ctime_empty'} and $fn_record->{'ctime'}) ? 'C' : '.';
	$t .= ($fn_record->{'crtime_empty'} and $fn_record->{'crtime'}) ? 'B' : '.';

	$fn_text = $t eq '....' ? '' : '[' . $t . ']';
	my $susp = 0;
	my $susp_text = '';

	# check if empty
	unless ( $fn_text eq '' and $si_text eq '' )
	{
		$susp_text .= '{SUSP ENTRY - second prec. ';
		$susp_text .= '$FN ' . $fn_text unless $fn_text eq '';
		$susp_text .= '$SI ' . $si_text unless $si_text eq '';
		$susp = 1;
	}

	# check the FN timestamp
	# 	For local file move both the modified and metadata timestamps are changed
	#	For Volume file move and File copy all timestamps are updated
	# 	For file deletion the modified time and metadata timestamps are changed
	#	For other actions the timestamp is not updated
	#
	#	=> access and creation time do not change except for "vol file move" and "file copy"
	#	So we need to look at either one of those $FN timestamps, and then find a method to detect
	# 	whether or not we have a $SI record that matches that behaviour
	#	
	#	Local File Move		-> metadata 
	#	Vol File Move		-> Access and MetaData
	#	File Copy		-> Access, Creation and Metadata
	#	
	#	-> modified stays the same
	#
	#	So we could compare $FN access or Creation to MetaData change date in $SI
	#		-> metadata always changes for each of those operations...
	#
	#	Perhaps : $FN->access > $SI->metadata
	#
	#my @d = ( $fn_record->{'mtime'},$fn_record->{'atime'},$fn_record->{'ctime'},$fn_record->{'crtime'});
	#my $fn_new = int( sprintf "%d", sort { return $b if $b == 0; $a > $b } @d );
	#@d = ( $si_record->{'mtime'},$si_record->{'atime'},$si_record->{'ctime'},$si_record->{'crtime'});
	#my $si_old = int( sprintf "%d", sort { return $b if $b == 0; $a > $b } @d);
	
	#if( $fn_new < $si_old )
	if( $fn_record->{'atime'} > $si_record->{'ctime'} )
	{
		$susp_text .= '{SUSP ENTRY -' unless $susp;
		$susp_text .= ' FN rec AFTER SI rec';
		$susp = 1;
	}

	# close the suspicious entry, if appropriate
	$susp_text .= '}' if $susp;

        # create the t_line variable
        %t_line = (
                'desc' => $text . $self->{'path'} . $self->{'filename'},
                'short' => $self->{'path'} . $self->{'filename'},
                'source' => 'FILE',
                'sourcetype' => 'NTFS $MFT',
                'version' => 2,
		'notes' => $susp_text,	# add the suspicious entry into the notes field
                'extra' => { 'inode' => $self->{'record_number'}-1, 'filename' => $self->{'filename'} } 
        );

	my $i = 0;
	# now to check the timestamps (initialize variables)
	%si_time = undef;
	%fn_time = undef;

        $si_time{$si_record->{'mtime'}} += 1;
        $si_time{$si_record->{'atime'}} += 2;
        $si_time{$si_record->{'ctime'}} += 4;
        $si_time{$si_record->{'crtime'}} += 8;

        $fn_time{$fn_record->{'mtime'}} += 1;
        $fn_time{$fn_record->{'atime'}} += 2;
        $fn_time{$fn_record->{'ctime'}} += 4;
        $fn_time{$fn_record->{'crtime'}} += 8;
     
        # and now to include the timestamps
        foreach( keys %si_time )
        {   
                my $t = ''; 
                $t .= ( $si_time{$_} & 0x01 ) ? 'M' : '.';
                $t .= ( $si_time{$_} & 0x02 ) ? 'A' : '.';
                $t .= ( $si_time{$_} & 0x04 ) ? 'C' : '.';
                $t .= ( $si_time{$_} & 0x08 ) ? 'B' : '.';

                $t_line{'time'}->{$i++} = { 
                        'value' => $_, 
                        'type' => '$SI [' . $t . '] time',
                        'legacy' => $si_time{$_}
                };  
        }   

        # and now to include the timestamp (if we want to)
	if( $self->{'detailed_time'} )
	{
        	foreach( keys %fn_time )
        	{   
        	        my $t = ''; 
        	        $t .= ( $fn_time{$_} & 0x01 ) ? 'M' : '.';
        	        $t .= ( $fn_time{$_} & 0x02 ) ? 'A' : '.';
        	        $t .= ( $fn_time{$_} & 0x04 ) ? 'C' : '.';
        	        $t .= ( $fn_time{$_} & 0x08 ) ? 'B' : '.';
	
	                $t_line{'time'}->{$i++} = { 
	                        'value' => $_, 
	                        'type' => '$FN [' . $t . '] time',
	                        'legacy' => $fn_time{$_}
	                };  
		}
	}

	return \%t_line;
}

#	get_help
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
	return "This parser parses the log file X and it might be found on location Y.";
}

sub _build_folder_structure
{
	my $self = shift;

	# get the filehandle
	my $fh = $self->{'file'};
	my $rec_nr = 0;
	my $ofs = 0;
	$self->{'record'} = 1;	 # the initial one
	my $mftr;
	my $read_ptr;
	my ($fn_record,$atr_record);

	# read through the entire MFT
	while ( $self->{'record'} )
	{
		# get the next record
		seek( $fh, $ofs, 0 );
		read( $fh, $self->{'record'}, $self->{'record_length'} );

		# increment the record number
		$rec_nr++;

		# increment the offset
		$ofs += $self->{'record_length'};

		# want to stop sometime
		next unless $self->{'record'};

		$mftr = $self->_decodeMFTHeader;

		next if $mftr->{'magic'} == 0x44414142;
		next unless $mftr->{'magic'} == 0x454C4946;

		# we got a valid MFT let's continue
	
		# go through the pointer
		$read_ptr = $mftr->{'attr_off'};
		while( $read_ptr < $self->{'record_length'} )
		{
			$atr_record = $self->_decodeATRHeader( substr $self->{'record'}, $read_ptr );

			# check if we need to break out (end of attributes)
			if( $atr_record->{'type'} == 0xffffffff )
			{
				$read_ptr = $self->{'record_length'} * 2;
				next;
			}
			elsif ( $atr_record->{'type'} == 0x30 )                 # File name
			{
				$fn_record = $self->_decodeFNAttribute( substr $self->{'record'}, $read_ptr+$atr_record->{'soff'} );
				$mftr->{'fn'}->{$mftr->{'fncnt'}++} = $fn_record;
			}

                	if ( $atr_record->{'len'} > 0 )
                	{    
                	        $read_ptr += $atr_record->{'len'};
                	}    
                	else 
                	{    
                	        print STDERR "ATRrecord->len < 0, exiting loop" if $self->{'debug'};
                	        $read_ptr = $self->{'record_length'} * 2; 
                	        next;
                	}   
		}

		# we've read the information we need... now check if we have a folder
		next unless $self->_decodeMFTrecordtype( int( $mftr->{'flags'} ) ) eq 'Folder';

		printf STDERR "BUILDING FOLDER [%s] FOR RECORD %d (parent %d)\n", $fn_record->{'name'},$rec_nr-1,$fn_record->{'par_ref'} if $self->{'debug'};

		# we need to populate the folder structure
		$self->{'folders'}->{$rec_nr-1} = {
			'parent' 	=> $fn_record->{'par_ref'},
			'name'		=> $fn_record->{'name'}
		};

	}
	
	
	seek( $fh, 0, 0 );	# rewind the file

	return 1;
}

sub _get_full_path
{
	my $self = shift;
	my $parent = shift;
	my $n = '';

	if ( $parent == 0 or $parent == 5 )
	{
		$self->{'filename'} = '/' . $self->{'filename'};
		return 1;
	}

	# not the end, so add to the filename
	$n = $self->{'folders'}->{$parent}->{'name'} . '/' . $self->{'filename'};
	$self->{'filename'} = $n;

	# and call the subroutine again
	$self->_get_full_path( $self->{'folders'}->{$parent}->{'parent'} );

	return 1;

}

#####################################################################################################
#		begin subroutines converted from analyzeMFT
#---------------------------------------------------------------------------------------------------#
# This section contains an almost direct convertion from Python to Perl of the tool analyzeMFT 
# written by David Kovar (http://www.integriography.com/)
#	- some code has been changed to integrate into l2t
# 
# This is done with his consent and with great gratitude
sub _decodeMFTmagic
{
	my $self = shift;
	my $s = shift;
	
	return "Good" if $s == 0x454c4946;
	return "Bad" if $s == 0x44414142;
	return "Zero" if $s == 0x00000000;

	# we get here if the value is different
        return 'Unknown';

}

sub _decodeMFTisactive
{
	my $self = shift;
	my $s = shift;
	
	return 1 if $s & 0x0001;

        return 0;
}

sub _decodeMFTrecordtype
{
	my $self = shift;
	my $s = shift;
	my $tmp_buffer;

	if ( $s & 0x0002 )
	{
		$tmp_buffer = 'Folder' 
	}
	else
	{
		$tmp_buffer = 'File'
	}

	$tmp_buffer = sprintf "%s %s",$tmp_buffer, '+ Unknown1' if $s & 0x0004;
     	$tmp_buffer = sprintf "%s %s",$tmp_buffer, '+ Unknown2' if $s & 0x0008;
	
	return $tmp_buffer;
}

sub _decodeMFTHeader
{
	my $i = 0;	
	my $self = shift;
	my %d = undef;

	$d{'magic'} = unpack( "I", substr $self->{'record'}, 0, 4 );
	$d{'udp_off'} = unpack( "S", substr $self->{'record'}, 4, 2 );
	$d{'udp_cnt'} = unpack( "S", substr $self->{'record'}, 6, 2 );
	$d{'lsn'} = unpack( "d*", substr $self->{'record'}, 8, 8 );
	$d{'seq'} = unpack( "S", substr $self->{'record'}, 16, 2 );
	$d{'link'} = unpack( "S", substr $self->{'record'}, 18, 2 );
	$d{'attr_off'} = unpack( "S", substr $self->{'record'}, 20, 2 );
	$d{'flags'} = unpack( "S", substr $self->{'record'}, 22, 2 );
	$d{'size'} = unpack( "I", substr $self->{'record'}, 24, 4 );
	$d{'alloc_size'} = unpack( "I", substr $self->{'record'}, 28, 4 );
	$d{'base_ref'} = unpack( "Lx*", substr $self->{'record'}, 32, 6 );
	$d{'base_seq'} = unpack( "S", substr $self->{'record'}, 38, 2 );
	$d{'next_attrid'} = unpack( "S", substr $self->{'record'}, 40, 2 );
	$d{'f1'} = substr $self->{'record'},42,2;
	$d{'entry'} = substr $self->{'record'},44,4;
    	$d{'fncnt'} = 0;                              # Counter for number of FN attributes

	return \%d;
}

sub _decodeATRHeader
{
	my $self = shift;
	my $s = shift;
	my %d;
		
	$d{'type'} = unpack( "L", substr $s, 0, 4 );
	
	return \%d if( $d{'type'} == 0xffffffff );

	$d{'len'} = unpack( "V", substr $s, 4, 4 );
	$d{'res'} = unpack( "C", substr $s, 8, 1 );
	$d{'nlen'} = unpack( "C", substr $s, 9,1 );
	$d{'name_off'} = unpack( "S", substr $s, 10,2);
	$d{'flags'} = unpack( "S", substr $s, 12,2);
	$d{'id'} = unpack( "S", substr $s, 14,2);
	
	if( $d{'res'} == 0 )
	{
		$d{'ssize'} = unpack( "L", substr $s, 16,4 );
		$d{'soff'} = unpack( "S", substr $s, 20, 2);
		$d{'idxflag'} = unpack( "S", substr $s, 22, 2);
	}
	else
	{
		$d{'start_vcn'} = unpack( "d*", substr $s, 16,8 );
		$d{'last_vcn'} = unpack( "d*", substr $s, 24, 8 );
		$d{'run_off'} = unpack( "S", substr $s, 32, 2 );
		$d{'compusize'} = unpack ( "S", substr $s, 34, 2 );
		$d{'f1'} = unpack ( "I", substr $s, 36, 4 );
		$d{'alen'} = unpack( "d*", substr $s, 40, 8 );
		$d{'ssize'} = unpack( "d*", substr $s, 48, 8 );
		$d{'initsize'} = unpack( "d*", substr $s, 56, 8 );
	}

	return \%d;
}

sub _decodeSIAttribute
{
	my $self = shift;
	my $s = shift;
	my %d = undef;

	# read the variable
	$d{'crtime'} = Log2t::Time::Win2Unix( unpack( "V", substr $s, 0, 4 ), unpack( "V", substr $s, 4, 4 ) );
	$d{'mtime'} = Log2t::Time::Win2Unix( unpack( "V", substr $s, 8, 4 ), unpack( "V", substr $s, 12, 4 ) );
	$d{'ctime'} = Log2t::Time::Win2Unix( unpack( "V", substr $s, 16, 4 ), unpack( "V", substr $s, 20, 4 ) );
	$d{'atime'} = Log2t::Time::Win2Unix( unpack( "V", substr $s, 24, 4 ), unpack( "V", substr $s, 28, 4 ) );
	$d{'dos'} = unpack( "I", substr $s, 32, 4 );
	$d{'maxver'} = unpack( "I", substr $s, 36, 4 );
	$d{'ver'} = unpack( "I", substr $s, 40, 4 );
	$d{'class_id'} = unpack( "I", substr $s, 44, 4 );
	$d{'own_id'} = unpack( "I", substr $s, 48, 4 );
	$d{'sec_id'} = unpack( "I", substr $s, 52, 4 );
	$d{'quota'} = unpack( "d*", substr $s, 56, 8 );
	$d{'usn'} = unpack( "d*", substr $s, 64, 8 );

	# check if we see empty nanoseconds
	$d{'crtime_empty'} = Log2t::Time::getNanoWinFileTime( unpack( "V", substr $s, 0, 4 ), unpack( "V", substr $s, 4, 4 ) ) == 0 ? 1 : 0;
	$d{'mtime_empty'} = Log2t::Time::getNanoWinFileTime( unpack( "V", substr $s, 8, 4 ), unpack( "V", substr $s, 12, 4 ) ) == 0 ? 1 : 0;
	$d{'ctime_empty'} = Log2t::Time::getNanoWinFileTime( unpack( "V", substr $s, 16, 4 ), unpack( "V", substr $s, 20, 4 ) ) == 0 ? 1 : 0;
	$d{'atime_empty'} = Log2t::Time::getNanoWinFileTime( unpack( "V", substr $s, 24, 4 ), unpack( "V", substr $s, 28, 4 ) ) == 0 ? 1 : 0;

	return \%d;
}

sub _decodeFNAttribute
{
	my $self = shift;
	my $s = shift;
	my %d = undef;

	# read the variable
	$d{'par_ref'} = unpack( "Lxx", substr $s, 0,6 );
	$d{'par_seq'} = unpack( "S", substr $s,6,2);
	$d{'crtime'} = Log2t::Time::Win2Unix( unpack( "L", substr $s, 8, 4 ), unpack( "L", substr $s, 12, 4 ) );
	$d{'mtime'} = Log2t::Time::Win2Unix( unpack( "L", substr $s, 16, 4 ), unpack( "L", substr $s, 20, 4 ) );
	$d{'ctime'} = Log2t::Time::Win2Unix( unpack( "L", substr $s, 24, 4 ), unpack( "L", substr $s, 28, 4 ) );
	$d{'atime'} = Log2t::Time::Win2Unix( unpack( "L", substr $s, 32, 4 ), unpack( "L", substr $s, 36, 4 ) );
	$d{'alloc_fsize'} = unpack( "d*", substr $s, 40, 8 );
	$d{'real_fsize'} = unpack( "d*", substr $s, 48, 8 );
	$d{'flags'} = unpack( "d*", substr $s, 56, 8 );
	$d{'nlen'} = unpack( "C", substr $s, 64, 1 );
	$d{'nspace'} = unpack( "C", substr $s, 65, 1 );


	# read the name
	for( my $i = 0; $i < $d{'nlen'}*2; $i+=2 )
	{
		#$d{'name'} .= encode('iso8859-1', substr $s, 66+$i,2);
		$d{'name'} .= encode('utf-8', substr $s, 66+$i,2);
		#$d{'name'} .=  unpack( "U*", substr $s, 66+$i,2);
#		$d{'name'} .=  substr $s, 66+$i,2;
	}

	$d{'name'} =~ s/\00//g;
	$d{'name'} =~ s/[[:cntrl:]]//g;

#	printf STDERR "NAME: %s\n\n", $d{'name'};

	# check the CR time
	$d{'crtime'} = $d{'ctime'} if( $d{'crtime'} == 0 );

	# check for empty upper half of timestamps (second precision)
	$d{'crtime_empty'} = unpack( "V", substr $s,12,4) == 0 ? 1 : 0;
	$d{'mtime_empty'} = unpack( "V", substr $s,20,4) == 0 ? 1 : 0;
	$d{'ctime_empty'} = unpack( "V", substr $s,28,4) == 0 ? 1 : 0;
	$d{'atime_empty'} =  unpack( "V", substr $s,36,4) == 0 ? 1 : 0;

	return \%d;
}

sub _decodeAttributeList
{
	my $self = shift;
	my $s = shift;

	my %d = undef;

	$d{'type'} = unpack( "I", substr $s, 0,4 );
	$d{'len'} = unpack( "S", substr $s, 4, 2 );
	$d{'nlen'} = unpack( "C", substr $s, 6, 1 );
	$d{'f1'} = unpack( "C", substr $s, 7, 1 );
	$d{'start_vcn'} = unpack( "d*", substr $s, 8, 8 );
	$d{'file_ref'} = unpack( "Lxx", substr $s, 16, 6 );
	$d{'seq'} = unpack( "S", substr $s, 22, 2 );
	$d{'id'} = unpack( "S", substr $s, 24, 2 );

	# read the name
	for( my $i = 0; $i < $d{'nlen'} * 2; $i+=2 )
	{
		$d{'name'} .= encode( 'utf-8', substr $s, 26+$i,2 );
	}
	$d{'name'} =~ s/[[:cntrl:]]//g;
	$d{'name'} =~ s/\00//g;
	
	return \%d;
}

sub _decodeVolumeInfo
{
	my $self = shift;
	my $s = shift;
	my %d = undef;

	$d{'f1'} = unpack( "d*", substr $s, 0, 8 );
	$d{'maj_ver'} = unpack( "C", substr $s, 8, 1 );
	$d{'min_ver'} = unpack( "C", substr $s, 9, 1 );
	$d{'flags'} = unpack( "S", substr $s, 10, 2 );
	$d{'f2'} = unpack( "I", substr $s, 12, 4 );

	if( $self->{'debug'} )
	{
        	print STDERR "+Volume Info\n";
        	print STDERR "++F1%d\n",$d{'f1'};
        	print STDERR "++Major Version: %d\n", $d{'maj_ver'}; 
        	print STDERR "++Minor Version: %d\n", $d{'min_ver'};
        	print STDERR "++Flags: %d\n", $d{'flags'};
        	print STDERR "++F2: %d\n", $d{'f2'};
	}

	return \%d;
}

sub _decodeObjectID
{
	my $self = shift;
	my $s = shift;
	my %d = undef;

	$d{'objid'} = _createObjectID( substr $s, 0, 16 );
	$d{'orig_volid'} = _createObjectID( substr $s, 16, 16 );
	$d{'orig_objid'} = _createObjectID( substr $s, 32, 16 );
	$d{'orig_domid'} = _createObjectID( substr $s, 48, 16 );

	return \%d;
}

sub _createObjectID
{
	my $s = shift;

	return sprintf "%x-%s-%s-%s-%s\n",(substr $s, 0,4),(substr $s, 4, 2 ), (substr $s, 6, 2 ), (substr $s, 8, 2), substr( $s, 10, 6 );
}



#---------------------------------------------------------------------------------------------------#
#			end of AnalyzeMFT subroutines
#####################################################################################################


#	verify
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
#	success		-> INT, either 0 or 1 (meaning not the correct structure, or the correct one)
#	msg		-> A short description why the verification failed (if the value of success
#			is zero that is).
sub verify
{
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

        # start by setting the endian correctly
        Log2t::BinRead::set_endian( LITTLE_E );

	my $ofs = 0;
	
	# now we try to read from the file
	eval
	{
		# a firewall log file should start with a comment, or #, let's verify that
		$line = Log2t::BinRead::read_ascii( $self->{'file'}, \$ofs, 5 );

		unless ( $line eq 'FILE0' )
		{
			$return{'msg'} = 'Wrong magic value';
			$return{'success'} = 0;
			return \%return;
		}
		
		$return{'success'} = 1;
	};
	if ( $@ )
	{
		$return{'success'} = 0;
		$return{'msg'} = "Unable to process file ($@)";

		return \%return;
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

