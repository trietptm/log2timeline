#################################################################################################
#		WIN_LINK
#################################################################################################
# this script reads a Windows shortcut file (lnk) and produces a bodyfile containing the 
# timeline information found inside it.  The timeline information can be used directly with 
# the script mactime from TSK collection (or with any other outplug plugin that exists within
# the log2timeline framework)
#
# The structure of a Windows LNK file has been reversed engineered by Jesse Hager, a document
# that was used to fix and create this parser
# 	http://www.i2s-lab.com/Papers/The_Windows_Shortcut_File_Format.pdf
# 
# Since H. Carvey already created a Perl script to parse shortcut files there was no need
# to re-create it.  So this script is more or less using the script lslnk.pl, originally
# written by H.Carvey
#
# Author: Kristinn Gudjonsson
# Version : 0.7
# Date : 31/03/11
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
# Information from lslnk.pl script that has most of the code for this
# format file.  Some functions have been changed from the original script
# to fix problems with it, as well as adding others to read the LNK file 
# more accurately
#---------------------------------------------------------------------
# lslnk.pl
# Perl script to parse a shortcut (LNK) file and retrieve data
#
# ...
#
# This script is intended to be used against LNK files extracted from 
# from an image, or for LNK files located on a system
#
# copyright 2006-2007 H. Carvey, keydet89@yahoo.com
#---------------------------------------------------------------------
package Log2t::input::win_link;

use strict;

use Encode;
# load log2timeline libraries
use Log2t::Time;
use Log2t::base::input; # the SUPER class or parent

use vars qw($VERSION @ISA);

# inherit the base input module, or the super class.
@ISA = ( "Log2t::base::input" );

# version number
$VERSION = '0.7';

# strings
my %flags; 
my %fileattr;
my %showwnd;
my %vol_type;

#       get_description
# A simple subroutine that returns a string containing a description of 
# the funcionality of the format file. This string is used when a list of
# all available format files is printed out
#
# @return A string containing a description of the format file's functionality
sub get_description()
{
	return "Parse the content of a Windows shortcut file (or a link file)"; 
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



# the constructor
sub new()
{
        my $class = shift;

        # bless the class ;)
        my $self = $class->SUPER::new();

	# indicate this is a binary file
        $self->{'multi_line'} = 0;

	# variable for encoding
	$self->{'encoding'} = 'UTF-8';

	bless($self,$class);

	# begin with original description from H. Carvey
#	%flags = (0x01 => "Shell Item ID List exists",
#	           0x02 => "Shortcut points to a file or directory",
#	           0x04 => "The shortcut has a descriptive string",
#	           0x08 => "The shortcut has a relative path string",
#	           0x10 => "The shortcut has working directory",
#	           0x20 => "The shortcut has command line arguments",
#	           0x40 => "The shortcut has a custom icon");
#
#	%fileattr = (0x01 => "Target is read only",
#                0x02 => "Target is hidden",
#                0x04 => "Target is a system file",
#                0x08 => "Target is a volume label",
#                0x10 => "Target is a directory",
#                0x20 => "Target was modified since last backup",
#                0x40 => "Target is encrypted",
#                0x80 => "Target is normal",
#                0x100 => "Target is temporary",
#                0x200 => "Target is a sparse file",
#                0x400 => "Target has a reparse point",
#                0x800 => "Target is compressed",
#                0x1000 => "Target is offline");
#
#	%showwnd = (0 => "SW_HIDE",
#               1 => "SW_NORMAL",
#               2 => "SW_SHOWMINIMIZED",
#               3 => "SW_SHOWMAXIMIZED",
#               4 => "SW_SHOWNOACTIVE",
#               5 => "SW_SHOW",
#               6 => "SW_MINIMIZE",
#               7 => "SW_SHOWMINNOACTIVE",
#               8 => "SW_SHOWNA",
#               9 => "SW_RESTORE",
#               10 => "SHOWDEFAULT");
#
#	%vol_type = (0 => "Unknown",
#                1 => "No root directory",
#                2 => "Removable",
#                3 => "Fixed",
#                4 => "Remote",
#                5 => "CD-ROM",
#                6 => "Ram drive");

	# and now move to the abbreviated version (to fit in one line)
	%flags = (0x01 => "SI ID exists",
	           0x02 => "points to a file or dir",
	           0x04 => "a descr. str",
	           0x08 => "a rel. path str",
	           0x10 => "working dir.",
	           0x20 => "cmd line args",
	           0x40 => "custom icon");

	%fileattr = (0x01 => "read only",
                0x02 => "hidden",
                0x04 => "system file",
                0x08 => "volume label",
                0x10 => "directory",
                0x20 => "mod since last backup",
                0x40 => "encrypted",
                0x80 => "normal",
                0x100 => "temporary",
                0x200 => "sparse file",
                0x400 => "has a reparse point",
                0x800 => "compressed",
                0x1000 => "is offline");

	%showwnd = (0 => "SW_HIDE",
               1 => "SW_NORMAL",
               2 => "SW_SHOWMINIMIZED",
               3 => "SW_SHOWMAXIMIZED",
               4 => "SW_SHOWNOACTIVE",
               5 => "SW_SHOW",
               6 => "SW_MINIMIZE",
               7 => "SW_SHOWMINNOACTIVE",
               8 => "SW_SHOWNA",
               9 => "SW_RESTORE",
               10 => "SHOWDEFAULT");

	%vol_type = (0 => "Unknown",
                1 => "No root directory",
                2 => "Removable",
                3 => "Fixed",
                4 => "Remote",
                5 => "CD-ROM",
                6 => "Ram drive");

	return $self;
}

#       get_time
# This is the main "juice" of the format file.  It takes care of parsing the actual
# shortcut file (LNK) creates a single line to return to the main script.
#
# This subroutine consists mostly of the code from lslnk.pl from H. Carvey
#
# @param A string (does not matter what's contained, since it is not used) 
# @return Returns a array containing the needed values to print a body file

sub get_time()
{
	my $self = shift;

	# the timestamp object
	my %t_line;
	my %container;
	my $flag = '';
	my $attr = '';
	my $show = '';
	my $loc = 'stored in a unknown location';
	my $path = '';
	my $extra = '';
	my $text;
	my $line;
	my %ret;
	my $fh = $self->{'file'};

	print STDERR "[WIN_LNK] Starting to read time.\n" if $self->{'debug'};

	# get some information about the file itself
	my ($inode,$size,$atime,$mtime,$ctime) = (stat(${$self->{'name'}}))[1,7,8,9,10];

	# Setup some variables 
	my $record;
	my %hdr;
	my $ofs = 0;

	# Get info about the file

	# Open file in binary mode
	seek($fh,$ofs,0);
	read($fh,$record,0x4c);
	if (unpack("Vx72",$record) == 0x4c) {
		%hdr = _parseHeader($record);
		# fetch summary info from header
		foreach my $i (keys %flags) {
			if ($hdr{flags} & $i)
			{
				if( $flag eq '' )
				{
					$flag = $flags{$i};
				}
				else
			{
					$flag = $flag . ',' . $flags{$i};
				}
			}
		}
		if (scalar keys %fileattr > 0) {
			foreach my $i (keys %fileattr) {
				if ($hdr{attr} & $i)
				{
					if( $attr eq '' )
					{
						$attr = $fileattr{$i};
					} else {
						$attr = $attr . ',' .  $fileattr{$i};
					}
				}
			}
		}
		foreach my $i (keys %showwnd) {
			if ($hdr{showwnd} & $i)
			{
				if( $show eq '' )
				{
					$show = $showwnd{$i};
				} else {
					$show = $show . ',' . $showwnd{$i};
				}
			} 
		}
		
		$ofs += 0x4c;
		# Check to see if Shell Item ID List exists.  If so, get the length
		# and skip it.	
		if ($hdr{flags} & 0x01) {
			#		print "Shell Item ID List exists.\n";
			seek($fh,$ofs,0);
			read($fh,$record,2);
			# Note: add 2 to the offset as the Shell Item ID list length is not included in the
			#       structure itself
			$ofs += unpack("v",$record) + 2;
		}
	
		# Check File Location Info
		if ($hdr{flags} & 0x02) {
			seek($fh,$ofs,0);
			read($fh,$record,4);
			my $l = unpack("V",$record);
			if ($l > 0) {
				seek($fh,$ofs,0);
				read($fh,$record,0x1c);
				my %li = _fileLocInfo($record);
				
				if ($li{flags} & 0x1) {
					# Get the local volume table
					my %lvt = _localVolTable($ofs + $li{vol_ofs}, $fh);
					# modifications made by Kristinn
					if( $lvt{name} eq 0x00 )
					{
						$loc = 'stored on a local vol (' . $lvt{name} . ') type ' . $vol_type{$lvt{type}} . ', SN ' . sprintf "0x%x",$lvt{vol_sn};
					} 
					else
					{
						$loc = 'stored on a local vol type - ' . $vol_type{$lvt{type}} . ', SN ' . sprintf "0x%x",$lvt{vol_sn};
					}
					#$loc = 'stored on a local vol (' . $lvt{name} . ') type ' . $vol_type{$lvt{type}} . ', SN ' . $lvt{vol_sn};
					#$loc = 'stored on a local vol (' . $lvt{name} . ') type ' . $vol_type{$lvt{type}} . ', SN 0x' . unpack ( 'H*', $lvt{vol_sn});
					#printf "Volume SN   = 0x%x\n",$lvt{vol_sn};
				}
			
				if ($li{flags} & 0x2) {
					# Get the network volume table				
					my %nvt = _netVolTable($ofs + $li{network_ofs}, $fh);
					if( $nvt{name} eq 0x00 )
					{
						$loc = 'stored on a net. share. ';
					}
					else
					{
						$line = $nvt{name};
						$line =~ s/\00//g;

						$loc = 'stored on a net. share: ' . $line;
					}
				} 
				if ($li{base_ofs} > 0) {
					$path = _getBasePathName($ofs + $li{base_ofs}, $li{len}+$ofs, $fh );

					# increment the offset (read the name part)
					$ofs = $ofs + $li{len};

					# check to see if there are extra strings
					if( $hdr{flags} & 0x04 )
					{
						# there is a description flag set
						%ret = _getString( $ofs, $fh );
						$ofs = $ret{ofs};
	
						$extra .= 'Desc: ' . $ret{line} . ' ';
					}
					if( $hdr{flags} & 0x08 )
					{
						# there is a relative path string
						%ret = _getString( $ofs, $fh );
						$ofs = $ret{ofs};

						$extra .= 'Rel path: ' . $ret{line} . ' ';
					}
					if( $hdr{flags} & 0x10 )
					{
						# there is a working directory
						%ret = _getString( $ofs, $fh );
						$ofs = $ret{ofs};

						$extra .= 'Working dir: ' . $ret{line} . ' ';
					}
					if( $hdr{flags} & 0x20 )
					{
						# there are some cmd line arguments
						%ret = _getString( $ofs, $fh );
						$ofs = $ret{ofs};

						$extra .= 'CMD arg: ' . $ret{line} . ' ';
					}

				}
			}
		
		}
		else
		{
			$path = "Shortcut file does not point to a file";
		} 	

	}
	else {
		print STDERR "[WIN_LNK] " . ${$self->{'name'}} . " does not have a valid shortcut header.\n";
		return \%t_line;
	}

	$text = encode( $self->{'encoding'}, $path ) . ' <-' . ${$self->{'name'}} . ', which is ' . encode( $self->{'encoding'}, $loc ). ' - ' . $extra . ' [' . $flag . '] - ' . $attr; 
	#$text = '[LNK] ' . $file  . ' points to {' . encode( $self->{'encoding'}, $path ) . '}, which is ' . encode( $self->{'encoding'}, $loc ). ' - ' . $extra . ' [' . $flag . '] - ' . $attr; 
	#$text = '[LNK] ' . $file . ' points to {' . $path . '}, which is ' . $loc . ' [' . $flag . '] - ' . $attr . ' - ' . $show; 
	
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
                'time' => { 
			0 => { 'value' => $hdr{atime}, 'type' => 'Access', 'legacy' => 2 },
			1 => { 'value' => $hdr{mtime}, 'type' => 'Modified', 'legacy' => 1 },
			2 => { 'value' => $hdr{ctime}, 'type' => 'Created', 'legacy' => 12 },
		},
                'desc' => $text,
                'short' => encode( $self->{'encoding'}, $path ),
                'source' => 'LNK',
                'sourcetype' => 'Shortcut LNK',
                'version' => 2,
                'extra' => { 'inode' => $inode, 'size' => $size  }
        );

	$container{1} = \%t_line;

	return \%container;
}

#       get_help
# A simple subroutine that returns a string containing the help 
# message for this particular format file.
# @return A string containing a help file for this format file
sub get_help()
{
	return "This format file parses the content of a Windows shortcut file (LNK) 
and produces a single line (body file).

This code is build originally using code from H. Carvey (lslnk.pl) but has since then been
modified to correct errors and add additional context 

This format file accepts the following parameters 
	--host HOST
	-u|--user USERNAME\n";

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
	my $temp;

	my $self = shift;
	my $fh = $self->{'file'};

	return \%return unless -f ${$self->{'name'}};

	# default values
	$return{'success'} = 1;		# start by assumming we have a link file
	$return{'msg'} = 'success';
	
	my %magic = (
		'0'	=> 76,
		'2'	=> 0,
		'4'	=> 5121,
		'6'	=> 2,
		'8'	=> 0,
		'10'	=> 0,
		'12'	=> 192
	);
	my $ofs;

	# open the file (at least try to open it)
	eval
	{
		for( $ofs = 0; $ofs < 13; $ofs+=2 )
		{
			next unless $return{'success'};

			seek($fh,$ofs,0);
			read($fh,$temp,2);

			$return{'success'} = 0 if unpack("v",$temp) ne $magic{$ofs};
		}

		if( ! $return{'success'} )
		{
			$return{'msg'} = "Wrong magic value in file.  Is this really a shortcut (LNK) file?\n";
		}

	};
	if ( $@ )
	{
		$return{'success'} = 0;
		$return{'msg'} = "Unable to open file";
	}

	return \%return;
}

# a function that reads a Unicode string from the shortcut,
# examples of such a string are:
# 	description string
#	relative path string
#	working directory
#	command line string
sub _getString {
	my $ofs = shift;
	my $fh = shift;
	my $data;
	my @char;
	my $line;
	my %return;

	my $length;
	my $i;

	# read the total length of string
	seek($fh,$ofs,0);
	read($fh,$data,2);
	$length = unpack( "v", $data );
	# increment the offset (since the length has been read)
	$ofs = $ofs+2;

	# get the returning offset
	$return{ofs} = $ofs + 2*$length;

	# read the entire name
	for( $i=$ofs; $i < $length*2+$ofs; $i=$i+2 )
	{
		seek($fh,$i,0);
		read($fh,$data,2);
		push(@char,$data);
	}

	# fix the end line, remove control characters, etc.
	$line = join('',@char);
	$line =~ s/\00//g;
	$line =~ s/\n/  /g;
	$line =~ s/[[:cntrl:]]/ /g;;

	$return{line} =  $line;
	
	return %return;
	
}

# originally a function from H. Carvey, but modified to read ASCII strings,
# since the name is in ASCII, not Unicode, and adding a length variable instead
# of just blindly read to the end (and removing control characters from name)
sub _getBasePathName {
	my $ofs = shift;
	my $end_ofs = shift;
	my $fh = shift;
	my $data;
	my @char;
	my $line;

	# the path name is an ASCII name 
	while( $ofs < $end_ofs ) {
		seek($fh,$ofs,0);
		read($fh,$data,1);

		$ofs = $end_ofs if $data eq "\0";
		
		next unless $ofs ne $end_ofs;
		push(@char,$data);
		$ofs ++;
	}

	# fix the end line, remove control characters, etc.
	$line = join('',@char);
	$line =~ s/\00//g;
	$line =~ s/\n/  /g;
	$line =~ s/[[:cntrl:]]/ /g;;

	return $line;
}

# the following subroutines are all taken from lslnk.pl from H. Carvey
# the only modifications are references to getTime (except for the getBasePathName function
# that was modified considerably)

sub _parseHeader {
	my $data = shift;
	my %hdr;
	my @hd = unpack("Vx16V12x8",$data);
	$hdr{id}       = $hd[0];
	$hdr{flags}    = $hd[1];
	$hdr{attr}     = $hd[2];
	$hdr{ctime}    = Log2t::Time::Win2Unix($hd[3],$hd[4]);
	$hdr{atime}    = Log2t::Time::Win2Unix($hd[5],$hd[6]);
	$hdr{mtime}    = Log2t::Time::Win2Unix($hd[7],$hd[8]);
	$hdr{length}   = $hd[9];
	$hdr{icon_num} = $hd[10];
	$hdr{showwnd}  = $hd[11];
	$hdr{hotkey}   = $hd[12];
	undef @hd;
	return %hdr;
}

sub _fileLocInfo {
	my $data = $_[0];
	my %fl;
	($fl{len},$fl{ptr},$fl{flags},$fl{vol_ofs},$fl{base_ofs},$fl{network_ofs},
	 $fl{path_ofs}) = unpack("V7",$data);
	return %fl;
}

sub _localVolTable {
	my $offset = shift;
	my $fh = shift;
	my $data;
	my %lv;
	seek($fh,$offset,0);
	read($fh,$data,0x10);
	($lv{len},$lv{type},$lv{vol_sn},$lv{ofs}) = unpack("V4",$data);
	seek($fh,$offset + $lv{ofs},0);
	read($fh,$data, $lv{len} - 0x10);
	$lv{name} = $data;
	return %lv;
}


sub _netVolTable {
	my $offset = shift;
	my $fh = shift;
	my $data;
	my %nv;
	seek($fh,$offset,0);
	read($fh,$data,0x14);
	($nv{len},$nv{ofs}) = unpack("Vx4Vx8",$data);
#	printf "Length of the network volume table = 0x%x\n",$nv{len};
#	printf "Offset to the network share name   = 0x%x\n",$nv{ofs};
	seek($fh,$offset + $nv{ofs},0);
	read($fh,$data, $nv{len} - 0x14);
	$nv{name} = $data;
	return %nv;
}

1;
