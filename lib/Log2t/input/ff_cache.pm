#!/usr/bin/perl
# ff_cache
# this script handles Firefox Cache entries and is a part of the log2timeline program.
# 
# Author: John Ritchie
# Version : 0.2
# Date : 2011-11-17
#
#  Distributed with and under the same licensing terms as log2timeline
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

package Log2t::input::ff_cache;

use strict;
use Log2t::base::input; # the SUPER class or parent
#use Log2t::Numbers;	# work with numbers, round-up, etc...
use Log2t::BinRead;	# to work with binary files (during verification all files are treaded as such)
use Log2t::Common ':binary';
use vars qw($VERSION @ISA);

# inherit the base input module, or the super class.
@ISA = ( "Log2t::base::input" );

# version number
$VERSION = '0.2';


#  These are hard-coded sanity checks against valid Mozilla version numbers from the cache headers
#    These will need to be changed when Mozilla changes version numbers
#   FF>=4.0 uses 19 as version.minor as of 2011. Set to 30 to give some breathing space. Don't want to
#    set this too flexible or sanity checks may produce false positives.

my $version_major_sanity = 1;
my $version_minor_sanity = 30;


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


#	new
# this is the constructor for the subroutine.  
#
# If this input module uses all of the default values and does not need to define any new value, it is best to 
# skip implementing it altogether (just remove it), since we are inheriting this subroutine from the SUPER
# class
sub new()
{
	my $class = shift;

	# now we call the SUPER class's new function, since we are inheriting all the 
	# functions from the SUPER class (input.pm), we start by inheriting it's calls
	# and if we would like to overwrite some of its subroutines we can do that, otherwise
	# we don't need to include that subroutine
        my $self = $class->SUPER::new();

	# indicate that this is a text based file, with one line per call to get_time
	#	This option determines the behaviour of the engine. If this variable is set
	# 	to 0 it means that we return a single hash that contains multiple timstamp objects
	#	Setting it to 1 means that we return a single timesetamp object for each line that
	# 	contains a timestamp in the file.
	# 	
	# 	So if this is a traditional log file, it is usually better to leave this as 1 and 
	# 	process one line at a time.  Otherwise the tool might use too much memory and become
	#	slow (storing all the lines in a large log file in memory might not be such a good idea).
	#
	#	However if you are parsing a binary file, or a file that you know contains few timestamps
	# 	in it, it might make more sense to just parse the entire file and return a single value
	#	instead of making the engine call the module in a loop. 
	
	#  we want to parse this file and return it in a single hash
	$self->{'multi_line'} = 0;	# default value is 1 - only need to change from the default value

	#$self->{'type'} = 'file';	# it's a file type, not a directory (default file)

        #$self->{'file_access'} = 0;    # do we need to parse the actual file or is it enough to get a file handle
					# defaults to 0

        # bless the class ;)
        bless($self,$class);

	return $self;
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
	return "Parse the content of a Firefox _CACHE_00[123]_ file";
}


sub init
{
	my $self = shift;

	# Try really hard to get a user name
	unless (defined($self->{'username'})) {
		$self->{'username'} = Log2t::Common::get_username_from_path(${$self->{'name'}});
	}

	return 1;
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
	my $date;

	my %container = undef;	# the container that stores all the timestamp data
	my $cont_index = 0;	# index into the container


	# get the filehandle
	my $fh = $self->{'file'};

	#  jump past header
	#    This is disabled for FF>=4.0 because header size varies depending upon the
	#    file (_00[123]_).  Rather than try to figure out what version of FF this is
	#    we'll just read the file from the beginning and trust our anti-garbage code
	#    to tell valid from invalid metadata records
#	seek ($fh, 4096, 0);

	##  This could be set globally?
	#  valid blocksizes for FF Cache files
	my %bs_hash = (
		'1',	256,
		'2',	1024,
		#  for FF>=4.0 we don't want to read past header into first record
		'3',	1024,
#		'3',	4096,
	);	

	#  Use the filename to determine which blocksize to use
	my $filename = ${$self->{'name'}};
	$filename =~ s/.*\/_CACHE_00(\d)_$/$1/;

	my $blocksize = $bs_hash{$filename};

	print STDERR "[FF_CACHE] Begin parsing using $blocksize byte blocks...\n" if $self->{'debug'};

	my $data = "";

	#  read to end-of-file
	until (eof($fh))
	{
		#  grab blocksize bytes
		my $readcount = read ($fh, $data, $blocksize);
		unless ($readcount == $blocksize)
		{
			#  last block will be truncated, so we don't always care if we got < $readcount
			unless ((defined $readcount) && ($readcount > 0))
			{
				print STDERR "[FF_CACHE] Read error on ${$self->{'name'}}: $!\n";
				return undef;
			}
		}

		#  try to ID beginning of data block.  We're looking for valid meta-data header values rather than
		#  cache content
		#	in all my testing these values have been big-endian.  This might not always be true though.

		my ($hVer_major, $hVer_minor, $location, $fetch_count, $fetch_time, $modify_time, $expire_time, $data_size, $request_size, $info_size) = unpack ('S> S> L>4 L>4 L>4 L>4 L>4 L>4 L>4 L>4', $data);

		#  check request size, info size and fetch_count for sanity.  Note that 6400 and 1000 were PIDOMA,
		#     there may be better values for these
		if ($hVer_major == $version_major_sanity && $hVer_minor < $version_minor_sanity && $request_size < 6400 && $info_size < 6400 && $request_size > 0 && $info_size > 0 && $fetch_count < 1000 && $fetch_count > 0)
		{
			#  check to make sure we've got the whole data packet
			my $packet_size = (9*4) + $request_size + $info_size;

			#  grab more blocks until we've got enough
			while ($packet_size > length($data))
			{
				my $newdata;
				$readcount = read ($fh, $newdata, $blocksize);
				unless ($readcount == $blocksize)
				{
					unless ((defined $readcount) && ($readcount > 0))
					{
						print STDERR "[FF_CACHE] Read error on ${$self->{'name'}}: $!\n";
						return undef;
					}
				}
				$data .= $newdata;
			}

			#  grab the request string
			my $request_string = substr ($data, 9*4, $request_size);
			#  get rid of NULLs
			$request_string =~ s/\0+/ /g;
			#  grab the info_string (webserver response codes, etc.)
			my $info_string = substr ($data, (9*4)+$request_size, $info_size);

			# build a new container (%t_line structure)

			$container{$cont_index}->{'source'} = 'WEBHIST';
			$container{$cont_index}->{'sourcetype'} = 'Firefox Cache';

			#  don't know where this comes in, nor what a proper value would be. I suspect it's
			#  the version of the format (i.e. index.dat v.2)
###			$container{$cont_index}->{'version'} = 2;
			$container{$cont_index}->{'extra'} = { 'user' => $self->{'username'}, };

			#  check the existence of a default browser for this particular user (copied from safari.pm - so far I've never seen this produce anything)
			if (defined $self->{'defbrowser'}->{lc($self->{'username'})} )
			{
				$container{$cont_index}->{'notes'} = $self->{'defbrowser'}->{$self->{'username'}} =~ m/firefox/ ? 'Default browser for user' : 'Not the default browser (' . $self->{'defbrowser'}->{$self->{'username'}} . ')';
			}
			elsif ( $self->{'defbrowser'}->{'os'} ne '' )
			{
				# check the default one (the OS)
				$container{$cont_index}->{'notes'} = $self->{'defbrowser'}->{'os'} =~ m/firefox/ ? 'Default browser for system' : 'Not the default system browser (' . $self->{'defbrowser'}->{'os'} . ')';
			}

			# Populate fields of %t_list structure from cache record
			#  don't know what to do with the "short"
			####$container{$cont_index}->{'short'} = ???

			$container{$cont_index}->{'desc'} = $request_string . " [Visit Count: " . $fetch_count . "]";

			#  split the request info by NULL characters - it should make key / value pairs
			my %info_hash = split(/\0/, $info_string);
			if (defined $info_hash{'request-method'})
			{
				$container{$cont_index}->{'desc'} .= " [Method: " . $info_hash{'request-method'} . "]";
			}
			if (defined $info_hash{'response-head'})
			{
				my $response = $info_hash{'response-head'};
				$response =~ s/^(.*?)\r\n.*/$1/s;
				$container{$cont_index}->{'desc'} .= " [Resp: " . $response . "]";
			}

			#  legacy is a binary mask: M:1 A:2 C:4 B:8
			$container{$cont_index}->{'time'}{0} = { 'value' => $fetch_time,
					'type' => 'Last visit',
					'legacy' => 1
				};
			$container{$cont_index}->{'time'}{1} = { 'value' => $modify_time,
					'type' => 'First',
					'legacy' => 14
				};

			$cont_index++;

		} # end if
		# else the values we checked don't make sense, this is actual cache data, not metadata
		#	but we're not worrying about that here
        

	}  # end (until eof)

	return \%container;

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
 #       %t_line = (
 #               'time' => { 0 => { 'value' => $date, 'type' => 'Time Written', 'legacy' => 15 } },
 #               'desc' => $text,
 #               'short' => $text,
 #               'source' => 'LOG',
 #               'sourcetype' => 'This log file',
 #               'version' => 2,
 #               'extra' => { 'user' => 'username extracted from line' } 
 #       );

##	return \%t_line;

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
	return "This parses Firefox browser cache files _CACHE_001_, _CACHE_002_ and _CACHE_003_,
typically located in the following places:

Win XP:

    * C:\Documents and Settings\[user]\Local Settings\Application Data\Mozilla\Firefox\Profiles\XXXXXXXX.default\Cache\

Win Vista and Win 7:

    * C:\Users\[user]\AppData\Local\Mozilla\Firefox\Profiles\XXXXXXXX.default\Cache\

Mac OS X:

    * ~/Library/Caches/Firefox/Profiles/XXXXXXXX.default/Cache
	(typically /Users/[user]/Library/Caches/Firefox/Profiles/XXXXXXXX.default/Cache)

Linux:

    * ~/.mozilla/firefox/XXXXXXXX.default/Cache/
	(typically /home/[user]/.mozilla/firefox/XXXXXXXX.default/Cache/)

For more information: https://code.google.com/p/firefox-cache-forensics/
";
}


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
	
	$return{'success'} = 0;
	$return{'msg'} = 'Invalid file name - not a Firefox cache file';

	# to make things faster, start by checking if this is a file or a directory, depending on what this
	# modules is about to parse (and to eliminate shortcut files, devices or other non-files immediately)
	return \%return unless -f ${$self->{'name'}};

	# first (and perhaps only check) will be to check filename
	return \%return unless (${$self->{'name'}} =~ /_CACHE_00[123]_$/);
	$return{'success'} = 1;

	#  possible verification could include looking for FFFFFFFFs in beginning of file (the alloc map)
	#  except that it's possible that this would be empty or different but still valid.  A more detailed
	#  verification might include
	#  trying to decode the alloc map and see if there's valid content at some of the allocated spaces

	return \%return;
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


1;

__END__
