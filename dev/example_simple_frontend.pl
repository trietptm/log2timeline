#!/usr/bin/perl
#################################################################################################
#               example front end for example front end for log2timeline
#################################################################################################
# This is a simple implementation of a front end for the tool log2timeline.  This is implemented
# just to show the possibility of developing front-ends for the tool or to use it in other scripts.
#
# So this template for a front-end can be used to include the log2timeline engine in other scripts,
# such as scripts to automate the collection of a supertimeline or really what ever comes in mind.
# Could be done to automate the collection of all information, where supertimeline is perhaps just
# a small part of it (could be part of a script that collects all sort of information from the drive)
#
# Author: Kristinn Gudjonsson
# Date : 13/04/11
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

use Log2Timeline;	# import the library that contains the log2timeline engine
use strict;

# create a new log2timeline object, with all the appropriate settings
#	All of the options are given here. But all of them are optional (default values assigned to them)
my $l = Log2Timeline->new( 
	file => '/mnt/analyze',		# point to the file/directory to parse
	'recursive' => 1,		# we want to recursively go through stuff
	#'debug' => 0,			# do we want debug to be turned on or off?
	#'hostname' => '',		# to include a hostname (done in preprocessing)
	'input' => 'winxp',		# which input modules to use (this is a Win XP machine)
	'output' => 'csv',		# what is the output module to be used
	#'offset' => 0,			# the time offset (if the time is wrong)  2996
	#'exclusions' => '',		# an exclusion list of one exists
	#'text' => '',			# text to prepend to path of files (like c:)
	#'quick' => 0,			# quick mode
	#'append' => 0,			# we are appending to an output file, instead of writing a new one
	#'temp'	=> '',			# the location of a temporary directory that the tool can write files to
					# by default empty => engine tries to determine automatically (/tmp *NIX 
					# Win32 API called on Windows)
	'time_zone' => 'CST6CDT',	# the time zone of the image
	#'raw' => 1,			# if we want raw mode and process the timestamp ourselves
	'preprocess' => 1, 		# turn on pre-processing modules 
	#'digest' => 0 			# calculate MD5 sums for all files
) or die( 'unable to start log2timeline');


# and to process the timestamps, or run the engine
$l->start;

#	print_line
# It is necessary to implement this routine in the front end.  The output modules call this method
# to print all the output from them.  The routine can be as simple as this one, that is just to
# print the lines to STDOUT or to print them to a file, or even some other funky stuff.
sub print_line($)
{
        my $line = shift;

        # print the line to STDOUT.... very simple processing
        print $line;
}

# it is also possible to use the raw mode of log2timeline. If you do that there will be no calls to 
# the output module.  If this option is used then the front-end needs to implement the function:
#	process_output($)
# This routine accepts one parameter, or the timestamp object.  The front-end then needs to process 
# it to be able to extract the needed information.
# 
# Although this is possible with this version it is still highly recommended to rather create a new
# output module than to use this option.  Creating new output module gives you all of the control 
# you need to process and work with the timestamp object.
# 


