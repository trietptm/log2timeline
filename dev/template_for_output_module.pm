#################################################################################################
#		OUTPUT	
#################################################################################################
# this package provides an output module for the tool log2timeline.
# The package takes as an input a hash that contains all the needed information to print or output
# the timeline that has been produced by a format file
# 
# Author: Kristinn Gudjonsson
# Version : 0.1
# Date : xx/xx/10
#
# Copyright 2009,2010 Kristinn Gudjonsson (kristinn ( a t ) log2timeline (d o t) net)
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

package Log2t::output::OUTPUT;

use strict;
use Getopt::Long;       # read parameters

my $version = "0.1";

#       get_version
# A simple subroutine that returns the version number of the format file
#
# @return A version number
sub get_version()
{
	return $version;
}

#	new
# A simple constructor of the output module. Takes care of parsing 
# parameters sent to the output module
sub new($)
{
	my $quiet;

        # read options from CMD
        @ARGV = @_;
        GetOptions(
                "quiet!"        =>\$quiet
        );
}

#       get_description
# A simple subroutine that returns a string containing a description of 
# the funcionality of the format file. This string is used when a list of
# all available format files is printed out
#
# @return A string containing a description of the format file's functionality
sub get_description()
{
	return "Output timeline using this particular output method"; 
}

sub print_header()
{
	return 1;
}

sub get_footer()
{
	return 0;	# no footer
}

sub print_footer()
{
	return 1;
}

#      	print_line 
# A subroutine that reads a line from the access file and returns it to the
# main script
# @return A string containing one line of the log file (or a -1 if we've reached 
#       the end of the log file)
sub print_line()
{
	# content of array t_line
	# %t_line {
	#       md5,
	#       name,
	#       inode,
	#       mode,
	#       uid,
	#       gid,
	#       size,
	#       atime,
	#       mtime,
	#       ctime,
	#       crtime
	# }
        my $class = shift;
        my $t_line= shift;
	my $text;

        if( scalar( %{$t_line} ) )

	while ( my ($key, $value) = each(%{$t_line}) ) 
	{
        	$text .= "$key => $value\n";
    	}

	::print_line( $text );

	return 1;
}

#       get_help
# A simple subroutine that returns a string containing the help 
# message for this particular format file.
# @return A string containing a help file for this format file
sub get_help()
{
	return "This is an unknown output method.  It prints out the timeline that comes 
from the input plugin (format file) and prints it blindly out, it contains no requirements or 
any other relevant options or possibilites, use with care...";

}

1;

__END__

=pod

=head1 NAME

structure - An example output plugin for log2timeline

=head1 METHODS

=over 4

=item get_help()

Returns a string that contains a longer version of the description of the output module, as well as possibly providing some assistance in how the module should be used.

=item print_line( $class, \%t_line )

Accepts as a parameter a reference to a hash that stores the timeline that is to be printed.  It then parses the reference and calls a method in the main script that takes care of printing a line in a particular output format

=item new()

A constructor that parses parameters passed to the output module, perhaps indicating a user name or additional information to include with the printed timeline

=item get_version()

Returns the version number of the plugin file

=item get_description()

Returns a string that contains a short description of the output module

=item print_header()

If applicaple this function calls a print function in the main script to add a header to the output file

=item print_footer()

If applicaple this function calls a print function in the main script to add a footer to the output file

=back

=cut
