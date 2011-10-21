#################################################################################################
#		OUTPUT	
#################################################################################################
# this package provides an output module for the tool log2timeline.
# The package takes as an input a hash that contains all the needed information to print or output
# the timeline that has been produced by a format file
# 
# Author: Kristinn Gudjonsson
# Version : 0.7
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

package Log2t::output::csv;

use strict;
use Getopt::Long;       # read parameters
use Log2t::Time;	# for time stuff

my $version = "0.7";

my $first_line;	# defines if we have printed a line or not

#       get_version
# A simple subroutine that returns the version number of the format file
#
# @return A version number
sub get_version()
{
	return $version;
}

#       new
# A simple constructor of the output module. Takes care of parsing 
# parameters sent to the output module
sub new($)
{
        my $class = shift;

        # bless the class ;)
        my $self = bless{}, $class;

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
	return "Output timeline using CSV (Comma Separated Value) file"; 
}

sub print_header()
{
	# since we really do not know how to construct the header, we need to wait
	$first_line = 1;
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
        my $self = shift;
        my $t_line= shift;	# the timestamp object
	my $text;
	my $temp;
	my $mactime;

	# check if this is the first line
	if( $first_line )
	{
		# start by printing out name of dates
		$text .= 'date,time,timezone,MACB,';

        # content of the timestamp object t_line 
        # optional fields are marked with [] 
        # 
        # %t_line {        
        #       time
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

		if( scalar( %{$t_line} ) )
		{

			$text .= 'source,sourcetype,type,user,host,short,desc,version,filename,inode,notes,format,extra';

			::print_line( $text ."\n");
		}

		# first line is finished
		$first_line = 0;
		$text = '';
	}

	# go through the line and print it out
        if( scalar( %{$t_line} ) )
	{
		# remove any instances of ::comma:: from the line
		$t_line->{'desc'} =~ s/::comma::/-/g;
		$t_line->{'title'} =~ s/::comma::/-/g;

		# remove any instances of tab
		$t_line->{'desc'} =~ s/\t/ /g;
		$t_line->{'title'} =~ s/\t/ /g;
		
		#printf STDERR "[PRINT] M %d A %d C %d B %d\n",$mtime,$atime,$ctime,$btime;
                # go through each defined timestamp
                foreach( keys %{$t_line->{'time'}} )
                {
			# don't want to print emtpy timestamps
			next if $t_line->{'time'}->{$_}->{'value'} le 0;

                	$mactime =  $t_line->{'time'}->{$_}->{'legacy'} & 0b0001 ? 'M' : '.';
                	$mactime .= $t_line->{'time'}->{$_}->{'legacy'} & 0b0010 ? 'A' : '.';
                	$mactime .= $t_line->{'time'}->{$_}->{'legacy'} & 0b0100 ? 'C' : '.';
                	$mactime .= $t_line->{'time'}->{$_}->{'legacy'} & 0b1000 ? 'B' : '.';

                	my ($a,$b) = Log2t::Time::epoch2text( $t_line->{'time'}->{$_}->{'value'}, 3, $self->{'tz'} );
                	$text .= $a . '::comma::' . $b . '::comma::' . $self->{'short_tz'}  . '::comma::' . $mactime . '::comma::';
			$text .=  $t_line->{'source'} . '::comma::' . $t_line->{'sourcetype'} . '::comma::' . $t_line->{'time'}->{$_}->{'type'} . '::comma::';

			# now to take the values from 'extra'
			if( $t_line->{'extra'}->{'user'} eq '' or $t_line->{'extra'}->{'user'} eq 'unknown' )
			{
				$text .= '-::comma::';
			}
			else
			{
				$text .= $t_line->{'extra'}->{'user'} . '::comma::';
			}

			if( $t_line->{'extra'}->{'host'} eq '' or $t_line->{'extra'}->{'host'} eq 'unknown' )
			{
				$text .= '-::comma::';
			}
			else
			{
				$text .= $t_line->{'extra'}->{'host'} . '::comma::';
			}

			$text .= $t_line->{'short'} . '::comma::' . $t_line->{'desc'} . '::comma::' . $t_line->{'version'} . '::comma::';

			# and for the filename
			$t_line->{'extra'}->{'filename'} =~ s/::comma::/-/g;
	                $text .= $t_line->{'extra'}->{'path'} if defined $t_line->{'extra'}->{'path'};

                	# check if we have the original directory definition
                	if( defined $t_line->{'extra'}->{'parse_dir'} )
                	{
                	        # we need to remove the "path" from the file before proceeding
	
	                        # get the file name
	                        my $fname = $t_line->{'extra'}->{'filename'};
	                        Log2t::Common::replace_char( \$fname, 0 );
	                        my $orig = $t_line->{'extra'}->{'parse_dir'};
	                        Log2t::Common::replace_char( \$orig, 0 );
	
	                        # remove the directory from the path
	                        $fname =~ s/^$orig//;
	
	                        Log2t::Common::replace_char( \$fname, 1 );
	
	                        $text .= $fname . '::comma::';
	                }
	                else
	                {
	                        # we don't have to worry about filename stuff
	                        $text .= $t_line->{'extra'}->{'filename'} . '::comma::';
        	        }

			$text .= $t_line->{'extra'}->{'inode'} . '::comma::';

			$temp = undef;

			# check the notes field
			$t_line->{'notes'} =~ s/::comma::/-/g if defined $t_line->{'notes'};
			$temp = $t_line->{'notes'} . ' ' if defined $t_line->{'notes'};

			# and the URL field
			$temp .= 'URL: ' . $t_line->{'extra'}->{'url'} if defined $t_line->{'extra'}->{'url'};
			
			$text .= $temp . '::comma::' if defined $temp;
			$text .= '-::comma::' unless defined $temp;


			$text .= $t_line->{'extra'}->{'format'} . '::comma::';


			$temp = undef;	# reset the temp variable
			# and now to go through the rest of the extra field
			foreach( keys %{$t_line->{'extra'}} )
			{
				next if $_ eq 'user';
				next if $_ eq 'host';
				next if $_ eq 'path';
				next if $_ eq 'inode';
				next if $_ eq 'url';
				next if $_ eq 'parse_dir';
				next if $_ eq 'format';
				next if $_ eq 'filename';

				$temp .= $_ . ': ' . $t_line->{'extra'}->{$_} . ' ';
			}

			# now we've gone through the extra field, let's include it
			$temp =~ s/,/-/g;
			$text .= $temp if defined $temp and $temp ne '';
			$text .= '-' unless defined $temp;

			$text =~ s/,$//;

			#print STDERR "[PRINTING] ", substr( $t_line->{'name'}, 20, 10 ), "...\n";

			# now to substitute any instances of , and ::comma::
			$text =~ s/,/-/g;
			$text =~ s/::comma::/,/g;

			::print_line( $text  . "\n");
			$text = '';
		}
	}

	return 1;
}

#       get_help
# A simple subroutine that returns a string containing the help 
# message for this particular format file.
# @return A string containing a help file for this format file
sub get_help()
{
	return "This output module takes the line and prints out all the fields in a comma separated value file (CSV)
that can be imported into programs like Excel for analysis";

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
