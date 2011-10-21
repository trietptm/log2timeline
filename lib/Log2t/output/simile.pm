#################################################################################################
#		SIMILE
#################################################################################################
# this package provides an output module for the tool log2timeline.
# The package takes as an input a reference to a hash that contains all the needed information to 
# print or output the timeline that has been produced by a format file
#
# The output of this format file is an XML document that can be used by the timeline visual tool
# SIMILE (http://www.simile-widgets.org/timeline/)
# 
# Author: Kristinn Gudjonsson
# Version : 0.5
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

package Log2t::output::simile;

use strict;
use HTML::Scrubber;
use Getopt::Long;       # read parameters

use Log2t::Time;	# for time manipulation

my $version = "0.5";

my %colors = (
	1 => 'black', 	# M
	2 => 'green',	# A
	3 => 'red',	# C
	8 => 'blue',	# B
	15 => 'yellow'	# MACB
	# otherwise orange
);

# to sanitize or scrub HTML elements of the entries
my $html = HTML::Scrubber->new();

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

	$self->{'json'} = 0;

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
	return "Output timeline in a XML format that can be read by a SIMILE widget"; 
}

sub print_header()
{
	my $self = shift;

	if( $self->{'json'} )
	{
		::print_line ("
{
	'dateTimeFormat': 'iso8601',
	'wikiURL': \"http://simile.mit.edu/shelf/\",
	'wikiSection': \"Timeline produced from log2timeline\",

'events' : [
		");
	}
	else
	{
		# XML
	        ::print_line ('
<data
        wiki-url="http://simile.mit.edu/shelf/"
        wikiSection="Timeline produced from log2timeline"
        >
        <!-- Sources:
                log2timeline produced timeline data
        -->

		');
	}

	return 1;
}

sub get_footer()
{
	my $self = shift;

	if( $self->{'json'} )
	{
		return '
]
}
';
	}
	else
	{
	        return '</data>';
	}
}

sub print_footer()
{
	my $self = shift;

	if( $self->{'json'} )
	{
		::print_line( '
]
}
' );
	}
	else
	{
	        ::print_line( "\n</data>" );
	}

	return 1;
}

#      	print_line 
# A subroutine that reads a line from the access file and returns it to the
# main script
# @return A string containing one line of the log file (or a -1 if we've reached 
#       the end of the log file)
sub print_line()
{
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

        my $self = shift;
        my $t_line= shift;
	my $text;
	my $color;
	my $date;
	my $extra;

        if( scalar( %{$t_line} ) )
	{
                # go through each defined timestamp
                foreach( keys %{$t_line->{'time'}} )
                {
			next unless $t_line->{'time'}->{$_}->{'value'} > 0;

			my $title = $t_line->{short};
			$title =~ s/\&/\&amp;/g;
			$title = $html->scrub($title);
			$title =~ s/\"//g;

			$extra = "\n'link': '" . $t_line->{'extra'}->{'url'} . "'," if defined $t_line->{'extra'}->{'url'} and $t_line->{'extra'}->{'url'} ne '';

			$text .= 'User: ' . $t_line->{'extra'}->{'user'} . ' ' unless $t_line->{'extra'}->{'user'} eq '' or $t_line->{'extra'}->{'user'} eq 'unknown';
			$text .= $t_line->{desc};
			$text =~ s/\&/\&amp;/g;
			$text = $html->scrub($text);
			$text =~ s/\'//g;
			$text =~ s/\"//g;

			# get the date in text format
			$date = Log2t::Time::epoch2iso( $t_line->{'time'}->{$_}->{'value'}, $self->{'tz'} ) if $self->{'json'};
			$date = Log2t::Time::epoch2text( $t_line->{'time'}->{$_}->{'value'}, 1, $self->{'tz'} ) unless $self->{'json'};
			$date =~ s/\(//;
			$date =~ s/\)//;

			# get the color
			$color = $colors{$t_line->{'time'}->{$_}->{'legacy'}} if defined $colors{$t_line->{'time'}->{$_}->{'legacy'}};
			$color = 'orange' unless defined $colors{$t_line->{'time'}->{$_}->{'legacy'}};
			
			# print the line
			::print_line( "
	{ 'start': '" . $date . "',
	'isDuration': false,
	'textColor': '"  . $color . "',
	'caption': '" . $t_line->{'sourcetype'} . "',
	'title': '" . $title . "', $extra
	'description': '[" . $t_line->{'source'} . '] (' . $t_line->{'time'}->{$_}->{'type'} . ') ' . $text . '(file: ' . $t_line->{'extra'}->{'path'} . $self->{'name'} . ")'
	},
			") if $self->{'json'};

			::print_line( '
        <event start="' . $date . '"
                durationEvent="false"
                title="' . $title . '"
                >
        [' . $t_line->{'source'} . '] (' . $t_line->{'time'}->{$_}->{'type'} . ') ' . $text . ' (file: ' . $t_line->{'extra'}->{'path'} . $self->{'name'} . ')
        </event>
			') unless $self->{'json'};
			
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
	return "This output plugin creates a XML document that can be read by the 
timeline visualization widget SIMILE (http://www.simile-widgets.org/timeline/).

The module accepts the parameter 
	-json
The default output is the XML document, but if the -jason option is passed the tool will
output using JSON file instead.

This is only the XML/JSON document, there is also a need to create a HTML document that parses
the XML/JSON document and displays the actual timeline";

}

1;
