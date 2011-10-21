#################################################################################################
#		CFTL	
#################################################################################################
# this package provides an output module for the tool log2timeline.
# The package takes as an input a reference to a hash that contains all the needed information to 
# print or output the timeline that has been produced by a format file
#
# The output of this format file is an XML document that can be used by the timeline visual tool
# CyberForensics TimeLab ( http://cftl.rby.se )
#
# More information about the CFTL can be read in the following paper:
# http://www.dfrws.org/2009/proceedings/p78-olsson.pdf
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

package Log2t::output::cftl;

use strict;
use HTML::Scrubber;
use Getopt::Long;       # read parameters
use Log2t::Time;	# for time manipulation

my $version = '0.7';

# to sanitize or scrub HTML elements of the entries
my $html = HTML::Scrubber->new();
my $index;

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
	return "Output timeline in a XML format that can be read by CFTL"; 
}

sub print_header()
{
	::print_line ("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\r<!DOCTYPE EvidenceCollection SYSTEM \"CyberForensicsTimeLab.dtd\">\n\r<!--\n\rCreated by log2timeline for CyberForensics TimeLab.\n\rCopyright(C) 2009 Kristinn Gudjonsson (log2timeline)\n\rCopyright(C) 2008 Jens Olsson (CFTL)\n\r-->\n\r<EvidenceCollection>\n\r");
	# initialize the index variable
	$index = 0;

	return 1;
}

sub print_footer()
{
	::print_line( "</EvidenceCollection>\n\r" );

	return 1;
}

sub get_footer()
{
	return "</EvidenceCollection>\n\r";
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
	my $title;
	my $time_text;
	
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
                # go through each defined timestamp
                foreach( keys %{$t_line->{'time'}} )
                {
			$time_text .= '<Timestamp type="' . $t_line->{'time'}->{$_}->{'type'} . '" value="' . Log2t::Time::epoch2cftl( $t_line->{'time'}->{$_}->{'value'}, $self->{'tz'} ) . '" origin="' . $t_line->{'sourcetype'} . '" />' . "\n\r\t";
		}

		# construct the title part
		$text = 'User: ' . $t_line->{'extra'}->{'user'} . ' ' unless $t_line->{'extra'}->{'user'} eq 'unknown';
		$text .= '(' . $t_line->{'extra'}->{'host'} . ') ' unless $t_line->{'extra'}->{'host'} eq 'unknown';
		$text .= $t_line->{'desc'};
		$text .= ' (file: ' . $t_line->{'extra'}->{'path'} . $self->{'name'} . ')';

		# fix the title
		$title = $html->scrub( $text );
        	$title =~ s/\"/\&quot;/g;
        	$title =~ s/\'/\&apos;/g;
        	$title =~ s/\&/\&amp;/g;
        	$title =~ s/</\&lt;/g;
        	$title =~ s/>/\&gt;/g;

		
		# one time
		::print_line(  "\n\r" . '<Evidence' . "\n\r\t" . 'title="' . $title . '"' . "\n\r\t" . 'type="' . $t_line->{sourcetype} . '"' . "\n\r\t" . 'id="' . $index++ . '" parent="">' . "\n\r\t" . '<Chunk from="0" to="0"/>' . "\n\r\t" . $time_text . "<Data />\n\r</Evidence>\n\r" );
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
timeline visualization tool CFTL (CyberForensics TimeLab) 

This is only the XML document, to visually examine the timeline, one needs to have
access to the CFTL tool";

}

1;

__END__

=pod

=head1 NAME

cftl - An output module for the CFTL XML document

=head1 DTD

The DTD for the XML format is the following:

<!ELEMENT EvidenceCollection (Evidence*)>

<!ELEMENT Evidence (Chunk+,Timestamp*,Data*)>
<!ATTLIST Evidence title CDATA #REQUIRED>
<!ATTLIST Evidence type CDATA #REQUIRED>
<!ATTLIST Evidence id CDATA #REQUIRED>
<!ATTLIST Evidence parent CDATA "">

<!ELEMENT Chunk EMPTY>
<!ATTLIST Chunk from CDATA #REQUIRED>
<!ATTLIST Chunk to CDATA #REQUIRED>

<!ELEMENT Timestamp EMPTY>
<!ATTLIST Timestamp type CDATA #REQUIRED>
<!ATTLIST Timestamp value CDATA #REQUIRED>
<!ATTLIST Timestamp origin CDATA #REQUIRED>

<!ELEMENT Data EMPTY>
<!ATTLIST Data name CDATA #REQUIRED>
<!ATTLIST Data value CDATA #REQUIRED>

=cut
