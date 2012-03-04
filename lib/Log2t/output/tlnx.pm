#################################################################################################
#		TLNX
#################################################################################################
# this package provides an output module for the tool log2timeline.
# The package takes as an input a hash that contains all the needed information to print or output
# the timeline that has been produced by a format file
#
# This output module outputs in the TIMELINE or TLN format that H. Carvey is using. The fields
# are:
# Time|Source|Host|User|Description|TZ|Notes
#
# The last two fielda are optional and provide more context.  This input module will utilize
# both of the optional fields, although some tools that will parse information in TLN format
# will choose to ignore those fields
#
# The format was described in this blog post:
# http://windowsir.blogspot.com/2009/02/timeline-analysis-pt-iii.html
#
# A better blog description of it can be found here:
# http://windowsir.blogspot.com/2010/02/timeline-analysisdo-we-need-standard.html
#
# Author: Kristinn Gudjonsson
# Version : 0.2
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

package Log2t::output::tlnx;

use strict;
use Getopt::Long;    # read parameters
use HTML::Scrubber;

my $version = "0.2";

#       get_version
# A simple subroutine that returns the version number of the format file
#
# @return A version number
sub get_version() {
    return $version;
}

#       new
# A simple constructor of the output module. Takes care of parsing
# parameters sent to the output module
sub new($) {
    my $class = shift;

    # bless the class ;)
    my $self = bless {}, $class;

    return $self;

}

#       get_description
# A simple subroutine that returns a string containing a description of
# the funcionality of the format file. This string is used when a list of
# all available format files is printed out
#
# @return A string containing a description of the format file's functionality
sub get_description() {
    return "Output timeline using H. Carvey's TLN format in XML";
}

sub print_header() {
    ::print_line(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\r<!--\n\rCreated by log2timeline.\n\rCopyright(C) 2009-2010 Kristinn Gudjonsson (log2timeline)\n\r-->\n\r<Events>\n\r"
    );
    return 1;
}

sub print_footer() {
    ::print_line("</Events>\n\r");
    return 1;
}

sub get_footer() {
    return "</Events>\n\r";
}

#      	print_line
# A subroutine that reads a line from the access file and returns it to the
# main script
# @return A string containing one line of the log file (or a -1 if we've reached
#       the end of the log file)
sub print_line() {

    # content of array t_line ([optional])
    # %t_line {
    #	time
    #		index
    #			value
    #			type
    #			legacy
    # 	desc
    #	short
    #	source
    #	sourcetype
    #	[notes]
    #	extra
    #		[filename]
    #		[md5]
    #		[mode]
    #		[host]
    #		[user]
    #		[url]
    #		[size]
    #		[...]
    # }
    my $self   = shift;
    my $t_line = shift;
    my $mactime;
    my $prefix;
    my $notes;
    my $p2;

    # to sanitize or scrub HTML elements of the entries
    my $html = HTML::Scrubber->new();

    if (scalar(%{$t_line})) {

# Print in the TLN format:
#  Time|Source|Host|User|Description|TS|Notes
# 	Time - MS systems use 64-bit FILETIME objects in many cases; however, for the purposes of normalization, 32-bit Unix epoch times will work just fine
#	Source - fixed-length field for the source of the data (i.e., file system, Registry, EVT/EVTX file, AV or application log file, etc.) and may require a key or legend. For graphical representation, each source can be associated with a color.
#	Host - The host system, defined by IP or MAC address, NetBIOS or DNS name, etc. (may also require a key or legend)
#	User - User, defined by user name, SID, email address, IM screenname, etc. (may also require a key or legend)
#	Description - The description of what happened; this is where context comes in...

        # add a check of the name field
        $t_line->{'extra'}->{'user'} = '-' unless defined $t_line->{'extra'}->{'user'};
        $t_line->{'extra'}->{'user'} = '-' if $t_line->{'extra'}->{'user'} eq 'unknown';

        $t_line->{'extra'}->{'host'} = '-' if $t_line->{'extra'}->{'host'} eq 'unknown';
        $t_line->{'extra'}->{'host'} = '-' if $t_line->{'extra'}->{'host'} eq '';

        # construct the notes field
        $notes = 'File:' . $t_line->{'extra'}->{'path'} . $t_line->{'extra'}->{'filename'}
          if (defined $t_line->{'extra'}->{'filename'} && -f $t_line->{'extra'}->{'filename'});
        $notes = 'Dir:' . $t_line->{'extra'}->{'path'} . $t_line->{'extra'}->{'filename'}
          if (defined $t_line->{'extra'}->{'filename'} && -d $t_line->{'extra'}->{'filename'});
        $notes .= ' URL: ' . $t_line->{'extra'}->{'url'} if defined $t_line->{'extra'}->{'url'};
        $notes .= ' ' . $t_line->{'notes'}               if defined $t_line->{'notes'};
        $notes .= ' inode:' . $t_line->{'extra'}->{'inode'}
          if defined $t_line->{'extra'}->{'inode'};

        # change \ to /
        $notes =~ s/\\/\//g;

        # create a prefix field
        $prefix =
          $t_line->{'sourcetype'} eq $t_line->{'source'}
          ? ''
          : '(' . $t_line->{'sourcetype'} . ') ';
        $prefix = '' if $t_line->{'source'} eq 'EVT';
        $prefix = '' if $t_line->{'source'} eq 'EVTX';

        # go through each defined timestamp
        foreach (keys %{ $t_line->{'time'} }) {

            # check if we have a file (need to include MACB)
            if (lc($t_line->{'source'}) eq 'file') {
                if ($t_line->{'time'}->{$_}->{'type'} =~ m/SI/) {
                    $mactime = $t_line->{'time'}->{$_}->{'legacy'} & 0b0001 ? 'M' : '.';
                    $mactime .= $t_line->{'time'}->{$_}->{'legacy'} & 0b0010 ? 'A' : '.';
                    $mactime .= $t_line->{'time'}->{$_}->{'legacy'} & 0b0100 ? 'C' : '.';
                    $mactime .= $t_line->{'time'}->{$_}->{'legacy'} & 0b1000 ? 'B' : '.';

                    $p2 = '[$SI ';
                }
                else {
                    $mactime = $t_line->{'time'}->{$_}->{'legacy'} & 0b0001 ? 'M' : '.';
                    $mactime .= $t_line->{'time'}->{$_}->{'legacy'} & 0b0010 ? 'A' : '.';
                    $mactime .= $t_line->{'time'}->{$_}->{'legacy'} & 0b0100 ? 'C' : '.';
                    $mactime .= $t_line->{'time'}->{$_}->{'legacy'} & 0b1000 ? 'B' : '.';

                    $p2 = '[$FN ';
                }

                $p2 .= $mactime . '] ';
            }
            else {
                $p2 = $prefix . '[' . $t_line->{'time'}->{$_}->{'type'} . '] ';
            }

            # don't want to print the line if the time is zero
            # Time|Source|Host|User|Description|TZ|Notes

            ::print_line("
<Event>
	<time>" . $html->scrub($t_line->{'time'}->{$_}->{'value'}) . "</time>
	<source>" . $html->scrub($t_line->{'source'}) . '</source>
	<host>' . $html->scrub($t_line->{'extra'}->{'host'}) . "</host>
	<user>" . $html->scrub($t_line->{'extra'}->{'user'}) . '</user>
	<description>' . $html->scrub($p2 . $t_line->{'desc'}) . '</description>
	<tz>' . $self->{'tz'} . '</tz>
	<notes>' . $html->scrub($notes) . "</notes>
</Event>\n") if $t_line->{'time'}->{$_}->{'value'} > 0;
        }
    }
    else {
        print STDERR "Error: t_line not scalar\n";
        return 0;
    }
    return 1;
}

#       get_help
# A simple subroutine that returns a string containing the help
# message for this particular format file.
# @return A string containing a help file for this format file
sub get_help() {
    return "Printing out in the TLN or timeline format as described by
H. Carvey in his blog post:
	http://windowsir.blogspot.com/2010/02/timeline-analysisdo-we-need-standard.html
	http://windowsir.blogspot.com/2009/02/timeline-analysis-pt-iii.html
Fields are
  Time|Source|Host|User|Description|TZ|Notes
 	Time - MS systems use 64-bit FILETIME objects in many cases; however, for the purposes of normalization, 32-bit Unix epoch times will work just fine
	Source - fixed-length field for the source of the data (i.e., file system, Registry, EVT/EVTX file, AV or application log file, etc.) and may require a key or legend. For graphical representation, each source can be associated with a color.
	Host - The host system, defined by IP or MAC address, NetBIOS or DNS name, etc. (may also require a key or legend)
	User - User, defined by user name, SID, email address, IM screenname, etc. (may also require a key or legend)
	Description - The description of what happened; this is where context comes in...
	TZ is timezone and is optional
	Notes is optional as well\n";

}

1;

