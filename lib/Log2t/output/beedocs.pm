#################################################################################################
#		BEEDOCS
#################################################################################################
# this package provides an output module for the tool log2timeline.
# It prints a simple TDL file that can be imported into the tool BeeDocs (a visualization tool
# for timelines).
#
# The timeline is really simple, so more work needs to be done to properly examine it.
# Notes can be exported to a different file, along with additional information
# and then a AppleScript can be created to open the timeline tool and make some
# modifications to the timeline to make it more "appealing"
#
# http://www.beedocs.com/help/articles/applescript.php
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

package Log2t::output::beedocs;

use strict;
use Getopt::Long;    # read parameters
use Log2t::Time;     # for time stuff

my $version = "0.2";
my $convert = 0;

my $first_line;      # defines if we have printed a line or not

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
sub new() {
    my $class = shift;

    # bless the class ;)
    my $self = bless {}, $class;

    $self->{'convert'} = $convert unless exists $self->{'convert'};

    return $self;
}

#       get_description
# A simple subroutine that returns a string containing a description of
# the funcionality of the format file. This string is used when a list of
# all available format files is printed out
#
# @return A string containing a description of the format file's functionality
sub get_description() {
    return "Output timeline using tab-delimited file to import into BeeDocs";
}

sub print_header() {

    # since we really do not know how to construct the header, we need to wait
    $first_line = 1;
    return 1;
}

sub get_footer() {
    return 0;    # no footer
}

sub print_footer() {
    return 1;
}

#      	print_line
# A subroutine that reads a line from the access file and returns it to the
# main script
# @return A string containing one line of the log file (or a -1 if we've reached
#       the end of the log file)
sub print_line($) {
    my $self   = shift;
    my $t_line = shift;    # the timestamp object
    my $text;
    my $temp;
    my $mactime;

    # check if this is the first line
    if ($first_line) {

        # start by printing out name of dates
        $text = "Label\tStart Time\tEnd Time\n";

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
        ::print_line($text);

        # first line is finished
        $first_line = 0;
        $text       = '';
    }

    # go through the line and print it out
    if (scalar(%{$t_line})) {

        #printf STDERR "[PRINT] M %d A %d C %d B %d\n",$mtime,$atime,$ctime,$btime;
        # go through each defined timestamp
        foreach (keys %{ $t_line->{'time'} }) {

            # don't want to print emtpy timestamps
            next unless $t_line->{'time'}->{$_}->{'value'} > 0;

            $mactime = $t_line->{'time'}->{$_}->{'legacy'} & 0b0001 ? 'M' : '.';
            $mactime .= $t_line->{'time'}->{$_}->{'legacy'} & 0b0010 ? 'A' : '.';
            $mactime .= $t_line->{'time'}->{$_}->{'legacy'} & 0b0100 ? 'C' : '.';
            $mactime .= $t_line->{'time'}->{$_}->{'legacy'} & 0b1000 ? 'B' : '.';

# now to construct the text field (or description), populating it with the missing fields needed to clarify the timeline field
            $text = '[' . $t_line->{'sourcetype'} . '] ' unless $convert;
            $text .= '(' . $t_line->{'time'}->{$_}->{'type'} . ' - ' . $mactime . ') '
              unless $convert;
            $text .= 'User: ' . $t_line->{'extra'}->{'user'} . ' '
              if (defined $t_line->{'extra'}->{'user'}
                  && $t_line->{'extra'}->{'user'} ne 'unknown');
            $text .= 'Host: ' . $t_line->{'extra'}->{'host'} . ' '
              if (defined $t_line->{'extra'}->{'host'}
                  && $t_line->{'extra'}->{'host'} ne 'unknown');
            $text .= $t_line->{'desc'};
            $text .=
              ' (file: ' . $t_line->{'extra'}->{'path'} . $t_line->{'extra'}->{'filename'} . ')';

            # remove all possible tabs in the text
            $text =~ s/\t/ /g;

            # add the timestamp to the output
            $text .= "\t"
              . Log2t::Time::epoch2text($t_line->{'time'}->{$_}->{'value'}, 2, $self->{'tz'}) . "\t"
              . Log2t::Time::epoch2text($t_line->{'time'}->{$_}->{'value'}, 2, $self->{'tz'});

            # and now for notes
            $temp = undef;

            # check the notes field
            #$temp = $t_line->{'notes'} if defined $t_line->{'notes'};
            # and the URL field
            #$temp .= 'URL: ' . $t_line->{'extra'}->{'url'} if defined $t_line->{'extra'}->{'url'};

            #$text .= $temp . ',' if defined $temp;
            #$text .= '-,' unless defined $temp;

            #$text .= $t_line->{'extra'}->{'format'} . ',';

            #print STDERR "[PRINTING] ", substr( $t_line->{'name'}, 20, 10 ), "...\n";
            ::print_line($text . "\n");
            $text = '';
        }
    }

    return 1;
}

#       get_help
# A simple subroutine that returns a string containing the help
# message for this particular format file.
# @return A string containing a help file for this format file
sub get_help() {
    return "This output module prints out information in a Tab Delimited File (TDF) 
that can be directly imported into BeeDocs for visualization of the timeline";

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
