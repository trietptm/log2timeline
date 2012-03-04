#################################################################################################
#		CEF (Commen Event Format)
#################################################################################################
# this package provides an output module for the tool log2timeline.
#
# The package takes as an input a hash that contains all the needed information to print or output
# the timeline that has been produced by an input module.
#
# This particular output module provides an output in the Common Event Format (CEF), revision 15,
# as published by ArcSight on July 17th of 2009.
#
# CEF format is an attempt to create a standard format that can be easily imported into any device
# capable of accepting log files
#
# This output module was created to begin with for importing timeline data into Splunk or OSSEC.
#
# The idea for creating this output module and the different extensions used came from Andrew
# Hay (http://www.andrewhay.ca/).  The goal of this output module is to be able to use the
# timeline created by log2timeline directly in tools like Splunk or other log processing
# devices for better and quicker analysis of the timeline.  Other possible connections would
# be to connect the CEF output to OSSEC for first line of analysis against the timeline or in
# fact any log processing device.
#
# The format is based on the following line:
# CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
#
# Taken from the documentation from ArcSight:
#
# -----------------------------------------------------------------------------------------------------
#
# Definitions of Prefix Fields
#
#	Version is an integer and identifies the version of the CEF format. Event consumers use
#	this information to determine what the following fields represent.
#
#	Device Vendor, Device Product and Device Version are strings that uniquely identify the
#	type of sending device. No two products may use the same device-vendor and device-product
#	pair. There is no central authority managing these pairs. Event producers have to ensure
#	that they assign unique name pairs.
#
#	Signature ID is a unique identifier per event-type. This can be a string or an integer.
#	Signature ID identifies the type of event reported. In the intrusion detection system (IDS)
#	world, each signature or rule that detects certain activity has a unique signature ID
#	assigned. This is a requirement for other types of devices as well, and helps correlation
#	engines deal with the events.
#
#	Name is a string representing a human-readable and understandable description of the event.
#	The event name should not contain information that is specifically mentioned in other fields.
#	For example: "Port scan from 10.0.0.1 targeting 20.1.1.1" is not a good event name. It should
#	be: "Port scan". The other information is redundant and can be picked up from the other fields.
#
#	Severity is an integer and reflects the importance of the event. Only numbers from 0 to 10
#	are allowed, where 10 indicates the most important event.
#
#	Extension is a collection of key-value pairs. The keys are part of a predefined set. The
#	standard allows for including additional keys as outlined under "The Extension Dictionary"
#	on page 4. An event can contain any number of key- value pairs in any order, separated by
#	spaces (" "). If a field contains a space, such as a file name, this is valid and can be
#	logged in exactly that manner, as shown below:
#
#		fileName=c:\Program<space>Files\ArcSight is a valid token.
#
#	The following example illustrates a CEF message using Syslog transport:
#
#		Sep 19 08:26:10 host CEF:0|security|threatmanager|1.0|100|worm successfully stopped
#		|10|src=10.0.0.1 dst=2.1.2.2 spt=1232
#
# -----------------------------------------------------------------------------------------------------
#
# Author: Kristinn Gudjonsson
# Version : 0.3
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

package Log2t::output::cef;

use strict;
use Getopt::Long;    # read parameters

my $version = "0.3";

# define the three needed strings that always follow
my $d_vendor  = 'log2timeline';
my $d_product = 'timeline_cef_output';
my $d_version = $version;

# define the version of CEF we are using
my $cef_version = 0;

# define the extra attributes that can be defined using parameters
my $dvc     = undef;
my $dvchost = undef;
my $smac    = undef;
my $suser   = undef;

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

    #        # read options from CMD
    #        @ARGV = @_;
    #        GetOptions(
    #		"dvc=s"=>\$dvc,
    #		"dvchost=s"=>\$dvchost,
    #		"smac=s"=>\$smac,
    #		"suser=s"=>\$suser
    #        );
}

#       get_description
# A simple subroutine that returns a string containing a description of
# the funcionality of the format file. This string is used when a list of
# all available format files is printed out
#
# @return A string containing a description of the format file's functionality
sub get_description() {
    return "Output timeline using the ArcSight Commen Event Format (CEF)";
}

sub print_header() {
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
sub print_line() {

    # the timestamp object
    my $class  = shift;
    my $t_line = shift;
    my $text;
    my $ext;
    my $scrub;
    my $mactime;

    # "fix" the name part so it can be included into CEF
    $scrub = $t_line->{'desc'};
    $scrub =~ s/=/\=/g;
    $scrub =~ s/\\/\\\\/g;

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
    if (scalar(%{$t_line})) {

      # CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
        $text = 'CEF:'
          . $cef_version . '|'
          . $d_vendor . '|'
          . $d_product . '|'
          . $d_version . '|'
          . $t_line->{'source'}
          . '|Timeline Event|5|';

        $ext = defined $dvc ? 'dvc=' . $dvc . ' ' : 'dvc=::IP:: ';
        $ext = $t_line->{'extra'}->{'src-ip'} if defined $t_line->{'extra'}->{'src-ip'};

        if ($t_line->{'extra'}->{'host'} ne 'unknown') {
            $ext .= 'dvchost=' . $t_line->{'extra'}->{'host'} . ' ';
        }
        else {
            $ext .= defined $dvchost ? 'dvchost=' . $dvchost . ' ' : 'dvchost=::HOSTNAME:: ';
        }

        $ext .= defined $smac ? 'smac=' . $smac . ' ' : 'smac=::MAC::';

        # now we need to figure out the fields that are defined or not
        $ext .=
          defined $t_line->{'extra'}->{'size'}
          ? ' fsize=' . $t_line->{'extra'}->{'size'}
          : ' fsize=0';
        $ext .= ' filePermission=';
        $ext .= defined $t_line->{'extra'}->{'mode'} ? $t_line->{'extra'}->{'mode'} : 0;
        $ext .= ' suid=';
        $ext .= defined $t_line->{'extra'}->{'uid'} ? $t_line->{'extra'}->{'uid'} : 0;
        $ext .= ' fileID=';
        $ext .= defined $t_line->{'extra'}->{'inode'} ? $t_line->{'extra'}->{'inode'} : 0;
        $ext .= ' fname=' . $t_line->{'extra'}->{'path'} . $t_line->{'extra'}->{'filename'};

        if ($t_line->{'extra'}->{'user'} ne 'unknown') {
            $ext .= ' suser=' . $t_line->{'extra'}->{'user'};
        }
        else {
            $ext .= defined $suser ? 'suser=' . $suser . ' ' : ' suser=::USERNAME::';
        }

        # go through each defined timestamp
        foreach (keys %{ $t_line->{'time'} }) {
            $mactime = $t_line->{'time'}->{$_}->{'legacy'} & 0b0001 ? 'M' : '.';
            $mactime .= $t_line->{'time'}->{$_}->{'legacy'} & 0b0010 ? 'A' : '.';
            $mactime .= $t_line->{'time'}->{$_}->{'legacy'} & 0b0100 ? 'C' : '.';
            $mactime .= $t_line->{'time'}->{$_}->{'legacy'} & 0b1000 ? 'B' : '.';
            ::print_line(  $text 
                         . $ext . ' act='
                         . $t_line->{'time'}->{$_}->{'type'} . ' rt='
                         . $t_line->{'time'}->{$_}->{'value'} * 1000
                         . ' msg=['
                         . $mactime . '] '
                         . $scrub
                         . "\n");
        }
    }

    return 1;
}

#       get_help
# A simple subroutine that returns a string containing the help
# message for this particular format file.
# @return A string containing a help file for this format file
sub get_help() {
    return "This output method prints the timeline in a Common Event Format as defined by ArcSight. 
This format can then be imported into any log device that supports CEF formats (there are some fields
that have not yet been filled out, please do so manually or by using a script";

}

1;

__END__

=pod

=head1 NAME

cef - Output plugin for the Commen Event Format (CEF) defined by ArcSight

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
