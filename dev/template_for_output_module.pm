#################################################################################################
#             OUTPUT
#################################################################################################
#
# Author: Kristinn Gudjonsson
# Version : 0.1
# Date : xx/xx/12
#
# Copyright 2009-2012 Kristinn Gudjonsson (kristinn ( a t ) log2timeline (d o t) net)
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

=pod
=head1 NAME

OUTPUT - an output module for log2timeline.

=head1 DESCRIPTION

This package provides an output module for the tool log2timeline.

The package takes as an input a hash that contains all the needed information to print or output
the timeline that has been produced by an input module.

=cut

package Log2t::output::OUTPUT;

use strict;
use Getopt::Long;    # read parameters

my $version = "0.1";

=head2 C<get_version>

A simple subroutine that returns the version number of the format file

=head3 Returns>

=head4  A version number, expressed as a string.
=cut

sub get_version() {
    return $version;
}

=head2 C<new>

A simple constructor of the output module. Takes care of parsing
parameters sent to the output module

=cut
sub new($) {
    my $quiet;

    # read options from CMD
    @ARGV = @_;
    GetOptions("quiet!" => \$quiet);
}

=head2 C<get_description>

A simple subroutine that returns a string containing a description of
the funcionality of the output module. This string is used when a list of
all available output modules is printed out

=head3 Returns:

=head4 A string containing a description of the output module and the
file format it uses.
=cut
sub get_description() {
    return "Output timeline using this particular output method";
}

=head2 C<print_header>

A simple sub routine that is called once before the processing is done
so that a header can be printed to the output file.

This can also be used to do some pre-processing on the file, even though
it is not necessarily connected to an output that gets printed. Such as
set up tables in a database, etc.

=head3 Returns:

=head4 1 if successful.

=cut
sub print_header() {
    return 1;
}

=head2 C<get_footer>

Some output modules print out a footer. That makes appending to the files
more difficult.

This sub routine simply returns the footer that it will print, so that the
main engine can remove the footer out of an already existing output file.

When the footer has been removed an output can be appended to the file.

=head3 Returns:

=head4 False if no footer is provided (0), or a string containing the
footer of the output format.

=cut
sub get_footer() {
    return 0;    # no footer
}

=head2 C<print_footer>

A simple output routine that prints out the footer of the format this
output module provides.

=head3 Returns:

=head4 1 if this completes successfully.

=cut
sub print_footer() {
    return 1;
}

=head2 C<print_line>

For each event extracted in the parsing phase of the engine a timestamp
object is created.

A timestamp object contains all the information and attributes of an event,
one if which is the 'time', which can contain more than one timestamp, there is
really no limit on the amount of timestamps that can be stored inside a single event.

All the attributes in the timestamp object describe all the timestamps that are
stored inside it, making it a more effecient form to store the timestamps.

This sub routine gets called once for each event or timestamp object created
inside the engine.

This sub routine should format the output in a way that fits the output
format that this module is implementing.

It then calls the function ::print_line, which is defined in the super
or parent (the front-end of the tool).

That subroutine is usally a very simple one, just calling the print
operation on the string this module produces.

However, since this module does not return a value that needs to be
printed the routine has the option of doing more complex operations
on the data, such as database manipulation/insertion, etc.

=head3 Args:

=head4 t_line: A timestamp object that needs to be outputted.

=head3 Returns:

=head4 Boolean value (0/1) indicating if there was some problems parsing the
timestamp object or not.

=cut
sub print_line() {

    my $self = shift;
    my $t_line = shift;
    my $text;

    if (scalar(%{$t_line}))

      while (my ($key, $value) = each(%{$t_line})) {
        $text .= "$key => $value\n";
    }

    ::print_line($text);

    return 1;
}

=head2 C<get_help>

A simple subroutine that returns a string containing the help
message for this particular output module.

This help file is called when using -h OUTPUT in the front-end.

It should usually contain information about the file format this
module uses, or some pointers into how to use the output for further
processing.

=head3 Returns:

=head4 A string containing a help file for this output module.

=cut
sub get_help() {
    return "This is an unknown output module. It must be very simple
since it is not being described here so no further information regarding the
output can be provided at this point.

Please change me....";
}

1;

__END__

=pod

=head1 SEE ALSO

L<log2timeline>

L<Log2Timeline>

=cut
