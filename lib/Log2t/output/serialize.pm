#################################################################################################
#   SERIALZE
#################################################################################################
#
# Author: Kristinn Gudjonsson
# Version : 0.1
# Date : 11/03/12
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

serialize - An output module that uses a simple JSON object to serialize the output.

=head1 DESCRIPTION

This output module of B<log2timeline> takes the t_line timesetamp object and serializes
it into a JSON object.

This makes the timestamp object saved in a 'native' object that can be loaded up
by the tool and simple filtering done on the object itself.

=cut
package Log2t::output::serialize;

use strict;
use Getopt::Long;    # read parameters
use Log2t::Time;     # for time stuff
use JSON::XS;        # for serializing the timestamp object

my $version = "0.1";

my $first_line;      # defines if we have printed a line or not


=head2 C<get_version>

A simple subroutine that returns the version number of the format file

=head3 Returns:

=head4 A version number of the module.

=cut
sub get_version() {
    return $version;
}

=head2 C<new>

A simple constructor of the output module. Takes care of parsing
parameters sent to the output module

=cut
sub new($) {
    my $class = shift;

    # bless the class ;)
    my $self = bless {}, $class;

    return $self;
}

=head2 C<get_description>

A simple subroutine that returns a string containing a description of
the funcionality of the format file. This string is used when a list of
all available format files is printed out

=head3 Returns:

=head4 A string containing a description of the format file's functionality.

=cut
sub get_description() {
    return "Save the output using a serialized object.";
}

=head2 C<print_header>

A simple sub routine that prints out a header. Since this serialied object
does not require any header information this sub routine does not really
do anything.

=head3 Returns:

=head4 Returns 1 if successful (which this sub routine always does).

=cut
sub print_header() {

    # since we really do not know how to construct the header, we need to wait
    $first_line = 1;
    return 1;
}

=head2 C<get_footer>

This simple sub routine is called to get a footer of the format. This is
done so that modules can append data to the output if wanted.

However, since this sub routine does not contain any footer it will
not return anym, insteead it returns a 0, indicating there is no footer to
be found.

=head3 Returns:

=head4 0 if no footer is there, otherwise a string cointaining the footer.

=cut
sub get_footer() {
    return 0;    # no footer
}

=head2 <print_footer>

A simple sub routine that is called after all lines have been printed, this is
called so that the module can print a footer.

Since this module does not contain any footer it simply returns straight away.

=head3 Returns:

=head4 A 1 indicating a success.

=cut
sub print_footer() {
    return 1;
}

=head2 C<print_line>

This routine gets sent a t_line or a timestamp object and stores it in a serialized
JSON object.

To make it easier to sort and do other filtering the output module splits up the timestamp
object into one object per timesstamp.

This increases space taken on hard drive, yet at the same time makes output processing
and sorting simpler.

=head3 Args:

=head4 t_line: A timestamp object, which is a reference to a hash that stores all the event information.

=cut
sub print_line() {
    my $self   = shift;
    my $t_line = shift;    # the timestamp object
    my $new_tline;

    if (!scalar(%{$t_line})) {
      return 0;
    }

    # copy the hash, without any timestamp
    $new_tline = $self->_copy_hash($t_line);

    #::print_line(encode_json($t_line) ."\n");
    foreach (keys %{$t_line->{'time'}}) {
        $new_tline->{'time'}->{0}->{'value'} = $t_line->{'time'}->{$_}->{'value'};
        $new_tline->{'time'}->{0}->{'legacy'} = $t_line->{'time'}->{$_}->{'legacy'};
        $new_tline->{'time'}->{0}->{'type'} = $t_line->{'time'}->{$_}->{'type'};
        ::print_line(encode_json($new_tline) . "\n");
    }
    return 1;
}

=head2 C<_copy_hash>

This sub routine is created to strip the timestamp out of a timestamp object.

Since we would like to serialize the timestamp as a single timestamp per entry, instead of
the default behaviour of possibly storing up to 8 timestamps, this routine copies the
timestamp object into a new reference to a hash, leaving the timestamps not copied.

That way the main routine can spawn copies of that new timestamp object and save
the values of all the timestamps stored in the original one, thus creating a single
timestamp object per timestamp.

=head3 Args:

=head4 t_line: A timestamp object that should be copied to a new value. This is a reference
to a hash.

=head3 Returns:

=head4 A copy of the hash, or a reference to that hash, which is an exact replica of the
original timestamp object without the timestamps associated to it.

=cut
sub _copy_hash($) {
    my $self = shift;
    my $t_line = shift;
    my %new;

    foreach (keys %{$t_line}) {
      next if /time/;
      $new{$_} = $t_line->{$_};
    }

    return \%new;
}


=head2 C<get_help>

A simple subroutine that returns a string containing the help
message for this particular output module.

=head3 Returns:

=head4 A string containing a help file for this format file
=cut
sub get_help() {
    return
      "This output module takes the timestamp object and simply serializes
it using the JSON::XS module, so the timestamp object can be read again
later for processing.i

The module splits the timestamp object into a single object per timestamp to
make filtering and sorting easier in the post-processing.";
}

1;

__END__

=pod

=head1 SEE ALSO

L<log2timeline> 
L<Log2Timeline>
